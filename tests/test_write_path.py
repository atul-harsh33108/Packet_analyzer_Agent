"""The write path (`T6-06`): the one door that changes policy, and its refusals.

The gate has four sentences, and every test here is one of them:

1. **One door verifies the digest and the tier.** A proposal that no longer
   hashes to its own digest is refused before the store is touched, and a
   refusal is refused rather than turned into an approval.
2. **It writes one new version and one audit entry.** The committed version is
   the one the proposal named, it becomes active, and exactly one chained entry
   names who, when, which agent, which run, which evidence, which prompt and
   which model.
3. **A replay is refused.** The same proposal digest cannot be applied twice,
   and a log that no longer verifies cannot be extended.
4. **The tier is not taken on trust.** Auto-apply requires a signature-table
   proposal and no approval; a human tier requires an *approved* request whose
   proposal and decision are the ones being applied. A record that is missing,
   pending, rejected, or about another change is refused.

The order is asserted structurally (digest check, then commit, then activate,
then append) and by failure: a commit that raises leaves nothing activated or
logged, and an activation that raises leaves nothing logged. The last write is
the audit entry so a record never claims a change that is not in force; the
honest cost is that a crash between activation and the append leaves the change
active and unlogged, which is named in the module rather than hidden.

The second half (`T6-07`) drives that door **end to end** over the real capture
and the real Policy agent: a scripted model proposes, the breaker classifies the
counterfactual that was actually run, a reviewer approves, the door applies, a
real pipeline run changes what it blocks, the log verifies, and a revert is a
new version that names the version it undid. The refusals are asserted on the
same road: a total loss is stopped before the store, the human gate cannot be
skipped by a missing, pending or rejected request, an approval for one change
cannot apply another, and the same change cannot be applied twice.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from agent_harness import connected, store_a_run, tool_schemas
from conftest import TEST_DPI_PCAP
from dpi_agents.model import ModelReply, ScriptedModel, ToolCall
from dpi_agents.nodes.policy import POLICY_TOOL_NAMES, StoreResolver, policy_node
from dpi_agents.runtime import Agent
from dpi_agents.tools import McpToolPort
from dpi_agents.trace import Trace
from dpi_engine.approval_queue import (
    ApprovalQueue,
    ApprovalQueueError,
    ApprovalRequest,
    ApprovalState,
)
from dpi_engine.audit_log import AUTO_ACTOR, AuditLog, AuditLogError
from dpi_engine.blast_radius import BreakerDecision, Reason, Tier, classify
from dpi_engine.pipeline import run_pipeline
from dpi_engine.proposal import Citation, Proposal
from dpi_engine.rule_manager import Provenance, RuleManager
from dpi_engine.rule_store import PolicyKind, PolicyVersion, RuleStore, RuleStoreError
from dpi_engine.rules.simulator import SimulationReport, simulate_ruleset
from dpi_engine.run_store import RunStore
from dpi_engine.types import AppType, FiveTuple, FlowRecord
from dpi_engine.write_path import AppliedChange, WritePath, WritePathError

RUN_ID = "0123456789abcdef"
REQUEST_ID = "fedcba9876543210"
OTHER_REQUEST_ID = "0011223344556677"
NOW = "2026-11-01T09:00:00+00:00"
LATER = "2026-11-01T10:30:00+00:00"
REVIEWER = "on-call-1"

_FLOW = FiveTuple(
    src_ip=0x0A000001,
    dst_ip=0x0A000002,
    src_port=49152,
    dst_port=443,
    protocol=6,
)
_RECORD = FlowRecord(
    src_ip=_FLOW.src_ip,
    dst_ip=_FLOW.dst_ip,
    src_port=_FLOW.src_port,
    dst_port=_FLOW.dst_port,
    protocol=_FLOW.protocol,
    app="TIKTOK",
    state="ESTABLISHED",
    packets=3,
    bytes=120,
)
_RULESET = {"blocked_apps": ["TIKTOK"]}
_SIGNATURES = {
    "version": 1,
    "signatures": [
        {"id": "sig-zoom", "app": "Zoom", "all_of": [{"field": "ja3", "value": "abcd"}]}
    ],
}


class _Resolver:
    def resolve(self, cited: Citation) -> FlowRecord | None:
        if cited.run_id == RUN_ID and cited.five_tuple == _FLOW:
            return _RECORD
        return None


def _proposal(
    *,
    kind: PolicyKind = PolicyKind.RULESET,
    document: dict[str, Any] | None = None,
    note: str = "blocked after review",
    parent: str | None = None,
) -> Proposal:
    default_document = _SIGNATURES if kind is PolicyKind.SIGNATURES else _RULESET
    return Proposal.build(
        kind=kind,
        document=default_document if document is None else document,
        provenance=Provenance(
            source="agent:policy",
            author="policy-agent/1",
            evidence=f"run {RUN_ID}",
            created_at=NOW,
        ),
        note=note,
        parent=parent,
        citations=(Citation(run_id=RUN_ID, five_tuple=_FLOW),),
        resolver=_Resolver(),
        agent_version="policy-agent/1",
        prompt_version="policy/1",
        model_version="model-x/2026-11-01",
    )


def _report(
    *,
    newly_blocked: tuple[Any, ...] = (),
    drop_rate_change_percent: float = 0.0,
    total_loss: bool = False,
) -> SimulationReport:
    return SimulationReport(
        newly_blocked=newly_blocked,
        newly_allowed=(),
        unchanged_blocked=(),
        baseline_blocked=0,
        candidate_blocked=len(newly_blocked),
        baseline_dropped=0,
        candidate_dropped=len(newly_blocked),
        baseline_forwarded=77,
        candidate_forwarded=77 - len(newly_blocked),
        baseline_total_packets=77,
        candidate_total_packets=77,
        drop_rate_change_percent=drop_rate_change_percent,
        total_loss=total_loss,
        baseline_output=Path("baseline_sim.pcap"),
        candidate_output=Path("candidate_sim.pcap"),
    )


def _one_click(proposal: Proposal | None = None) -> BreakerDecision:
    return classify(_proposal() if proposal is None else proposal, _report())


def _explicit(proposal: Proposal | None = None) -> BreakerDecision:
    return classify(
        _proposal() if proposal is None else proposal,
        _report(drop_rate_change_percent=6.0),
    )


def _auto(proposal: Proposal | None = None) -> BreakerDecision:
    chosen = _proposal(kind=PolicyKind.SIGNATURES) if proposal is None else proposal
    return classify(chosen, _report())


def _store_audit(tmp_path: Path) -> tuple[RuleStore, AuditLog]:
    return (
        RuleStore(tmp_path / "store", clock=lambda: NOW),
        AuditLog(tmp_path / "audit", clock=lambda: NOW),
    )


def _queue(tmp_path: Path) -> ApprovalQueue:
    return ApprovalQueue(tmp_path / "queue", clock=lambda: NOW)


def _approved(
    tmp_path: Path,
    proposal: Proposal,
    decision: BreakerDecision,
    *,
    request_id: str = REQUEST_ID,
    reviewer: str = REVIEWER,
) -> ApprovalRequest:
    queue = _queue(tmp_path)
    queue.submit(request_id, proposal, decision)
    return queue.approve(
        request_id, digest=proposal.digest, reviewer=reviewer
    )


class _RecordingStore(RuleStore):
    """A real store that also reports the order of the calls made to it."""

    def __init__(self, root: Path, calls: list[str]) -> None:
        super().__init__(root, clock=lambda: NOW)
        self.calls = calls

    def commit(self, *args: Any, **kwargs: Any) -> PolicyVersion:
        self.calls.append("commit")
        return super().commit(*args, **kwargs)

    def activate(self, *args: Any, **kwargs: Any) -> PolicyVersion:
        self.calls.append("activate")
        return super().activate(*args, **kwargs)


class _RecordingAudit(AuditLog):
    """A real log that also reports the order of the calls made to it."""

    def __init__(self, root: Path, calls: list[str]) -> None:
        super().__init__(root, clock=lambda: NOW)
        self.calls = calls

    def applied_digests(self) -> frozenset[str]:
        self.calls.append("digests")
        return super().applied_digests()

    def append(self, **kwargs: Any) -> Any:
        self.calls.append("append")
        return super().append(**kwargs)


class _FailingCommitStore(RuleStore):
    def __init__(self, root: Path, calls: list[str]) -> None:
        super().__init__(root)
        self.calls = calls

    def commit(self, *args: Any, **kwargs: Any) -> PolicyVersion:
        self.calls.append("commit")
        raise RuleStoreError("the store refused this document")


class _FailingActivateStore(RuleStore):
    def __init__(self, root: Path) -> None:
        super().__init__(root)

    def activate(self, *args: Any, **kwargs: Any) -> PolicyVersion:
        raise RuleStoreError("the pointer could not be written")


# ---------------------------------------------------------------------------
# The happy path: commit, activate, record
# ---------------------------------------------------------------------------


class TestTheHappyPath:
    def test_a_one_click_approval_commits_activates_and_records(
        self, tmp_path: Path
    ) -> None:
        store, audit = _store_audit(tmp_path)
        proposal = _proposal()
        decision = _one_click(proposal)
        approval = _approved(tmp_path, proposal, decision)
        path = WritePath(store, audit)

        change = path.apply(proposal, decision, approval=approval)

        assert isinstance(change, AppliedChange)
        assert path.store is store
        assert path.audit is audit
        assert change.version_id == proposal.version_id
        assert change.proposal_digest == proposal.digest
        assert change.tier is Tier.ONE_CLICK
        assert store.active(proposal.kind) is not None
        active = store.active(proposal.kind)
        assert active is not None
        assert active.version_id == change.version.version_id == proposal.version_id
        assert [version.version_id for version in store.history()] == [
            proposal.version_id
        ]
        assert audit.verify_chain() == (change.record,)
        assert change.record.actor == REVIEWER
        assert change.record.applied_at == NOW
        assert change.record.tier is Tier.ONE_CLICK
        assert change.record.request_id == REQUEST_ID
        assert change.record.proposal_digest == proposal.digest
        assert change.record.version_id == proposal.version_id
        assert change.record.agent_version == "policy-agent/1"
        assert change.record.prompt_version == "policy/1"
        assert change.record.model_version == "model-x/2026-11-01"
        assert change.record.runs == (RUN_ID,)
        assert audit.applied_digests() == {proposal.digest}

    def test_an_explicit_confirmation_is_recorded_as_one(self, tmp_path: Path) -> None:
        store, audit = _store_audit(tmp_path)
        proposal = _proposal()
        decision = _explicit(proposal)
        approval = _approved(tmp_path, proposal, decision)

        change = WritePath(store, audit).apply(proposal, decision, approval=approval)

        assert change.record.tier is Tier.EXPLICIT_CONFIRM
        assert change.record.actor == REVIEWER

    def test_an_auto_applied_signature_change_needs_no_request(
        self, tmp_path: Path
    ) -> None:
        store, audit = _store_audit(tmp_path)
        proposal = _proposal(kind=PolicyKind.SIGNATURES)
        decision = _auto(proposal)

        change = WritePath(store, audit).apply(proposal, decision)

        assert decision.tier is Tier.AUTO_APPLY
        assert change.record.tier is Tier.AUTO_APPLY
        assert change.record.actor == AUTO_ACTOR
        assert change.record.request_id is None
        active = store.active(PolicyKind.SIGNATURES)
        assert active is not None
        assert active.version_id == proposal.version_id
        assert audit.verify_chain() == (change.record,)

    def test_the_audit_entry_names_the_evidence_it_was_reviewed_with(
        self, tmp_path: Path
    ) -> None:
        store, audit = _store_audit(tmp_path)
        proposal = _proposal()
        decision = _one_click(proposal)

        change = WritePath(store, audit).apply(
            proposal, decision, approval=_approved(tmp_path, proposal, decision)
        )

        assert change.record.citations == proposal.citations
        assert change.record.runs == (RUN_ID,)


# ---------------------------------------------------------------------------
# The digest is re-derived, not trusted
# ---------------------------------------------------------------------------


class TestTheDigestIsRechecked:
    def test_an_edited_document_is_refused_before_the_store_is_touched(
        self, tmp_path: Path
    ) -> None:
        calls: list[str] = []
        store = _RecordingStore(tmp_path / "store", calls)
        audit = _RecordingAudit(tmp_path / "audit", calls)
        proposal = _proposal()
        decision = _one_click(proposal)
        approval = _approved(tmp_path, proposal, decision)
        proposal.document["blocked_apps"] = ["YOUTUBE"]

        with pytest.raises(WritePathError, match="digest"):
            WritePath(store, audit).apply(proposal, decision, approval=approval)

        assert calls == []
        assert audit.verify_chain() == ()
        assert store.active(proposal.kind) is None

    def test_a_forged_version_id_is_caught_before_activation(
        self, tmp_path: Path
    ) -> None:
        store, audit = _store_audit(tmp_path)
        proposal = _proposal()
        object.__setattr__(proposal, "version_id", "f" * 16)
        object.__setattr__(proposal, "digest", proposal.computed_digest)
        decision = _one_click(proposal)
        # Built directly rather than through the queue: the queue would refuse
        # this proposal on load, and the point here is what the apply door does
        # when a corrupted value reaches it anyway.
        approval = ApprovalRequest(
            request_id=REQUEST_ID,
            state=ApprovalState.APPROVED,
            created_at=NOW,
            decided_at=LATER,
            reviewer=REVIEWER,
            note="",
            proposal=proposal,
            decision=decision,
        )

        with pytest.raises(WritePathError, match="version"):
            WritePath(store, audit).apply(proposal, decision, approval=approval)

        assert store.active(proposal.kind) is None
        assert audit.verify_chain() == ()


# ---------------------------------------------------------------------------
# The tier is re-checked, not taken on trust
# ---------------------------------------------------------------------------


class TestTheTierIsRechecked:
    def test_a_refused_decision_never_touches_the_store(self, tmp_path: Path) -> None:
        calls: list[str] = []
        store = _RecordingStore(tmp_path / "store", calls)
        audit = _RecordingAudit(tmp_path / "audit", calls)
        proposal = _proposal()
        decision = classify(
            proposal, _report(newly_blocked=(), total_loss=True)
        )

        assert decision.tier is Tier.REFUSED
        with pytest.raises(WritePathError, match="breaker refused"):
            WritePath(store, audit).apply(proposal, decision)

        assert calls == []
        assert audit.verify_chain() == ()
        assert store.history() == ()

    def test_an_auto_apply_of_a_ruleset_is_refused(self, tmp_path: Path) -> None:
        """A forged tier must not turn a ruleset change into an automatic one."""
        calls: list[str] = []
        store = _RecordingStore(tmp_path / "store", calls)
        audit = _RecordingAudit(tmp_path / "audit", calls)
        proposal = _proposal()
        forged = BreakerDecision(
            tier=Tier.AUTO_APPLY,
            reasons=(Reason.SIGNATURE_TABLE,),
            flows_newly_blocked=0,
            drop_rate_change_percent=0.0,
            protected_apps=(),
        )

        with pytest.raises(WritePathError, match="signature"):
            WritePath(store, audit).apply(proposal, forged)

        assert calls == []
        assert audit.verify_chain() == ()

    def test_an_auto_apply_cannot_carry_an_approval(self, tmp_path: Path) -> None:
        store, audit = _store_audit(tmp_path)
        proposal = _proposal(kind=PolicyKind.SIGNATURES)
        decision = _auto(proposal)
        approval = ApprovalRequest(
            request_id=REQUEST_ID,
            state=ApprovalState.APPROVED,
            created_at=NOW,
            decided_at=LATER,
            reviewer=REVIEWER,
            note="",
            proposal=proposal,
            decision=BreakerDecision(
                tier=Tier.EXPLICIT_CONFIRM,
                reasons=(Reason.CRITIC_OBJECTION,),
                flows_newly_blocked=0,
                drop_rate_change_percent=0.0,
                protected_apps=(),
            ),
        )

        with pytest.raises(WritePathError, match="auto-apply"):
            WritePath(store, audit).apply(proposal, decision, approval=approval)

        assert audit.verify_chain() == ()
        assert store.active(PolicyKind.SIGNATURES) is None


# ---------------------------------------------------------------------------
# The human gate is required for every human tier
# ---------------------------------------------------------------------------


class TestTheApprovalIsRequired:
    @pytest.mark.parametrize("decision_kind", ["one-click", "explicit-confirm"])
    def test_a_human_tier_without_an_approval_is_refused(
        self, tmp_path: Path, decision_kind: str
    ) -> None:
        store, audit = _store_audit(tmp_path)
        proposal = _proposal()
        decision = _one_click(proposal) if decision_kind == "one-click" else _explicit(
            proposal
        )

        with pytest.raises(WritePathError, match="approv"):
            WritePath(store, audit).apply(proposal, decision)

        assert audit.verify_chain() == ()
        assert store.active(proposal.kind) is None

    def test_a_pending_request_is_not_an_approval(self, tmp_path: Path) -> None:
        store, audit = _store_audit(tmp_path)
        proposal = _proposal()
        decision = _one_click(proposal)
        queue = _queue(tmp_path)
        queue.submit(REQUEST_ID, proposal, decision)
        pending = queue.load(REQUEST_ID)

        with pytest.raises(WritePathError, match="approv"):
            WritePath(store, audit).apply(proposal, decision, approval=pending)

        assert pending.state is ApprovalState.PENDING
        assert audit.verify_chain() == ()

    def test_a_rejected_request_is_not_an_approval(self, tmp_path: Path) -> None:
        store, audit = _store_audit(tmp_path)
        proposal = _proposal()
        decision = _one_click(proposal)
        queue = _queue(tmp_path)
        queue.submit(REQUEST_ID, proposal, decision)
        rejected = queue.reject(REQUEST_ID, reviewer=REVIEWER, note="not today")

        with pytest.raises(WritePathError, match="approv"):
            WritePath(store, audit).apply(proposal, decision, approval=rejected)

        assert rejected.state is ApprovalState.REJECTED
        assert audit.verify_chain() == ()

    def test_an_approval_for_another_proposal_is_refused(
        self, tmp_path: Path
    ) -> None:
        store, audit = _store_audit(tmp_path)
        approved_proposal = _proposal()
        other = _proposal(note="a different change")
        decision = _one_click(approved_proposal)
        approval = _approved(tmp_path, approved_proposal, decision)
        other_decision = _one_click(other)

        with pytest.raises(WritePathError, match="digest"):
            WritePath(store, audit).apply(
                other, other_decision, approval=approval
            )

        assert audit.verify_chain() == ()
        assert store.active(other.kind) is None

    def test_an_approval_for_another_decision_is_refused(
        self, tmp_path: Path
    ) -> None:
        store, audit = _store_audit(tmp_path)
        proposal = _proposal()
        approved = _one_click(proposal)
        approval = _approved(tmp_path, proposal, approved)
        escalated = _explicit(proposal)

        with pytest.raises(WritePathError, match="decision"):
            WritePath(store, audit).apply(proposal, escalated, approval=approval)

        assert audit.verify_chain() == ()
        assert store.active(proposal.kind) is None


# ---------------------------------------------------------------------------
# Replay, and a log that no longer verifies
# ---------------------------------------------------------------------------


class TestReplay:
    def test_the_same_digest_cannot_be_applied_twice(self, tmp_path: Path) -> None:
        calls: list[str] = []
        store = _RecordingStore(tmp_path / "store", calls)
        audit = _RecordingAudit(tmp_path / "audit", calls)
        proposal = _proposal()
        decision = _one_click(proposal)
        approval = _approved(tmp_path, proposal, decision)
        path = WritePath(store, audit)
        change = path.apply(proposal, decision, approval=approval)
        calls.clear()

        with pytest.raises(WritePathError, match="already applied"):
            path.apply(proposal, decision, approval=approval)

        assert calls == ["digests"]
        assert audit.verify_chain() == (change.record,)
        assert store.active(proposal.kind) is not None
        active = store.active(proposal.kind)
        assert active is not None
        assert active.version_id == proposal.version_id
        assert len(store.history()) == 1

    def test_a_broken_log_cannot_be_extended(self, tmp_path: Path) -> None:
        store, audit = _store_audit(tmp_path)
        first = _proposal()
        first_decision = _one_click(first)
        WritePath(store, audit).apply(
            first, first_decision, approval=_approved(tmp_path, first, first_decision)
        )
        raw = json.loads(audit.path.read_text(encoding="utf-8"))
        raw["actor"] = "someone-else"
        audit.path.write_text(json.dumps(raw) + "\n", encoding="utf-8")

        second = _proposal(note="a second change")
        second_decision = _one_click(second)
        second_approval = _approved(
            tmp_path, second, second_decision, request_id=OTHER_REQUEST_ID
        )
        with pytest.raises(AuditLogError, match="hash"):
            WritePath(store, audit).apply(
                second, second_decision, approval=second_approval
            )

        active = store.active(second.kind)
        assert active is not None
        assert active.version_id == first.version_id
        assert len(store.history()) == 1


# ---------------------------------------------------------------------------
# The order: check, commit, activate, append
# ---------------------------------------------------------------------------


class TestTheOrder:
    def test_the_calls_happen_in_the_order_the_door_promises(
        self, tmp_path: Path
    ) -> None:
        calls: list[str] = []
        store = _RecordingStore(tmp_path / "store", calls)
        audit = _RecordingAudit(tmp_path / "audit", calls)
        proposal = _proposal()
        decision = _one_click(proposal)
        approval = _approved(tmp_path, proposal, decision)

        WritePath(store, audit).apply(proposal, decision, approval=approval)

        assert calls == ["digests", "commit", "activate", "append"]

    def test_a_failed_commit_activates_and_logs_nothing(
        self, tmp_path: Path
    ) -> None:
        calls: list[str] = []
        store = _FailingCommitStore(tmp_path / "store", calls)
        audit = _RecordingAudit(tmp_path / "audit", calls)
        proposal = _proposal()
        decision = _one_click(proposal)
        approval = _approved(tmp_path, proposal, decision)

        with pytest.raises(RuleStoreError, match="refused"):
            WritePath(store, audit).apply(proposal, decision, approval=approval)

        assert calls == ["digests", "commit"]
        assert audit.verify_chain() == ()
        assert store.history() == ()

    def test_a_failed_activation_logs_nothing(self, tmp_path: Path) -> None:
        store = _FailingActivateStore(tmp_path / "store")
        audit = _RecordingAudit(tmp_path / "audit", [])
        proposal = _proposal()
        decision = _one_click(proposal)
        approval = _approved(tmp_path, proposal, decision)

        with pytest.raises(RuleStoreError, match="pointer"):
            WritePath(store, audit).apply(proposal, decision, approval=approval)

        assert audit.verify_chain() == ()
        assert store.active(proposal.kind) is None
        # The version was committed, but an inert version is not a change.
        assert len(store.history()) == 1


# ---------------------------------------------------------------------------
# Construction and the value it returns
# ---------------------------------------------------------------------------


class TestTheDoorItself:
    def test_the_door_needs_a_store_and_a_log(self, tmp_path: Path) -> None:
        store, audit = _store_audit(tmp_path)

        with pytest.raises(WritePathError, match="RuleStore"):
            WritePath("not a store", audit)  # type: ignore[arg-type]
        with pytest.raises(WritePathError, match="AuditLog"):
            WritePath(store, "not a log")  # type: ignore[arg-type]

    def test_a_change_cannot_be_edited_after_it_is_returned(
        self, tmp_path: Path
    ) -> None:
        store, audit = _store_audit(tmp_path)
        proposal = _proposal()
        decision = _one_click(proposal)

        change = WritePath(store, audit).apply(
            proposal, decision, approval=_approved(tmp_path, proposal, decision)
        )

        with pytest.raises(AttributeError):
            change.version = change.version  # type: ignore[misc]
        with pytest.raises(AttributeError):
            change.record.actor = "someone-else"  # type: ignore[misc]

    def test_apply_refuses_the_wrong_kind_of_argument(self, tmp_path: Path) -> None:
        store, audit = _store_audit(tmp_path)
        proposal = _proposal()
        decision = _one_click(proposal)
        path = WritePath(store, audit)

        with pytest.raises(WritePathError, match="Proposal"):
            path.apply("not a proposal", decision)  # type: ignore[arg-type]
        with pytest.raises(WritePathError, match="BreakerDecision"):
            path.apply(proposal, "not a decision")  # type: ignore[arg-type]
        with pytest.raises(WritePathError, match="ApprovalRequest"):
            path.apply(
                proposal,
                decision,
                approval="not an approval",  # type: ignore[arg-type]
            )
        assert audit.verify_chain() == ()

    def test_an_approval_that_disagrees_about_the_proposal_is_refused(
        self, tmp_path: Path
    ) -> None:
        store, audit = _store_audit(tmp_path)
        proposal = _proposal()
        other = _proposal(note="a different change")
        object.__setattr__(other, "digest", proposal.digest)
        decision = _one_click(proposal)
        approval = ApprovalRequest(
            request_id=REQUEST_ID,
            state=ApprovalState.APPROVED,
            created_at=NOW,
            decided_at=LATER,
            reviewer=REVIEWER,
            note="",
            proposal=other,
            decision=decision,
        )

        with pytest.raises(WritePathError, match="proposal"):
            WritePath(store, audit).apply(proposal, decision, approval=approval)

        assert audit.verify_chain() == ()
        assert store.active(proposal.kind) is None

    def test_an_approved_request_with_no_reviewer_is_refused(
        self, tmp_path: Path
    ) -> None:
        """The record is checked here too, not trusted because a loader built it."""
        store, audit = _store_audit(tmp_path)
        proposal = _proposal()
        decision = _one_click(proposal)
        approval = _approved(tmp_path, proposal, decision)
        object.__setattr__(approval, "reviewer", None)

        with pytest.raises(WritePathError, match="reviewer"):
            WritePath(store, audit).apply(proposal, decision, approval=approval)

        assert audit.verify_chain() == ()
        assert store.active(proposal.kind) is None


# ---------------------------------------------------------------------------
# End to end: propose, classify, approve, apply, run, revert (`T6-07`)
# ---------------------------------------------------------------------------

_MODEL_VERSION = "scripted/1"
_REVERT_REQUEST_ID = "aabbccddeeff0011"


@dataclasses.dataclass(slots=True)
class _EndToEnd:
    """The state one full pass through the write path leaves behind."""

    capture: Path
    runs: Path
    run_id: str
    store: RuleStore
    audit: AuditLog
    queue: ApprovalQueue
    baseline: Proposal
    baseline_change: AppliedChange
    change: Proposal
    change_decision: BreakerDecision
    applied: AppliedChange


@dataclasses.dataclass(slots=True)
class _Candidate:
    """One real proposal, classified, and not yet applied."""

    capture: Path
    runs: Path
    run_id: str
    store: RuleStore
    audit: AuditLog
    queue: ApprovalQueue
    proposal: Proposal
    decision: BreakerDecision


def _captured_run(tmp_path: Path) -> tuple[Path, Path, str]:
    """A real capture, the run store it is recorded in, and its run id."""
    capture = Path(TEST_DPI_PCAP)
    runs = tmp_path / "runs"
    return capture, runs, store_a_run(capture, runs)


def _tiktok_flow(run_id: str, runs: Path) -> FlowRecord:
    return next(
        flow
        for flow in RunStore(runs).query(run_id)
        if flow.app == AppType.TIKTOK.name and flow.hostname == "www.tiktok.com"
    )


def _propose(
    tmp_path: Path,
    *,
    capture: Path,
    runs: Path,
    run_id: str,
    document: dict[str, Any],
    note: str,
    parent: str | None = None,
    simulate: bool = True,
) -> Proposal:
    """Drives the real Policy agent over the real capture and MCP server.

    The model is scripted, so the test still needs no provider key; the tools,
    the dry run and the citation resolution are the production ones. The
    proposal's parent and versions are the node's, never the model's.
    """
    flow = _tiktok_flow(run_id, runs)
    answer = json.dumps(
        {
            "kind": "ruleset",
            "document": document,
            "note": note,
            "citations": [dict(flow.five_tuple._asdict())],
        }
    )
    simulation_dir = tmp_path / "simulation"

    async def scenario() -> Proposal:
        async with connected(runs) as session:
            schemas = await tool_schemas(session, POLICY_TOOL_NAMES)
            replies = [
                ModelReply(
                    text="reading the run",
                    tool_calls=(
                        ToolCall(
                            name="query_flows",
                            arguments={"run_id": run_id, "app": "TIKTOK"},
                        ),
                    ),
                )
            ]
            if simulate:
                replies.append(
                    ModelReply(
                        text="simulating the change",
                        tool_calls=(
                            ToolCall(
                                name="simulate_ruleset",
                                arguments={
                                    "capture": str(capture),
                                    "candidate": document,
                                    "output_dir": str(simulation_dir),
                                },
                            ),
                        ),
                    )
                )
            replies.append(ModelReply(text=answer))
            node = policy_node(
                schemas,
                run_id=run_id,
                capture=capture,
                simulation_dir=simulation_dir,
                resolver=StoreResolver(RunStore(runs)),
                model_version=_MODEL_VERSION,
                parent=parent,
            )
            with Trace(tmp_path / "trace.jsonl") as trace:
                outcome = await Agent(
                    model=ScriptedModel(replies), trace=trace
                ).run(node, tools=McpToolPort(session))
        assert outcome.reason == "verdict", outcome.error
        proposal = outcome.verdict
        assert isinstance(proposal, Proposal)
        return proposal

    return asyncio.run(scenario())


def _active_rules(store: RuleStore) -> RuleManager:
    version = store.active(PolicyKind.RULESET)
    assert version is not None, "the change did not leave an active version"
    return RuleManager.from_dict(version.document)


def _blocked_apps(capture: Path, rules: RuleManager, output: Path) -> list[str]:
    """The apps a real pipeline run blocks under `rules`."""
    result = run_pipeline(str(capture), output, rules, with_flow_table=True)
    return [app.name for _five_tuple, app, _sni in result.blocked_flows]


def _simulate(
    capture: Path,
    baseline: RuleManager,
    candidate: RuleManager,
    output_dir: Path,
) -> SimulationReport:
    return simulate_ruleset(baseline, candidate, capture, output_dir=output_dir)


def _ground_truth(capture: Path, proposal: Proposal, output_dir: Path) -> SimulationReport:
    """The counterfactual the breaker reads: the policy in force versus this one."""
    return _simulate(
        capture,
        RuleManager(),
        RuleManager.from_dict(proposal.document),
        output_dir,
    )


def _end_to_end(tmp_path: Path) -> _EndToEnd:
    """Baseline version, then a real TikTok block, each reviewed and applied."""
    capture, runs, run_id = _captured_run(tmp_path)
    store, audit = _store_audit(tmp_path)
    queue = _queue(tmp_path)
    path = WritePath(store, audit)

    baseline = _propose(
        tmp_path,
        capture=capture,
        runs=runs,
        run_id=run_id,
        document={},
        note="Establish the empty ruleset as the version this change is measured against.",
        simulate=False,
    )
    baseline_decision = classify(baseline, _ground_truth(capture, baseline, tmp_path / "sim-baseline"))
    assert baseline_decision.tier is Tier.ONE_CLICK
    queue.submit(REQUEST_ID, baseline, baseline_decision)
    baseline_change = path.apply(
        baseline,
        baseline_decision,
        approval=queue.approve(
            REQUEST_ID, digest=baseline.digest, reviewer=REVIEWER
        ),
    )

    change = _propose(
        tmp_path,
        capture=capture,
        runs=runs,
        run_id=run_id,
        document={"blocked_apps": [AppType.TIKTOK.name]},
        note="The run shows a TikTok flow the policy in force allows.",
        parent=baseline_change.version_id,
        simulate=False,
    )
    decision = classify(
        change,
        _simulate(
            capture,
            _active_rules(store),
            RuleManager.from_dict(change.document),
            tmp_path / "sim-change",
        ),
    )
    queue.submit(OTHER_REQUEST_ID, change, decision)
    applied = path.apply(
        change,
        decision,
        approval=queue.approve(
            OTHER_REQUEST_ID, digest=change.digest, reviewer=REVIEWER
        ),
    )
    return _EndToEnd(
        capture=capture,
        runs=runs,
        run_id=run_id,
        store=store,
        audit=audit,
        queue=queue,
        baseline=baseline,
        baseline_change=baseline_change,
        change=change,
        change_decision=decision,
        applied=applied,
    )


def _candidate(tmp_path: Path) -> _Candidate:
    """One real proposal classified against the policy in force, not applied."""
    capture, runs, run_id = _captured_run(tmp_path)
    store, audit = _store_audit(tmp_path)
    proposal = _propose(
        tmp_path,
        capture=capture,
        runs=runs,
        run_id=run_id,
        document={"blocked_apps": [AppType.TIKTOK.name]},
        note="The run shows a TikTok flow the policy in force allows.",
        simulate=False,
    )
    decision = classify(
        proposal, _ground_truth(capture, proposal, tmp_path / "sim-candidate")
    )
    return _Candidate(
        capture=capture,
        runs=runs,
        run_id=run_id,
        store=store,
        audit=audit,
        queue=_queue(tmp_path),
        proposal=proposal,
        decision=decision,
    )


class TestTheWritePathEndToEnd:
    def test_a_reviewed_change_is_applied_and_the_run_changes(
        self, tmp_path: Path
    ) -> None:
        world = _end_to_end(tmp_path)

        # The change is a real one: the policy in force before it blocked
        # nothing, and the fixture has a TikTok flow for the new policy to block.
        baseline_rules = RuleManager.from_dict(
            world.store.load(world.baseline_change.version_id).document
        )
        assert _blocked_apps(
            world.capture, baseline_rules, tmp_path / "before.pcap"
        ) == []
        assert world.change_decision.tier is Tier.EXPLICIT_CONFIRM
        assert world.change_decision.flows_newly_blocked == 1

        blocked = _blocked_apps(
            world.capture, _active_rules(world.store), tmp_path / "after.pcap"
        )
        assert blocked == [AppType.TIKTOK.name]

        # One change, one active version, one chained audit entry -- all naming
        # the same proposal, run and reviewer.
        active = world.store.active(PolicyKind.RULESET)
        assert active is not None
        assert active.version_id == world.applied.version_id == world.change.version_id
        assert active.parent == world.baseline_change.version_id
        assert {version.version_id for version in world.store.history()} == {
            world.baseline_change.version_id,
            world.applied.version_id,
        }
        records = world.audit.verify_chain()
        assert [record.version_id for record in records] == [
            world.baseline_change.version_id,
            world.applied.version_id,
        ]
        record = records[-1]
        assert record == world.applied.record
        assert record.actor == REVIEWER
        assert record.request_id == OTHER_REQUEST_ID
        assert record.tier is Tier.EXPLICIT_CONFIRM
        assert record.runs == (world.run_id,)
        assert record.citations == world.change.citations
        assert record.agent_version == world.change.agent_version
        assert record.prompt_version == world.change.prompt_version
        assert record.model_version == world.change.model_version
        assert world.audit.applied_digests() == {
            world.baseline.digest,
            world.change.digest,
        }

    def test_a_revert_is_a_new_version_that_names_and_undoes_the_change(
        self, tmp_path: Path
    ) -> None:
        world = _end_to_end(tmp_path)
        prior = world.store.load(world.baseline_change.version_id)
        applied = world.store.load(world.applied.version_id)
        assert _blocked_apps(
            world.capture, _active_rules(world.store), tmp_path / "applied.pcap"
        ) == [AppType.TIKTOK.name]

        revert = _propose(
            tmp_path,
            capture=world.capture,
            runs=world.runs,
            run_id=world.run_id,
            document=prior.document,
            note=f"Revert {applied.version_id}: restore the policy in force before it.",
            parent=applied.version_id,
            simulate=False,
        )
        report = _simulate(
            world.capture,
            _active_rules(world.store),
            RuleManager.from_dict(revert.document),
            tmp_path / "sim-revert",
        )
        decision = classify(revert, report)
        assert decision.tier is Tier.ONE_CLICK
        assert decision.flows_newly_blocked == 0
        assert len(report.newly_allowed) == 1

        world.queue.submit(_REVERT_REQUEST_ID, revert, decision)
        revert_change = WritePath(world.store, world.audit).apply(
            revert,
            decision,
            approval=world.queue.approve(
                _REVERT_REQUEST_ID, digest=revert.digest, reviewer=REVIEWER
            ),
        )

        # A revert is a new version, not a rollback of the pointer: it names
        # the version it undid, and that version stays in history.
        assert revert_change.version_id != prior.version_id
        assert revert_change.version.parent == applied.version_id
        assert revert_change.version.document == prior.document
        active = world.store.active(PolicyKind.RULESET)
        assert active is not None
        assert active.version_id == revert_change.version_id
        assert {version.version_id for version in world.store.history()} == {
            prior.version_id,
            applied.version_id,
            revert_change.version_id,
        }

        # The run is restored, and every change is still in the chain.
        assert _blocked_apps(
            world.capture, _active_rules(world.store), tmp_path / "reverted.pcap"
        ) == []
        records = world.audit.verify_chain()
        assert [record.version_id for record in records] == [
            world.baseline_change.version_id,
            applied.version_id,
            revert_change.version_id,
        ]
        assert records[-1] == revert_change.record
        assert records[-1].request_id == _REVERT_REQUEST_ID
        assert world.audit.applied_digests() == {
            world.baseline.digest,
            world.change.digest,
            revert.digest,
        }


class TestTheEndToEndRefusals:
    def test_a_total_loss_is_refused_before_the_store_is_touched(
        self, tmp_path: Path
    ) -> None:
        capture, runs, run_id = _captured_run(tmp_path)
        store, audit = _store_audit(tmp_path)
        queue = _queue(tmp_path)
        loss = RuleManager()
        loss.block_cidr("0.0.0.0/0")
        proposal = _propose(
            tmp_path,
            capture=capture,
            runs=runs,
            run_id=run_id,
            document=loss.to_dict(),
            note="Block every address, which is the change that must never apply.",
            simulate=False,
        )
        report = _simulate(capture, RuleManager(), loss, tmp_path / "sim-loss")
        decision = classify(proposal, report)

        assert report.total_loss
        assert decision.tier is Tier.REFUSED
        with pytest.raises(ApprovalQueueError, match="forwards nothing"):
            queue.submit(REQUEST_ID, proposal, decision)
        with pytest.raises(WritePathError, match="breaker refused this proposal"):
            WritePath(store, audit).apply(proposal, decision)

        assert store.history() == ()
        assert audit.verify_chain() == ()
        assert audit.applied_digests() == frozenset()

    @pytest.mark.parametrize(
        ("state", "message"),
        [
            ("missing", "requires an approved request"),
            ("pending", "is pending, not approved"),
            ("rejected", "is rejected, not approved"),
        ],
    )
    def test_the_human_gate_cannot_be_skipped(
        self, tmp_path: Path, state: str, message: str
    ) -> None:
        candidate = _candidate(tmp_path)
        approval: ApprovalRequest | None = None
        if state == "pending":
            candidate.queue.submit(
                REQUEST_ID, candidate.proposal, candidate.decision
            )
            approval = candidate.queue.load(REQUEST_ID)
        elif state == "rejected":
            candidate.queue.submit(
                REQUEST_ID, candidate.proposal, candidate.decision
            )
            approval = candidate.queue.reject(
                REQUEST_ID, reviewer=REVIEWER, note="not today"
            )

        with pytest.raises(WritePathError, match=message):
            WritePath(candidate.store, candidate.audit).apply(
                candidate.proposal, candidate.decision, approval=approval
            )

        assert candidate.store.active(PolicyKind.RULESET) is None
        assert candidate.store.history() == ()
        assert candidate.audit.verify_chain() == ()

    def test_an_approval_for_another_change_cannot_apply_this_one(
        self, tmp_path: Path
    ) -> None:
        candidate = _candidate(tmp_path)
        other = _propose(
            tmp_path,
            capture=candidate.capture,
            runs=candidate.runs,
            run_id=candidate.run_id,
            document={"blocked_apps": [AppType.YOUTUBE.name]},
            note="A different change, reviewed under a different request.",
            simulate=False,
        )
        other_decision = classify(
            other, _ground_truth(candidate.capture, other, tmp_path / "sim-other")
        )
        candidate.queue.submit(REQUEST_ID, candidate.proposal, candidate.decision)
        approval = candidate.queue.approve(
            REQUEST_ID, digest=candidate.proposal.digest, reviewer=REVIEWER
        )

        with pytest.raises(
            WritePathError, match="Approving one change cannot apply another"
        ):
            WritePath(candidate.store, candidate.audit).apply(
                other, other_decision, approval=approval
            )

        assert candidate.store.active(PolicyKind.RULESET) is None
        assert candidate.store.history() == ()
        assert candidate.audit.verify_chain() == ()

    def test_a_change_cannot_be_applied_twice(self, tmp_path: Path) -> None:
        world = _end_to_end(tmp_path)
        approval = world.queue.load(OTHER_REQUEST_ID)

        with pytest.raises(WritePathError, match="already applied"):
            WritePath(world.store, world.audit).apply(
                world.change, world.change_decision, approval=approval
            )

        assert len(world.store.history()) == 2
        assert len(world.audit.verify_chain()) == 2
        active = world.store.active(PolicyKind.RULESET)
        assert active is not None
        assert active.version_id == world.applied.version_id

    def test_an_edited_proposal_is_refused_before_the_store_is_touched(
        self, tmp_path: Path
    ) -> None:
        candidate = _candidate(tmp_path)
        candidate.queue.submit(REQUEST_ID, candidate.proposal, candidate.decision)
        approval = candidate.queue.approve(
            REQUEST_ID, digest=candidate.proposal.digest, reviewer=REVIEWER
        )
        candidate.proposal.document["blocked_apps"] = [AppType.YOUTUBE.name]

        with pytest.raises(WritePathError, match="does not match its contents"):
            WritePath(candidate.store, candidate.audit).apply(
                candidate.proposal, candidate.decision, approval=approval
            )

        assert candidate.store.active(PolicyKind.RULESET) is None
        assert candidate.store.history() == ()
        assert candidate.audit.verify_chain() == ()

    def test_a_ruleset_cannot_be_smuggled_through_auto_apply(
        self, tmp_path: Path
    ) -> None:
        candidate = _candidate(tmp_path)
        forged = BreakerDecision(
            tier=Tier.AUTO_APPLY,
            reasons=(Reason.SIGNATURE_TABLE,),
            flows_newly_blocked=0,
            drop_rate_change_percent=0.0,
            protected_apps=(),
        )

        with pytest.raises(
            WritePathError, match="only for a signatures proposal"
        ):
            WritePath(candidate.store, candidate.audit).apply(
                candidate.proposal, forged
            )

        assert candidate.store.active(PolicyKind.RULESET) is None
        assert candidate.store.history() == ()
        assert candidate.audit.verify_chain() == ()
