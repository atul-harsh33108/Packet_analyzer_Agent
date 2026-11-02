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
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from dpi_engine.approval_queue import (
    ApprovalQueue,
    ApprovalRequest,
    ApprovalState,
)
from dpi_engine.audit_log import AUTO_ACTOR, AuditLog, AuditLogError
from dpi_engine.blast_radius import BreakerDecision, Reason, Tier, classify
from dpi_engine.proposal import Citation, Proposal
from dpi_engine.rule_manager import Provenance
from dpi_engine.rule_store import PolicyKind, PolicyVersion, RuleStore, RuleStoreError
from dpi_engine.rules.simulator import SimulationReport
from dpi_engine.types import FiveTuple, FlowRecord
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
