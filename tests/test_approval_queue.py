"""The durable approval queue (`T6-05`): a request that outlives the process.

The gate is four sentences, and each is a test group here:

1. **A request survives process death.** The agent run is not suspended in
   memory across a reviewer's lunch break: the proposal is written as a file and
   the process ends. So the queue is built over a directory, every operation
   reads the file, and a second `ApprovalQueue` over the same root approves a
   request the first one wrote.
2. **It applies exactly the digest that was reviewed.** `approve` requires the
   caller to name the digest it reviewed and refuses one that is not the
   proposal in the request. A substitution is caught by the digest, not by
   good faith.
3. **A substituted proposal is refused.** A request's proposal is a full
   `Proposal` record, re-validated on load, so editing the document, the
   citations or the provenance is refused rather than queued.
4. **A rejection is terminal.** It cannot be revived by a later approve, and an
   approval cannot be rewritten into a rejection by a second reviewer.

The other half is what the queue must **not** do: it is the human gate, so it
refuses a candidate the breaker refused (there is nothing to approve) and a
candidate the breaker auto-applied (there is no human needed). It never imports
a store and never applies anything; `T6-06` is the only door that does.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from dpi_engine import approval_queue as queue_module
from dpi_engine.approval_queue import (
    ApprovalQueue,
    ApprovalQueueError,
    ApprovalRequest,
    ApprovalState,
)
from dpi_engine.blast_radius import BreakerDecision, Tier, classify
from dpi_engine.proposal import Citation, Proposal
from dpi_engine.rule_manager import Provenance
from dpi_engine.rule_store import PolicyKind
from dpi_engine.rules.simulator import FlowDelta, SimulationReport
from dpi_engine.types import AppType, FiveTuple, FlowRecord

RUN_ID = "0123456789abcdef"
REQUEST_ID = "fedcba9876543210"
OTHER_REQUEST_ID = "0011223344556677"
REVIEWER = "on-call-1"
NOW = "2026-10-30T12:00:00+00:00"
LATER = "2026-10-30T13:30:00+00:00"

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
        {
            "id": "tiktok-client",
            "app": "TIKTOK",
            "all_of": [{"field": "sni_present", "value": True}],
        }
    ],
}


class _Resolver:
    def resolve(self, cited: Citation) -> FlowRecord | None:
        if cited.run_id == RUN_ID and cited.five_tuple == _FLOW:
            return _RECORD
        return None


def _proposal(kind: PolicyKind = PolicyKind.RULESET) -> Proposal:
    return Proposal.build(
        kind=kind,
        document=_RULESET if kind is PolicyKind.RULESET else _SIGNATURES,
        provenance=Provenance(
            source="agent:policy",
            author="policy-agent/1",
            evidence=f"run {RUN_ID}",
        ),
        note="blocked after review",
        citations=(Citation(run_id=RUN_ID, five_tuple=_FLOW),),
        resolver=_Resolver(),
        agent_version="policy-agent/1",
        prompt_version="policy/1",
        model_version="model-x/2026-10-30",
    )


def _delta(app: AppType, index: int = 0) -> FlowDelta:
    return FlowDelta(
        flow_key=FiveTuple(
            src_ip=0x0A000000 + index,
            dst_ip=0x0A000100 + index,
            src_port=49152 + index,
            dst_port=443,
            protocol=6,
        ),
        app_type=app,
        sni=f"{app.name.lower()}.example",
    )


def _report(
    *,
    newly_blocked: tuple[FlowDelta, ...] = (),
    drop_rate_change_percent: float = 0.0,
    total_loss: bool = False,
    forwarded: int = 77,
) -> SimulationReport:
    return SimulationReport(
        newly_blocked=newly_blocked,
        newly_allowed=(),
        unchanged_blocked=(),
        baseline_blocked=0,
        candidate_blocked=len(newly_blocked),
        baseline_dropped=0,
        candidate_dropped=77 - forwarded,
        baseline_forwarded=77,
        candidate_forwarded=forwarded,
        baseline_total_packets=77,
        candidate_total_packets=77,
        drop_rate_change_percent=drop_rate_change_percent,
        total_loss=total_loss,
        baseline_output=Path("baseline_sim.pcap"),
        candidate_output=Path("candidate_sim.pcap"),
    )


def _one_click() -> BreakerDecision:
    return classify(_proposal(), _report())


def _explicit() -> BreakerDecision:
    return classify(_proposal(), _report(drop_rate_change_percent=6.0))


def _auto_apply() -> BreakerDecision:
    return classify(_proposal(PolicyKind.SIGNATURES), _report())


def _refused() -> BreakerDecision:
    return classify(_proposal(), _report(total_loss=True, forwarded=0))


def _queue(root: Path, *times: str) -> ApprovalQueue:
    remaining = list(times) or [NOW]
    ticks = iter(remaining)
    return ApprovalQueue(root, clock=lambda: next(ticks, remaining[-1]))


def _written(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return raw


def _rewrite(path: Path, mutate: Any) -> None:
    record = _written(path)
    mutate(record)
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# The state vocabulary and the request value
# ---------------------------------------------------------------------------


class TestTheRequest:
    def test_the_three_states_are_persisted_spellings(self) -> None:
        assert [state.value for state in ApprovalState] == [
            "pending",
            "approved",
            "rejected",
        ]

    def test_a_pending_request_record_round_trips(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path)
        request = queue.submit(REQUEST_ID, _proposal(), _one_click())

        record = request.to_json()
        again = ApprovalRequest.from_json(record)

        assert again == request
        assert again.state is ApprovalState.PENDING
        assert again.decided_at is None
        assert again.reviewer is None
        assert again.proposal_digest == request.proposal.digest

    def test_an_approved_request_record_round_trips(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path, NOW, LATER)
        request = queue.submit(REQUEST_ID, _proposal(), _explicit())
        approved = queue.approve(
            REQUEST_ID, digest=request.proposal.digest, reviewer=REVIEWER
        )

        assert ApprovalRequest.from_json(approved.to_json()) == approved
        assert approved.decided_at == LATER
        assert approved.reviewer == REVIEWER

    @pytest.mark.parametrize("value", ["", "pending "])
    def test_an_unknown_state_is_refused(self, value: str, tmp_path: Path) -> None:
        raw = _queue(tmp_path).submit(REQUEST_ID, _proposal(), _one_click()).to_json()
        raw["state"] = value

        with pytest.raises(ApprovalQueueError, match="state"):
            ApprovalRequest.from_json(raw)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("request_id", "not-an-id"),
            ("request_id", "../../etc/passwd"),
            ("created_at", ""),
            ("note", 7),
        ],
    )
    def test_the_record_refuses_bad_scalar_fields(
        self, field: str, value: Any, tmp_path: Path
    ) -> None:
        raw = _queue(tmp_path).submit(REQUEST_ID, _proposal(), _one_click()).to_json()
        raw[field] = value

        with pytest.raises(ApprovalQueueError, match=field):
            ApprovalRequest.from_json(raw)

    def test_a_pending_request_cannot_carry_a_decision(self) -> None:
        """A decision time alone is enough to be inconsistent: no reviewer needed."""
        with pytest.raises(ApprovalQueueError, match="pending"):
            ApprovalRequest(
                request_id=REQUEST_ID,
                state=ApprovalState.PENDING,
                created_at=NOW,
                decided_at=LATER,
                reviewer=None,
                note="",
                proposal=_proposal(),
                decision=_one_click(),
            )

    def test_a_pending_request_cannot_carry_a_reviewer(self) -> None:
        with pytest.raises(ApprovalQueueError, match="reviewer"):
            ApprovalRequest(
                request_id=REQUEST_ID,
                state=ApprovalState.PENDING,
                created_at=NOW,
                decided_at=None,
                reviewer=REVIEWER,
                note="",
                proposal=_proposal(),
                decision=_one_click(),
            )

    @pytest.mark.parametrize("field", ["decided_at", "reviewer"])
    def test_a_decided_request_needs_both_decision_fields(self, field: str) -> None:
        kwargs: dict[str, Any] = {
            "request_id": REQUEST_ID,
            "state": ApprovalState.APPROVED,
            "created_at": NOW,
            "decided_at": LATER,
            "reviewer": REVIEWER,
            "note": "",
            "proposal": _proposal(),
            "decision": _one_click(),
        }
        kwargs[field] = None

        with pytest.raises(ApprovalQueueError, match=field):
            ApprovalRequest(**kwargs)

    def test_a_request_needs_a_proposal_and_a_decision(self) -> None:
        with pytest.raises(ApprovalQueueError, match="Proposal"):
            ApprovalRequest(
                request_id=REQUEST_ID,
                state=ApprovalState.PENDING,
                created_at=NOW,
                decided_at=None,
                reviewer=None,
                note="",
                proposal={"digest": "x"},  # type: ignore[arg-type]
                decision=_one_click(),
            )
        with pytest.raises(ApprovalQueueError, match="BreakerDecision"):
            ApprovalRequest(
                request_id=REQUEST_ID,
                state=ApprovalState.PENDING,
                created_at=NOW,
                decided_at=None,
                reviewer=None,
                note="",
                proposal=_proposal(),
                decision={"tier": "one-click"},  # type: ignore[arg-type]
            )

    def test_the_request_is_frozen(self, tmp_path: Path) -> None:
        request = _queue(tmp_path).submit(REQUEST_ID, _proposal(), _one_click())

        with pytest.raises(dataclasses.FrozenInstanceError):
            request.state = ApprovalState.APPROVED  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Submitting: the request is a file, and the queue is the human gate
# ---------------------------------------------------------------------------


class TestSubmitting:
    def test_a_submitted_request_is_pending_on_disk(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path)

        request = queue.submit(REQUEST_ID, _proposal(), _explicit(), note="why me")

        path = tmp_path / "requests" / f"{REQUEST_ID}.json"
        assert path.exists()
        record = _written(path)
        assert record["request_id"] == REQUEST_ID
        assert record["state"] == "pending"
        assert record["note"] == "why me"
        assert record["proposal"]["digest"] == request.proposal.digest
        assert record["decision"]["tier"] == "explicit-confirm"
        assert queue.load(REQUEST_ID) == request

    def test_the_decision_on_disk_is_the_one_classified(self, tmp_path: Path) -> None:
        decision = _explicit()

        request = _queue(tmp_path).submit(REQUEST_ID, _proposal(), decision)

        assert request.decision == decision
        assert request.decision.reasons == decision.reasons
        assert _written(
            tmp_path / "requests" / f"{REQUEST_ID}.json"
        )["decision"]["reasons"] == [reason.value for reason in decision.reasons]

    def test_pending_lists_only_undecided_requests_oldest_first(
        self, tmp_path: Path
    ) -> None:
        queue = _queue(tmp_path, "2026-10-30T10:00:00+00:00", "2026-10-30T11:00:00+00:00")
        first = queue.submit(OTHER_REQUEST_ID, _proposal(), _one_click())
        second = queue.submit(REQUEST_ID, _proposal(), _explicit())

        assert queue.pending() == (first, second)

        queue.approve(
            OTHER_REQUEST_ID, digest=first.proposal.digest, reviewer=REVIEWER
        )

        assert queue.pending() == (second,)

    def test_a_refused_candidate_never_enters_the_queue(self, tmp_path: Path) -> None:
        """There is nothing to approve: the breaker already said no."""
        with pytest.raises(ApprovalQueueError, match="refused"):
            _queue(tmp_path).submit(REQUEST_ID, _proposal(), _refused())

        assert not (tmp_path / "requests" / f"{REQUEST_ID}.json").exists()

    def test_an_auto_applied_candidate_does_not_wait_for_a_human(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(ApprovalQueueError, match="auto-apply"):
            _queue(tmp_path).submit(REQUEST_ID, _proposal(PolicyKind.SIGNATURES), _auto_apply())

    def test_a_refused_record_cannot_be_hand_written_into_the_queue(
        self, tmp_path: Path
    ) -> None:
        queue = _queue(tmp_path)
        queue.submit(REQUEST_ID, _proposal(), _one_click())
        path = tmp_path / "requests" / f"{REQUEST_ID}.json"

        _rewrite(path, lambda record: record.__setitem__("decision", _refused().to_json()))

        with pytest.raises(ApprovalQueueError, match="refused"):
            queue.load(REQUEST_ID)

    def test_an_auto_applied_record_cannot_be_hand_written_into_the_queue(
        self, tmp_path: Path
    ) -> None:
        """The file is the trusted boundary on a later process, so it re-checks."""
        queue = _queue(tmp_path)
        queue.submit(REQUEST_ID, _proposal(), _one_click())
        path = tmp_path / "requests" / f"{REQUEST_ID}.json"

        _rewrite(
            path,
            lambda record: record.__setitem__("decision", _auto_apply().to_json()),
        )

        with pytest.raises(ApprovalQueueError, match="auto-apply"):
            queue.load(REQUEST_ID)

    def test_submitting_the_same_request_twice_is_idempotent(
        self, tmp_path: Path
    ) -> None:
        queue = _queue(tmp_path, NOW, LATER)

        first = queue.submit(REQUEST_ID, _proposal(), _one_click())
        second = queue.submit(REQUEST_ID, _proposal(), _one_click())

        assert second == first
        assert second.created_at == NOW
        assert len(list((tmp_path / "requests").glob("*.json"))) == 1

    def test_the_same_request_id_with_another_decision_is_refused(
        self, tmp_path: Path
    ) -> None:
        queue = _queue(tmp_path)
        queue.submit(REQUEST_ID, _proposal(), _one_click())

        with pytest.raises(ApprovalQueueError, match="different"):
            queue.submit(REQUEST_ID, _proposal(), _explicit())

    def test_the_same_request_id_with_another_proposal_is_refused(
        self, tmp_path: Path
    ) -> None:
        queue = _queue(tmp_path)
        queue.submit(REQUEST_ID, _proposal(), _one_click())
        other = Proposal.build(
            kind=PolicyKind.RULESET,
            document={"blocked_apps": ["YOUTUBE"]},
            provenance=_proposal().provenance,
            note="another change",
            citations=(Citation(run_id=RUN_ID, five_tuple=_FLOW),),
            resolver=_Resolver(),
            agent_version="policy-agent/1",
            prompt_version="policy/1",
            model_version="model-x/2026-10-30",
        )

        with pytest.raises(ApprovalQueueError, match="different"):
            queue.submit(REQUEST_ID, other, _one_click())

    @pytest.mark.parametrize(
        "request_id", ["", "0123456789abcde", "0123456789ABCDEF", "../escape"]
    )
    def test_a_request_id_is_validated_before_it_names_a_file(
        self, tmp_path: Path, request_id: str
    ) -> None:
        with pytest.raises(ApprovalQueueError, match="request id"):
            _queue(tmp_path).submit(request_id, _proposal(), _one_click())

    def test_a_traversing_request_id_cannot_write_outside_the_root(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "queue"
        with pytest.raises(ApprovalQueueError):
            _queue(root).submit("../../escape", _proposal(), _one_click())

        assert list(tmp_path.glob("*.json")) == []

    def test_a_request_note_must_be_text(self, tmp_path: Path) -> None:
        with pytest.raises(ApprovalQueueError, match="note"):
            _queue(tmp_path).submit(
                REQUEST_ID, _proposal(), _one_click(), note=3  # type: ignore[arg-type]
            )

    def test_the_default_clock_writes_a_sortable_utc_timestamp(
        self, tmp_path: Path
    ) -> None:
        """Production uses wall-clock time; `pending` sorts on this string."""
        request = ApprovalQueue(tmp_path).submit(
            REQUEST_ID, _proposal(), _one_click()
        )

        parsed = datetime.fromisoformat(request.created_at)

        assert parsed.tzinfo is not None
        assert parsed.utcoffset() == timedelta(0)


# ---------------------------------------------------------------------------
# Loading: an edited record is refused, not repaired
# ---------------------------------------------------------------------------


class TestLoading:
    def test_a_missing_request_says_so(self, tmp_path: Path) -> None:
        with pytest.raises(ApprovalQueueError, match="no request"):
            _queue(tmp_path).load(REQUEST_ID)

    def test_an_edited_proposal_is_refused(self, tmp_path: Path) -> None:
        """The proposal's own content checks catch this, on load.

        Editing the document invalidates the version id before the digest, so
        the assertion names the guarantee -- an edited record -- rather than
        pinning which of the proposal's two ids noticed first.
        """
        queue = _queue(tmp_path)
        queue.submit(REQUEST_ID, _proposal(), _one_click())
        path = tmp_path / "requests" / f"{REQUEST_ID}.json"

        _rewrite(
            path,
            lambda record: record["proposal"]["document"].__setitem__(
                "blocked_apps", ["YOUTUBE"]
            ),
        )

        with pytest.raises(ValueError, match="edited"):
            queue.load(REQUEST_ID)

    def test_an_edited_provenance_is_refused(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path)
        queue.submit(REQUEST_ID, _proposal(), _one_click())
        path = tmp_path / "requests" / f"{REQUEST_ID}.json"

        _rewrite(
            path,
            lambda record: record["proposal"]["provenance"].__setitem__(
                "source", "operator"
            ),
        )

        with pytest.raises(ValueError, match="edited"):
            queue.load(REQUEST_ID)

    def test_an_edited_decision_is_refused(self, tmp_path: Path) -> None:
        """A tier and its reasons must agree, so a doctored decision will not load."""
        queue = _queue(tmp_path)
        queue.submit(REQUEST_ID, _proposal(), _one_click())
        path = tmp_path / "requests" / f"{REQUEST_ID}.json"

        _rewrite(
            path,
            lambda record: record["decision"].__setitem__(
                "tier", "explicit-confirm"
            ),
        )

        with pytest.raises(ValueError, match="explicit-confirm"):
            queue.load(REQUEST_ID)

    def test_a_record_whose_id_disagrees_with_its_name_is_refused(
        self, tmp_path: Path
    ) -> None:
        queue = _queue(tmp_path)
        queue.submit(REQUEST_ID, _proposal(), _one_click())
        path = tmp_path / "requests" / f"{REQUEST_ID}.json"

        _rewrite(path, lambda record: record.__setitem__("request_id", OTHER_REQUEST_ID))

        with pytest.raises(ApprovalQueueError, match="filed as"):
            queue.load(REQUEST_ID)

    def test_an_unknown_key_is_refused(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path)
        queue.submit(REQUEST_ID, _proposal(), _one_click())
        path = tmp_path / "requests" / f"{REQUEST_ID}.json"

        _rewrite(path, lambda record: record.__setitem__("approved_by_ceo", True))

        with pytest.raises(ApprovalQueueError, match="unknown key"):
            queue.load(REQUEST_ID)

    def test_a_missing_key_is_refused(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path)
        queue.submit(REQUEST_ID, _proposal(), _one_click())
        path = tmp_path / "requests" / f"{REQUEST_ID}.json"

        _rewrite(path, lambda record: record.pop("decision"))

        with pytest.raises(ApprovalQueueError, match="missing"):
            queue.load(REQUEST_ID)

    def test_another_schema_is_refused(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path)
        queue.submit(REQUEST_ID, _proposal(), _one_click())
        path = tmp_path / "requests" / f"{REQUEST_ID}.json"

        _rewrite(path, lambda record: record.__setitem__("schema", "other/v9"))

        with pytest.raises(ApprovalQueueError, match="schema"):
            queue.load(REQUEST_ID)

    def test_a_truncated_file_is_refused(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path)
        queue.submit(REQUEST_ID, _proposal(), _one_click())
        path = tmp_path / "requests" / f"{REQUEST_ID}.json"
        path.write_text('{"schema": "dpi-engine-approval', encoding="utf-8")

        with pytest.raises(ApprovalQueueError, match="not valid JSON"):
            queue.load(REQUEST_ID)


# ---------------------------------------------------------------------------
# Approving: the digest reviewed is the digest decided
# ---------------------------------------------------------------------------


class TestApproving:
    def test_an_approval_names_the_reviewer_and_the_time(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path, NOW, LATER)
        request = queue.submit(REQUEST_ID, _proposal(), _explicit())

        approved = queue.approve(
            REQUEST_ID, digest=request.proposal.digest, reviewer=REVIEWER
        )

        assert approved.state is ApprovalState.APPROVED
        assert approved.reviewer == REVIEWER
        assert approved.decided_at == LATER
        assert approved.proposal == request.proposal
        assert _written(tmp_path / "requests" / f"{REQUEST_ID}.json")["state"] == "approved"

    def test_the_approval_survives_a_new_queue_over_the_same_root(
        self, tmp_path: Path
    ) -> None:
        first = _queue(tmp_path, NOW)
        request = first.submit(REQUEST_ID, _proposal(), _one_click())
        del first

        second = _queue(tmp_path, LATER)
        approved = second.approve(
            REQUEST_ID, digest=request.proposal.digest, reviewer=REVIEWER
        )

        assert _queue(tmp_path).load(REQUEST_ID) == approved

    def test_approving_with_the_wrong_digest_is_refused(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path)
        request = queue.submit(REQUEST_ID, _proposal(), _one_click())
        other_digest = _proposal(PolicyKind.SIGNATURES).digest

        with pytest.raises(ApprovalQueueError, match="reviewed"):
            queue.approve(
                REQUEST_ID, digest=other_digest, reviewer=REVIEWER
            )

        assert queue.load(REQUEST_ID).state is ApprovalState.PENDING
        assert queue.load(REQUEST_ID).proposal == request.proposal

    def test_a_reviewer_is_required_to_approve(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path)
        request = queue.submit(REQUEST_ID, _proposal(), _one_click())

        for reviewer in ("", "   ", None):
            with pytest.raises(ApprovalQueueError, match="reviewer"):
                queue.approve(
                    REQUEST_ID,
                    digest=request.proposal.digest,
                    reviewer=reviewer,  # type: ignore[arg-type]
                )

        assert queue.load(REQUEST_ID).state is ApprovalState.PENDING

    def test_the_same_approval_twice_is_idempotent(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path, NOW, LATER, "2026-10-30T15:00:00+00:00")
        request = queue.submit(REQUEST_ID, _proposal(), _one_click())
        first = queue.approve(
            REQUEST_ID, digest=request.proposal.digest, reviewer=REVIEWER
        )

        second = queue.approve(
            REQUEST_ID, digest=request.proposal.digest, reviewer=REVIEWER
        )

        assert second == first
        assert second.decided_at == LATER

    def test_a_second_reviewer_cannot_rewrite_an_approval(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path, NOW, LATER)
        request = queue.submit(REQUEST_ID, _proposal(), _one_click())
        queue.approve(REQUEST_ID, digest=request.proposal.digest, reviewer=REVIEWER)

        with pytest.raises(ApprovalQueueError, match="already approved"):
            queue.approve(
                REQUEST_ID, digest=request.proposal.digest, reviewer="someone-else"
            )

        assert queue.load(REQUEST_ID).reviewer == REVIEWER

    def test_an_approved_request_cannot_be_approved_again_with_another_digest(
        self, tmp_path: Path
    ) -> None:
        """The retry may repeat the decision; it may not replace it."""
        queue = _queue(tmp_path, NOW, LATER)
        request = queue.submit(REQUEST_ID, _proposal(), _one_click())
        queue.approve(REQUEST_ID, digest=request.proposal.digest, reviewer=REVIEWER)

        with pytest.raises(ApprovalQueueError, match="already approved"):
            queue.approve(
                REQUEST_ID,
                digest=_proposal(PolicyKind.SIGNATURES).digest,
                reviewer=REVIEWER,
            )

        assert queue.load(REQUEST_ID).proposal == request.proposal


# ---------------------------------------------------------------------------
# Rejecting: terminal, and not a way to rewrite an approval
# ---------------------------------------------------------------------------


class TestRejecting:
    def test_a_rejection_names_the_reviewer_and_the_time(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path, NOW, LATER)

        request = queue.submit(REQUEST_ID, _proposal(), _explicit())
        rejected = queue.reject(
            REQUEST_ID, reviewer=REVIEWER, note="blocks a customer"
        )

        assert rejected.state is ApprovalState.REJECTED
        assert rejected.reviewer == REVIEWER
        assert rejected.decided_at == LATER
        assert rejected.note == "blocks a customer"
        assert request.state is ApprovalState.PENDING

    def test_a_rejection_cannot_be_revived_by_a_later_approve(
        self, tmp_path: Path
    ) -> None:
        queue = _queue(tmp_path, NOW, LATER)
        request = queue.submit(REQUEST_ID, _proposal(), _one_click())
        queue.reject(REQUEST_ID, reviewer=REVIEWER, note="no")

        with pytest.raises(ApprovalQueueError, match="terminal"):
            queue.approve(
                REQUEST_ID, digest=request.proposal.digest, reviewer="second-reviewer"
            )

        assert _queue(tmp_path).load(REQUEST_ID).state is ApprovalState.REJECTED

    def test_the_same_rejection_twice_is_idempotent(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path, NOW, LATER, "2026-10-30T15:00:00+00:00")
        queue.submit(REQUEST_ID, _proposal(), _one_click())
        first = queue.reject(REQUEST_ID, reviewer=REVIEWER, note="no")
        second = queue.reject(REQUEST_ID, reviewer=REVIEWER, note="no")

        assert second == first
        assert second.decided_at == LATER

    def test_a_different_rejection_cannot_overwrite_the_decision(
        self, tmp_path: Path
    ) -> None:
        queue = _queue(tmp_path, NOW, LATER)
        queue.submit(REQUEST_ID, _proposal(), _one_click())
        queue.reject(REQUEST_ID, reviewer=REVIEWER, note="no")

        with pytest.raises(ApprovalQueueError, match="already rejected"):
            queue.reject(REQUEST_ID, reviewer="someone-else", note="no")

        assert queue.load(REQUEST_ID).reviewer == REVIEWER

    def test_an_approval_cannot_be_turned_into_a_rejection(
        self, tmp_path: Path
    ) -> None:
        queue = _queue(tmp_path, NOW, LATER)
        request = queue.submit(REQUEST_ID, _proposal(), _one_click())
        queue.approve(REQUEST_ID, digest=request.proposal.digest, reviewer=REVIEWER)

        with pytest.raises(ApprovalQueueError, match="already approved"):
            queue.reject(REQUEST_ID, reviewer=REVIEWER, note="changed my mind")

        assert queue.load(REQUEST_ID).state is ApprovalState.APPROVED

    def test_a_rejection_note_is_optional_but_must_be_text(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path, NOW, LATER)
        queue.submit(REQUEST_ID, _proposal(), _one_click())
        assert queue.reject(REQUEST_ID, reviewer=REVIEWER).note == ""

        queue.submit(OTHER_REQUEST_ID, _proposal(), _one_click())
        with pytest.raises(ApprovalQueueError, match="note"):
            queue.reject(
                OTHER_REQUEST_ID, reviewer=REVIEWER, note=7  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# The decision the queue records: the breaker's tier, not a re-classification
# ---------------------------------------------------------------------------


class TestTheRecordedDecision:
    def test_a_decision_round_trips_through_its_record(self) -> None:
        decision = _explicit()

        assert BreakerDecision.from_json(decision.to_json()) == decision

    def test_a_protected_app_round_trips_by_engine_name(self) -> None:
        decision = classify(
            _proposal(),
            _report(
                newly_blocked=(_delta(AppType.TIKTOK),),
                drop_rate_change_percent=1.0,
            ),
            config=__import__(
                "dpi_engine.blast_radius", fromlist=["BreakerConfig"]
            ).BreakerConfig(protected_apps=frozenset({AppType.TIKTOK})),
        )

        record = decision.to_json()

        assert record["protected_apps"] == ["TIKTOK"]
        assert BreakerDecision.from_json(record) == decision

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("tier", "one_click", "tier"),
            ("reasons", "within-caps", "reasons"),
            ("reasons", ["within_caps"], "reasons"),
            ("flows_newly_blocked", -1, "flows_newly_blocked"),
            ("drop_rate_change_percent", "0.1", "drop_rate_change_percent"),
            ("protected_apps", ["tiktok"], "protected_apps"),
            ("protected_apps", ["TIKTOK"], "protected_apps"),
        ],
    )
    def test_a_hand_edited_decision_is_refused(
        self, field: str, value: Any, message: str
    ) -> None:
        record = _one_click().to_json()
        record[field] = value

        with pytest.raises(ValueError, match=message):
            BreakerDecision.from_json(record)

    def test_a_decision_record_refuses_unknown_and_missing_keys(self) -> None:
        record = _one_click().to_json()

        with pytest.raises(ValueError, match="unknown key"):
            BreakerDecision.from_json(record | {"approved": True})
        with pytest.raises(ValueError, match="missing"):
            BreakerDecision.from_json({key: value for key, value in record.items() if key != "tier"})


# ---------------------------------------------------------------------------
# Over a real proposal and a real counterfactual
# ---------------------------------------------------------------------------


class TestOverARealCounterfactual:
    def test_propose_classify_submit_survive_and_approve(self, tmp_path: Path) -> None:
        from conftest import TEST_DPI_PCAP
        from dpi_engine.rule_manager import RuleManager
        from dpi_engine.rules.simulator import simulate_ruleset

        candidate = RuleManager()
        candidate.block_app(AppType.TIKTOK)
        report = simulate_ruleset(
            RuleManager(),
            candidate,
            TEST_DPI_PCAP,
            output_dir=tmp_path / "simulation",
        )

        proposal = _proposal()
        decision = classify(proposal, report)
        queue = _queue(tmp_path / "queue", NOW)
        request = queue.submit(REQUEST_ID, proposal, decision, note="real capture")
        del queue

        # A decision that needed a human, recorded with the figures it was
        # taken from, and the request readable by a process that never saw it.
        assert decision.tier is Tier.EXPLICIT_CONFIRM
        assert queue_module.ApprovalQueue(tmp_path / "queue").load(REQUEST_ID) == request

        reloaded = ApprovalRequest.from_json(
            _written(tmp_path / "queue" / "requests" / f"{REQUEST_ID}.json")
        )
        assert reloaded.decision.flows_newly_blocked == len(report.newly_blocked)
        assert (
            reloaded.decision.drop_rate_change_percent
            == report.drop_rate_change_percent
        )

        approved = queue_module.ApprovalQueue(tmp_path / "queue", clock=lambda: LATER).approve(
            REQUEST_ID, digest=proposal.digest, reviewer=REVIEWER
        )
        assert approved.state is ApprovalState.APPROVED
        assert approved.proposal.digest == proposal.digest


# ---------------------------------------------------------------------------
# No path from an approval to an applied rule
# ---------------------------------------------------------------------------


class TestNoPathToApplication:
    def test_the_queue_does_not_import_a_store_or_a_rule_manager(self) -> None:
        tree = ast.parse(inspect.getsource(queue_module))
        imported = {
            (alias.name or "").split(".")[-1]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        imported_modules = {
            node.module.split(".")[-1]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }

        assert "RuleStore" not in imported
        assert "RuleManager" not in imported
        assert "rule_manager" not in imported_modules

    def test_the_queue_calls_nothing_that_applies(self) -> None:
        tree = ast.parse(inspect.getsource(queue_module))
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }

        assert not calls & {"commit", "activate", "apply", "publish", "install"}

    def test_an_approved_request_is_not_a_policy_version(self, tmp_path: Path) -> None:
        queue = _queue(tmp_path, NOW, LATER)
        request = queue.submit(REQUEST_ID, _proposal(), _one_click())
        approved = queue.approve(
            REQUEST_ID, digest=request.proposal.digest, reviewer=REVIEWER
        )

        assert not hasattr(approved, "activate")
        assert not hasattr(approved.proposal, "commit")
