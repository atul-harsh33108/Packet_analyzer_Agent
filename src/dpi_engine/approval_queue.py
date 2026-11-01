"""The durable approval queue (`T6-05`): a request that outlives the process.

**Why this exists.** The breaker (`T6-04`) can say "a human must look at this",
but a human is not a stack frame. The agent run ends, the reviewer goes to lunch,
and the process that held the proposal in memory is gone. So a request is not an
object in a list: it is **one file per request**, written atomically under
`requests/`, and every operation here reads that file. A second `ApprovalQueue`
over the same root picks up exactly where the first one stopped.

**Three states, two of them terminal.** A request is `pending`, then `approved`
or `rejected`. `approved` and `rejected` are terminal in the sense that matters:
a rejection cannot be revived by a later approval, and a decision cannot be
rewritten by a second reviewer. Retrying the *same* decision is idempotent --
reviewers double-click, and a retry that failed would push them to work around
the queue. Retrying a *different* one is refused.

**The digest is the contract.** `approve` takes the digest the reviewer saw and
refuses any other. The proposal in the file was already content-checked when it
was built and is checked again on load by `Proposal.from_json`, so editing the
document, its provenance or its citations is refused rather than queued. The
digest check is the second lock: it catches a caller that approved one request
while looking at another.

**The queue is the human gate, so it refuses what a human cannot usefully
decide.** A `REFUSED` candidate never enters: the breaker already said no, and
queueing it would offer a reviewer a door that must stay shut. An `AUTO_APPLY`
candidate never enters either: no human is needed, and queueing it would turn a
safe automatic change into a stall. The queue records the breaker's tier and
figures; it does not re-classify the candidate, because a second classification
is a second verdict free to disagree with the first.

**Nothing here applies anything.** This module imports no rule store and no rule
manager and calls nothing that commits, activates or publishes. `T6-06` is the
only door that moves an active version, and it must refuse what the breaker
refused. An approval here is permission to ask, not a change in force.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from dpi_engine.blast_radius import BreakerDecision, Tier
from dpi_engine.proposal import Proposal
from dpi_engine.rule_store import RuleStoreError, is_version_id, write_json_atomic

__all__ = [
    "SCHEMA",
    "ApprovalQueue",
    "ApprovalQueueError",
    "ApprovalRequest",
    "ApprovalState",
]

#: The on-disk shape of a request. A later binary reads this or refuses it; a
#: record is never half-read through meanings it did not have when written.
SCHEMA = "dpi-engine-approval/v1"

_RECORD_KEYS = frozenset(
    {
        "schema",
        "request_id",
        "state",
        "created_at",
        "decided_at",
        "reviewer",
        "note",
        "proposal",
        "decision",
    }
)


class ApprovalQueueError(ValueError):
    """A request is malformed, missing, or its state transition is not allowed.

    A `ValueError` so it joins the engine's other refusals, and named so a caller
    can tell "this request is wrong" from "this directory is unreadable".
    """


def _require_request_id(value: object) -> str:
    """A request id names a file, so it is validated before it is used as one."""
    if not isinstance(value, str) or not is_version_id(value):
        raise ApprovalQueueError(
            "a request id (request_id) must be 16 lowercase hex characters, got "
            f"{value!r}"
        )
    return value


def _require_reviewer(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ApprovalQueueError(
            f"a reviewer must be a non-empty name, got {value!r}"
        )
    return value.strip()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class ApprovalState(StrEnum):
    """The three states a request may be in. Values are persisted spellings."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """One proposal awaiting, or having received, a human decision.

    The record is frozen and checks its own consistency: a pending request has no
    reviewer and no decision time; a decided one has both. `proposal` is a
    `Proposal` and `decision` a `BreakerDecision`, not their JSON records, so a
    queued request is the same value the breaker classified.
    """

    request_id: str
    state: ApprovalState
    created_at: str
    decided_at: str | None
    reviewer: str | None
    note: str
    proposal: Proposal
    decision: BreakerDecision

    def __post_init__(self) -> None:
        if not isinstance(self.state, ApprovalState):
            raise ApprovalQueueError(
                f"a request state must be an ApprovalState, got "
                f"{type(self.state).__name__}"
            )
        _require_request_id(self.request_id)
        if not isinstance(self.created_at, str) or not self.created_at:
            raise ApprovalQueueError("created_at must be a non-empty timestamp string")
        if not isinstance(self.note, str):
            raise ApprovalQueueError(
                f"a request note must be text, got {type(self.note).__name__}"
            )
        if not isinstance(self.proposal, Proposal):
            raise ApprovalQueueError(
                f"a request must carry a Proposal, got "
                f"{type(self.proposal).__name__}"
            )
        if not isinstance(self.decision, BreakerDecision):
            raise ApprovalQueueError(
                "a request must carry the breaker's BreakerDecision, got "
                f"{type(self.decision).__name__}"
            )

        if self.decision.tier is Tier.REFUSED:
            raise ApprovalQueueError(
                "a request for a refused candidate is not queueable: the breaker "
                "already answered, and a human cannot approve a total loss."
            )
        if self.decision.tier is Tier.AUTO_APPLY:
            raise ApprovalQueueError(
                "a request with the auto-apply tier never waits for a human, so it "
                "does not belong in the queue."
            )

        if self.state is ApprovalState.PENDING:
            if self.decided_at is not None:
                raise ApprovalQueueError(
                    f"request {self.request_id} is pending, so it has no decision time"
                )
            if self.reviewer is not None:
                raise ApprovalQueueError(
                    f"request {self.request_id} is pending, so it has no reviewer"
                )
        else:
            if not isinstance(self.decided_at, str) or not self.decided_at:
                raise ApprovalQueueError(
                    f"request {self.request_id} is {self.state.value}, so decided_at "
                    "is required"
                )
            _require_reviewer(self.reviewer)

    @property
    def proposal_digest(self) -> str:
        """The digest this request was reviewed at."""
        return self.proposal.digest

    def to_json(self) -> dict[str, Any]:
        """The whole on-disk record, as JSON-ready data."""
        return {
            "schema": SCHEMA,
            "request_id": self.request_id,
            "state": self.state.value,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
            "reviewer": self.reviewer,
            "note": self.note,
            "proposal": self.proposal.to_json(),
            "decision": self.decision.to_json(),
        }

    @classmethod
    def from_json(cls, raw: object) -> ApprovalRequest:
        """Decodes and re-checks a stored request. An edited record is refused.

        The proposal and the decision are decoded by their own `from_json`, so
        the digest and the tier invariants are checked here rather than trusted.
        """
        if not isinstance(raw, Mapping):
            raise ApprovalQueueError(
                f"a request must be a JSON object, got {type(raw).__name__}"
            )
        unknown = sorted(set(raw) - _RECORD_KEYS)
        if unknown:
            raise ApprovalQueueError(f"a request has an unknown key {unknown[0]!r}")
        missing = sorted(_RECORD_KEYS - set(raw))
        if missing:
            raise ApprovalQueueError(f"a request is missing the {missing[0]!r} key")

        schema = raw["schema"]
        if schema != SCHEMA:
            raise ApprovalQueueError(
                f"this request is schema {schema!r}, but this build reads {SCHEMA!r}"
            )

        state_raw = raw["state"]
        try:
            state = ApprovalState(state_raw)
        except (TypeError, ValueError) as exc:
            known = ", ".join(member.value for member in ApprovalState)
            raise ApprovalQueueError(
                f"a request has an unknown state {state_raw!r}. Expected one of: "
                f"{known}"
            ) from exc

        decided_at = raw["decided_at"]
        if decided_at is not None and not isinstance(decided_at, str):
            raise ApprovalQueueError(
                f"decided_at must be a timestamp string or None, got "
                f"{type(decided_at).__name__}"
            )
        reviewer = raw["reviewer"]
        if reviewer is not None and not isinstance(reviewer, str):
            raise ApprovalQueueError(
                f"reviewer must be a name or None, got {type(reviewer).__name__}"
            )

        return cls(
            request_id=raw["request_id"],
            state=state,
            created_at=raw["created_at"],
            decided_at=decided_at,
            reviewer=reviewer,
            note=raw["note"],
            proposal=Proposal.from_json(raw["proposal"]),
            decision=BreakerDecision.from_json(raw["decision"]),
        )


class ApprovalQueue:
    """A directory of request files, and the transitions allowed between states.

    `clock` is injected so a test can produce a deterministic `created_at` and
    `decided_at`; production uses wall-clock UTC. Nothing else is configurable:
    the root is the whole durable state.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        clock: Callable[[], str] | None = None,
    ) -> None:
        self._root = Path(root)
        self._clock = _now if clock is None else clock

    @property
    def root(self) -> Path:
        """The directory holding this queue's request files."""
        return self._root

    def path_for(self, request_id: str) -> Path:
        """Where a request is filed. Validates the id before it becomes a path."""
        return self._root / "requests" / f"{_require_request_id(request_id)}.json"

    def submit(
        self,
        request_id: str,
        proposal: Proposal,
        decision: BreakerDecision,
        *,
        note: str = "",
    ) -> ApprovalRequest:
        """Files a pending request for a candidate the breaker sent to a human.

        `REFUSED` and `AUTO_APPLY` are not queueable: the first has already been
        answered and the second needs no answer. Re-submitting the same request
        is idempotent; a different one under the same id is refused.
        """
        request_id = _require_request_id(request_id)
        if not isinstance(decision, BreakerDecision):
            raise ApprovalQueueError(
                "a request needs the breaker's BreakerDecision, got "
                f"{type(decision).__name__}"
            )
        if decision.tier is Tier.REFUSED:
            raise ApprovalQueueError(
                f"request {request_id} was refused by the breaker: a candidate that "
                "forwards nothing is not something a human can approve."
            )
        if decision.tier is Tier.AUTO_APPLY:
            raise ApprovalQueueError(
                f"request {request_id} has the auto-apply tier: a signature-table "
                "change needs no human, so there is nothing to queue."
            )

        path = self.path_for(request_id)
        if path.exists():
            existing = self.load(request_id)
            if (
                existing.proposal != proposal
                or existing.decision != decision
                or existing.note != note
            ):
                raise ApprovalQueueError(
                    f"request {request_id} is already on file for a different "
                    "proposal, decision or note. A request id names one request."
                )
            if existing.state is not ApprovalState.PENDING:
                raise ApprovalQueueError(
                    f"request {request_id} has already been "
                    f"{existing.state.value} and cannot be resubmitted."
                )
            return existing

        request = ApprovalRequest(
            request_id=request_id,
            state=ApprovalState.PENDING,
            created_at=self._clock(),
            decided_at=None,
            reviewer=None,
            note=note,
            proposal=proposal,
            decision=decision,
        )
        self._write(request)
        return request

    def load(self, request_id: str) -> ApprovalRequest:
        """Reads one request from disk, re-checking the record it finds."""
        request_id = _require_request_id(request_id)
        path = self.path_for(request_id)
        if not path.exists():
            raise ApprovalQueueError(
                f"no request {request_id!r} is queued under {self._root}"
            )
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ApprovalQueueError(f"{path} is not valid JSON: {exc}") from exc
        except OSError as exc:
            raise ApprovalQueueError(f"cannot read {path}: {exc}") from exc

        request = ApprovalRequest.from_json(raw)
        if request.request_id != request_id:
            raise ApprovalQueueError(
                f"{path} is filed as request {request.request_id!r}, but the file "
                f"name says {request_id!r}"
            )
        return request

    def pending(self) -> tuple[ApprovalRequest, ...]:
        """Every undecided request, oldest first. The reviewer's worklist."""
        requests_dir = self._root / "requests"
        if not requests_dir.exists():
            return ()
        requests = [
            self.load(path.stem) for path in sorted(requests_dir.glob("*.json"))
        ]
        return tuple(
            sorted(
                (
                    request
                    for request in requests
                    if request.state is ApprovalState.PENDING
                ),
                key=lambda request: (request.created_at, request.request_id),
            )
        )

    def approve(
        self, request_id: str, *, digest: str, reviewer: str
    ) -> ApprovalRequest:
        """Approves the exact proposal that was reviewed.

        `digest` is what the reviewer saw. If it is not the request's proposal,
        the approval is refused rather than applied to whatever is in the file.
        Repeating the same approval is idempotent; a different one is not.
        """
        request = self.load(request_id)
        if request.state is ApprovalState.REJECTED:
            raise ApprovalQueueError(
                f"request {request.request_id} was rejected, and a rejection is "
                "terminal: it cannot be approved later."
            )
        if request.state is ApprovalState.APPROVED:
            if digest == request.proposal.digest and reviewer == request.reviewer:
                return request
            raise ApprovalQueueError(
                f"request {request.request_id} is already approved by "
                f"{request.reviewer!r}; a second approval cannot rewrite the decision."
            )

        reviewer = _require_reviewer(reviewer)
        if not isinstance(digest, str) or digest != request.proposal.digest:
            raise ApprovalQueueError(
                f"the digest {digest!r} is not the digest of the proposal that was "
                f"reviewed ({request.proposal.digest}). An approval names the record "
                "the reviewer actually saw."
            )

        approved = replace(
            request,
            state=ApprovalState.APPROVED,
            reviewer=reviewer,
            decided_at=self._clock(),
        )
        self._write(approved)
        return approved

    def reject(
        self, request_id: str, *, reviewer: str, note: str = ""
    ) -> ApprovalRequest:
        """Rejects a pending request. A rejection is terminal.

        Repeating the same rejection is idempotent; a different reviewer or note
        is refused, because the decision has already been made.
        """
        request = self.load(request_id)
        if request.state is ApprovalState.APPROVED:
            raise ApprovalQueueError(
                f"request {request.request_id} is already approved and cannot be "
                "turned into a rejection."
            )
        if request.state is ApprovalState.REJECTED:
            if reviewer == request.reviewer and note == request.note:
                return request
            raise ApprovalQueueError(
                f"request {request.request_id} is already rejected by "
                f"{request.reviewer!r}; a decision cannot be rewritten."
            )

        reviewer = _require_reviewer(reviewer)

        rejected = replace(
            request,
            state=ApprovalState.REJECTED,
            reviewer=reviewer,
            decided_at=self._clock(),
            note=note,
        )
        self._write(rejected)
        return rejected

    def _write(self, request: ApprovalRequest) -> None:
        """Publishes one request under `os.replace`, so a reader never sees half."""
        try:
            write_json_atomic(self.path_for(request.request_id), request.to_json())
        except RuleStoreError as exc:
            raise ApprovalQueueError(
                f"cannot write request {request.request_id}: {exc}"
            ) from exc
