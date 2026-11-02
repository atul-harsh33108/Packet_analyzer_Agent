"""The write path (`T6-06`): the one door that changes policy.

**Why one door.** The store (`T6-01`), the proposal (`T6-02`), the breaker
(`T6-04`), the queue (`T6-05`) and the audit log (`T6-06`) each protect one
property. A caller that used them separately could commit without logging,
activate a version nobody reviewed, or record an approval for one proposal and
apply another. So there is exactly one function that commits and exactly one
that appends, and they are the same function: `WritePath.apply`. Nothing in the
engine calls `RuleStore.commit` or `AuditLog.append` for a change; they are
reached through here.

**The checks are re-derived, not trusted.** The proposal is asked for its own
digest again (a value that was mutated after construction is refused before the
store is touched), and the version the store mints is compared with the one the
proposal named. The tier is read from the decision and re-checked against the
proposal and the approval: auto-apply is only for a signature-table proposal and
carries no request; a human tier requires an **approved** request whose proposal
digest and whose breaker decision are the ones being applied. The queue recorded
those values; this door proves they still agree.

**The order is commit, activate, append.** A record never claims a change that
is not in force, so the audit entry is the last write. The cost is named rather
than hidden: a crash between `activate` and the append leaves the version active
and unlogged, because the store and the log are two files and this door does not
pretend to be a transaction across them. The log verifies what it holds; a
deployment that needs the gap closed needs an anchor outside the directory (a
signed checkpoint, a remote witness), not another local write.

**A replay is refused.** The log's applied digests are read before anything is
written, and reading verifies the chain, so an edited log cannot be extended and
a proposal that was already applied cannot be applied a second time. A retry is
therefore safe: it fails loudly instead of producing a second version or a
second entry.

**What this module does not do.** It does not classify (the breaker did), does
not decide whether a human was needed (the queue recorded that), and does not
revert (a revert is a new proposal, committed and applied through this same
door in `T6-07`).
"""

from __future__ import annotations

from dataclasses import dataclass

from dpi_engine.approval_queue import ApprovalRequest, ApprovalState
from dpi_engine.audit_log import AUTO_ACTOR, AuditLog, AuditRecord
from dpi_engine.blast_radius import BreakerDecision, Tier
from dpi_engine.proposal import Proposal
from dpi_engine.rule_store import PolicyKind, PolicyVersion, RuleStore

__all__ = ["AppliedChange", "WritePath", "WritePathError"]


class WritePathError(ValueError):
    """A change was asked for that the door refuses to apply.

    A `ValueError` so it joins the engine's other refusals, and named so a caller
    can tell "this change is not allowed" from "the store or the log is
    unreadable" (which are their own errors and are not caught here).
    """


@dataclass(frozen=True, slots=True)
class AppliedChange:
    """The committed version and the audit entry that records it.

    Returned rather than logged elsewhere so the caller can report the version
    id and the entry hash together, and the two cannot be paired up wrongly.
    """

    version: PolicyVersion
    record: AuditRecord

    @property
    def version_id(self) -> str:
        """The id of the version that is now active."""
        return self.version.version_id

    @property
    def proposal_digest(self) -> str:
        """The digest of the proposal that was applied."""
        return self.record.proposal_digest

    @property
    def tier(self) -> Tier:
        """The breaker's tier for this change, as it was recorded."""
        return self.record.tier


class WritePath:
    """The single door: verify, commit, activate, append.

    The store and the log are the whole durable state. Neither is optional:
    construct this with both or not at all, so there is no configuration in
    which a caller has a store to write through but no log to write to.
    """

    def __init__(self, store: RuleStore, audit: AuditLog) -> None:
        if not isinstance(store, RuleStore):
            raise WritePathError(
                f"WritePath needs a RuleStore, got {type(store).__name__}"
            )
        if not isinstance(audit, AuditLog):
            raise WritePathError(
                f"WritePath needs an AuditLog, got {type(audit).__name__}"
            )
        self._store = store
        self._audit = audit

    @property
    def store(self) -> RuleStore:
        """The policy store this door writes through."""
        return self._store

    @property
    def audit(self) -> AuditLog:
        """The log every change through this door is recorded in."""
        return self._audit

    def apply(
        self,
        proposal: Proposal,
        decision: BreakerDecision,
        *,
        approval: ApprovalRequest | None = None,
    ) -> AppliedChange:
        """Applies one proposal, or refuses and leaves the active version alone.

        `approval` is the request the reviewer decided. It is ignored only for
        auto-apply, where by definition no reviewer was involved -- and even then
        supplying one is refused, because an approval that was never needed is a
        record that says something false about the change.
        """
        if not isinstance(proposal, Proposal):
            raise WritePathError(
                f"apply needs a Proposal, got {type(proposal).__name__}"
            )
        if not isinstance(decision, BreakerDecision):
            raise WritePathError(
                "apply needs the breaker's BreakerDecision, got "
                f"{type(decision).__name__}"
            )
        if approval is not None and not isinstance(approval, ApprovalRequest):
            raise WritePathError(
                "an approval must be an ApprovalRequest or None, got "
                f"{type(approval).__name__}"
            )

        computed = proposal.computed_digest
        if computed != proposal.digest:
            raise WritePathError(
                f"the proposal's digest {proposal.digest} does not match its "
                f"contents ({computed}). The bytes reviewed must be the bytes "
                "applied, so an edited proposal is refused."
            )

        if decision.tier is Tier.REFUSED:
            raise WritePathError(
                "the breaker refused this proposal: a change that forwards "
                "nothing is not made approvable by reaching the write path."
            )

        if decision.tier is Tier.AUTO_APPLY:
            request_id, actor = self._auto_apply(proposal, approval)
        else:
            request_id, actor = self._human_tier(proposal, decision, approval)

        if proposal.digest in self._audit.applied_digests():
            raise WritePathError(
                f"proposal {proposal.digest} is already applied. A digest names "
                "one change, and applying it twice would file a second version "
                "and a second audit entry for one review."
            )

        version = self._store.commit(
            proposal.kind,
            proposal.document,
            provenance=proposal.provenance,
            note=proposal.note,
            parent=proposal.parent,
        )
        if version.version_id != proposal.version_id:
            raise WritePathError(
                f"the store committed version {version.version_id}, but the "
                f"proposal addresses {proposal.version_id}. Refusing to activate "
                "a version that is not the one the reviewer saw; the committed "
                "file is inert until something points at it."
            )

        self._store.activate(version.version_id)
        record = self._audit.append(
            proposal=proposal,
            version=version,
            tier=decision.tier,
            actor=actor,
            request_id=request_id,
        )
        return AppliedChange(version=version, record=record)

    def _auto_apply(
        self, proposal: Proposal, approval: ApprovalRequest | None
    ) -> tuple[None, str]:
        """The eligibility check for the one path that skips the human gate."""
        if approval is not None:
            raise WritePathError(
                "an auto-apply change needs no human approval, so an approval "
                f"must not be supplied (request {approval.request_id})."
            )
        if proposal.kind is not PolicyKind.SIGNATURES:
            raise WritePathError(
                "auto-apply is only for a signatures proposal, because only a "
                "signature-table entry identifies traffic instead of dropping "
                f"it. This proposal is a {proposal.kind.value} proposal."
            )
        return None, AUTO_ACTOR

    def _human_tier(
        self,
        proposal: Proposal,
        decision: BreakerDecision,
        approval: ApprovalRequest | None,
    ) -> tuple[str, str]:
        """The approval check for the two tiers that wait for a person."""
        if approval is None:
            raise WritePathError(
                f"a {decision.tier.value} change requires an approved request. "
                "Without one the change has no reviewer, and the audit entry "
                "would name a person who never saw it."
            )
        if approval.state is not ApprovalState.APPROVED:
            raise WritePathError(
                f"request {approval.request_id} is {approval.state.value}, not "
                "approved. Only a decision in the approved state permits a write."
            )
        if approval.proposal.digest != proposal.digest:
            raise WritePathError(
                f"the approved request names proposal digest "
                f"{approval.proposal.digest}, but this proposal is "
                f"{proposal.digest}. Approving one change cannot apply another."
            )
        if approval.proposal != proposal:
            raise WritePathError(
                "the approved request's proposal is not the proposal being "
                "applied. The two records disagree about the change itself."
            )
        if approval.decision != decision:
            raise WritePathError(
                f"the approved request's decision is a "
                f"{approval.decision.tier.value} change, but this apply names a "
                f"{decision.tier.value} one. The tier recorded by the reviewer is "
                "the tier that may be applied."
            )
        if approval.reviewer is None:
            raise WritePathError(
                f"request {approval.request_id} is approved but names no reviewer. "
                "An approval with no accountable person is not an approval."
            )
        return approval.request_id, approval.reviewer
