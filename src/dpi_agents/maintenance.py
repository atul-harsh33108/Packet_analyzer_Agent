"""The agent half of the maintenance loop (`T5-06`).

**A proposal names the run that can check it.** `T5-05`'s candidate is checked
against the flows the node was *given*; a maintenance proposal has to survive a
check against the run that produced it, because that run is where the flows with
known labels live. `Proposal` binds the two together -- run id, signature id and
the candidate -- and `review` resolves the citations against the stored run and
hands the result to the engine's deterministic falsifier.

**Why the candidate is not re-derived here.** The engine computes what the cited
flows share and refuses a pattern that is not in that conjunction (`T5-05`), and
`critique` refuses a citation that is not under review or a cited flow that does
not hold the signature (`T5-06`). This module adds no third opinion; it only
says *which run* the review is against. An invariant that lives in two places is
an invariant that will differ in one of them.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from dpi_agents.schemas import NewAppCandidate
from dpi_engine.maintenance import Critique, critique
from dpi_engine.run_store import RunStore
from dpi_engine.signatures import Signature

__all__ = ["Proposal", "review"]


@dataclasses.dataclass(frozen=True, slots=True)
class Proposal:
    """A candidate, the run it was derived from, and the id it would install under."""

    run_id: str
    signature_id: str
    candidate: NewAppCandidate

    def __post_init__(self) -> None:
        if not isinstance(self.run_id, str) or not self.run_id.strip():
            raise ValueError(
                f"a proposal must name the run it came from, got {self.run_id!r}"
            )
        if not isinstance(self.signature_id, str) or not self.signature_id.strip():
            raise ValueError(
                "a proposal must name the signature it would install, "
                f"got {self.signature_id!r}"
            )
        if not isinstance(self.candidate, NewAppCandidate):
            raise ValueError(
                "a proposal must hold a candidate (NewAppCandidate), "
                f"got {type(self.candidate).__name__}"
            )

    @property
    def signature(self) -> Signature:
        """The table entry this proposal would install."""
        return self.candidate.to_signature(self.signature_id)

    def to_json(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "signature_id": self.signature_id,
            "candidate": self.candidate.to_json(),
        }


def review(proposal: Proposal, *, store: RunStore) -> Critique:
    """Review `proposal` against the run it names.

    The whole run is the review's evidence; the candidate's citations are the
    part of it that must hold the signature. A citation from another run is
    refused by `critique` rather than silently dropped, because that is what makes
    the citation checkable at all.
    """
    return critique(
        proposal.signature,
        store.query(proposal.run_id),
        cited=proposal.candidate.citations,
    )
