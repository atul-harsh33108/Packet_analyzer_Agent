"""The deterministic half of the maintenance loop (`T5-06`).

**A proposal becomes a table entry only if a falsifier fails to kill it.** `T5-05`
produces a name, a conjunction and the flows those facts came from; nothing in
it yet stops that conjunction from being true of traffic the engine already
knows. A signature is a claim that *this conjunction means this app*, and the
cheapest way for such a claim to be wrong is that it also matches a flow with a
different known label. `critique` is that check, and it is computed here rather
than argued by a model: the model can only name what the bytes show, and the
model that follows it can only argue about what this returns.

**What counts as a contradiction.** A flow the signature matches whose `app` is
a different *known* label. `UNKNOWN` never contradicts -- it is the absence of a
label, not a label that disagrees -- and a flow already labelled with the
proposed app is support, not a contradiction. The list is sorted by five-tuple
so two runs over the same flows produce the same critique; a review that
reorders itself cannot be compared between runs.

**A proposal that cannot be cited is not reviewed.** Every citation must be one
of the flows under review, and the cited flow must actually hold the signature.
Those refusals are not pedantry: a citation from somewhere else is a claim
nobody can check, and a cited flow that does not match is evidence that argues
against the proposal while pretending to argue for it.

**`install` is the only door.** It refuses a contradicted proposal *even when
the Critic approved it*, and refuses an uncontradicted one the Critic vetoed.
Both directions matter: a deterministic floor the model can wave through is not
a floor, and a Critic that cannot veto is decoration.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from dpi_engine.signatures import Signature, SignatureTable
from dpi_engine.types import AppType, FiveTuple, FlowRecord

__all__ = ["Contradiction", "Critique", "Verdict", "critique", "install"]

#: The two outcomes the loop understands. Anything else is a malformed verdict.
_OUTCOMES = ("approved", "falsified")


def _five_tuple_to_json(five_tuple: FiveTuple) -> dict[str, int]:
    return {
        "src_ip": five_tuple.src_ip,
        "dst_ip": five_tuple.dst_ip,
        "src_port": five_tuple.src_port,
        "dst_port": five_tuple.dst_port,
        "protocol": five_tuple.protocol,
    }


@dataclass(frozen=True, slots=True)
class Contradiction:
    """One flow that falsifies a proposal: it matches, and it is another app."""

    five_tuple: FiveTuple
    label: str

    def to_json(self) -> dict[str, Any]:
        return {"five_tuple": _five_tuple_to_json(self.five_tuple), "label": self.label}


@dataclass(frozen=True, slots=True)
class Critique:
    """The computed review of one proposed signature.

    Built only by `critique`, which is what keeps `approved` honest: it is
    derived from `contradictions`, not a second opinion that could disagree with
    them.
    """

    signature: Signature
    cited: tuple[FiveTuple, ...]
    contradictions: tuple[Contradiction, ...]

    @property
    def signature_id(self) -> str:
        return self.signature.id

    @property
    def app(self) -> str:
        return self.signature.app

    @property
    def approved(self) -> bool:
        """True when no flow the engine knows contradicts the conjunction."""
        return not self.contradictions

    def to_json(self) -> dict[str, Any]:
        """The review state the Critic is given. `approved` is included so a
        reader does not have to re-derive it from the contradiction list."""
        return {
            "signature": self.signature.to_json(),
            "cited": [_five_tuple_to_json(five_tuple) for five_tuple in self.cited],
            "approved": self.approved,
            "contradictions": [
                contradiction.to_json() for contradiction in self.contradictions
            ],
        }


@dataclass(frozen=True, slots=True)
class Verdict:
    """The Critic's answer: approve, or falsify with a reason.

    A `falsified` verdict has to say what is wrong -- an objection or a named
    counterexample -- because "no" with no reason cannot be reviewed, and the
    loop's whole point is that its refusals are inspectable. An `approved`
    verdict cannot carry a counterexample: a flow that contradicts the proposal
    and an approval of it cannot both be true.
    """

    outcome: str
    reason: str
    objections: tuple[str, ...]
    counterexamples: tuple[FiveTuple, ...]

    def __post_init__(self) -> None:
        if self.outcome not in _OUTCOMES:
            raise ValueError(
                "a verdict's outcome must be 'approved' or 'falsified', "
                f"got {self.outcome!r}"
            )
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("a verdict needs a non-empty reason")
        if not isinstance(self.objections, tuple) or not all(
            isinstance(objection, str) and objection.strip()
            for objection in self.objections
        ):
            raise ValueError(
                f"a verdict's objections must be non-empty text, got {self.objections!r}"
            )
        if len(set(self.counterexamples)) != len(self.counterexamples):
            raise ValueError("a verdict names the same counterexample twice")
        if self.outcome == "approved" and self.counterexamples:
            raise ValueError(
                "an approval cannot name a counterexample: the flow would falsify "
                "what the verdict approves"
            )
        if self.outcome == "falsified" and not self.objections and not self.counterexamples:
            raise ValueError(
                "a falsified verdict must say what is wrong: give at least one "
                "objection or counterexample"
            )

    def to_json(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "reason": self.reason,
            "objections": list(self.objections),
            "counterexamples": [
                _five_tuple_to_json(counterexample)
                for counterexample in self.counterexamples
            ],
        }


def critique(
    signature: Signature,
    flows: Sequence[FlowRecord],
    *,
    cited: Sequence[FiveTuple],
) -> Critique:
    """Falsify `signature` against `flows`, using `cited` as its evidence.

    Raises for a proposal that cannot be cited at all (no citation, a duplicate
    citation, the same flow twice under review, a citation outside the review, or
    a cited flow that does not hold the signature). Those are malformed evidence,
    not a failed falsification: a falsification is a `Critique`, not an error.
    """
    if not cited:
        raise ValueError(
            "a proposal must cite at least one flow: a signature with no evidence "
            "cannot be reviewed"
        )
    if len(set(cited)) != len(cited):
        raise ValueError(f"citation {cited[0]} is cited twice")

    by_tuple: dict[FiveTuple, FlowRecord] = {}
    for flow in flows:
        if flow.five_tuple in by_tuple:
            raise ValueError(f"flow {flow.five_tuple} appears twice in the review evidence")
        by_tuple[flow.five_tuple] = flow

    cited_flows: list[FlowRecord] = []
    for five_tuple in cited:
        cited_flow = by_tuple.get(five_tuple)
        if cited_flow is None:
            raise ValueError(
                f"citation {five_tuple} cannot be cited: it is not one of the flows "
                "under review"
            )
        if not signature.matches(cited_flow.features):
            raise ValueError(
                f"cited flow {five_tuple} does not match signature {signature.id!r}: "
                "a citation that does not show the patterns is not evidence"
            )
        cited_flows.append(cited_flow)

    contradictions = tuple(
        sorted(
            (
                Contradiction(five_tuple=flow.five_tuple, label=flow.app)
                for flow in flows
                if flow.app not in (AppType.UNKNOWN.name, signature.app)
                and signature.matches(flow.features)
            ),
            key=lambda contradiction: contradiction.five_tuple,
        )
    )
    return Critique(
        signature=signature,
        cited=tuple(flow.five_tuple for flow in cited_flows),
        contradictions=contradictions,
    )


def install(
    table: SignatureTable, review: Critique, verdict: Verdict
) -> SignatureTable:
    """Put the reviewed signature into a copy of `table`, or raise.

    The deterministic check is applied first: an approving verdict cannot
    override a contradiction. The Critic's veto is applied second, so a clean
    proposal the model refused is refused too. `SignatureTable` then enforces the
    table's own invariants (unique ids, no duplicate conjunction) by
    construction.
    """
    if review.contradictions:
        first = review.contradictions[0]
        raise ValueError(
            f"the proposal for {review.app!r} is falsified: flow {first.five_tuple} "
            f"is labelled {first.label!r}, which the conjunction also matches"
        )
    if verdict.outcome != "approved":
        raise ValueError(f"the Critic vetoed this proposal: {verdict.reason}")
    return SignatureTable(signatures=(*table.signatures, review.signature))
