"""What a set of unknown flows supports in common (`T5-05`).

**The gap has two halves, and this is the deterministic one.** `T5-04`'s table
says what an app is; a flow no signature claims is a gap. Closing it is a claim
about a *set* of flows -- "these clients all offered this, and none of them
offered that" -- and a claim of that shape can be computed rather than guessed.
`common_predicates` is that computation.

**Why the intersection, and not the union.** A predicate is positive evidence:
it says every flow a signature matches shows this. The union of what several
flows showed would produce a signature that matches none of them, which is the
opposite of a signature. So a scalar is proposed only when **every** flow agrees
on an observed value, and a list element only when **every** flow lists it.

**Why the order is pinned.** A signature is compared, diffed and reviewed, not
just matched, so two runs over the same flows have to produce the same tuple.
Scalars follow the vocabulary's own order and list elements are sorted by value;
neither depends on how the flows happened to arrive.

**Why an absence is not a fact.** ``""``, ``None`` and ``()`` are what an
unobserved field reads as. Proposing ``ja3s: ""`` would be proposing a signature
that matches every flow that showed nothing -- a category, not an app. The one
exception is deliberate: ``sni_present: False`` is something a client *did*
(send a ClientHello with no SNI), so it is observed and it identifies.

**Why the input is policed.** A known flow is not part of the gap: a proposal
built from a flow the engine already classified would be re-deriving a fact and
calling it a discovery. So a non-``UNKNOWN`` flow is refused rather than quietly
filtered, and an empty set is refused rather than answered with the empty
conjunction -- which matches everything and is the worst possible signature.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from dpi_engine.signatures import (
    LIST_FIELDS,
    SCALAR_FIELDS,
    Predicate,
    observed_fields,
)
from dpi_engine.types import AppType, FlowRecord

__all__ = ["common_predicates"]


def common_predicates(flows: Sequence[FlowRecord]) -> tuple[Predicate, ...]:
    """The predicates every one of `flows` supports, in a canonical order.

    Raises for an empty set (nothing is shared by nothing, and the empty
    conjunction matches every flow) and for any flow the engine already
    classified (that flow is not part of the gap).
    """
    if not flows:
        raise ValueError(
            "common predicates need at least one flow: the empty conjunction "
            "matches every flow, which is not an app"
        )
    for flow in flows:
        if flow.app != AppType.UNKNOWN.name:
            raise ValueError(
                f"flow {flow.five_tuple} is classified {flow.app!r}, not UNKNOWN: "
                "only unclassified flows are part of the classifier gap"
            )

    observed = [observed_fields(flow.features) for flow in flows]
    predicates: list[Predicate] = []

    for field in SCALAR_FIELDS:
        value = observed[0][field]
        if _is_observed(value) and all(row[field] == value for row in observed[1:]):
            predicates.append(Predicate(field=field, value=value))

    for field in LIST_FIELDS:
        shared = set(observed[0][field])
        for row in observed[1:]:
            shared &= set(row[field])
        for value in sorted(shared):
            predicates.append(Predicate(field=field, value=value))

    return tuple(predicates)


def _is_observed(value: Any) -> bool:
    """Whether a scalar was actually seen, rather than a field's empty default.

    ``False`` is observed: a client that sent no SNI did something checkable.
    ``""`` and ``None`` are not: they are how an absent observation reads.
    """
    return value is not None and value != ""
