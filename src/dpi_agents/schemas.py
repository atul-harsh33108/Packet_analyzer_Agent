"""The agents' typed verdicts (`T4-03`).

**A verdict that cannot be checked is an assertion.** The design's Triage
verdict is `{severity, categories[], flows[], needs_deep}` \u2014 and the `flows`
are the point: they are the five-tuples the verdict is *about*, so a reader can
check the claim against the run it came from. A verdict that says "high" and
names nothing can be neither checked nor argued with.

**Validation is deterministic, and it happens here.** Layer 7: *deterministic
validation of every proposal. Garbage is caught by code, not by hope.* A model
that invents a severity, or a flow that is not five integers, or a
``needs_deep`` that is not a boolean, is refused \u2014 the parse raises, and the
runtime records an invalid verdict rather than a wrong one.

**The `flows` are the engine's own five-tuple**, not a copy of it, so a verdict
can be compared with the store's rows without a translation step that could
disagree with them.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from dpi_engine.types import FiveTuple

__all__ = ["SEVERITIES", "TriageVerdict", "parse_triage_verdict"]

#: The severities a verdict may carry.
#:
#: A fixed set, because "very high" is not a severity: a free-text severity is a
#: severity nobody can compare across runs, and the whole point of a typed
#: verdict is that two of them can be compared.
SEVERITIES: tuple[str, ...] = ("none", "low", "medium", "high", "critical")


@dataclasses.dataclass(frozen=True, slots=True)
class TriageVerdict:
    """What Triage concluded about a run.

    `flows` are the five-tuples the verdict is about, and `categories` are the
    buckets it sorted them into. `needs_deep` says whether a deeper agent should
    look \u2014 and in Phase 4 nothing does, which is the honest state of it: the
    design's AnomalyDeep agent is Phase 5's business, so the flag is reported
    and nothing acts on it yet.
    """

    severity: str
    categories: tuple[str, ...]
    flows: tuple[FiveTuple, ...]
    needs_deep: bool


def _parse_five_tuple(raw: Any) -> FiveTuple:
    """One five-tuple, or a raise.

    The five fields are required, and they must be integers \u2014 a tuple with a
    string in it is not a flow, and a verdict that points at a thing that is not
    a flow points at nothing.
    """
    if not isinstance(raw, dict):
        raise ValueError(f"a flow must be an object, got {type(raw).__name__}")
    missing = [
        name
        for name in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")
        if name not in raw
    ]
    if missing:
        raise ValueError(f"a flow is missing {', '.join(missing)}")
    values: list[int] = []
    for name in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol"):
        value = raw[name]
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{name} must be an integer, got {value!r}")
        values.append(value)
    return FiveTuple(
        src_ip=values[0],
        dst_ip=values[1],
        src_port=values[2],
        dst_port=values[3],
        protocol=values[4],
    )


def parse_triage_verdict(text: str) -> TriageVerdict:
    """Parse and validate a Triage verdict.

    Raises on anything malformed, and the runtime turns that into "no verdict"
    with the reason recorded \u2014 which is the outcome the design wants: a
    malformed answer is not a verdict, and it is not silently half of one.
    """
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"a verdict must be JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"a verdict must be an object, got {type(raw).__name__}")

    severity = raw.get("severity")
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {', '.join(SEVERITIES)}, got {severity!r}")

    categories = raw.get("categories", [])
    if not isinstance(categories, list) or not all(
        isinstance(item, str) and item for item in categories
    ):
        raise ValueError(f"categories must be a list of non-empty strings, got {categories!r}")

    flows = raw.get("flows", [])
    if not isinstance(flows, list):
        raise ValueError(f"flows must be a list, got {type(flows).__name__}")

    needs_deep = raw.get("needs_deep", False)
    if not isinstance(needs_deep, bool):
        raise ValueError(f"needs_deep must be a boolean, got {needs_deep!r}")

    return TriageVerdict(
        severity=severity,
        categories=tuple(categories),
        flows=tuple(_parse_five_tuple(flow) for flow in flows),
        needs_deep=needs_deep,
    )
