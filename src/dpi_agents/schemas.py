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

__all__ = [
    "SEVERITIES",
    "IncidentNarrative",
    "NarrativeClaim",
    "TriageVerdict",
    "parse_incident_narrative",
    "parse_triage_verdict",
]

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


# ---------------------------------------------------------------------------
# The narrative (`T4-04`)
# ---------------------------------------------------------------------------
#
# A narrative is prose, and prose is exactly where "every sentence carries its
# evidence" stops being a property and becomes a hope. So a claim carries its
# evidence **structurally**: the five-tuples and the apps it rests on. Both are
# checkable against the run.
#
# What is *not* checkable here is whether the cited evidence **supports** the
# claim in the prose -- that is a judgement, and it is `T4-06`'s job
# (citation-enforced RAG). The boundary is stated rather than blurred: this
# layer guarantees the citation is real; the next one guarantees it is apt.


@dataclasses.dataclass(frozen=True, slots=True)
class NarrativeClaim:
    """One claim, and what it rests on."""

    text: str
    flows: tuple[FiveTuple, ...] = ()
    apps: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class IncidentNarrative:
    """What the Explainer concluded, as a summary and the claims under it."""

    summary: str
    claims: tuple[NarrativeClaim, ...] = ()


def _parse_apps(raw: Any) -> tuple[str, ...]:
    """The apps a claim rests on, if it names any."""
    if "apps" not in raw:
        return ()
    apps = raw["apps"]
    if not isinstance(apps, list) or not all(isinstance(item, str) and item for item in apps):
        raise ValueError(f"apps must be a list of non-empty strings, got {apps!r}")
    return tuple(apps)


def parse_incident_narrative(text: str) -> IncidentNarrative:
    """Parse and validate an incident narrative.

    A claim with no citation is **not** refused: "nothing notable" is a
    legitimate narrative, and the summary says so. What is refused is a claim
    that cites something malformed \u2014 a flow that is not five integers, an app
    that is not a name \u2014 because a citation that cannot be checked is worse
    than no citation, since it looks like evidence.
    """
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"a narrative must be JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"a narrative must be an object, got {type(raw).__name__}")

    summary = raw.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError(f"a narrative needs a non-empty summary, got {summary!r}")

    claims = raw.get("claims", [])
    if not isinstance(claims, list):
        raise ValueError(f"claims must be a list, got {type(claims).__name__}")

    parsed: list[NarrativeClaim] = []
    for claim in claims:
        if not isinstance(claim, dict):
            raise ValueError(f"a claim must be an object, got {type(claim).__name__}")
        claim_text = claim.get("text")
        if not isinstance(claim_text, str) or not claim_text.strip():
            raise ValueError(f"a claim needs non-empty text, got {claim_text!r}")
        flows = claim.get("flows", [])
        if not isinstance(flows, list):
            raise ValueError(f"a claim's flows must be a list, got {type(flows).__name__}")
        parsed.append(
            NarrativeClaim(
                text=claim_text,
                flows=tuple(_parse_five_tuple(flow) for flow in flows),
                apps=_parse_apps(claim),
            )
        )

    return IncidentNarrative(summary=summary, claims=tuple(parsed))
