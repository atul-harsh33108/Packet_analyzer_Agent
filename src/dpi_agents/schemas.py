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
from collections.abc import Sequence
from typing import Any

from dpi_engine.maintenance import Critique, Verdict
from dpi_engine.proposals import common_predicates
from dpi_engine.signatures import (
    Predicate,
    Signature,
    predicate_from_json,
    predicate_to_json,
)
from dpi_engine.types import AppType, FiveTuple, FlowRecord

__all__ = [
    "SEVERITIES",
    "DocumentCitation",
    "IncidentNarrative",
    "NarrativeClaim",
    "NewAppCandidate",
    "TriageVerdict",
    "parse_critic_verdict",
    "parse_incident_narrative",
    "parse_new_app_candidate",
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
class DocumentCitation:
    """A citation of a document: the chunk, and the quote taken from it.

    The **quote** is the point. A citation that names a chunk without saying
    what was taken from it cannot be checked \u2014 and a citation that cannot be
    checked is worse than none, because it looks like evidence.
    """

    chunk_id: str
    quote: str


@dataclasses.dataclass(frozen=True, slots=True)
class NarrativeClaim:
    """One claim, and what it rests on."""

    text: str
    flows: tuple[FiveTuple, ...] = ()
    apps: tuple[str, ...] = ()
    citations: tuple[DocumentCitation, ...] = ()


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


def _parse_citations(raw: Any) -> tuple[DocumentCitation, ...]:
    """A claim's document citations, or a raise.

    A citation must name a chunk **and** quote something: a citation that
    names a chunk and says nothing is a reference, and a reference that cannot
    be checked is not evidence.
    """
    if "citations" not in raw:
        return ()
    citations = raw["citations"]
    if not isinstance(citations, list):
        raise ValueError(f"citations must be a list, got {type(citations).__name__}")
    parsed: list[DocumentCitation] = []
    for citation in citations:
        if not isinstance(citation, dict):
            raise ValueError(f"a citation must be an object, got {type(citation).__name__}")
        chunk_id = citation.get("chunk_id")
        quote = citation.get("quote")
        if not isinstance(chunk_id, str) or not chunk_id.strip():
            raise ValueError(f"a citation needs a chunk id, got {chunk_id!r}")
        if not isinstance(quote, str) or not quote.strip():
            raise ValueError(f"a citation needs a quote, got {quote!r}")
        parsed.append(DocumentCitation(chunk_id=chunk_id, quote=quote))
    return tuple(parsed)


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
                citations=_parse_citations(claim),
            )
        )

    return IncidentNarrative(summary=summary, claims=tuple(parsed))


# ---------------------------------------------------------------------------
# The classifier gap: a proposed app, and the evidence it has to earn (`T5-05`)
# ---------------------------------------------------------------------------
#
# The engine computes what the unknown flows share (`common_predicates`); the
# model names the app and selects the patterns, and this parser checks the
# selection against the computation. That split is the point: a model cannot
# invent a fingerprint, because a pattern it did not see in the cited flows is
# refused here. `to_signature` then makes "proposed signature" literal -- the
# candidate becomes an entry `T5-04`'s table can identify flows with.

#: Every key a candidate must carry. Missing one is refused, never defaulted:
#: a defaulted citation list would be a proposal with no evidence.
_CANDIDATE_KEYS = frozenset(
    {"name", "evidence", "confidence", "proposed_patterns", "citations"}
)


@dataclasses.dataclass(frozen=True, slots=True)
class NewAppCandidate:
    """A proposed app, the facts it rests on, and the flows those facts came from.

    The invariants live here rather than only in the parser, for the reason
    `T5-04` learned: `T5-06`'s maintenance loop builds candidates in memory, and
    an invariant that holds only when a value arrives through one door does not
    hold. A candidate with no citation, no pattern or a pattern-less
    ``proposed_patterns`` is refused at construction.
    """

    name: str
    evidence: tuple[str, ...]
    confidence: float
    proposed_patterns: tuple[Predicate, ...]
    citations: tuple[FiveTuple, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError(f"a candidate needs a non-empty name, got {self.name!r}")
        if not isinstance(self.evidence, tuple) or not self.evidence:
            raise ValueError("a candidate needs evidence: a claim with no reason cannot be checked")
        if not all(isinstance(item, str) and item.strip() for item in self.evidence):
            raise ValueError(f"a candidate's evidence must be non-empty text, got {self.evidence!r}")
        if not _valid_confidence(self.confidence):
            raise ValueError(
                "a candidate's confidence must be a number in [0, 1], "
                f"got {self.confidence!r}"
            )
        if not isinstance(self.proposed_patterns, tuple) or not self.proposed_patterns:
            raise ValueError(
                "a candidate's proposed_patterns must be a non-empty conjunction: "
                "an empty one matches every flow"
            )
        if len(set(self.proposed_patterns)) != len(self.proposed_patterns):
            raise ValueError("a candidate lists the same pattern twice")
        if not isinstance(self.citations, tuple) or not self.citations:
            raise ValueError("a candidate cites no flow: a proposal that names no flow is uncheckable")
        if len(set(self.citations)) != len(self.citations):
            raise ValueError("a candidate cites the same flow twice")

    def to_json(self) -> dict[str, Any]:
        """The wire shape. Citations flatten like a `query_flows` row."""
        return {
            "name": self.name,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "proposed_patterns": [
                predicate_to_json(predicate) for predicate in self.proposed_patterns
            ],
            "citations": [
                {
                    "src_ip": citation.src_ip,
                    "dst_ip": citation.dst_ip,
                    "src_port": citation.src_port,
                    "dst_port": citation.dst_port,
                    "protocol": citation.protocol,
                }
                for citation in self.citations
            ],
        }

    def to_signature(self, signature_id: str) -> Signature:
        """Compose the candidate into a table entry, under `signature_id`."""
        return Signature(id=signature_id, app=self.name, all_of=self.proposed_patterns)


def _valid_confidence(value: Any) -> bool:
    """A probability: a real number in [0, 1], and not a bool dressed as one."""
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and value == value  # NaN compares unequal to itself
        and 0.0 <= value <= 1.0
    )


def _candidate_required(raw: dict[str, Any], key: str) -> Any:
    if key not in raw:
        raise ValueError(f"a candidate is missing the {key} field")
    return raw[key]


def _candidate_text(raw: dict[str, Any], key: str) -> str:
    value = _candidate_required(raw, key)
    if not isinstance(value, str):
        raise ValueError(f"a candidate's {key} must be a string, got {type(value).__name__}")
    return value


def _candidate_evidence(raw: dict[str, Any]) -> tuple[str, ...]:
    value = _candidate_required(raw, "evidence")
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item.strip() for item in value)
    ):
        raise ValueError(
            f"a candidate's evidence must be a list of non-empty strings, got {value!r}"
        )
    return tuple(value)


def _candidate_confidence(raw: dict[str, Any]) -> float:
    value = _candidate_required(raw, "confidence")
    if not _valid_confidence(value):
        raise ValueError(
            f"a candidate's confidence must be a number in [0, 1], got {value!r}"
        )
    return float(value)


def _candidate_patterns(raw: dict[str, Any]) -> tuple[Predicate, ...]:
    value = _candidate_required(raw, "proposed_patterns")
    if not isinstance(value, list):
        raise ValueError(
            "a candidate's proposed_patterns must be a list, "
            f"got {type(value).__name__}"
        )
    return tuple(
        predicate_from_json(entry, f"proposed_patterns[{index}]")
        for index, entry in enumerate(value)
    )


def _candidate_citations(
    raw: dict[str, Any], flows: Sequence[FlowRecord]
) -> tuple[FiveTuple, ...]:
    value = _candidate_required(raw, "citations")
    if not isinstance(value, list):
        raise ValueError(f"a candidate's citations must be a list, got {type(value).__name__}")
    supplied = {flow.five_tuple for flow in flows}
    citations: list[FiveTuple] = []
    for citation in value:
        parsed = _parse_five_tuple(citation)
        if parsed not in supplied:
            raise ValueError(
                f"citation {parsed} is not one of the flows this proposal was given"
            )
        citations.append(parsed)
    return tuple(citations)


def parse_new_app_candidate(
    text: str, *, flows: Sequence[FlowRecord]
) -> NewAppCandidate:
    """Parse a proposal and check every pattern against the flows it cites.

    `flows` are the unknown flows the agent was given. A citation must name one
    of them, and every proposed pattern must be a fact those cited flows share
    -- recomputed here with `common_predicates`, so the check cannot be talked
    around by a confident sentence.
    """
    if not flows:
        raise ValueError(
            "a proposal cannot be checked against no flows: none were supplied"
        )
    for flow in flows:
        if flow.app != AppType.UNKNOWN.name:
            raise ValueError(
                f"flow {flow.five_tuple} is classified {flow.app!r}, not UNKNOWN: "
                "only unclassified flows are part of the classifier gap"
            )

    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"a candidate must be JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"a candidate must be an object, got {type(raw).__name__}")
    unknown = sorted(set(raw) - _CANDIDATE_KEYS)
    if unknown:
        raise ValueError(f"a candidate has an unknown key {unknown[0]!r}")

    name = _candidate_text(raw, "name")
    evidence = _candidate_evidence(raw)
    confidence = _candidate_confidence(raw)
    patterns = _candidate_patterns(raw)
    citations = _candidate_citations(raw, flows)

    # Shape first: a candidate with no citation or no pattern is malformed
    # regardless of what the flows show, so it must be refused as such.
    candidate = NewAppCandidate(
        name=name,
        evidence=evidence,
        confidence=confidence,
        proposed_patterns=patterns,
        citations=citations,
    )

    cited = tuple(flow for flow in flows if flow.five_tuple in set(citations))
    supported = common_predicates(cited)
    for pattern in candidate.proposed_patterns:
        if pattern not in supported:
            raise ValueError(
                f"pattern {pattern.field}={pattern.value!r} is not supported by "
                "the flows it cites"
            )

    return candidate


# ---------------------------------------------------------------------------
# The Critic's verdict: shaped by code, argued by the model (`T5-06`)
# ---------------------------------------------------------------------------
#
# The engine has already computed what is wrong (`Critique`). The model's job is
# to argue about it, not to redo it, so the parser pins the answer to that
# critique: an approval of a contradicted proposal is refused as a rubber stamp,
# and a named counterexample has to be one of the contradictions. A clean
# proposal may still be vetoed -- the deterministic check only knows what the
# engine has labelled -- but a veto must say what is wrong.

#: Every key a Critic verdict must carry. Missing one is refused, never defaulted.
_CRITIC_VERDICT_KEYS = frozenset(
    {"outcome", "reason", "objections", "counterexamples"}
)


def _critic_required(raw: dict[str, Any], key: str) -> Any:
    if key not in raw:
        raise ValueError(f"a critic verdict is missing the {key} field")
    return raw[key]


def _critic_objections(raw: dict[str, Any]) -> tuple[str, ...]:
    value = _critic_required(raw, "objections")
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ValueError(
            "a critic verdict's objections must be a list of non-empty strings, "
            f"got {value!r}"
        )
    return tuple(value)


def _parse_counterexample(raw: Any) -> FiveTuple:
    """One counterexample, with the integer check ahead of the missing-key one.

    A malformed value is the more useful error than a missing sibling: when the
    model supplied `src_ip` as a string, saying "src_ip must be an integer" is
    what a reader can act on. `_parse_five_tuple` then enforces the rest.
    """
    if isinstance(raw, dict):
        for name in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol"):
            if name in raw:
                value = raw[name]
                if not isinstance(value, int) or isinstance(value, bool):
                    raise ValueError(
                        f"a counterexample's {name} must be an integer, got {value!r}"
                    )
    return _parse_five_tuple(raw)


def _critic_counterexamples(raw: dict[str, Any]) -> tuple[FiveTuple, ...]:
    value = _critic_required(raw, "counterexamples")
    if not isinstance(value, list):
        raise ValueError(
            "a critic verdict's counterexamples must be a list, "
            f"got {type(value).__name__}"
        )
    return tuple(_parse_counterexample(entry) for entry in value)


def parse_critic_verdict(text: str, *, critique: Critique) -> Verdict:
    """Parse the Critic's answer and pin it to the computed critique.

    The shape is checked first, then the two coherence rules: an approval of a
    contradicted proposal is a rubber stamp, and every named counterexample must
    be a flow the critique actually found. An uncited veto is allowed, because
    the deterministic check cannot see everything a reviewer can.
    """
    if not isinstance(critique, Critique):
        raise ValueError(
            "a critic verdict must be checked against a Critique, "
            f"got {type(critique).__name__}"
        )

    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"a critic verdict must be JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(
            f"a critic verdict must be an object, got {type(raw).__name__}"
        )
    unknown = sorted(set(raw) - _CRITIC_VERDICT_KEYS)
    if unknown:
        raise ValueError(f"a critic verdict has an unknown key {unknown[0]!r}")

    outcome = _critic_required(raw, "outcome")
    reason = _critic_required(raw, "reason")
    objections = _critic_objections(raw)
    counterexamples = _critic_counterexamples(raw)

    if outcome == "approved" and critique.contradictions:
        raise ValueError(
            "the Critic approved a proposal the corpus contradicts: that is a "
            "rubber stamp, not a review"
        )

    verdict = Verdict(
        outcome=outcome,
        reason=reason,
        objections=objections,
        counterexamples=counterexamples,
    )

    if verdict.outcome == "falsified":
        contradictions = {entry.five_tuple for entry in critique.contradictions}
        for counterexample in verdict.counterexamples:
            if counterexample not in contradictions:
                raise ValueError(
                    f"counterexample {counterexample} is not one of the "
                    "contradictions this critique found"
                )
        if critique.contradictions and not verdict.counterexamples:
            raise ValueError(
                "the Critic falsified a contradicted proposal but did not name "
                "at least one of the contradictions"
            )

    return verdict
