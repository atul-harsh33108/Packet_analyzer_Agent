"""Verdict evaluation (`T4-05`).

**The ground truth is derived, not asserted** (`DEC-12`). Each synthetic corpus
case knows how it was built, so its expected verdict follows from its class:
the categories and the flows are the corpus's own, and the severity is a
**stated mapping** from the class \u2014 five entries, not thirty-three hand-written
ones. Hand-asserted verdicts are what `T2-01` deliberately avoided, and a
hand-written expectation for every case is a second place for the truth to live.

**The criterion has two sides, like `T4-02`'s did.** *Verdict accuracy* alone is
won by an agent that never says "high" \u2014 the corpus already carries the control
for the other side: the legitimate-enterprise cases are traffic that must
**not** be flagged, and an agent that flags them is counted as a false positive.
A corpus without that class would make the accuracy number meaningless.

**What this cannot measure.** The deterministic fake in CI is *scripted*, so a
corpus-wide accuracy figure measured against it measures the **plumbing** \u2014 did
the agent reach the right run, and does it cite the right flows. The *quality*
of a verdict needs a real model, and that is `T4-07`'s, against this same
corpus and this same scorer. The scorer is built to be used by both.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping, Sequence

from dpi_agents.schemas import TriageVerdict
from dpi_agents.trace import TraceStep
from dpi_mcp.run_store import FlowRecord
from golden.corpus import GoldenCase, GoldenClass

__all__ = [
    "SEVERITY_BY_CLASS",
    "ExpectedVerdict",
    "VerdictScore",
    "expected_verdict",
    "score_verdict",
    "trace_covers_verdict",
]


#: How much a scenario class is worth \u2014 the one place a human's judgement
#: enters this module, and it is named as such.
#:
#: It is a mapping over the **five classes**, not over the thirty-three cases:
#: five stated opinions, and every case's expectation follows from the class it
#: was built as. The corpus is the ground truth; this table is the policy for
#: reading it, and a test pins it so a change to it is deliberate.
SEVERITY_BY_CLASS: Mapping[str, str] = {
    GoldenClass.C2_BEACONING: "high",
    GoldenClass.EXFILTRATION: "high",
    GoldenClass.ACTIVE_EVASION: "high",
    GoldenClass.AD_TRAFFIC: "low",
    GoldenClass.LEGITIMATE_ENTERPRISE: "none",
}

#: The classes whose traffic must **not** be flagged. The false-positive control.
QUIET_CLASSES: frozenset[str] = frozenset({GoldenClass.LEGITIMATE_ENTERPRISE})


@dataclasses.dataclass(frozen=True, slots=True)
class ExpectedVerdict:
    """What the agent should have said about a case."""

    severity: str
    categories: tuple[str, ...]
    hostnames: tuple[str, ...]
    #: True when the case is traffic that must not be flagged.
    quiet: bool = False


@dataclasses.dataclass(frozen=True, slots=True)
class VerdictScore:
    """How one verdict measured up against its expectation."""

    case: str
    severity_ok: bool
    category_ok: bool
    flows_ok: bool
    #: True when the agent flagged a case that must not be flagged.
    false_positive: bool

    @property
    def correct(self) -> bool:
        """Whether the verdict matched its expectation on every axis."""
        return self.severity_ok and self.category_ok and self.flows_ok and not self.false_positive


def expected_verdict(case: GoldenCase) -> ExpectedVerdict:
    """What the agent should say about `case`, derived from how it was built."""
    severity = SEVERITY_BY_CLASS.get(case.golden_class)
    if severity is None:
        raise KeyError(
            f"no severity is stated for the class {case.golden_class!r}; a class with no "
            "stated severity has no expected verdict, and guessing one would make the "
            "accuracy number a fiction"
        )
    return ExpectedVerdict(
        severity=severity,
        categories=(case.golden_class,),
        hostnames=tuple(flow.hostname for flow in case.expected),
        quiet=case.golden_class in QUIET_CLASSES,
    )


def _cited_hostnames(
    verdict: TriageVerdict, rows: Sequence[FlowRecord]
) -> set[str]:
    """The hostnames of the flows the verdict cites.

    The verdict cites five-tuples and the run's rows carry hostnames, so the
    citation is checked *through* the run: a cited flow that is not in the run
    has no hostname, and therefore cites nothing.
    """
    by_key = {
        (row.src_ip, row.dst_ip, row.src_port, row.dst_port, row.protocol): row.hostname
        for row in rows
    }
    hostnames: set[str] = set()
    for five_tuple in verdict.flows:
        hostname = by_key.get(
            (
                five_tuple.src_ip,
                five_tuple.dst_ip,
                five_tuple.src_port,
                five_tuple.dst_port,
                five_tuple.protocol,
            )
        )
        if hostname is not None:
            hostnames.add(str(hostname))
    return hostnames


def score_verdict(
    case: GoldenCase,
    verdict: TriageVerdict,
    rows: Sequence[FlowRecord],
) -> VerdictScore:
    """Measure one verdict against its expectation.

    `rows` are the run's own flow rows, so the citation is resolved to the
    hostnames the corpus knows. The store's type rather than its wire form:
    the scorer should not need a projection of the data to check a citation.
    """
    expected = expected_verdict(case)
    cited = _cited_hostnames(verdict, rows)

    severity_ok = verdict.severity == expected.severity
    category_ok = any(category in verdict.categories for category in expected.categories)
    # A claim is right when it names flows of the case. For a quiet case the
    # expectation is the opposite: it names none.
    flows_ok = not cited if expected.quiet else bool(cited & set(expected.hostnames))
    false_positive = expected.quiet and verdict.severity != "none"

    return VerdictScore(
        case=case.name,
        severity_ok=severity_ok,
        category_ok=category_ok,
        flows_ok=flows_ok,
        false_positive=false_positive,
    )


def trace_covers_verdict(steps: Sequence[TraceStep]) -> bool:
    """Whether a trace records everything needed to replay the node.

    "A full replayable trace for every verdict" is the phase's third exit
    criterion, and it is checkable: the trace has to hold the prompt the model
    was given, the observations it was shown, and the verdict it produced. A
    trace with the verdict but not the prompt cannot be replayed, because
    replaying it means running the node again with the same prompt.
    """
    kinds = [getattr(step, "kind", "") for step in steps]
    if "model" not in kinds or "verdict" not in kinds:
        return False
    model_steps = [step for step in steps if getattr(step, "kind", "") == "model"]
    if not all(step.payload.get("system") for step in model_steps):
        return False
    if not all(step.payload.get("prompt_version") for step in model_steps):
        return False
    verdict_steps = [step for step in steps if getattr(step, "kind", "") == "verdict"]
    return any(step.payload.get("parsed") is True for step in verdict_steps)
