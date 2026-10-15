"""Precision/recall scoring over the golden corpus (`T1-02`... `T2-01`).

Layer 6's gate for the golden-capture suite is "Precision/recall per class". This
implements that, and the scoring choice is deliberately strict about one thing:

**A detected domain that is not in the labels counts against precision.**

That is the whole reason a golden corpus is worth more than a test that asserts
"the flows I built are found". A suite that only checks recall would pass while the
engine invented classifications nobody asked for — and for a *blocking* engine, a
false positive is a false block, which is the expensive direction.

Known divergences are **allowlisted explicitly**, never absorbed into the score.
The precedent is `tests/differential/README.md` entries 6 and 8: a deliberate
divergence belongs in a named list with the reason attached, so a reviewer can see
what is accepted rather than inferring it from a passing number.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

from dpi_engine.pipeline import PipelineResult, run_pipeline
from dpi_engine.types import AppType
from golden.corpus import GoldenCase, iter_cases, materialise


@dataclasses.dataclass(frozen=True, slots=True)
class Divergence:
    """An accepted difference between what the corpus expects and what runs."""

    case: str
    hostname: str
    expected: AppType
    actual: AppType
    #: Why this is accepted rather than fixed. Must not be empty -- an unexplained
    #: divergence is an unexplained bug, and making the reason mandatory is what
    #: stops the allowlist becoming a place to hide regressions.
    reason: str


#: Accepted divergences, each with its reason.
#:
#: `substring_false_positive` is the big one and is **not** a fixed bug: the engine
#: matches most apps by bare substring, mirroring the C++ original, so an
#: attacker-controlled hostname containing an app name classifies as that app. The
#: project's own `types.py` docstring records recognising this class twice — Twitter's
#: rule was anchored, and Cloudflare's `"cf-"` substring was dropped — for exactly
#: this reason. Every other rule still carries it. Recorded as `D-27`.
KNOWN_DIVERGENCES: tuple[Divergence, ...] = (
    Divergence(
        case="c2_lookalike_tld",
        hostname="microsoft-update.evil.example",
        expected=AppType.HTTPS,
        actual=AppType.MICROSOFT,
        reason=(
            "substring match on 'microsoft'. The hostname is attacker-controlled "
            "and is NOT Microsoft. Parity-preserving (the C++ original does the "
            "same), but a real false positive. See D-27."
        ),
    ),
    Divergence(
        case="c2_lookalike_tld",
        hostname="cdn.apple.evil.example",
        expected=AppType.HTTPS,
        actual=AppType.APPLE,
        reason="substring match on 'apple'; same class as above. See D-27.",
    ),
    Divergence(
        case="evasion_subdomain_app",
        hostname="cdn.facebook.com.attacker.example",
        expected=AppType.HTTPS,
        actual=AppType.FACEBOOK,
        reason="substring match on 'facebook'; same class. See D-27.",
    ),
    Divergence(
        case="evasion_legitimate_prefix",
        hostname="www.facebook.com.evil.example",
        expected=AppType.HTTPS,
        actual=AppType.FACEBOOK,
        reason="substring match on 'facebook'; same class. See D-27.",
    ),
    Divergence(
        case="evasion_legitimate_prefix",
        hostname="microsoft.com.attacker.example",
        expected=AppType.HTTPS,
        actual=AppType.MICROSOFT,
        reason="substring match on 'microsoft'; same class. See D-27.",
    ),
    Divergence(
        case="evasion_trailing_dot",
        hostname="evil.example.",
        expected=AppType.HTTPS,
        actual=AppType.UNKNOWN,
        reason=(
            "a fully-qualified trailing dot is refused by the hostname policy "
            "(`D-18`), so no SNI is reported at all. Correct behaviour, but it "
            "means the label records the *intent* (classify as unrecognised TLS) "
            "rather than the mechanism (policy refusal). Worth revisiting: a "
            "trailing dot is legal DNS and the SNI is legible."
        ),
    ),
)


@dataclasses.dataclass(frozen=True, slots=True)
class ClassScore:
    """Precision and recall for one `AppType` across the whole corpus."""

    app: AppType
    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def precision(self) -> float:
        """Of everything predicted as this app, how much was right.

        Returns 1.0 when nothing was predicted: no prediction, no error. Returning
        0.0 instead would make an unused class look like a total failure and would
        punish a corpus that legitimately contains no instances of it.
        """
        predicted = self.true_positives + self.false_positives
        if predicted == 0:
            return 1.0
        return self.true_positives / predicted

    @property
    def recall(self) -> float:
        expected = self.true_positives + self.false_negatives
        if expected == 0:
            return 1.0
        return self.true_positives / expected

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)

    def describe(self) -> str:
        return (
            f"{self.app.name:<12} P={self.precision:.3f} R={self.recall:.3f} "
            f"F1={self.f1:.3f}  (tp={self.true_positives} fp={self.false_positives} "
            f"fn={self.false_negatives})"
        )


@dataclasses.dataclass(frozen=True, slots=True)
class CaseScore:
    """One capture's result."""

    case: GoldenCase
    matched: int
    expected_total: int
    unexpected: tuple[str, ...]
    missing: tuple[str, ...]
    #: Mismatches that ARE allowlisted, each with its reason.
    accepted: tuple[Divergence, ...]
    #: Mismatches that are NOT allowlisted. Always a bug, never a known limitation.
    unaccepted: tuple[tuple[str, AppType, AppType], ...]

    @property
    def perfect(self) -> bool:
        """True when every label matched and nothing extra was reported.

        `unexpected` counts even when the extra domain is one the corpus did not
        label -- an unlabelled detection is a candidate false positive, and the
        corpus cannot distinguish "correct but unlabelled" from "wrong" without a
        human. So it is reported rather than assumed harmless.
        """
        return self.matched == self.expected_total and not self.unexpected


@dataclasses.dataclass(frozen=True, slots=True)
class CorpusScore:
    """The whole corpus, scored."""

    cases: tuple[CaseScore, ...]
    per_app: tuple[ClassScore, ...]
    unaccepted: tuple[tuple[str, str, AppType, AppType], ...]

    @property
    def perfect_cases(self) -> int:
        return sum(1 for c in self.cases if c.perfect)

    @property
    def total_cases(self) -> int:
        return len(self.cases)

    @property
    def micro_precision(self) -> float:
        tp = sum(s.true_positives for s in self.per_app)
        fp = sum(s.false_positives for s in self.per_app)
        return 1.0 if tp + fp == 0 else tp / (tp + fp)

    @property
    def micro_recall(self) -> float:
        tp = sum(s.true_positives for s in self.per_app)
        fn = sum(s.false_negatives for s in self.per_app)
        return 1.0 if tp + fn == 0 else tp / (tp + fn)

    def summary(self) -> str:
        lines = [f"corpus: {self.perfect_cases}/{self.total_cases} cases perfect"]
        lines.append(
            f"micro: P={self.micro_precision:.3f} R={self.micro_recall:.3f}"
        )
        lines.extend("  " + s.describe() for s in self.per_app)
        return "\n".join(lines)


def _is_known(case: str, hostname: str) -> Divergence | None:
    for d in KNOWN_DIVERGENCES:
        if d.case == case and d.hostname == hostname:
            return d
    return None


def score_case(
    case: GoldenCase, result: PipelineResult
) -> tuple[CaseScore, dict[AppType, list[int]]]:
    """Scores one capture. Also returns per-app tallies, for the caller to merge."""
    detected = {host.lower(): app for host, app in result.detected_domains.items()}
    expected = {host.lower(): app for host, app in case.expected_apps.items()}
    tallies: dict[AppType, list[int]] = {}

    def bump(app: AppType, slot: int) -> None:
        tallies.setdefault(app, [0, 0, 0])[slot] += 1

    matched = 0
    missing: list[str] = []
    unexpected: list[str] = []
    accepted: list[Divergence] = []
    unaccepted: list[tuple[str, AppType, AppType]] = []

    for hostname, want in expected.items():
        got = detected.get(hostname)
        if got == want:
            matched += 1
            bump(want, 0)  # true positive
            continue

        known = _is_known(case.name, hostname)
        if known is not None:
            # Counted against the *actual* class, so a divergence that hands traffic
            # to the wrong app shows up as that app's false positive and cannot be
            # hidden by being "expected".
            bump(known.actual, 1)  # false positive
            accepted.append(known)
        else:
            bump(want, 2)  # false negative
            unaccepted.append((hostname, want, got if got is not None else AppType.UNKNOWN))

    # Anything detected that no label mentions is a false positive for its class.
    # Allowlisted domains are already accounted for above and must not be counted
    # twice.
    accounted = {d.hostname for d in accepted}
    for hostname, app in detected.items():
        if hostname in expected or hostname in accounted:
            continue
        unexpected.append(hostname)
        bump(app, 1)

    score = CaseScore(
        case=case,
        matched=matched,
        expected_total=len(expected),
        unexpected=tuple(sorted(unexpected)),
        missing=tuple(sorted(missing)),
        accepted=tuple(accepted),
        unaccepted=tuple(unaccepted),
    )
    return score, tallies


def score_corpus(
    capture_dir: Path, *, write_output_to: Path | None = None
) -> CorpusScore:
    """Materialises the corpus into `capture_dir` and scores every case."""
    paths = materialise(capture_dir)
    if write_output_to is not None:
        write_output_to.mkdir(parents=True, exist_ok=True)

    case_scores: list[CaseScore] = []
    merged: dict[AppType, list[int]] = {}

    for case in iter_cases():
        out = (
            write_output_to / f"{case.name}.out.pcap"
            if write_output_to is not None
            else capture_dir / f"{case.name}.out.pcap"
        )
        result = run_pipeline(paths[case.name], out)
        score, tallies = score_case(case, result)
        case_scores.append(score)
        for app, (tp, fp, fn) in tallies.items():
            slot = merged.setdefault(app, [0, 0, 0])
            slot[0] += tp
            slot[1] += fp
            slot[2] += fn

    per_app = tuple(
        ClassScore(app=app, true_positives=v[0], false_positives=v[1], false_negatives=v[2])
        for app, v in sorted(merged.items(), key=lambda kv: kv[0].name)
    )

    unaccepted: list[tuple[str, str, AppType, AppType]] = []
    for score in case_scores:
        unaccepted.extend(score.unaccepted)

    return CorpusScore(
        cases=tuple(case_scores), per_app=per_app, unaccepted=tuple(unaccepted)
    )


__all__ = [
    "KNOWN_DIVERGENCES",
    "CaseScore",
    "ClassScore",
    "CorpusScore",
    "Divergence",
    "score_case",
    "score_corpus",
]
