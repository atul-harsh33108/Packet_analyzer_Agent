"""Eval run history and the non-worse gate (`T2-04`).

Layer 6 asks for two things:

> **Change tracking:** every eval run recorded; any agent, prompt, model or
> rule-template change must be non-worse | **CI gate**

## The tension this has to resolve

The tracker's own note on `T2-04` flags it: *"the baseline it compares against is
itself a number in a repo"*. A stored baseline has two ways to go stale, and they
need **different** responses:

1. **The engine got worse.** The baseline is right and the run is a regression. Fail.
2. **The corpus changed.** A case was added, removed, or relabelled. Every count
   shifts at once and the baseline is meaningless. Failing as "the engine got worse"
   would be a lie about the cause, and the fix (refresh the baseline) is a different
   action from fixing a regression.

So the run carries a **corpus fingerprint**, and a mismatch is reported as its own
failure with its own instruction. Without it, a corpus edit looks like dozens of
simultaneous regressions and the real signal drowns.

## What "non-worse" means here

Aggregate metrics are the hard gate: micro precision, micro recall, perfect cases,
and unaccepted divergences. Plus one per-class rule:

- **A false positive in any class is a hard regression.** A new FP is precisely the
  `D-27` shape -- something being classified that should not be -- and it should
  never be bought with a gain elsewhere.
- **A true-positive *decrease* is reported, not failed.** A flow legitimately moving
  from one class to another lowers the old class's `tp` while raising the new one's.
  Failing on that would punish a correctness improvement. It is surfaced in the run
  record so a human can see it, which is the honest treatment.

That asymmetry is a deliberate choice, not an oversight, and `test_eval_gate.py`
pins both directions: a synthetic run with a new false positive must fail the gate,
and one whose only difference is a class-to-class flow move must pass.

## This gate actually runs

`score_corpus` executes the real pipeline over all 33 captures: **measured 0.11 s**.
Unlike `tests/benchmarks/`, which reports *passed* without executing unless
`--benchmark-enable` is passed, this gate has no opt-in flag and no skip path. A test
asserts it, because a gate that silently stops executing is the worst shape a CI gate
can take.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from golden.corpus import iter_cases
from golden.scoring import CorpusScore, score_corpus

EVAL_DIR = Path(__file__).resolve().parent
BASELINE_PATH = EVAL_DIR / "baseline.json"
HISTORY_PATH = EVAL_DIR / "history.jsonl"

#: Ratios are compared with this slack. The corpus is small enough that these are
#: ratios of single-digit integers, but division is not exact in binary and a hard
#: `>=` would eventually fail on a value that is arithmetically equal.
EPSILON = 1e-9


# ---------------------------------------------------------------------------
# Corpus fingerprint
# ---------------------------------------------------------------------------


def corpus_fingerprint() -> str:
    """A stable hash of the corpus's shape *and* its labels.

    Deliberately covers expected flows and policies, not just case names: renaming
    a case is harmless, but relabelling a case changes what every count means while
    leaving every name identical. Without that, a relabelled corpus would silently
    pass the fingerprint check and then report a wall of invented regressions.
    """
    payload = []
    for case in iter_cases():
        flows = sorted(
            (f.hostname, f.app.name, f.dst_port) for f in case.expected
        )
        payload.append(
            {
                "name": case.name,
                "golden_class": case.golden_class,
                "description": case.description,
                "flows": flows,
            }
        )
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# The run record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClassCounts:
    true_positives: int
    false_positives: int
    false_negatives: int

    def to_json(self) -> dict[str, int]:
        return {
            "tp": self.true_positives,
            "fp": self.false_positives,
            "fn": self.false_negatives,
        }

    @classmethod
    def from_json(cls, raw: dict) -> ClassCounts:
        return cls(
            true_positives=int(raw["tp"]),
            false_positives=int(raw["fp"]),
            false_negatives=int(raw["fn"]),
        )


@dataclass(frozen=True)
class EvalRun:
    """One execution of the corpus, reduced to comparable numbers."""

    corpus_fingerprint: str
    micro_precision: float
    micro_recall: float
    perfect_cases: int
    total_cases: int
    unaccepted: int
    per_class: dict[str, ClassCounts] = field(default_factory=dict)
    recorded_at: str = ""
    commit: str = ""

    def to_json(self) -> dict:
        return {
            "recorded_at": self.recorded_at,
            "commit": self.commit,
            "corpus_fingerprint": self.corpus_fingerprint,
            "micro_precision": round(self.micro_precision, 9),
            "micro_recall": round(self.micro_recall, 9),
            "perfect_cases": self.perfect_cases,
            "total_cases": self.total_cases,
            "unaccepted": self.unaccepted,
            "per_class": {k: v.to_json() for k, v in sorted(self.per_class.items())},
        }

    @classmethod
    def from_json(cls, raw: dict) -> EvalRun:
        return cls(
            corpus_fingerprint=str(raw["corpus_fingerprint"]),
            micro_precision=float(raw["micro_precision"]),
            micro_recall=float(raw["micro_recall"]),
            perfect_cases=int(raw["perfect_cases"]),
            total_cases=int(raw["total_cases"]),
            unaccepted=int(raw["unaccepted"]),
            per_class={
                k: ClassCounts.from_json(v) for k, v in raw.get("per_class", {}).items()
            },
            recorded_at=str(raw.get("recorded_at", "")),
            commit=str(raw.get("commit", "")),
        )


def run_from_score(
    score: CorpusScore, *, fingerprint: str | None = None, commit: str = ""
) -> EvalRun:
    """Reduces a live `CorpusScore` to an `EvalRun`.

    A separate function from `score_corpus` so the comparison logic can be tested
    against hand-built runs without materialising a capture 33 times.
    """
    return EvalRun(
        corpus_fingerprint=fingerprint if fingerprint is not None else corpus_fingerprint(),
        micro_precision=score.micro_precision,
        micro_recall=score.micro_recall,
        perfect_cases=score.perfect_cases,
        total_cases=score.total_cases,
        unaccepted=len(score.unaccepted),
        per_class={
            s.app.name: ClassCounts(s.true_positives, s.false_positives, s.false_negatives)
            for s in score.per_app
        },
        recorded_at=datetime.now(UTC).isoformat(timespec="seconds"),
        commit=commit,
    )


def current_git_commit() -> str:
    """The short SHA, or '' outside a checkout.

    Never raises: a missing git is a missing field, not a failed test.
    """
    import subprocess

    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def run_corpus(capture_root: Path) -> EvalRun:
    """Scores the real corpus and returns the resulting run record."""
    score = score_corpus(capture_root, write_output_to=capture_root / "out")
    return run_from_score(score, commit=current_git_commit())


# ---------------------------------------------------------------------------
# Comparison: the non-worse rule
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Regression:
    """One way in which `current` is worse than `baseline`."""

    metric: str
    baseline: object
    current: object
    hard: bool
    detail: str = ""

    def describe(self) -> str:
        kind = "REGRESSION" if self.hard else "advisory"
        tail = f" -- {self.detail}" if self.detail else ""
        return f"[{kind}] {self.metric}: baseline {self.baseline}, now {self.current}{tail}"


def compare(baseline: EvalRun, current: EvalRun) -> list[Regression]:
    """Every respect in which `current` is worse than `baseline`.

    Returns an empty list when the run is non-worse. Callers decide whether
    advisories matter; only `hard` entries fail the gate.
    """
    found: list[Regression] = []

    if baseline.corpus_fingerprint != current.corpus_fingerprint:
        # Not a regression, and reporting it as one would bury the real cause.
        return [
            Regression(
                "corpus_fingerprint",
                baseline.corpus_fingerprint,
                current.corpus_fingerprint,
                hard=True,
                detail=(
                    "the corpus changed since this baseline was recorded, so every "
                    "count below is measured against a different set of cases. This "
                    "is not an engine regression. Review the corpus change, then "
                    "refresh the baseline deliberately"
                ),
            )
        ]

    def ratio(name: str, was: float, now: float) -> None:
        if now < was - EPSILON:
            found.append(
                Regression(
                    name,
                    round(was, 6),
                    round(now, 6),
                    hard=True,
                    detail=f"fell by {was - now:.6f}",
                )
            )

    ratio("micro_precision", baseline.micro_precision, current.micro_precision)
    ratio("micro_recall", baseline.micro_recall, current.micro_recall)

    if current.perfect_cases < baseline.perfect_cases:
        found.append(
            Regression(
                "perfect_cases",
                baseline.perfect_cases,
                current.perfect_cases,
                hard=True,
                detail=(
                    f"{baseline.perfect_cases} of {baseline.total_cases} cases were "
                    f"scored perfectly, now {current.perfect_cases} of "
                    f"{current.total_cases}"
                ),
            )
        )

    if current.unaccepted > baseline.unaccepted:
        found.append(
            Regression(
                "unaccepted_divergences",
                baseline.unaccepted,
                current.unaccepted,
                hard=True,
                detail=(
                    "a mismatch with no entry in KNOWN_DIVERGENCES is an unexplained "
                    "bug, not a known trade-off"
                ),
            )
        )

    for name, was in baseline.per_class.items():
        now = current.per_class.get(name, ClassCounts(0, 0, 0))

        if now.false_positives > was.false_positives:
            found.append(
                Regression(
                    f"{name}.false_positives",
                    was.false_positives,
                    now.false_positives,
                    hard=True,
                    detail=(
                        "a new false positive in a class that was clean. This is the "
                        "D-27 shape: something classified that should not be. It is "
                        "never acceptable to buy with a gain elsewhere"
                    ),
                )
            )

        if now.true_positives < was.true_positives:
            found.append(
                Regression(
                    f"{name}.true_positives",
                    was.true_positives,
                    now.true_positives,
                    hard=False,
                    detail=(
                        "advisory only: a flow may legitimately have moved to another "
                        "class, which lowers this one and raises another. Worth a "
                        "look, not a failure"
                    ),
                )
            )

    return found


def hard_failures(regressions: list[Regression]) -> list[Regression]:
    return [r for r in regressions if r.hard]


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def load_baseline() -> EvalRun:
    if not BASELINE_PATH.exists():
        raise FileNotFoundError(
            f"{BASELINE_PATH} is missing. Without a recorded run there is nothing to "
            "compare against; create it by running `uv run pytest "
            "tests/test_eval_gate.py --record-baseline`."
        )
    return EvalRun.from_json(json.loads(BASELINE_PATH.read_text(encoding="utf-8")))


def write_baseline(run: EvalRun) -> None:
    BASELINE_PATH.write_text(
        json.dumps(run.to_json(), indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )


def load_history() -> list[EvalRun]:
    """Every recorded run, oldest first.

    A malformed line is an error, not a skip. Silently dropping unparseable history
    would make the history look shorter and cleaner than it is, which is the exact
    "looks green while doing nothing" failure this project keeps running into.
    """
    if not HISTORY_PATH.exists():
        return []
    runs: list[EvalRun] = []
    for number, line in enumerate(HISTORY_PATH.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            runs.append(EvalRun.from_json(json.loads(line)))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                f"{HISTORY_PATH}:{number} is not a valid run record: {exc}. History is "
                "append-only and never edited, so a bad line means the file was "
                "corrupted rather than that a run failed to record."
            ) from exc
    return runs


def append_history(run: EvalRun) -> None:
    """Append one run. Never rewrites or truncates."""
    with HISTORY_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(run.to_json(), sort_keys=False) + "\n")
