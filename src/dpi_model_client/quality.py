"""The quality thresholds, and how a measurement is judged against them (`T4-08`).

**A threshold belongs to a model, not to the project.** The same question asked of
two different models has two different answers, so a single number for "the
product's quality" would be a number about nothing. The bar is therefore a
**table keyed by model name**, and a model that is not in the table has no bar.

**The table is empty, and that is the honest state of it.** `T4-07` measured the
plumbing with a deterministic fake; a fake that is scripted to the expected
verdicts scores 100% by construction, so its figure says nothing about a real
model. The first figure with a model behind it is the first number that can
set a bar, and it comes from the operator's own run of
`tests/test_model_quality.py` -- which prints the line to paste in here when it
has one. A threshold set before that measurement would be a number with nothing
behind it, which is the thing this module exists to avoid.

**The false-positive side has no free parameter.** The accuracy side is the
model's, and it is measured. But a model that flags the legitimate-enterprise
cases in the corpus is *wrong* whatever its accuracy, and the corpus carries
that class precisely so this can be counted (`DEC-12`). So that bar is zero,
and it is not a number to be tuned -- it is the criterion.

**Three states, not two.** A model with a bar is *gated*: the run passes or
fails. A model without one is a *measurement*: the run reports the figure and
says so, and does not report a pass. Collapsing those two is how an
ungated number gets read as a green light.
"""

from __future__ import annotations

import dataclasses

__all__ = [
    "MAX_FALSE_POSITIVES",
    "QUALITY_THRESHOLDS",
    "QualityJudgement",
    "judge_quality",
    "threshold_for",
]

#: How many false positives a model may produce on the golden corpus.
#:
#: Zero, and not a number to be tuned: the corpus's legitimate-enterprise cases
#: are traffic that must not be flagged, so a model that flags one has made an
#: error whatever its accuracy says.
MAX_FALSE_POSITIVES = 0

#: Model name -> the minimum accuracy that model must reach on the golden corpus.
#:
#: **Empty until the first real measurement.** To set an entry, run
#: `tests/test_model_quality.py` with `DPI_MODEL_API_KEY` and `DPI_MODEL_NAME`
#: set; it prints the figure and the exact line to paste here. Record the
#: measurement's date in the commit that adds the entry, so a bar can be traced
#: to the run that produced it.
QUALITY_THRESHOLDS: dict[str, float] = {}


def threshold_for(model: str) -> float | None:
    """The accuracy bar for `model`, or `None` when it has none yet.

    The name is matched exactly after stripping whitespace: two spellings of one
    model are two entries, and a threshold that applies to a model nobody
    measured is a threshold about nothing.
    """
    return QUALITY_THRESHOLDS.get(model.strip())


@dataclasses.dataclass(frozen=True, slots=True)
class QualityJudgement:
    """One measurement, judged against the thresholds.

    `passed` is three-valued on purpose: `True` and `False` are the gated
    outcomes, and `None` means the model has no bar, so the run is a
    **measurement** and not a pass.
    """

    model: str
    accuracy: float
    false_positives: int
    threshold: float | None

    @property
    def passed(self) -> bool | None:
        """Whether the measurement clears the bar, or `None` when there is none."""
        if self.threshold is None:
            return None
        if self.false_positives > MAX_FALSE_POSITIVES:
            return False
        return self.accuracy >= self.threshold

    @property
    def gated(self) -> bool:
        """Whether this model has a bar at all."""
        return self.threshold is not None

    def describe(self) -> str:
        """The judgement in one line, for a run's output and for a failure message."""
        bar = f"threshold {self.threshold:.2f}" if self.gated else "no threshold set for this model"
        if self.passed is None:
            outcome = "MEASUREMENT, not a pass"
        elif self.passed:
            outcome = "PASS"
        else:
            outcome = "FAIL"
        return (
            f"{self.model}: accuracy {self.accuracy:.3f} against {bar}; "
            f"false positives {self.false_positives} (max {MAX_FALSE_POSITIVES}) -> {outcome}"
        )


def judge_quality(model: str, accuracy: float, false_positives: int) -> QualityJudgement:
    """Judge one measurement against the thresholds.

    The figures are validated rather than trusted: an accuracy outside `[0, 1]`
    or a negative count of false positives is a mistake in the measurement, and
    a mistake that reads as "no false positives" is the one that matters.
    """
    if not 0.0 <= accuracy <= 1.0:
        raise ValueError(f"accuracy must be a fraction in [0, 1], got {accuracy!r}")
    if false_positives < 0:
        raise ValueError(f"the false-positive count cannot be negative, got {false_positives!r}")
    name = model.strip()
    if not name:
        raise ValueError("the measurement has no model name, so it cannot be judged")
    return QualityJudgement(
        model=name,
        accuracy=accuracy,
        false_positives=false_positives,
        threshold=threshold_for(name),
    )
