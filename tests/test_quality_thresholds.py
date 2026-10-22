"""The threshold mechanism, and the three states a measurement can be in (`T4-08`).

`T4-07` deliberately left the quality figure ungated, because a number set
before the first real measurement is a number with nothing behind it. This
file tests the **mechanism** that a measurement is judged by -- and it runs
**without a key and without a model**, because the mechanism is the part that
can be wrong quietly: a gate that never gates, a measurement that reads as a
pass, and a bar that applies to a model nobody measured.

The *value* of the bar is not tested here, and cannot be: it comes from a run
against a real model (`tests/test_model_quality.py`), and until that run has
happened the table is empty.
"""

from __future__ import annotations

import pytest

from dpi_model_client.quality import (
    MAX_FALSE_POSITIVES,
    QUALITY_THRESHOLDS,
    judge_quality,
    threshold_for,
)
from eval.verdicts import VerdictScore, report_from_scores


def _score(*, correct: bool, false_positive: bool = False) -> VerdictScore:
    """One case's score, with the axes collapsed onto `correct`."""
    return VerdictScore(
        case="case",
        severity_ok=correct,
        category_ok=correct,
        flows_ok=correct,
        false_positive=false_positive,
    )


class TestAModelWithNoBarIsAMeasurement:
    """The state that matters most: an ungated figure must not read as a pass."""

    def test_it_is_not_a_pass(self) -> None:
        judgement = judge_quality("a-model-nobody-measured", 0.5, 0)
        assert judgement.passed is None, (
            "a model with no bar has no verdict to pass or fail; `passed` must be "
            "None so a caller cannot mistake it for a green light"
        )

    def test_it_says_so(self) -> None:
        judgement = judge_quality("a-model-nobody-measured", 0.5, 0)
        assert "MEASUREMENT" in judgement.describe()
        assert "PASS" not in judgement.describe().replace("not a pass", "")

    def test_it_is_not_gated(self) -> None:
        assert judge_quality("a-model-nobody-measured", 0.5, 0).gated is False


class TestAModelWithABarIsGated:
    def test_below_the_bar_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(QUALITY_THRESHOLDS, "measured-model", 0.8)
        judgement = judge_quality("measured-model", 0.79, 0)
        assert judgement.passed is False
        assert "FAIL" in judgement.describe()

    def test_at_the_bar_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The bar is a floor, not a hurdle just above the floor."""
        monkeypatch.setitem(QUALITY_THRESHOLDS, "measured-model", 0.8)
        assert judge_quality("measured-model", 0.8, 0).passed is True

    def test_above_the_bar_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(QUALITY_THRESHOLDS, "measured-model", 0.8)
        assert judge_quality("measured-model", 0.95, 0).passed is True

    def test_the_bar_belongs_to_one_model_only(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A bar measured on one model says nothing about another."""
        monkeypatch.setitem(QUALITY_THRESHOLDS, "measured-model", 0.8)
        assert judge_quality("a-different-model", 0.1, 0).passed is None

    def test_the_lookup_is_by_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(QUALITY_THRESHOLDS, "measured-model", 0.8)
        assert threshold_for("measured-model") == 0.8
        assert threshold_for("another-model") is None


class TestTheFalsePositiveSide:
    """The side with no free parameter (`DEC-12`)."""

    def test_the_bar_is_zero(self) -> None:
        assert MAX_FALSE_POSITIVES == 0, (
            "the corpus's legitimate-enterprise cases are traffic that must not be "
            "flagged; a model that flags one is wrong whatever its accuracy"
        )

    def test_one_false_positive_fails_a_perfect_accuracy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Accuracy is won by never saying "high" -- this is what catches that."""
        monkeypatch.setitem(QUALITY_THRESHOLDS, "measured-model", 0.0)
        judgement = judge_quality("measured-model", 1.0, 1)
        assert judgement.passed is False, (
            "a model with perfect accuracy that flagged a case it must not flag has "
            "not passed; the two sides of the criterion are not one number"
        )


class TestTheFiguresAreValidated:
    def test_an_impossible_accuracy_is_refused(self) -> None:
        with pytest.raises(ValueError):
            judge_quality("m", 1.5, 0)

    def test_a_negative_accuracy_is_refused(self) -> None:
        with pytest.raises(ValueError):
            judge_quality("m", -0.1, 0)

    def test_a_negative_false_positive_count_is_refused(self) -> None:
        with pytest.raises(ValueError):
            judge_quality("m", 0.5, -1)

    def test_a_measurement_with_no_model_is_refused(self) -> None:
        """An unjudgeable measurement is a mistake, not a silent pass."""
        with pytest.raises(ValueError):
            judge_quality("   ", 0.5, 0)


class TestTheShippedTable:
    def test_every_bar_is_a_fraction(self) -> None:
        """A typo in the table must not make the gate vacuous.

        A bar of `1.5` would pass every measurement, and a bar of `0` would fail
        every model that ever answers.
        """
        for model, bar in QUALITY_THRESHOLDS.items():
            assert 0.0 < bar <= 1.0, (
                f"the bar for {model!r} is {bar!r}; a bar is a fraction in (0, 1]"
            )

    def test_every_bar_names_a_model(self) -> None:
        for model in QUALITY_THRESHOLDS:
            assert model.strip(), "a bar with an empty model name applies to nothing"


class TestTheReport:
    """The figure the run produces, before any threshold is consulted."""

    def test_a_refused_case_is_counted_but_not_judged(self) -> None:
        report = report_from_scores([_score(correct=True), None, _score(correct=False)])
        assert report.cases == 3
        assert report.judged == 2
        assert report.correct == 1
        assert report.accuracy == 0.5

    def test_false_positives_are_counted_separately(self) -> None:
        report = report_from_scores(
            [_score(correct=True), _score(correct=False, false_positive=True)]
        )
        assert report.false_positives == 1

    def test_a_run_with_no_verdicts_has_no_accuracy(self) -> None:
        """A figure of zero out of zero is not 100% -- it is nothing."""
        report = report_from_scores([None, None])
        with pytest.raises(ValueError):
            _ = report.accuracy
