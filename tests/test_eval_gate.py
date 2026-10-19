"""`T2-04` — every eval run recorded, and any change must be non-worse.

Layer 6's two requirements, as a CI gate:

> **Change tracking:** every eval run recorded; any agent, prompt, model or
> rule-template change must be non-worse | **CI gate**

**This gate executes.** `run_corpus` materialises all 33 captures and runs the real
pipeline over them — measured at **0.11 s** — so there is no `--eval-enable` flag, no
skip path, and no way for this suite to report *passed* while measuring nothing. That
is deliberately unlike `tests/benchmarks/`, which does exactly that. The first test
class below asserts it, because "the gate quietly stopped running" is the worst shape
a gate can take and it would be invisible.

**Advisories are not failures.** A class's `true_positives` dropping is reported but
does not fail: a flow can legitimately move from one class to another, and failing on
that would punish a correctness improvement. A new **false positive** does fail, in any
class, because that is the `D-27` shape and should never be bought with a gain
elsewhere. Both directions are pinned in `TestGateCanActuallyFail` -- an assertion that
cannot fail is not a gate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval.history import (
    BASELINE_PATH,
    HISTORY_PATH,
    ClassCounts,
    EvalRun,
    compare,
    corpus_fingerprint,
    hard_failures,
    load_baseline,
    load_history,
    run_corpus,
)
from golden.corpus import iter_cases

FP = "fixedfingerprin"  # 16 chars, matching a real fingerprint's width


@pytest.fixture(scope="module")
def live_run(tmp_path_factory: pytest.TempPathFactory) -> EvalRun:
    """One real execution of the corpus, shared by the tests that need it."""
    root = tmp_path_factory.mktemp("eval")
    return run_corpus(root)


def _run(**overrides: object) -> EvalRun:
    """A hand-built run, so comparison logic can be tested without the pipeline."""
    base = {
        "corpus_fingerprint": FP,
        "micro_precision": 0.9,
        "micro_recall": 1.0,
        "perfect_cases": 30,
        "total_cases": 33,
        "unaccepted": 0,
        "per_class": {
            "GOOGLE": ClassCounts(4, 0, 0),
            "FACEBOOK": ClassCounts(2, 2, 0),
        },
    }
    base.update(overrides)
    return EvalRun(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


class TestTheGateRunsAndIsNotWorse:
    def test_the_gate_actually_executes_the_pipeline(self, live_run: EvalRun) -> None:
        """**The most important assertion in this file.**

        `tests/benchmarks/` reports *passed* without running anything unless
        `--benchmark-enable` is passed. A reader who misses that treats green as a
        measurement. This gate has no such flag -- but that is a property of the code,
        not a guarantee, so it is asserted: a real run must carry real numbers from a
        real execution.
        """
        assert live_run.total_cases >= 30, (
            f"the gate scored only {live_run.total_cases} cases; if that is not the "
            "whole corpus the gate is not measuring what it claims to"
        )
        assert live_run.perfect_cases > 0
        assert live_run.per_class, "no per-class results, so nothing was measured"
        assert 0.0 <= live_run.micro_precision <= 1.0
        assert live_run.micro_recall == pytest.approx(1.0, abs=1e-9), (
            "recall is total on this corpus; if it is not, a detection regressed "
            "before the non-worse comparison even runs"
        )
        assert live_run.corpus_fingerprint == corpus_fingerprint()
        assert live_run.recorded_at, "a run must record when it was taken"
        assert live_run.commit, (
            "a run must record which commit produced it, or it cannot be traced "
            "back to the change that caused it"
        )

    def test_the_live_corpus_is_not_worse_than_the_recorded_baseline(
        self, live_run: EvalRun
    ) -> None:
        baseline = load_baseline()
        regressions = compare(baseline, live_run)
        failures = hard_failures(regressions)

        assert not failures, (
            "the corpus scored WORSE than the recorded baseline:\n  "
            + "\n  ".join(r.describe() for r in failures)
            + "\n\nIf this is an intended improvement, refresh the baseline "
            "deliberately: uv run pytest tests/test_eval_gate.py --record-baseline"
        )

    def test_advisories_are_reported_but_do_not_fail(self, live_run: EvalRun) -> None:
        """A class losing true positives is worth seeing, not worth failing on."""
        baseline = load_baseline()
        advisories = [r for r in compare(baseline, live_run) if not r.hard]
        for r in advisories:
            assert r.detail, "an advisory with no explanation is not reviewable"


# ---------------------------------------------------------------------------
# The gate must be able to fail
# ---------------------------------------------------------------------------
#
# Every assertion above is satisfied by a healthy run, so on their own they cannot
# distinguish a working gate from one that compares nothing. These force the bad
# cases and require them to be caught.


class TestGateCanActuallyFail:
    def test_lower_precision_fails(self) -> None:
        got = compare(_run(), _run(micro_precision=0.8))
        assert hard_failures(got), "a precision drop must fail the gate"

    def test_lower_recall_fails(self) -> None:
        got = compare(_run(), _run(micro_recall=0.9))
        assert hard_failures(got), "a recall drop must fail the gate"

    def test_fewer_perfect_cases_fails(self) -> None:
        got = compare(_run(), _run(perfect_cases=29))
        assert hard_failures(got)

    def test_a_new_unaccepted_divergence_fails(self) -> None:
        got = compare(_run(), _run(unaccepted=1))
        failures = hard_failures(got)
        assert failures
        assert "KNOWN_DIVERGENCES" in failures[0].detail

    def test_a_new_false_positive_fails_in_any_class(self) -> None:
        """The `D-27` shape: something classified that should not be.

        Asserted against a class that was previously *clean*, because that is the case
        worth catching -- GOOGLE has zero false positives in the hand-built baseline,
        so introducing one cannot be explained away as noise.
        """
        got = compare(
            _run(),
            _run(
                per_class={
                    "GOOGLE": ClassCounts(4, 1, 0),
                    "FACEBOOK": ClassCounts(2, 2, 0),
                }
            ),
        )
        failures = hard_failures(got)
        assert failures, "a new false positive must fail the gate"
        assert failures[0].metric == "GOOGLE.false_positives"

    def test_a_false_positive_fails_even_when_the_overall_improves(self) -> None:
        """A gain elsewhere must not buy a new false positive away.

        This is the rule that makes the gate worth having: precision and recall
        *improve* in this run, and it must still fail.
        """
        got = compare(
            _run(micro_precision=0.9),
            _run(
                micro_precision=0.95,
                micro_recall=1.0,
                perfect_cases=31,
                per_class={
                    "GOOGLE": ClassCounts(5, 1, 0),
                    "FACEBOOK": ClassCounts(2, 2, 0),
                },
            ),
        )
        failures = hard_failures(got)
        assert failures, (
            "improved overall metrics must not excuse a new false positive; this is "
            "the trade the gate exists to refuse"
        )
        assert failures[0].metric == "GOOGLE.false_positives"

    def test_a_flow_moving_between_classes_does_not_fail(self) -> None:
        """The counterpart, and the reason advisories exist.

        A flow correctly reclassified from GOOGLE to FACEBOOK lowers GOOGLE's `tp` and
        raises FACEBOOK's. Failing on that would punish a fix.
        """
        got = compare(
            _run(),
            _run(
                micro_precision=0.95,
                perfect_cases=31,
                per_class={
                    "GOOGLE": ClassCounts(3, 0, 0),
                    "FACEBOOK": ClassCounts(3, 2, 0),
                },
            ),
        )
        assert not hard_failures(got), (
            "a class-to-class flow move is an improvement and must pass: "
            + "; ".join(r.describe() for r in hard_failures(got))
        )
        advisories = [r for r in got if not r.hard]
        assert advisories, "the dropped true positive should still be reported as advisory"
        assert advisories[0].metric == "GOOGLE.true_positives"

    def test_an_identical_run_passes(self) -> None:
        assert not compare(_run(), _run()), "an identical run must produce no findings"

    def test_a_strictly_better_run_passes(self) -> None:
        got = compare(
            _run(),
            _run(
                micro_precision=1.0,
                perfect_cases=33,
                per_class={
                    "GOOGLE": ClassCounts(4, 0, 0),
                    "FACEBOOK": ClassCounts(3, 1, 0),
                },
            ),
        )
        assert not hard_failures(got)

    def test_a_changed_corpus_is_reported_as_its_own_failure(self) -> None:
        """**A corpus change is not an engine regression.**

        Every count shifts at once when cases are added or relabelled. Reporting that
        as dozens of regressions would bury the real cause and send someone hunting
        for an engine bug that does not exist.
        """
        got = compare(_run(), _run(corpus_fingerprint="somethingelse"))
        assert len(got) == 1, (
            f"a fingerprint change must produce exactly one finding, not {len(got)}; "
            "every count moving at once is one event, not many regressions"
        )
        failure = got[0]
        assert failure.hard
        assert failure.metric == "corpus_fingerprint"
        assert "not an engine regression" in failure.detail
        assert "refresh" in failure.detail, (
            "the message must say what to do, or the reader has to work it out"
        )

    def test_a_fingerprint_change_masks_no_real_regression(self) -> None:
        """A corpus change short-circuits the count comparison -- which means a real
        engine regression alongside it goes unreported.

        Asserted rather than left to be discovered later: the early return is the
        right call (comparing across corpora is meaningless), but it must be a
        *documented* consequence, not an accident.
        """
        got = compare(
            _run(),
            _run(corpus_fingerprint="somethingelse", micro_precision=0.1),
        )
        assert [r.metric for r in got] == ["corpus_fingerprint"]


# ---------------------------------------------------------------------------
# History: recorded, well-formed, and not quietly wrong
# ---------------------------------------------------------------------------


class TestHistory:
    def test_history_exists_and_is_not_empty(self) -> None:
        """Layer 6 says *every* eval run recorded. An empty history is not that."""
        runs = load_history()
        assert runs, (
            f"{HISTORY_PATH} is empty or missing. Layer 6 requires every eval run to "
            "be recorded, and a gate with no history has nothing to trend against."
        )

    def test_every_recorded_run_is_well_formed(self) -> None:
        for run in load_history():
            assert run.recorded_at, "a run with no timestamp cannot be ordered"
            assert run.corpus_fingerprint, "a run with no corpus fingerprint is not comparable"
            assert run.total_cases > 0
            assert 0 <= run.perfect_cases <= run.total_cases
            assert 0.0 <= run.micro_precision <= 1.0
            assert 0.0 <= run.micro_recall <= 1.0

    def test_history_is_ordered_by_time(self) -> None:
        stamps = [r.recorded_at for r in load_history()]
        assert stamps == sorted(stamps), (
            "history is append-only and must read oldest-first; a run appended out of "
            "order makes 'the latest run' ambiguous"
        )

    def test_history_is_append_only_and_never_rewrites(self, tmp_path: Path) -> None:
        """Proved by mutating a copy, not the committed file.

        The store opens in append mode and writes exactly one line. That is what makes
        the history evidence rather than a number someone could tidy.
        """
        import eval.history as hist

        target = tmp_path / "history.jsonl"
        original = hist.HISTORY_PATH
        try:
            hist.HISTORY_PATH = target
            hist.append_history(_run(perfect_cases=31, recorded_at="2026-01-01T00:00:00+00:00"))
            hist.append_history(_run(perfect_cases=32, recorded_at="2026-01-02T00:00:00+00:00"))
            lines = target.read_text(encoding="utf-8").splitlines()
            assert len(lines) == 2, f"expected 2 lines, got {len(lines)}"
            assert json.loads(lines[0])["perfect_cases"] == 31
            assert json.loads(lines[1])["perfect_cases"] == 32
        finally:
            hist.HISTORY_PATH = original

    def test_a_corrupt_history_line_is_an_error_not_a_silent_skip(self, tmp_path: Path) -> None:
        """Dropping an unparseable line would make history look cleaner than it is."""
        import eval.history as hist

        target = tmp_path / "history.jsonl"
        original = hist.HISTORY_PATH
        try:
            hist.HISTORY_PATH = target
            target.write_text(
                json.dumps(_run().to_json()) + "\n{ this is not json\n", encoding="utf-8"
            )
            with pytest.raises(ValueError, match="append-only"):
                hist.load_history()
        finally:
            hist.HISTORY_PATH = original

    def test_an_empty_history_file_is_valid_not_an_error(self, tmp_path: Path) -> None:
        import eval.history as hist

        target = tmp_path / "history.jsonl"
        original = hist.HISTORY_PATH
        try:
            hist.HISTORY_PATH = target
            target.write_text("", encoding="utf-8")
            assert hist.load_history() == []
            target.write_text("\n\n", encoding="utf-8")
            assert hist.load_history() == []
        finally:
            hist.HISTORY_PATH = original


class TestBaselineAndHistoryAgree:
    """The rot guard -- the same idea as `test_benchmark_baseline.py`.

    A baseline that disagrees with the newest recorded run means one of them was
    updated without the other, which is how a gate comes to compare against a run
    nobody can point to. This is the concrete answer to the tracker's note that the
    baseline is "itself a number in a repo" that can rot.
    """

    def test_the_baseline_matches_the_newest_recorded_run(self) -> None:
        baseline = load_baseline()
        runs = load_history()
        assert runs, "no history to check the baseline against"
        newest = runs[-1]
        assert baseline.to_json() == newest.to_json(), (
            "the committed baseline and the newest history entry disagree. One was "
            "updated without the other.\n"
            f"  baseline: {json.dumps(baseline.to_json(), sort_keys=True)[:220]}\n"
            f"  newest:   {json.dumps(newest.to_json(), sort_keys=True)[:220]}"
        )

    def test_the_baseline_matches_the_corpus_it_was_recorded_against(self) -> None:
        """Guards against the common failure: editing the corpus and not the baseline."""
        baseline = load_baseline()
        assert baseline.corpus_fingerprint == corpus_fingerprint(), (
            "the baseline was recorded against a different corpus. If the corpus "
            "change was intended, refresh the baseline deliberately; if not, the "
            "corpus changed by accident."
        )

    def test_the_baseline_file_is_committed_json_not_a_placeholder(self) -> None:
        raw = BASELINE_PATH.read_text(encoding="utf-8")
        parsed = json.loads(raw)
        assert parsed["total_cases"] >= 30, (
            "the baseline records fewer cases than the corpus has; it is a stub"
        )
        assert "micro_precision" in parsed and "per_class" in parsed


# ---------------------------------------------------------------------------
# The fingerprint itself
# ---------------------------------------------------------------------------


class TestRuleCoverage:
    """What the gate *cannot* see.

    The gate compares corpus results, so its sensitivity is bounded by what the
    corpus exercises. `T2-04` measured that bound and it is wider than expected:
    **six of sixteen SNI rules are never triggered by any hostname in the corpus.**

    INSTAGRAM, WHATSAPP, TELEGRAM, TIKTOK, SPOTIFY and ZOOM have no hostname that
    contains any of their substrings. A regression in any of them -- a substring
    dropped, a rule deleted, a table reorder -- leaves every recorded number
    untouched and the gate green.

    That is a gap in the *corpus*, not a defect in the gate, and it is recorded here
    rather than fixed, because extending the corpus changes the baseline and belongs
    in its own change where the numbers are re-derived deliberately.

    The assertion pins the set exactly, in both directions:

    - a rule becoming **unexercised** is a real loss of coverage and fails;
    - a rule becoming **exercised** is good news, and fails only to say "update this
      list, the corpus just got better" -- the same courtesy
      `test_every_allowlisted_divergence_still_occurs` extends to `D-27`.
    """

    #: AppType names with no corpus hostname matching any of their substrings.
    #: Regenerate with tests/eval/coverage.py when the corpus changes.
    UNEXERCISED_RULES: frozenset[str] = frozenset(
        {"INSTAGRAM", "WHATSAPP", "TELEGRAM", "TIKTOK", "SPOTIFY", "ZOOM"}
    )

    @staticmethod
    def _unexercised() -> set[str]:
        from dpi_engine.types import _SNI_RULES

        hostnames = {f.hostname for case in iter_cases() for f in case.expected}
        unexercised = set()
        for rule in _SNI_RULES:
            if not any(s in h.lower() for h in hostnames for s in rule.substrings):
                unexercised.add(rule.app.name)
        return unexercised

    def test_the_unexercised_rules_are_exactly_these(self) -> None:
        """The gate is blind to these rules; this makes that a stated fact."""
        measured = self._unexercised()
        assert measured == set(self.UNEXERCISED_RULES), (
            "the set of rules the corpus never exercises changed.\n"
            f"  newly unexercised: {sorted(measured - self.UNEXERCISED_RULES)}\n"
            f"  newly exercised:   {sorted(set(self.UNEXERCISED_RULES) - measured)}\n"
            "\nIf a rule is newly unexercised, the corpus lost the only hostname that "
            "covered it and the gate is now blind to that rule. If one is newly "
            "exercised, the corpus got better - update UNEXERCISED_RULES so this "
            "record stays accurate."
        )

    def test_the_blind_set_is_not_growing(self) -> None:
        """The direction that matters, stated separately.

        A *shrinking* blind set is good news and only needs the list refreshed. A
        *growing* one means the gate silently lost reach, which is the failure this
        whole class exists to prevent.
        """
        grew = self._unexercised() - set(self.UNEXERCISED_RULES)
        assert not grew, (
            f"{sorted(grew)} are no longer exercised by any corpus hostname. The "
            "gate compares corpus results, so a regression in those rules would now "
            "leave every number untouched and the gate green."
        )

    def test_coverage_is_most_of_the_table_not_a_handful(self) -> None:
        """A floor, so the corpus cannot be gutted and still satisfy the list above."""
        from dpi_engine.types import _SNI_RULES

        total = len(_SNI_RULES)
        blind = len(self._unexercised())
        assert total - blind >= 10, (
            f"only {total - blind} of {total} SNI rules are exercised by the corpus; "
            "the gate's reach has collapsed"
        )


class TestCorpusFingerprint:
    def test_it_is_stable_across_calls(self) -> None:
        """A fingerprint that changed between calls would make every run incomparable."""
        assert corpus_fingerprint() == corpus_fingerprint()

    def test_it_is_the_shape_of_the_corpus_not_the_engine(self) -> None:
        """It must not move when the engine's behaviour changes.

        If it did, every engine change would read as a corpus change and the gate
        would never compare anything.
        """
        assert len(corpus_fingerprint()) == 16
        assert corpus_fingerprint() != "fixedfingerprin"

    def test_it_changes_when_a_case_is_relabelled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The reason it hashes labels and not just names.

        A renamed case is harmless; a relabelled one changes what every count means
        while leaving every name identical. Without label coverage, relabelling would
        pass the fingerprint check and then report a wall of invented regressions.
        """
        import golden.corpus as corpus_mod

        real = corpus_mod.iter_cases
        cases = list(real())
        before = corpus_fingerprint()

        relabelled = []
        for case in cases:
            if case.expected:
                relabelled.append(
                    case.__class__(
                        name=case.name,
                        golden_class=case.golden_class,
                        description=case.description,
                        expected=(),
                    )
                )
            else:
                relabelled.append(case)

        monkeypatch.setattr(corpus_mod, "iter_cases", lambda: iter(relabelled))
        monkeypatch.setattr("eval.history.iter_cases", lambda: iter(relabelled), raising=False)

        assert corpus_fingerprint() != before, (
            "relabelling the corpus must change the fingerprint, or the gate will "
            "compare counts measured against different labels"
        )
