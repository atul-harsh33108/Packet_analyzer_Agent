"""`T1-08` — the published baseline must match what the benchmarks actually record.

The whole point of publishing a baseline is that it can be compared against later.
That only works if the two files agree, and the failure mode is quiet: someone
re-runs the benchmarks, gets different numbers, and updates the JSON while the
prose keeps quoting the old ones. Nothing breaks, nothing fails, and the document
becomes fiction that still looks authoritative.

So the numbers in `BENCHMARKS.md` are checked against `tests/benchmarks/baseline.json`
here. Cheap, and it converts rot into a red test.

These tests do **not** run the benchmarks. Doing so needs `--benchmark-enable`,
which `--benchmark-disable` in `addopts` otherwise suppresses, and a benchmark run
is seconds of wall clock that a correctness suite has no business paying. What is
checked is the *agreement* between the two committed artefacts; the benchmarks
themselves stay the thing you run deliberately.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

BASELINE = Path(__file__).resolve().parents[1] / "tests" / "benchmarks" / "baseline.json"
DOC = Path(__file__).resolve().parents[1] / "docs" / "BENCHMARKS.md"

#: Packets in the synthetic capture `test_end_to_end.py` builds. Mirrored rather
#: than imported: importing the benchmark module would pull in `pytest-benchmark`
#: fixtures at collection time.
PACKET_COUNT = 4000

VARIANTS = {
    "single_process": "run_pipeline (single process)",
    "multiprocess": "run_pipeline_multiprocess",
    "staged": "run_pipeline_staged",
}


@pytest.fixture(scope="module")
def baseline() -> dict:
    if not BASELINE.exists():
        pytest.fail(
            f"{BASELINE} is missing. Without a published baseline there is "
            "nothing to compare a regression against; regenerate it with "
            "`uv run pytest tests/benchmarks --benchmark-enable --benchmark-save=baseline.json`."
        )
    return json.loads(BASELINE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def doc() -> str:
    if not DOC.exists():
        pytest.fail(f"{DOC} is missing; it is the human-readable half of the baseline.")
    return DOC.read_text(encoding="utf-8")


def _means(baseline: dict) -> dict[str, float]:
    """Benchmark name -> mean in **seconds**, for the end-to-end variants."""
    out: dict[str, float] = {}
    for entry in baseline["benchmarks"]:
        for key in VARIANTS:
            if entry["name"].endswith(key):
                out[key] = entry["stats"]["mean"]
    return out


class TestBaselineIsWellFormed:
    def test_every_benchmark_suite_is_represented(self, baseline: dict) -> None:
        names = {b["name"] for b in baseline["benchmarks"]}
        assert len(names) == 8, f"expected 8 benchmarks, found {len(names)}: {sorted(names)}"

    def test_stats_are_seconds_not_nanoseconds(self, baseline: dict) -> None:
        """Guard a units mistake that would misreport every figure by 1e9.

        `pytest-benchmark` stores seconds as a float. A consumer assuming
        nanoseconds would print "137500000000 ms" and look absurd, but a
        *consumer* dividing by 1e6 instead of multiplying by 1000 prints a
        plausible-looking "0.0 ms" — which is worse, because it is silent.
        """
        means = _means(baseline)
        for key, mean in means.items():
            assert 0.01 < mean < 60, (
                f"{key}: mean {mean} is not a plausible duration in seconds. "
                "The baseline may have been written with nanoseconds."
            )

    def test_the_variants_are_ordered_as_documented(
        self, baseline: dict
    ) -> None:
        """Single-process must be the fastest, or the headline claim is inverted.

        `D-23`'s content is precisely this ordering. Asserting it means a future
        change that genuinely fixes the IPC cost cannot land without also updating
        the document and this test.
        """
        means = _means(baseline)
        assert means["single_process"] < means["multiprocess"]
        assert means["multiprocess"] < means["staged"]

    def test_the_machine_is_recorded(self, baseline: dict) -> None:
        """A baseline without its machine is not comparable to anything."""
        info = baseline.get("machine_info", {})
        assert info.get("system") and info.get("python_version")
        assert baseline.get("datetime"), "the baseline must record when it was taken"


class TestDocumentAgreesWithBaseline:
    """The rot guard. This is the test that makes the pair trustworthy."""

    def test_every_variant_mean_appears_in_the_document(
        self, baseline: dict, doc: str
    ) -> None:
        means = _means(baseline)
        for key in VARIANTS:
            milliseconds = means[key] * 1000
            # Rendered to one decimal, matching how the table shows them.
            rendered = f"{milliseconds:.1f} ms"
            assert rendered in doc, (
                f"{key}: the baseline records {rendered} but {DOC.name} does not "
                "contain that figure. One of the two is stale."
            )

    def test_the_ratios_in_the_document_are_recomputable(
        self, baseline: dict, doc: str
    ) -> None:
        """The relative figures must follow from the absolute ones.

        A hand-edited "7.26x slower" is the most likely thing to rot, because it
        looks authoritative and nobody recomputes it. So recompute and compare.
        """
        means = _means(baseline)
        expected = {
            "multiprocess": means["multiprocess"] / means["single_process"],
            "staged": means["staged"] / means["single_process"],
        }
        for key, ratio in expected.items():
            rendered = f"{ratio:.2f}x"
            assert rendered in doc, (
                f"{key}: recomputed ratio is {rendered} but {DOC.name} does not "
                "contain it."
            )

    def test_the_throughput_figures_are_consistent_with_the_means(
        self, baseline: dict, doc: str
    ) -> None:
        """Kpps must equal packets/mean, or the two columns contradict.

        Cheap arithmetic that catches a copy-paste slip between the duration and
        the throughput column of the same table.
        """
        means = _means(baseline)
        kpps = PACKET_COUNT / means["single_process"] / 1000
        rendered = f"{kpps:.0f} Kpps"
        assert rendered in doc, (
            f"single-process throughput recomputes to {rendered}, which "
            f"{DOC.name} does not contain."
        )

    def test_the_document_records_the_benchmark_disable_caveat(
        self, doc: str
    ) -> None:
        """The most dangerous property of this suite must be documented.

        Without `--benchmark-enable` these tests report as *passed* without
        running. A reader who does not know that will treat a green run as a
        measurement, so the caveat has to be in the document, not just in a
        test docstring.
        """
        assert "--benchmark-enable" in doc
        assert "without executing" in doc or "did not" in doc.lower()

    def test_the_document_points_at_the_json(self, doc: str) -> None:
        """The document must name its source, so a stale copy is traceable."""
        assert "baseline.json" in doc
