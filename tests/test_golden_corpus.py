"""The golden-capture corpus is trustworthy, and the engine still scores against it.

Four properties, in order of how much damage their absence would do:

1. **The corpus is reproducible.** Synthetic captures are only trustworthy as ground
   truth if rebuilding them yields the same bytes. A generator whose output drifted
   would make every label a claim about a capture that no longer exists.
2. **No unaccepted divergence.** A mismatch that is not in `KNOWN_DIVERGENCES` is a
   regression, and this fails. The allowlist has to stay small and justified: it
   exists so a *named, reasoned* limitation is visible to a reviewer, not so
   failures can be parked.
3. **Recall is total.** Every labelled flow is found. Recall loss means the engine
   stopped seeing something it used to see, which is invisible to a precision-only
   gate.
4. **The corpus keeps its shape.** 30+ captures across all five of Layer 6's
   classes, so "30+ labelled pcaps" is a fact about this file rather than a claim in
   a document that nobody re-reads.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dpi_engine.types import AppType
from golden.corpus import ALL_CLASSES, build_corpus, materialise
from golden.scoring import KNOWN_DIVERGENCES, CorpusScore, score_corpus

#: Layer 6 states "30+ labelled pcaps". This is that floor, asserted.
MINIMUM_CAPTURES = 30


@pytest.fixture(scope="module")
def score(tmp_path_factory: pytest.TempPathFactory) -> CorpusScore:
    """Scores the whole corpus once; it is 33 pipeline runs and the tests share it."""
    root = tmp_path_factory.mktemp("golden")
    return score_corpus(root / "captures", write_output_to=root / "out")


class TestCorpusShape:
    def test_the_corpus_meets_layer_six_floor(self) -> None:
        assert len(build_corpus()) >= MINIMUM_CAPTURES, (
            f"Layer 6 asks for {MINIMUM_CAPTURES}+ labelled pcaps; "
            f"there are {len(build_corpus())}"
        )

    def test_every_class_is_represented(self) -> None:
        present = {c.golden_class for c in build_corpus()}
        assert present == set(ALL_CLASSES), (
            f"missing classes: {set(ALL_CLASSES) - present}"
        )

    def test_every_class_has_at_least_three_captures(self) -> None:
        """One capture per class would satisfy "represented" and score nothing.

        A precision or recall figure derived from a single capture is a coin flip
        wearing a decimal point, so the floor here is three.
        """
        counts: dict[str, int] = {}
        for case in build_corpus():
            counts[case.golden_class] = counts.get(case.golden_class, 0) + 1
        thin = {k: v for k, v in counts.items() if v < 3}
        assert not thin, f"classes with fewer than 3 captures: {thin}"

    def test_case_names_are_unique(self) -> None:
        names = [c.name for c in build_corpus()]
        assert len(names) == len(set(names)), "two cases share a name"

    def test_every_case_has_a_description(self) -> None:
        for case in build_corpus():
            assert case.description.strip(), f"{case.name} has no description"

    def test_every_expected_flow_declares_a_policy(self) -> None:
        """A label that omits `should_block` cannot be used for policy evals."""
        for case in build_corpus():
            for flow in case.expected:
                assert isinstance(flow.should_block, bool)

    def test_the_corpus_is_deterministic(self) -> None:
        """Two builds of `build_corpus()` must be identical.

        Guards against a set or dict iteration leaking into the case order, which
        would make the generated pcaps differ run to run.
        """
        first = [(c.name, c.golden_class, c.expected) for c in build_corpus()]
        second = [(c.name, c.golden_class, c.expected) for c in build_corpus()]
        assert first == second


class TestReproducibility:
    def test_materialising_twice_produces_identical_bytes(
        self, tmp_path: Path
    ) -> None:
        """The load-bearing property of a *synthetic* corpus.

        Every label is a claim about specific bytes. If the generator is not
        byte-reproducible then the labels describe a capture that no longer exists,
        and "ground truth is true by construction" becomes "was true once".
        """
        first = materialise(tmp_path / "a")
        second = materialise(tmp_path / "b")

        assert set(first) == set(second)
        differing = [
            name for name in first if first[name].read_bytes() != second[name].read_bytes()
        ]
        assert not differing, f"these captures are not reproducible: {differing}"

    def test_a_materialised_capture_is_a_readable_pcap(self, tmp_path: Path) -> None:
        from dpi_engine.pcap_io import PcapReader

        paths = materialise(tmp_path / "caps")
        for name, path in paths.items():
            with PcapReader(path) as reader:
                packets = list(reader)
            assert packets, f"{name} produced no packets"


class TestGatesCanActuallyFail:
    """The scorer must be able to report failure, proven by making it fail.

    Every gate above asserts something that currently *passes* -- recall is total,
    no divergence is unaccepted, precision clears its floor. That is a real weakness
    in those tests, and mutation testing exposed it: eight mutants survived,
    including `recall` hard-coded to 1.0 and `micro_precision` hard-coded to 1.0,
    because on a corpus with nothing wrong **a broken gate and a working one produce
    identical output**.

    So the gate machinery is tested against deliberately corrupted input. A scorer
    that cannot fail here cannot be trusted when it does.
    """

    def test_a_wrong_label_is_reported_as_unaccepted(self, tmp_path: Path) -> None:
        """Relabel a real flow to the wrong app; the scorer must notice.

        Done by corrupting the *label*, not the capture, so the engine's behaviour is
        unchanged and only the scorer's judgement is under test.
        """

        from dpi_engine.pipeline import run_pipeline
        from golden.corpus import ExpectedFlow, GoldenCase, GoldenClass
        from golden.scoring import score_case

        case = GoldenCase(
            name="probe",
            golden_class=GoldenClass.LEGITIMATE_ENTERPRISE,
            description="probe",
            expected=(ExpectedFlow("www.facebook.com", AppType.NETFLIX),),  # wrong
        )
        # A capture the engine will classify as FACEBOOK, labelled NETFLX.
        from dpi_engine.pcap_io import PcapWriter
        from golden.corpus import build_case_packets

        pcap = tmp_path / "probe.pcap"
        with PcapWriter(pcap) as writer:
            for pkt in build_case_packets(
                GoldenCase(
                    name="p",
                    golden_class=GoldenClass.LEGITIMATE_ENTERPRISE,
                    description="p",
                    expected=case.expected,
                )
            ):
                writer.write(pkt)

        result = run_pipeline(pcap, tmp_path / "out.pcap")
        case_score, _ = score_case(case, result)

        assert not case_score.perfect
        assert case_score.unaccepted, "a wrong label must be reported, not absorbed"

    def test_a_missing_flow_lowers_recall(self, tmp_path: Path) -> None:
        """Label a flow the capture does not contain; recall must fall."""
        from golden.scoring import ClassScore

        merged = ClassScore(app=AppType.FACEBOOK, true_positives=1, false_positives=0, false_negatives=2)
        assert merged.recall < 1.0, "two misses against one hit must not read as perfect"

    def test_an_extra_detection_lowers_precision(self, tmp_path: Path) -> None:
        """A detection nobody labelled is a false positive."""
        from golden.scoring import ClassScore

        polluted = ClassScore(app=AppType.FACEBOOK, true_positives=1, false_positives=3, false_negatives=0)
        assert polluted.precision < 1.0

    def test_an_unexpected_domain_lands_in_unexpected(self, tmp_path: Path) -> None:
        """The end-to-end version: an unlabelled detection is surfaced.

        `c2_dns_tunnel` labels exactly its own hostnames. Anything else the engine
        reports for that capture is, by definition, unlabelled -- and must be
        reported rather than assumed harmless.
        """
        from dpi_engine.pipeline import run_pipeline
        from golden.corpus import GoldenCase, GoldenClass
        from golden.scoring import score_case

        # Label nothing at all, so every real detection is unlabelled.
        case = GoldenCase(
            name="empty",
            golden_class=GoldenClass.C2_BEACONING,
            description="labels nothing",
            expected=(),
        )
        result = run_pipeline(
            materialise(tmp_path / "caps")["c2_dns_tunnel"], tmp_path / "out.pcap"
        )
        case_score, _ = score_case(case, result)

        assert case_score.unexpected, (
            "detections with no label must be reported as unexpected, or the "
            "precision number is measuring nothing"
        )

    def test_micro_recall_can_fail(self) -> None:
        """The *aggregate* recall must be able to report a miss.

        Mutation testing showed this is a distinct code path from
        `ClassScore.recall`, and testing only the per-class one left
        `CorpusScore.micro_recall` free to return 1.0 unconditionally.
        """
        from golden.scoring import ClassScore, CorpusScore

        # Two apps: one perfect, one that missed three of four.
        per_app = (
            ClassScore(app=AppType.FACEBOOK, true_positives=4, false_positives=0, false_negatives=0),
            ClassScore(app=AppType.NETFLIX, true_positives=1, false_positives=0, false_negatives=3),
        )
        degraded = CorpusScore(cases=(), per_app=per_app, unaccepted=())

        assert degraded.micro_recall < 1.0, (
            f"micro recall reported {degraded.micro_recall} with 3 of 8 missed"
        )
        assert degraded.micro_recall == pytest.approx(5 / 8)

    def test_micro_precision_can_fail(self) -> None:
        """Likewise for the aggregate precision gate."""
        from golden.scoring import ClassScore, CorpusScore

        per_app = (
            ClassScore(app=AppType.FACEBOOK, true_positives=1, false_positives=3, false_negatives=0),
        )
        degraded = CorpusScore(cases=(), per_app=per_app, unaccepted=())

        assert degraded.micro_precision == pytest.approx(0.25)
        assert degraded.micro_precision < 0.85, (
            "a 3-in-4 false-positive rate must not pass a precision gate"
        )

    def test_score_case_counts_a_miss_as_a_false_negative(self, tmp_path: Path) -> None:
        """A miss must land in the false-negative slot, not be absorbed.

        The per-class arithmetic above proves a miss *reduces* recall when it is
        counted. This proves `score_case` actually counts it — that it increments
        the `fn` slot rather than, say, the `tp` slot, which would leave every
        aggregate looking perfect.
        """
        from dpi_engine.pipeline import run_pipeline
        from golden.corpus import ExpectedFlow, GoldenCase, GoldenClass
        from golden.scoring import score_case

        case = GoldenCase(
            name="miss",
            golden_class=GoldenClass.LEGITIMATE_ENTERPRISE,
            description="labels a flow the capture cannot contain",
            expected=(
                ExpectedFlow("www.facebook.com", AppType.FACEBOOK),
                ExpectedFlow("absent.example.invalid", AppType.NETFLIX),
            ),
        )
        result = run_pipeline(
            materialise(tmp_path / "caps")["ent_saas"], tmp_path / "out.pcap"
        )
        case_score, tallies = score_case(case, result)

        assert case_score.unaccepted, "the absent flow must be reported as unaccepted"
        netflix = tallies.get(AppType.NETFLIX)
        assert netflix is not None, "a missed flow must still be tallied"
        tp, fp, fn = netflix
        assert fn >= 1, f"the missed flow should be a false negative, got {(tp, fp, fn)}"
        assert tp == 0

    def test_the_reproducibility_check_notices_differing_bytes(self, tmp_path: Path) -> None:
        """The property, tested directly rather than only through the corpus.

        Two identical builds are equal; the check must fail when they differ. Built
        as an explicit comparison so a future refactor that quietly makes the check
        vacuous is caught here.
        """
        a = materialise(tmp_path / "a")
        b = materialise(tmp_path / "b")
        same = [n for n in a if a[n].read_bytes() == b[n].read_bytes()]

        # Now corrupt one and confirm the comparison that guards reproducibility
        # would report it.
        victim = next(iter(b))
        b[victim].write_bytes(b[victim].read_bytes() + b"\x00")
        differing = [n for n in a if a[n].read_bytes() != b[n].read_bytes()]

        assert len(same) == len(a), "identical builds must compare equal"
        assert victim in differing, "a corrupted capture must compare unequal"


class TestScoring:
    def test_nothing_is_unaccepted(self, score: CorpusScore) -> None:
        """A mismatch outside the allowlist is a regression, and this fails.

        The allowlist exists so a *named and reasoned* limitation is visible in
        review. It must not become a place to park failures, so any entry that
        stops matching turns this red -- which is also how an entry retires itself
        when the underlying issue is fixed.
        """
        assert not score.unaccepted, (
            "unaccepted divergences (each is a real regression):\n"
            + "\n".join(
                f"  {case}: {host} expected {want.name}, got {got.name}"
                for case, host, want, got in score.unaccepted
            )
        )

    def test_every_allowlisted_divergence_still_occurs(self, score: CorpusScore) -> None:
        """An allowlist entry that no longer matches is a stale excuse.

        Kept honest by the same mechanism as the test above: once the engine fixes
        the case, this fails and the entry must be deleted rather than left to rot.
        """
        observed = {
            (d.case, d.hostname) for c in score.cases for d in c.accepted
        }
        expected = {(d.case, d.hostname) for d in KNOWN_DIVERGENCES}
        assert observed == expected, (
            "allowlist is out of step with reality -- entries that no longer occur "
            f"should be deleted: {sorted(expected - observed)}; "
            f"unlisted: {sorted(observed - expected)}"
        )

    def test_every_divergence_has_a_reason(self) -> None:
        """An unexplained divergence is an unexplained bug.

        Mandatory in the type's spirit and enforced here, because the failure mode
        of an allowlist is a list of bare hostnames that quietly becomes a list of
        things nobody fixed.
        """
        for d in KNOWN_DIVERGENCES:
            assert d.reason.strip(), f"{d.case}/{d.hostname} has no reason"

    def test_recall_is_total(self, score: CorpusScore) -> None:
        """Every labelled flow was found.

        Recall loss means the engine stopped seeing something it used to see — the
        kind of regression a precision-only gate cannot see, and the reason Layer 6
        asks for both numbers rather than one.
        """
        assert score.micro_recall == 1.0, (
            "a labelled flow went missing:\n" + score.summary()
        )

    def test_precision_clears_the_gate_layer_6_implies(self, score: CorpusScore) -> None:
        """Precision must stay at or above its measured floor.

        Layer 6 gives no numeric gate, so this pins the *current* value rather than
        inventing a target. The value is low because of `D-27` — most apps are
        matched by bare substring, so attacker-controlled hostnames inherit their
        classification. That is a real weakness, not test noise, and raising this
        number means fixing it rather than relaxing the threshold.
        """
        assert score.micro_precision >= 0.85, (
            f"micro precision fell to {score.micro_precision:.3f}:\n{score.summary()}"
        )

    def test_per_app_scores_are_reported(self, score: CorpusScore) -> None:
        """Layer 6 asks for precision/recall *per class*, so every app is scored."""
        scored = {s.app for s in score.per_app}
        assert AppType.FACEBOOK in scored
        assert AppType.HTTPS in scored, "the fallback class must be scored too"
        for s in score.per_app:
            assert 0.0 <= s.precision <= 1.0
            assert 0.0 <= s.recall <= 1.0

    def test_an_unused_class_does_not_score_zero(self) -> None:
        """Precision of an unpredicted class is 1.0, not 0.0.

        Otherwise adding a class to the corpus that the engine happens not to
        encounter would look like a total failure, and the incentive would be to
        delete such cases rather than investigate.
        """
        from golden.scoring import ClassScore

        unused = ClassScore(app=AppType.QUIC, true_positives=0, false_positives=0, false_negatives=0)
        assert unused.precision == 1.0
        assert unused.recall == 1.0

    def test_the_summary_names_the_known_weak_classes(self, score: CorpusScore) -> None:
        """`D-27` should stay visible in the report, not buried in a pass rate.

        The classes losing precision to substring matching are precisely the ones
        with a bare-substring rule, so a reader can connect the number to the cause.

        This is the test that makes `DEC-07` self-enforcing. The decision was to
        **keep** the weakness, so a passing suite must not mean "no longer weak" -
        if FACEBOOK ever stops losing precision, `D-27` has been fixed by someone and
        this fails, telling them to shrink `KNOWN_DIVERGENCES` rather than leaving a
        stale allowlist entry to rot silently.
        """
        weak = {s.app for s in score.per_app if s.precision < 1.0}
        assert AppType.FACEBOOK in weak, (
            "FACEBOOK is expected to lose precision to the substring rule "
            "(D-27, accepted as DEC-07); if it no longer does, D-27 has been fixed "
            "and KNOWN_DIVERGENCES should shrink to match"
        )
        assert "corpus:" in score.summary()
