"""`T5-07`: the classifier measured, the proposal checkable, the exit criterion executed.

**A phase that cannot be measured is a phase that cannot be said to have happened.**
Phase 5 ends with three claims, and this file turns each into an assertion.

1. **The classifier's accuracy is measured against the corpus.** The same scorer
   `T4-05` built (`golden.scoring.score_corpus`) runs the real pipeline over all
   33 captures. The expectation is *derived* rather than copied: every label is
   either matched or one of the named `KNOWN_DIVERGENCES`, so precision is
   `(labels - allowlist) / labels`. The fingerprint table is the second
   classifier: measured over the same labelled flows it must never contradict a
   corpus label -- abstain or agree.

2. **Every accepted proposal is checkable.** A proposal is only accepted if each
   citation resolves through the run store and every pattern it proposes is a
   fact the cited flows actually share -- recomputed here with
   `common_predicates`, never trusted. A corpus-wide sweep builds every proposal
   the corpus can produce and asserts that no uncheckable one is accepted; a
   fabricated citation is refused outright.

3. **The phase's exit criterion is executed, not described.** An unknown app is
   proposed from cited flows, reviewed, approved by the Critic, installed, and
   then identified. The corpus-contradicted proposal is falsified by the Critic,
   and `install` refuses it even when handed an approving verdict -- the
   deterministic floor, not the model's opinion, is what stops it.

**Why the gap is synthetic here.** The corpus is fully classified by design
(recall is total), so it contains no unknown flow for the agent to close. The gap
configuration is the same one `T5-06` exercises: a client whose SNI names nothing,
on a port no rule classifies, built by the corpus's own generator. The bytes, the
fingerprint and the engine path are real; only the label is the absence of one.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from agent_harness import store_a_run
from dpi_agents.maintenance import Proposal, review
from dpi_agents.model import ModelReply, ScriptedModel
from dpi_agents.nodes.critic import critic_node
from dpi_agents.runtime import Agent
from dpi_agents.schemas import NewAppCandidate
from dpi_agents.trace import Trace
from dpi_engine.flow_features import observe_flow_features
from dpi_engine.maintenance import Critique, Verdict, install
from dpi_engine.pipeline import PipelineResult
from dpi_engine.proposals import common_predicates
from dpi_engine.run_store import RunStore
from dpi_engine.signatures import DEFAULT_TABLE, Predicate
from dpi_engine.types import AppType, DPIStats, FiveTuple, FlowRecord
from golden.corpus import (
    ExpectedFlow,
    GoldenCase,
    GoldenClass,
    build_client_hello,
    iter_cases,
    write_case,
)
from golden.scoring import KNOWN_DIVERGENCES, CorpusScore, score_case, score_corpus

#: The gap configuration: a port no rule classifies, and an SNI that names nothing.
GAP_PORT = 8443
GAP_APP = "GAP-CLIENT"


# ---------------------------------------------------------------------------
# The measurement: the corpus's own labels, the real pipeline
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def measured(tmp_path_factory: pytest.TempPathFactory) -> CorpusScore:
    """One real execution of the whole corpus, shared by the measurement tests."""
    return score_corpus(tmp_path_factory.mktemp("classifier-accuracy"))


class TestTheMeasurementCoversTheCorpus:
    def test_it_scores_every_capture_and_every_label(self, measured: CorpusScore) -> None:
        """A score that skipped a capture would be a smaller, easier corpus."""
        cases = tuple(iter_cases())
        labels = sum(len(case.expected) for case in cases)

        assert measured.total_cases == len(cases), "the score skipped a capture"
        assert measured.total_cases >= 30, "Layer 6's corpus floor is 30 labelled captures"
        assert [score.case.name for score in measured.cases] == [case.name for case in cases]
        assert sum(score.expected_total for score in measured.cases) == labels
        assert labels >= 59, "every expected flow in the corpus must be measured"

    def test_the_score_is_not_a_ratio_over_nothing(self, measured: CorpusScore) -> None:
        """The empty denominator would make precision and recall both 1.0."""
        assert measured.per_app, "no per-app tallies, so nothing was classified"
        assert sum(score.true_positives for score in measured.per_app) > 0


class TestTheClassifiersMeasuredAccuracy:
    def test_recall_is_total_and_every_miss_is_allowlisted(self, measured: CorpusScore) -> None:
        assert measured.micro_recall == pytest.approx(1.0)
        assert measured.unaccepted == (), (
            "an unlisted mismatch is a bug, not a known limitation: "
            f"{measured.unaccepted}"
        )
        assert sum(score.false_negatives for score in measured.per_app) == 0

        for score in measured.cases:
            assert score.matched + len(score.accepted) == score.expected_total, (
                f"{score.case.name}: every label must be matched or explicitly accepted"
            )
            assert not score.unaccepted

    def test_precision_is_the_allowlist_and_nothing_else(self, measured: CorpusScore) -> None:
        """False positives are exactly the named divergences -- never a hidden extra."""
        labels = sum(score.expected_total for score in measured.cases)
        false_positives = sum(score.false_positives for score in measured.per_app)
        assert false_positives == len(KNOWN_DIVERGENCES), (
            "the false-positive count must equal the allowlist; an unlisted false "
            "positive would be counted without a reason"
        )

        derived = (labels - len(KNOWN_DIVERGENCES)) / labels
        assert measured.micro_precision == pytest.approx(derived)
        # The measured figure recorded by this task: 53/59 = 0.8983...
        assert measured.micro_precision == pytest.approx(53 / 59)
        # ...and the cases with a divergence are exactly the ones that are not perfect.
        divergence_cases = {divergence.case for divergence in KNOWN_DIVERGENCES}
        assert measured.perfect_cases == measured.total_cases - len(divergence_cases)
        assert measured.perfect_cases == 29

    def test_every_accepted_divergence_names_a_real_flow_and_a_reason(
        self, measured: CorpusScore
    ) -> None:
        """An allowlist entry is a claim about a specific capture, not a hall pass."""
        cases = {case.name: case for case in iter_cases()}
        accepted = [divergence for score in measured.cases for divergence in score.accepted]

        assert len(accepted) == len(KNOWN_DIVERGENCES)
        for divergence in accepted:
            assert divergence in KNOWN_DIVERGENCES
            assert divergence.reason.strip(), "an accepted divergence must say why"
            case = cases[divergence.case]
            expected = {flow.hostname: flow.app for flow in case.expected}
            assert expected[divergence.hostname] == divergence.expected, (
                "the allowlist entry must name a hostname the capture actually labels"
            )


class TestTheMeasurementCanFail:
    """A measurement that cannot report a regression is decoration.

    The corpus currently has **no** unlisted mismatch, so the healthy run never
    executes the failure path. That is exactly the shape `T2-04` warned about: a
    green gate that measures nothing. These cases force the failures by hand --
    a wrong label, an invented detection, an allowlist entry that covers only one
    hostname -- and require each one to be reported.

    They call `score_case`, the same scorer the corpus-wide measurement uses, so
    the forced failure exercises the real path rather than a parallel one.
    """

    def _case(self, *flows: ExpectedFlow) -> GoldenCase:
        return GoldenCase(
            name="measurement_can_fail",
            golden_class=GoldenClass.LEGITIMATE_ENTERPRISE,
            description="a hand-built case whose wrong answer must be visible",
            expected=flows,
        )

    @staticmethod
    def _result(detected: dict[str, AppType]) -> PipelineResult:
        return PipelineResult(stats=DPIStats(), detected_domains=detected)

    def test_an_unlisted_mismatch_is_a_false_negative(self) -> None:
        case = self._case(ExpectedFlow("example.com", AppType.HTTPS))
        result = self._result({"example.com": AppType.NETFLIX})

        score, tallies = score_case(case, result)

        assert score.matched == 0
        assert score.unaccepted == (("example.com", AppType.HTTPS, AppType.NETFLIX),)
        assert tallies[AppType.HTTPS] == [0, 0, 1]
        assert not score.perfect

    def test_an_invented_detection_is_a_false_positive(self) -> None:
        case = self._case(ExpectedFlow("example.com", AppType.HTTPS))
        result = self._result(
            {
                "example.com": AppType.HTTPS,
                "invented.example": AppType.NETFLIX,
            }
        )

        score, tallies = score_case(case, result)

        assert score.unexpected == ("invented.example",)
        assert tallies[AppType.NETFLIX] == [0, 1, 0]
        assert not score.perfect

    def test_a_known_divergence_is_accepted_but_still_counted_against_the_actual(
        self,
    ) -> None:
        divergence = KNOWN_DIVERGENCES[0]
        case = GoldenCase(
            name=divergence.case,
            golden_class=GoldenClass.LEGITIMATE_ENTERPRISE,
            description="one allowlisted hostname",
            expected=(ExpectedFlow(divergence.hostname, divergence.expected),),
        )
        result = self._result({divergence.hostname: divergence.actual})

        score, tallies = score_case(case, result)

        assert score.accepted == (divergence,)
        assert score.unaccepted == ()
        assert tallies[divergence.actual] == [0, 1, 0], (
            "an accepted divergence is a false positive for the app it actually "
            "classified as; 'expected' must not hide it"
        )
        assert tallies.get(divergence.expected, [0, 0, 0])[2] == 0

    def test_the_allowlist_is_matched_by_case_and_hostname(self) -> None:
        """A case name alone must not excuse a different hostname in that case."""
        divergence = KNOWN_DIVERGENCES[0]
        case = GoldenCase(
            name=divergence.case,
            golden_class=GoldenClass.LEGITIMATE_ENTERPRISE,
            description="the allowlisted hostname plus an unlisted wrong one",
            expected=(
                ExpectedFlow(divergence.hostname, divergence.expected),
                ExpectedFlow("other.example", AppType.HTTPS),
            ),
        )
        result = self._result(
            {
                divergence.hostname: divergence.actual,
                "other.example": AppType.NETFLIX,
            }
        )

        score, _tallies = score_case(case, result)

        assert score.accepted == (divergence,)
        assert score.unaccepted == (("other.example", AppType.HTTPS, AppType.NETFLIX),)


class TestTheFingerprintTableAsASecondClassifier:
    def test_over_the_same_labelled_flows_it_never_contradicts_a_label(self) -> None:
        """A fingerprint may abstain; it must never claim a different app.

        The corpus's TLS traffic is one synthetic client, so a positive answer
        here would mean the generator was recognised as an application. That is
        why the measured state is "abstained on every flow" -- but the rule this
        test pins is the one that must survive new signatures: **agree or
        abstain, never contradict**.
        """
        checked = abstained = agreed = 0
        contradictions: list[tuple[str, str, str, str]] = []

        for case in iter_cases():
            for flow in case.expected:
                checked += 1
                observed = observe_flow_features(build_client_hello(flow.hostname))
                found = DEFAULT_TABLE.identify(observed)
                if found.app is None:
                    abstained += 1
                elif found.app == flow.app.name:
                    agreed += 1
                else:
                    contradictions.append(
                        (case.name, flow.hostname, found.app, flow.app.name)
                    )

        assert checked >= 59
        assert checked == abstained + agreed
        assert not contradictions, (
            "the fingerprint table labelled a corpus flow as a different app: "
            f"{contradictions}"
        )
        # The recorded measurement: the shipped table claims nothing here.
        assert abstained == checked
        assert agreed == 0


# ---------------------------------------------------------------------------
# The gap cases: the corpus's generator with the label removed
# ---------------------------------------------------------------------------


def _gap_case() -> GoldenCase:
    """Two clients whose SNI names nothing, on a port nothing classifies."""
    return GoldenCase(
        name="accuracy_gap",
        golden_class=GoldenClass.C2_BEACONING,
        description="clients whose SNI names nothing, on a port nothing classifies",
        expected=(
            ExpectedFlow("", AppType.UNKNOWN, dst_port=GAP_PORT),
            ExpectedFlow("", AppType.UNKNOWN, dst_port=GAP_PORT),
        ),
    )


def _mixed_case() -> GoldenCase:
    """The same gap client beside a flow the engine already labels."""
    return GoldenCase(
        name="accuracy_mixed",
        golden_class=GoldenClass.C2_BEACONING,
        description="a nameless client beside a known app",
        expected=(
            ExpectedFlow("", AppType.UNKNOWN, dst_port=GAP_PORT),
            ExpectedFlow("netflix.com", AppType.NETFLIX),
        ),
    )


def _stored(tmp_path: Path, case: GoldenCase) -> tuple[RunStore, str, tuple[FlowRecord, ...]]:
    capture = write_case(tmp_path / f"{case.name}.pcap", case)
    store_root = tmp_path / "store"
    run_id = store_a_run(capture, store_root)
    store = RunStore(store_root)
    return store, run_id, store.query(run_id)


def _unknown_groups(flows: Sequence[FlowRecord]) -> dict[str, tuple[FlowRecord, ...]]:
    """The run's unclassified, fingerprinted flows, grouped by their fingerprint."""
    groups: dict[str, list[FlowRecord]] = {}
    for flow in flows:
        if flow.app == AppType.UNKNOWN.name and flow.features.ja4:
            groups.setdefault(flow.features.ja4, []).append(flow)
    return {ja4: tuple(group) for ja4, group in groups.items()}


def _only_unknown_group(flows: Sequence[FlowRecord]) -> tuple[FlowRecord, ...]:
    groups = _unknown_groups(flows)
    assert len(groups) == 1, f"expected one unclassified fingerprint, got {sorted(groups)}"
    return next(iter(groups.values()))


def _candidate(
    patterns: Sequence[Predicate],
    citations: Sequence[FiveTuple],
    *,
    name: str = GAP_APP,
) -> NewAppCandidate:
    return NewAppCandidate(
        name=name,
        evidence=(f"{len(citations)} cited flows share every proposed fact",),
        confidence=0.5,
        proposed_patterns=tuple(patterns),
        citations=tuple(citations),
    )


def _proposal(
    cited: Sequence[FlowRecord], run_id: str, *, signature_id: str = "gap-01"
) -> tuple[Proposal, tuple[Predicate, ...]]:
    patterns = common_predicates(cited)
    assert patterns, "the cited gap flows share no observed fact"
    return (
        Proposal(
            run_id=run_id,
            signature_id=signature_id,
            candidate=_candidate(patterns, tuple(flow.five_tuple for flow in cited)),
        ),
        patterns,
    )


def _assert_checkable(
    proposal: Proposal, review_result: Critique, flows: Sequence[FlowRecord]
) -> None:
    """An accepted proposal must be fully recomputable from the run it names."""
    by_tuple = {flow.five_tuple: flow for flow in flows}
    citations = proposal.candidate.citations

    assert len(set(citations)) == len(citations), "a citation is repeated"
    assert review_result.cited == citations, (
        "the review resolved different citations than the proposal named"
    )

    cited_flows = tuple(by_tuple[five_tuple] for five_tuple in citations)
    shared = common_predicates(cited_flows)
    for pattern in proposal.candidate.proposed_patterns:
        assert pattern in shared, (
            f"{pattern!r} is proposed but not shared by the cited flows: an accepted "
            "proposal must be recomputable from its evidence"
        )
        # Independent of `common_predicates`: an absence is not a fact. This is
        # what stops the recomputation above from validating a bug in itself.
        assert pattern.value is not None and pattern.value != "", (
            f"{pattern!r} proposes an unobserved value as evidence"
        )

    assert review_result.signature.id == proposal.signature_id
    assert review_result.signature.all_of == proposal.candidate.proposed_patterns
    for five_tuple in citations:
        assert review_result.signature.matches(by_tuple[five_tuple].features), (
            f"the accepted signature does not match its own citation {five_tuple}"
        )


# ---------------------------------------------------------------------------
# Every accepted proposal is checkable
# ---------------------------------------------------------------------------


class TestEveryAcceptedProposalIsCheckable:
    def test_the_corpus_gap_proposal_is_recomputable_from_its_citations(
        self, tmp_path: Path
    ) -> None:
        store, run_id, flows = _stored(tmp_path, _gap_case())
        cited = _only_unknown_group(flows)
        proposal, patterns = _proposal(cited, run_id)

        assert patterns
        assert DEFAULT_TABLE.identify(cited[0].features).app is None, (
            "the gap must be real before a proposal can close it"
        )

        result = review(proposal, store=store)

        assert result.approved, result.contradictions
        _assert_checkable(proposal, result, flows)

    def test_a_proposal_citing_a_flow_outside_its_run_is_never_accepted(
        self, tmp_path: Path
    ) -> None:
        """The contrapositive: what cannot be cited is refused, not scored."""
        store, run_id, flows = _stored(tmp_path, _gap_case())
        cited = _only_unknown_group(flows)
        patterns = common_predicates(cited)
        fabricated = FiveTuple(167772161, 167772162, 59999, GAP_PORT, 6)

        proposal = Proposal(
            run_id=run_id,
            signature_id="gap-02",
            candidate=_candidate(patterns, (fabricated,)),
        )

        with pytest.raises(ValueError, match="cannot be cited"):
            review(proposal, store=store)

    def test_no_accepted_proposal_over_the_corpus_is_uncheckable(self, tmp_path: Path) -> None:
        """Build every proposal the corpus can produce and check each acceptance.

        The corpus itself has no unknown, fingerprinted flow -- recall is total --
        so the gap and mixed captures are included. The sweep is still a
        measurement, not a formality: it asserts that at least one proposal was
        accepted, that the corpus contradicts at least one, and that no accepted
        proposal was accepted without evidence that recomputes.
        """
        accepted = contradicted = uncheckable = 0

        for case in (*iter_cases(), _gap_case(), _mixed_case()):
            capture = write_case(tmp_path / f"{case.name}.pcap", case)
            store_root = tmp_path / case.name / "store"
            store_root.parent.mkdir(parents=True, exist_ok=True)
            run_id = store_a_run(capture, store_root)
            store = RunStore(store_root)
            flows = store.query(run_id)

            for cited in _unknown_groups(flows).values():
                patterns = common_predicates(cited)
                if not patterns:
                    continue
                proposal = Proposal(
                    run_id=run_id,
                    signature_id=f"{case.name}-gap",
                    candidate=_candidate(patterns, tuple(flow.five_tuple for flow in cited)),
                )
                try:
                    result = review(proposal, store=store)
                except ValueError:
                    uncheckable += 1
                    continue

                if not result.approved:
                    contradicted += 1
                    continue

                accepted += 1
                _assert_checkable(proposal, result, flows)

        assert accepted >= 1, "the sweep accepted nothing, so it checked nothing"
        assert contradicted >= 1, "the corpus-contradicted proposal was never exercised"
        assert uncheckable == 0, (
            "a well-formed proposal must be reviewed, not refused as uncheckable"
        )


# ---------------------------------------------------------------------------
# The phase's exit criterion, executed
# ---------------------------------------------------------------------------


class _NoTools:
    """A tool port that fails if the Critic asks for anything."""

    async def call(self, name: str, arguments: Any) -> Any:
        raise AssertionError(f"the Critic has no tools, but it called {name!r}: {arguments}")


def _ask_the_critic(
    tmp_path: Path, critique: Critique, answer: dict[str, Any]
) -> tuple[Any, ScriptedModel]:
    model = ScriptedModel([ModelReply(text=json.dumps(answer))])

    async def scenario() -> Any:
        with Trace(tmp_path / "critic.jsonl") as trace:
            return await Agent(model=model, trace=trace).run(
                critic_node(critique=critique),
                tools=_NoTools(),  # type: ignore[arg-type]
                state=json.dumps(critique.to_json()),
            )

    return asyncio.run(scenario()), model


class TestThePhaseExitCriterion:
    def test_an_unknown_app_is_identified_by_the_installed_signature(
        self, tmp_path: Path
    ) -> None:
        """The first half of the exit criterion, all the way to a real answer."""
        store, run_id, flows = _stored(tmp_path, _gap_case())
        cited = _only_unknown_group(flows)
        assert DEFAULT_TABLE.identify(cited[0].features).app is None

        proposal, _patterns = _proposal(cited, run_id)
        reviewed = review(proposal, store=store)
        assert reviewed.approved
        _assert_checkable(proposal, reviewed, flows)

        outcome, model = _ask_the_critic(
            tmp_path,
            reviewed,
            {
                "outcome": "approved",
                "reason": "no flow the engine classifies contradicts it",
                "objections": [],
                "counterexamples": [],
            },
        )
        assert outcome.reason == "verdict", outcome.error
        verdict = outcome.verdict
        assert isinstance(verdict, Verdict)
        assert verdict.outcome == "approved"

        installed = install(DEFAULT_TABLE, reviewed, verdict)

        assert installed.identify(cited[0].features).app == GAP_APP
        assert DEFAULT_TABLE.identify(cited[0].features).app is None, (
            "installing must return a new table, not mutate the shipped one"
        )
        assert len(installed.signatures) == len(DEFAULT_TABLE.signatures) + 1

        # The Critic saw the evidence it approved, not a blank page.
        state = json.loads(model.requests[0].messages[0].content)
        assert state["cited"], "the Critic must be given the cited evidence"
        assert state["signature"]["app"] == GAP_APP
        assert state["contradictions"] == []

    def test_the_critic_falsifies_the_proposal_the_corpus_contradicts(
        self, tmp_path: Path
    ) -> None:
        """The second half: the code names a contradiction, the model argues it."""
        store, run_id, flows = _stored(tmp_path, _mixed_case())
        cited = _only_unknown_group(flows)
        fingerprint = cited[0].features.ja4
        proposal = Proposal(
            run_id=run_id,
            signature_id="gap-ja4",
            candidate=_candidate(
                (Predicate("ja4", fingerprint),),
                tuple(flow.five_tuple for flow in cited),
            ),
        )

        reviewed = review(proposal, store=store)
        assert not reviewed.approved
        assert {contradiction.label for contradiction in reviewed.contradictions} == {
            AppType.NETFLIX.name
        }
        contradiction = reviewed.contradictions[0]

        outcome, _model = _ask_the_critic(
            tmp_path,
            reviewed,
            {
                "outcome": "falsified",
                "reason": "it matches a flow the engine already calls Netflix",
                "objections": [
                    "one JA4 is the corpus generator's fingerprint, not this app's"
                ],
                "counterexamples": [
                    {
                        "src_ip": contradiction.five_tuple.src_ip,
                        "dst_ip": contradiction.five_tuple.dst_ip,
                        "src_port": contradiction.five_tuple.src_port,
                        "dst_port": contradiction.five_tuple.dst_port,
                        "protocol": contradiction.five_tuple.protocol,
                    }
                ],
            },
        )
        assert outcome.reason == "verdict", outcome.error
        verdict = outcome.verdict
        assert isinstance(verdict, Verdict)
        assert verdict.outcome == "falsified"
        assert verdict.counterexamples == (contradiction.five_tuple,)

        # The model's veto is not what stops the install: the deterministic
        # floor refuses the contradicted proposal even with an approval in hand.
        approving = Verdict(
            outcome="approved",
            reason="looks fine",
            objections=(),
            counterexamples=(),
        )
        with pytest.raises(ValueError, match="falsified"):
            install(DEFAULT_TABLE, reviewed, approving)
        with pytest.raises(ValueError, match="falsified"):
            install(DEFAULT_TABLE, reviewed, verdict)
        assert DEFAULT_TABLE.identify(cited[0].features).app is None
