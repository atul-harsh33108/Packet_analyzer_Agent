"""`T5-06`: the maintenance loop and the Critic -- what stops an install being a rubber stamp.

**The loop has a floor and a judgement, in that order.** A proposal becomes a
table entry only after two things agree: the *deterministic* critique, which
recomputes the proposal against the flows that carry a known app, and the
*Critic*, which reads that critique adversarially. Either one can stop the
install -- a contradiction the corpus proves, or the model's veto -- and neither
can overrule the other. That is what makes falsification a first-class outcome:
`Verdict(outcome="falsified", ...)` is a value the loop handles, not an error
path, while an *incoherent* verdict (approving a contradicted proposal, or
inventing a counterexample) is refused by the parser.

So the file has four layers:

* **`critique`** -- the deterministic falsifier. It is given a signature, the
  flows under review and the citations the proposal claims, and it answers with
  the flows whose own label contradicts the proposal. It refuses a citation it
  cannot resolve or a cited flow that does not hold the signature: those are not
  evidence, and a proposal that cannot be cited is not reviewed.
* **`install`** -- the only door into a table. It refuses a contradicted
  proposal even when the Critic approved it, and refuses a clean proposal the
  Critic vetoed. Both directions are tested, because a Critic that cannot veto
  is decoration.
* **`parse_critic_verdict` / the node** -- the model's half. The verdict carries
  objections and counterexamples, and the parser pins it to the computed
  contradictions so the model can neither approve a falsified proposal nor
  invent one.
* **The loop over a real run** -- a real MCP server and the corpus's own
  generator. The gap flows it can propose for share the generator's single JA4,
  so the *corpus itself* contradicts the proposal: the loop's job is to catch
  that, not to install it.
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
from dpi_agents.nodes.critic import (
    CRITIC_PROMPT,
    CRITIC_TOOL_NAMES,
    critic_node,
)
from dpi_agents.runtime import Agent
from dpi_agents.schemas import NewAppCandidate, parse_critic_verdict
from dpi_agents.trace import Trace
from dpi_engine.flow_features import FlowFeatures
from dpi_engine.maintenance import Contradiction, Critique, Verdict, critique, install
from dpi_engine.run_store import RunStore
from dpi_engine.signatures import Predicate, Signature, SignatureTable
from dpi_engine.types import AppType, FiveTuple, FlowRecord
from golden.corpus import ExpectedFlow, GoldenCase, GoldenClass, write_case


def _features(**overrides: Any) -> FlowFeatures:
    """A small, fully observed client half, with only the named changes."""
    base: dict[str, Any] = {
        "ja3": "ja3-a",
        "ja4": "ja4-a",
        "sni_present": True,
        "client_version": 771,
        "cipher_suites": (4865,),
        "extensions": (0,),
        "alpn": ("h2",),
    }
    base.update(overrides)
    return FlowFeatures(**base)


def _flow(
    features: FlowFeatures,
    *,
    src_port: int,
    app: str,
    hostname: str = "",
) -> FlowRecord:
    return FlowRecord(
        src_ip=167772161,
        dst_ip=167772162,
        src_port=src_port,
        dst_port=443,
        protocol=6,
        app=app,
        state="ESTABLISHED",
        hostname=hostname,
        features=features,
    )


_CITED = _flow(_features(), src_port=40000, app=AppType.UNKNOWN.name)
_NETFLIX = _flow(_features(), src_port=40001, app=AppType.NETFLIX.name, hostname="netflix.com")
_OTHER_FINGERPRINT = _flow(_features(ja4="ja4-b"), src_port=40002, app=AppType.NETFLIX.name)
_SAME_APP = _flow(_features(), src_port=40003, app="GAP-CLIENT")

_SIGNATURE = Signature(id="gap-01", app="GAP-CLIENT", all_of=(Predicate("ja4", "ja4-a"),))


def _json_tuple(flow: FlowRecord) -> dict[str, int]:
    return {
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
    }


# ---------------------------------------------------------------------------
# The deterministic falsifier
# ---------------------------------------------------------------------------


class TestCritique:
    def test_a_matching_flow_from_another_app_contradicts_the_proposal(self) -> None:
        result = critique(
            _SIGNATURE,
            (_CITED, _NETFLIX, _OTHER_FINGERPRINT, _SAME_APP),
            cited=(_CITED.five_tuple,),
        )

        assert result.contradictions == (
            Contradiction(five_tuple=_NETFLIX.five_tuple, label=AppType.NETFLIX.name),
        )

    def test_an_unclassified_flow_cannot_contradict(self) -> None:
        """`UNKNOWN` is the absence of a label, not a label that disagrees."""
        result = critique(_SIGNATURE, (_CITED,), cited=(_CITED.five_tuple,))

        assert result.contradictions == ()
        assert result.approved

    def test_a_flow_labelled_with_the_proposed_app_supports_it(self) -> None:
        result = critique(
            _SIGNATURE, (_CITED, _SAME_APP), cited=(_CITED.five_tuple,)
        )

        assert result.contradictions == ()
        assert result.approved

    def test_a_flow_the_signature_does_not_match_cannot_contradict(self) -> None:
        result = critique(
            _SIGNATURE, (_CITED, _OTHER_FINGERPRINT), cited=(_CITED.five_tuple,)
        )

        assert result.contradictions == ()

    def test_contradictions_are_ordered_by_five_tuple(self) -> None:
        """Two runs over the same flows must produce the same critique."""
        later = _flow(_features(), src_port=40099, app=AppType.GOOGLE.name)
        result = critique(
            _SIGNATURE, (later, _NETFLIX, _CITED), cited=(_CITED.five_tuple,)
        )

        assert [c.five_tuple.src_port for c in result.contradictions] == [40001, 40099]

    def test_a_citation_that_is_not_under_review_is_refused(self) -> None:
        missing = FiveTuple(1, 2, 3, 4, 6)

        with pytest.raises(ValueError, match="cannot be cited"):
            critique(_SIGNATURE, (_CITED,), cited=(missing,))

    def test_a_cited_flow_that_does_not_hold_the_signature_is_refused(self) -> None:
        """A citation is evidence only if it actually shows the patterns."""
        with pytest.raises(ValueError, match="does not match"):
            critique(
                _SIGNATURE,
                (_CITED, _OTHER_FINGERPRINT),
                cited=(_OTHER_FINGERPRINT.five_tuple,),
            )

    def test_a_proposal_with_no_citation_is_refused(self) -> None:
        with pytest.raises(ValueError, match="cite at least one flow"):
            critique(_SIGNATURE, (_CITED,), cited=())

    def test_the_same_citation_twice_is_refused(self) -> None:
        with pytest.raises(ValueError, match="twice"):
            critique(
                _SIGNATURE,
                (_CITED,),
                cited=(_CITED.five_tuple, _CITED.five_tuple),
            )

    def test_the_same_flow_twice_in_the_evidence_is_refused(self) -> None:
        with pytest.raises(ValueError, match="twice"):
            critique(
                _SIGNATURE, (_CITED, _CITED), cited=(_CITED.five_tuple,)
            )

    def test_a_critique_carries_the_signature_it_judged(self) -> None:
        result = critique(_SIGNATURE, (_CITED,), cited=(_CITED.five_tuple,))

        assert result.signature == _SIGNATURE
        assert result.signature_id == "gap-01"
        assert result.app == "GAP-CLIENT"

    def test_a_critique_is_json_ready(self) -> None:
        result = critique(
            _SIGNATURE, (_CITED, _NETFLIX), cited=(_CITED.five_tuple,)
        )

        raw = json.loads(json.dumps(result.to_json()))

        assert raw["signature"]["id"] == "gap-01"
        assert raw["approved"] is False
        assert raw["contradictions"] == [
            {
                "five_tuple": _json_tuple(_NETFLIX),
                "label": AppType.NETFLIX.name,
            }
        ]

    def test_an_approved_critique_says_so_in_json(self) -> None:
        result = critique(_SIGNATURE, (_CITED,), cited=(_CITED.five_tuple,))

        assert result.to_json()["approved"] is True
        assert result.to_json()["contradictions"] == []


# ---------------------------------------------------------------------------
# The verdict's own invariants
# ---------------------------------------------------------------------------


class TestVerdict:
    def test_a_falsified_verdict_must_say_what_is_wrong(self) -> None:
        with pytest.raises(ValueError, match="say what is wrong"):
            Verdict(outcome="falsified", reason="no", objections=(), counterexamples=())

    def test_an_outcome_is_one_of_the_two_the_loop_understands(self) -> None:
        with pytest.raises(ValueError, match=r"approved.*falsified"):
            Verdict(outcome="maybe", reason="no", objections=(), counterexamples=())

    def test_an_approval_cannot_name_a_counterexample(self) -> None:
        with pytest.raises(ValueError, match="approval cannot name a counterexample"):
            Verdict(
                outcome="approved",
                reason="fine",
                objections=(),
                counterexamples=(_NETFLIX.five_tuple,),
            )

    def test_a_verdict_needs_a_reason(self) -> None:
        with pytest.raises(ValueError, match="reason"):
            Verdict(outcome="approved", reason="  ", objections=(), counterexamples=())

    def test_the_same_counterexample_twice_is_refused(self) -> None:
        with pytest.raises(ValueError, match="twice"):
            Verdict(
                outcome="falsified",
                reason="no",
                objections=("too broad",),
                counterexamples=(_NETFLIX.five_tuple, _NETFLIX.five_tuple),
            )

    def test_objections_are_a_tuple_of_non_empty_text(self) -> None:
        with pytest.raises(ValueError, match="objections"):
            Verdict(outcome="approved", reason="fine", objections=("",), counterexamples=())

    def test_a_counterexample_alone_says_what_is_wrong(self) -> None:
        """A named flow is an answer; `objections` is not the only way to explain a veto."""
        verdict = Verdict(
            outcome="falsified",
            reason="it matches a flow the engine calls Netflix",
            objections=(),
            counterexamples=(_NETFLIX.five_tuple,),
        )

        assert verdict.to_json()["counterexamples"] == [_json_tuple(_NETFLIX)]

    def test_a_verdict_is_json_ready(self) -> None:
        verdict = Verdict(
            outcome="falsified",
            reason="it matches Netflix",
            objections=("the JA4 is the generator's, not an app",),
            counterexamples=(_NETFLIX.five_tuple,),
        )

        raw = json.loads(json.dumps(verdict.to_json()))

        assert raw["outcome"] == "falsified"
        assert raw["counterexamples"] == [_json_tuple(_NETFLIX)]
        assert raw["objections"] == ["the JA4 is the generator's, not an app"]


# ---------------------------------------------------------------------------
# The only door into a table
# ---------------------------------------------------------------------------


def _approved_critique() -> Critique:
    return critique(_SIGNATURE, (_CITED,), cited=(_CITED.five_tuple,))


def _falsified_critique() -> Critique:
    return critique(
        _SIGNATURE, (_CITED, _NETFLIX), cited=(_CITED.five_tuple,)
    )


def _approval() -> Verdict:
    return Verdict(
        outcome="approved", reason="nothing contradicts it", objections=(), counterexamples=()
    )


def _veto() -> Verdict:
    return Verdict(
        outcome="falsified",
        reason="the name is not supported by one fingerprint",
        objections=("a JA4 alone is a generator, not an app",),
        counterexamples=(),
    )


class TestInstall:
    def test_an_approved_proposal_becomes_a_table_entry(self) -> None:
        table = install(SignatureTable(signatures=()), _approved_critique(), _approval())

        assert table.signatures == (_SIGNATURE,)
        assert table.identify(_features()).app == "GAP-CLIENT"

    def test_the_install_keeps_the_existing_table(self) -> None:
        existing = Signature(
            id="chrome-ja4", app="CHROME", all_of=(Predicate("ja4", "chrome-ja4"),)
        )
        table = SignatureTable(signatures=(existing,))

        after = install(table, _approved_critique(), _approval())

        assert table.signatures == (existing,), "the input table must not be mutated"
        assert after.signatures == (existing, _SIGNATURE)

    def test_a_contradicted_proposal_is_never_installed(self) -> None:
        """The deterministic floor holds even when the model says approve."""
        with pytest.raises(ValueError, match="falsified"):
            install(SignatureTable(signatures=()), _falsified_critique(), _approval())

    def test_the_critics_veto_is_enforced(self) -> None:
        with pytest.raises(ValueError, match="vetoed"):
            install(SignatureTable(signatures=()), _approved_critique(), _veto())

    def test_a_veto_names_the_reason_it_stopped_the_install(self) -> None:
        with pytest.raises(ValueError, match="not supported"):
            install(SignatureTable(signatures=()), _approved_critique(), _veto())

    def test_a_falsified_critique_names_the_first_contradiction(self) -> None:
        with pytest.raises(ValueError, match="NETFLIX"):
            install(SignatureTable(signatures=()), _falsified_critique(), _approval())

    def test_an_id_already_in_the_table_is_refused(self) -> None:
        existing = Signature(id="gap-01", app="OTHER", all_of=(Predicate("ja4", "ja4-z"),))

        with pytest.raises(ValueError, match="share the id"):
            install(SignatureTable(signatures=(existing,)), _approved_critique(), _approval())

    def test_an_identical_conjunction_under_another_id_is_refused(self) -> None:
        existing = Signature(id="gap-00", app="OTHER", all_of=(Predicate("ja4", "ja4-a"),))

        with pytest.raises(ValueError, match="same predicates"):
            install(SignatureTable(signatures=(existing,)), _approved_critique(), _approval())


# ---------------------------------------------------------------------------
# The proposal names the run that can check it
# ---------------------------------------------------------------------------


def _candidate(**overrides: Any) -> NewAppCandidate:
    base: dict[str, Any] = {
        "name": "GAP-CLIENT",
        "evidence": ("the cited flow shows this fingerprint",),
        "confidence": 0.55,
        "proposed_patterns": (Predicate("ja4", "ja4-a"),),
        "citations": (_CITED.five_tuple,),
    }
    base.update(overrides)
    return NewAppCandidate(**base)


class TestProposal:
    def test_a_proposal_names_the_run_and_the_signature(self) -> None:
        proposal = Proposal(run_id="run-1", signature_id="gap-01", candidate=_candidate())

        assert proposal.signature == _SIGNATURE
        assert proposal.run_id == "run-1"

    def test_a_proposal_is_json_ready(self) -> None:
        proposal = Proposal(run_id="run-1", signature_id="gap-01", candidate=_candidate())

        raw = json.loads(json.dumps(proposal.to_json()))

        assert raw["run_id"] == "run-1"
        assert raw["signature_id"] == "gap-01"
        assert raw["candidate"]["citations"] == [_json_tuple(_CITED)]

    def test_a_proposal_must_name_its_run(self) -> None:
        with pytest.raises(ValueError, match="run"):
            Proposal(run_id=" ", signature_id="gap-01", candidate=_candidate())

    def test_a_proposal_must_name_its_signature(self) -> None:
        with pytest.raises(ValueError, match="signature"):
            Proposal(run_id="run-1", signature_id="", candidate=_candidate())

    def test_a_proposal_holds_a_candidate(self) -> None:
        with pytest.raises(ValueError, match="candidate"):
            Proposal(run_id="run-1", signature_id="gap-01", candidate=object())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Reviewing a proposal against the run that produced it
# ---------------------------------------------------------------------------


GAP_PORT = 8443


def _gap_case() -> GoldenCase:
    """Two clients whose SNI names nothing, on a port nothing classifies."""
    return GoldenCase(
        name="critic_gap",
        golden_class=GoldenClass.C2_BEACONING,
        description="clients whose SNI names nothing, on a port nothing classifies",
        expected=(
            ExpectedFlow("", AppType.UNKNOWN, dst_port=GAP_PORT),
            ExpectedFlow("", AppType.UNKNOWN, dst_port=GAP_PORT),
        ),
    )


def _mixed_case() -> GoldenCase:
    """The same gap client, next to traffic the engine already classifies."""
    return GoldenCase(
        name="critic_mixed",
        golden_class=GoldenClass.C2_BEACONING,
        description="a nameless client beside a known app",
        expected=(
            ExpectedFlow("", AppType.UNKNOWN, dst_port=GAP_PORT),
            ExpectedFlow("netflix.com", AppType.NETFLIX),
        ),
    )


def _stored(tmp_path: Path, case: GoldenCase) -> tuple[RunStore, str, tuple[FlowRecord, ...]]:
    capture = write_case(tmp_path / "case.pcap", case)
    store_root = tmp_path / "store"
    run_id = store_a_run(capture, store_root)
    store = RunStore(store_root)
    return store, run_id, store.query(run_id)


def _candidate_for(
    flows: Sequence[FlowRecord], *, fields: tuple[str, ...]
) -> NewAppCandidate:
    """A proposal built from the run's unclassified, fingerprinted flows."""
    cited = tuple(
        flow
        for flow in flows
        if flow.app == AppType.UNKNOWN.name and flow.features.ja4
    )
    assert cited, "the corpus case produced no fingerprinted unknown flow"
    first = cited[0].features
    values: dict[str, Any] = {
        "ja4": first.ja4,
        "sni_present": first.sni_present,
        "client_version": first.client_version,
    }
    return NewAppCandidate(
        name="GAP-CLIENT",
        evidence=("the cited flows share this fingerprint",),
        confidence=0.55,
        proposed_patterns=tuple(Predicate(field, values[field]) for field in fields),
        citations=tuple(flow.five_tuple for flow in cited),
    )


class TestReviewAgainstARun:
    def test_review_resolves_the_citations_against_the_run(self, tmp_path: Path) -> None:
        store, run_id, flows = _stored(tmp_path, _gap_case())
        candidate = _candidate_for(flows, fields=("ja4", "sni_present", "client_version"))

        result = review(
            Proposal(run_id=run_id, signature_id="gap-01", candidate=candidate),
            store=store,
        )

        assert result.approved
        assert result.signature.all_of == candidate.proposed_patterns

    def test_a_citation_from_outside_the_run_is_refused(self, tmp_path: Path) -> None:
        """A proposal that cannot be cited is refused, not scored."""
        store, run_id, _flows = _stored(tmp_path, _gap_case())
        fabricated = _candidate(
            citations=(FiveTuple(167772161, 167772162, 59999, 443, 6),)
        )

        with pytest.raises(ValueError, match="cannot be cited"):
            review(
                Proposal(run_id=run_id, signature_id="gap-01", candidate=fabricated),
                store=store,
            )

    def test_a_citation_the_stored_flow_does_not_support_is_refused(
        self, tmp_path: Path
    ) -> None:
        store, run_id, flows = _stored(tmp_path, _gap_case())
        cited = _candidate_for(flows, fields=("ja4",)).citations
        forged = _candidate(
            proposed_patterns=(Predicate("ja4", "not-the-stored-fingerprint"),),
            citations=cited,
        )

        with pytest.raises(ValueError, match="does not match"):
            review(
                Proposal(run_id=run_id, signature_id="gap-01", candidate=forged),
                store=store,
            )

    def test_review_of_a_mixed_run_finds_the_known_app(self, tmp_path: Path) -> None:
        store, run_id, flows = _stored(tmp_path, _mixed_case())
        candidate = _candidate_for(flows, fields=("ja4",))

        result = review(
            Proposal(run_id=run_id, signature_id="gap-01", candidate=candidate),
            store=store,
        )

        assert not result.approved
        assert {c.label for c in result.contradictions} == {AppType.NETFLIX.name}


# ---------------------------------------------------------------------------
# The Critic's verdict: shaped by code, argued by the model
# ---------------------------------------------------------------------------


def _answer(**overrides: Any) -> str:
    base: dict[str, Any] = {
        "outcome": "approved",
        "reason": "nothing contradicts it",
        "objections": [],
        "counterexamples": [],
    }
    base.update(overrides)
    return json.dumps(base)


class TestParseCriticVerdict:
    def test_an_approval_of_a_clean_proposal(self) -> None:
        verdict = parse_critic_verdict(_answer(), critique=_approved_critique())

        assert verdict.outcome == "approved"
        assert verdict.reason == "nothing contradicts it"
        assert verdict.objections == ()

    def test_an_approval_of_a_contradicted_proposal_is_a_rubber_stamp(self) -> None:
        with pytest.raises(ValueError, match="rubber stamp"):
            parse_critic_verdict(_answer(), critique=_falsified_critique())

    def test_a_falsification_names_the_contradicting_flow(self) -> None:
        verdict = parse_critic_verdict(
            _answer(
                outcome="falsified",
                reason="it matches a flow the engine calls Netflix",
                objections=["one fingerprint is not an app"],
                counterexamples=[_json_tuple(_NETFLIX)],
            ),
            critique=_falsified_critique(),
        )

        assert verdict.outcome == "falsified"
        assert verdict.counterexamples == (_NETFLIX.five_tuple,)

    def test_a_falsification_of_a_contradicted_proposal_must_name_a_flow(self) -> None:
        with pytest.raises(ValueError, match="name at least one"):
            parse_critic_verdict(
                _answer(
                    outcome="falsified",
                    reason="too broad",
                    objections=["one fingerprint is not an app"],
                ),
                critique=_falsified_critique(),
            )

    def test_a_counterexample_must_be_one_of_the_contradictions(self) -> None:
        with pytest.raises(ValueError, match="not one of the contradictions"):
            parse_critic_verdict(
                _answer(
                    outcome="falsified",
                    reason="too broad",
                    objections=["one fingerprint is not an app"],
                    counterexamples=[_json_tuple(_OTHER_FINGERPRINT)],
                ),
                critique=_falsified_critique(),
            )

    def test_the_critic_may_veto_a_clean_proposal(self) -> None:
        """The model's judgement is not limited to the deterministic check."""
        verdict = parse_critic_verdict(
            _answer(
                outcome="falsified",
                reason="a JA4 alone names a generator, not an app",
                objections=["the evidence supports a TLS stack, not this app"],
            ),
            critique=_approved_critique(),
        )

        assert verdict.outcome == "falsified"
        assert verdict.counterexamples == ()

    def test_a_falsification_must_say_what_is_wrong(self) -> None:
        with pytest.raises(ValueError, match="say what is wrong"):
            parse_critic_verdict(
                _answer(outcome="falsified", reason="no"),
                critique=_approved_critique(),
            )

    def test_an_approval_cannot_carry_a_counterexample(self) -> None:
        with pytest.raises(ValueError, match="approval cannot name a counterexample"):
            parse_critic_verdict(
                _answer(counterexamples=[_json_tuple(_NETFLIX)]),
                critique=_approved_critique(),
            )

    @pytest.mark.parametrize(
        ("text", "reason"),
        [
            pytest.param("not json", "JSON", id="not-json"),
            pytest.param("[]", "object", id="not-an-object"),
        ],
    )
    def test_the_answer_must_be_a_json_object(self, text: str, reason: str) -> None:
        with pytest.raises(ValueError, match=reason):
            parse_critic_verdict(text, critique=_approved_critique())

    @pytest.mark.parametrize(
        ("overrides", "key"),
        [
            pytest.param({"outcome": "falsified", "objections": [], "counterexamples": []}, "outcome", id="outcome"),
            pytest.param({"reason": "x"}, "reason", id="reason"),
            pytest.param({"objections": []}, "objections", id="objections"),
            pytest.param({"counterexamples": []}, "counterexamples", id="counterexamples"),
        ],
    )
    def test_every_key_is_required(
        self, overrides: dict[str, Any], key: str
    ) -> None:
        raw = json.loads(_answer())
        del raw[key]

        with pytest.raises(ValueError, match=key):
            parse_critic_verdict(json.dumps(raw), critique=_approved_critique())

    def test_an_unknown_key_is_refused(self) -> None:
        raw = json.loads(_answer())
        raw["approve"] = True

        with pytest.raises(ValueError, match="approve"):
            parse_critic_verdict(json.dumps(raw), critique=_approved_critique())

    @pytest.mark.parametrize(
        ("overrides", "reason"),
        [
            pytest.param({"outcome": "maybe"}, "approved.*falsified", id="outcome"),
            pytest.param({"reason": "   "}, "reason", id="blank-reason"),
            pytest.param({"reason": 7}, "reason", id="typed-reason"),
            pytest.param({"objections": "no"}, "objections", id="objections-not-a-list"),
            pytest.param({"objections": ["  "]}, "objections", id="blank-objection"),
            pytest.param({"counterexamples": {}}, "counterexamples", id="counterexamples-not-a-list"),
        ],
    )
    def test_the_verdict_shape_is_strict(
        self, overrides: dict[str, Any], reason: str
    ) -> None:
        with pytest.raises(ValueError, match=reason):
            parse_critic_verdict(_answer(**overrides), critique=_approved_critique())

    def test_a_counterexample_must_be_a_five_tuple(self) -> None:
        with pytest.raises(ValueError, match="integer"):
            parse_critic_verdict(
                _answer(
                    outcome="falsified",
                    reason="too broad",
                    objections=["one fingerprint is not an app"],
                    counterexamples=[{"src_ip": "not-an-int"}],
                ),
                critique=_falsified_critique(),
            )

    def test_a_counterexample_must_be_an_object(self) -> None:
        with pytest.raises(ValueError, match="object"):
            parse_critic_verdict(
                _answer(
                    outcome="falsified",
                    reason="too broad",
                    objections=["one fingerprint is not an app"],
                    counterexamples=["not-a-flow"],
                ),
                critique=_falsified_critique(),
            )

    def test_a_counterexample_with_a_missing_field_is_refused(self) -> None:
        """The integer check is for values that are present; a missing one is still missing."""
        with pytest.raises(ValueError, match="missing"):
            parse_critic_verdict(
                _answer(
                    outcome="falsified",
                    reason="too broad",
                    objections=["one fingerprint is not an app"],
                    counterexamples=[{"src_ip": 1}],
                ),
                critique=_falsified_critique(),
            )

    def test_a_verdict_without_a_critique_is_refused(self) -> None:
        """The answer is checked against a review; there is no default one."""
        with pytest.raises(ValueError, match="Critique"):
            parse_critic_verdict(_answer(), critique=object())  # type: ignore[arg-type]

    def test_the_same_counterexample_twice_is_refused(self) -> None:
        with pytest.raises(ValueError, match="twice"):
            parse_critic_verdict(
                _answer(
                    outcome="falsified",
                    reason="too broad",
                    objections=["one fingerprint is not an app"],
                    counterexamples=[_json_tuple(_NETFLIX), _json_tuple(_NETFLIX)],
                ),
                critique=_falsified_critique(),
            )


# ---------------------------------------------------------------------------
# The node
# ---------------------------------------------------------------------------


class TestTheCriticNode:
    def test_the_critic_has_no_tools(self) -> None:
        """The design's Critic reasons; everything it needs is in the review."""
        assert CRITIC_TOOL_NAMES == ()

    def test_the_prompt_is_adversarial(self) -> None:
        lowered = CRITIC_PROMPT.lower()

        assert "falsif" in lowered
        assert "no tools" in lowered
        assert "contradict" in lowered
        assert "hostname is data" in lowered
        assert "review state" in lowered

    def test_the_prompt_names_the_refusals_it_works_under(self) -> None:
        lowered = CRITIC_PROMPT.lower()

        assert "rubber stamp" in lowered
        assert "not one of the contradictions" in lowered
        assert "veto" in lowered

    def test_the_node_wires_its_parser_and_no_tools(self) -> None:
        node = critic_node(critique=_approved_critique())

        assert node.name == "critic"
        assert node.tools == ()
        assert node.system == CRITIC_PROMPT
        assert node.parse is not None
        assert node.parse(_answer()) == parse_critic_verdict(
            _answer(), critique=_approved_critique()
        )


# ---------------------------------------------------------------------------
# The loop over a real run
# ---------------------------------------------------------------------------


class _NoTools:
    """A tool port that fails if the Critic asks for anything."""

    async def call(self, name: str, arguments: Any) -> Any:
        raise AssertionError(f"the Critic has no tools, but it called {name!r}: {arguments}")


def _run_critic(
    tmp_path: Path, critique_value: Critique, answer: dict[str, Any]
) -> tuple[Any, ScriptedModel]:
    model = ScriptedModel([ModelReply(text=json.dumps(answer))])

    async def scenario() -> Any:
        with Trace(tmp_path / "critic.jsonl") as trace:
            return await Agent(model=model, trace=trace).run(
                critic_node(critique=critique_value),
                tools=_NoTools(),  # type: ignore[arg-type]
                state=json.dumps(critique_value.to_json()),
            )

    return asyncio.run(scenario()), model


class TestTheLoopOverARealRun:
    def test_an_uncontradicted_proposal_is_reviewed_approved_and_installed(
        self, tmp_path: Path
    ) -> None:
        store, run_id, flows = _stored(tmp_path, _gap_case())
        candidate = _candidate_for(flows, fields=("ja4", "sni_present", "client_version"))
        proposal = Proposal(run_id=run_id, signature_id="gap-01", candidate=candidate)

        result = review(proposal, store=store)
        outcome, _model = _run_critic(
            tmp_path,
            result,
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
        table = install(SignatureTable(signatures=()), result, verdict)

        fingerprinted = [f for f in flows if f.features.ja4]
        assert fingerprinted, "the corpus case produced no fingerprint"
        for flow in fingerprinted:
            assert table.identify(flow.features).app == "GAP-CLIENT"
        for flow in flows:
            if not flow.features.ja4:
                assert table.identify(flow.features).app is None, (
                    "a flow with no fingerprint must not be identified"
                )

    def test_the_corpus_contradiction_falsifies_the_proposal(
        self, tmp_path: Path
    ) -> None:
        store, run_id, flows = _stored(tmp_path, _mixed_case())
        candidate = _candidate_for(flows, fields=("ja4",))
        proposal = Proposal(run_id=run_id, signature_id="gap-01", candidate=candidate)

        result = review(proposal, store=store)
        assert not result.approved
        contradiction = result.contradictions[0]
        outcome, model = _run_critic(
            tmp_path,
            result,
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

        with pytest.raises(ValueError, match="falsified"):
            install(SignatureTable(signatures=()), result, verdict)

        # The Critic saw the proposal and the contradiction, not a blank page.
        state = json.loads(model.requests[0].messages[0].content)
        assert state["signature"]["id"] == "gap-01"
        assert state["contradictions"][0]["label"] == AppType.NETFLIX.name

    def test_a_rubber_stamp_is_an_invalid_verdict(self, tmp_path: Path) -> None:
        store, run_id, flows = _stored(tmp_path, _mixed_case())
        candidate = _candidate_for(flows, fields=("ja4",))
        result = review(
            Proposal(run_id=run_id, signature_id="gap-01", candidate=candidate),
            store=store,
        )

        outcome, _model = _run_critic(
            tmp_path,
            result,
            {
                "outcome": "approved",
                "reason": "looks fine",
                "objections": [],
                "counterexamples": [],
            },
        )

        assert outcome.verdict is None
        assert outcome.reason == "invalid verdict"
        assert outcome.error is not None and "rubber stamp" in outcome.error

    def test_the_critics_veto_blocks_a_clean_install(self, tmp_path: Path) -> None:
        store, run_id, flows = _stored(tmp_path, _gap_case())
        candidate = _candidate_for(flows, fields=("ja4",))
        result = review(
            Proposal(run_id=run_id, signature_id="gap-01", candidate=candidate),
            store=store,
        )
        assert result.approved

        outcome, _model = _run_critic(
            tmp_path,
            result,
            {
                "outcome": "falsified",
                "reason": "a JA4 names a TLS stack, not an application",
                "objections": ["the evidence does not support a name"],
                "counterexamples": [],
            },
        )

        assert outcome.reason == "verdict", outcome.error
        verdict = outcome.verdict
        assert isinstance(verdict, Verdict)
        with pytest.raises(ValueError, match="vetoed"):
            install(SignatureTable(signatures=()), result, verdict)
