"""`T5-05`: the classifier gap — an unknown app, a proposed signature, its evidence.

**The gap is where a classifier stops and a hypothesis starts.** Triage can say
"this flow is UNKNOWN", and `T5-04`'s table can say "no signature claims it", and
between them there is no answer. This task builds the answer in the only shape
that survives review: the agent **names** the app and **selects** the facts, and
the engine **checks** that every fact it selected is one the flows it cited
actually share. A model cannot invent a fingerprint, because the verifier
recomputes the conjunction from the cited flows and refuses anything else.

So the file has three layers, and each one bites on its own:

* **`common_predicates`** — the engine's deterministic half. Two flows support a
  fact only if both show it, and a list fact only if both list it. Order is
  pinned, because a signature is compared and diffed, not just matched.
* **`NewAppCandidate` / `parse_new_app_candidate`** — the claim. Its shape is
  strict, it must cite at least one flow, and every pattern must already be in
  the cited flows' conjunction. `to_signature` is what makes "proposed signature"
  literal: the candidate becomes a table entry that identifies the flows it came
  from.
* **The node** — the ReAct loop over a real MCP server, with `query_flows` as its
  only tool. No web search, no ASN lookup and no `get_fingerprints`: this build
  has none of them, and the prompt says so rather than letting a model read the
  absence as a clean signal.

The integration tests use the corpus's own `build_client_hello`, so the flows the
agent reasons about are bytes the engine parsed, not fixtures this file shaped.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from agent_harness import connected, store_a_run, tool_schemas
from dpi_agents.model import ModelReply, ScriptedModel, ToolCall
from dpi_agents.nodes.classifier_gap import (
    CLASSIFIER_GAP_PROMPT,
    CLASSIFIER_GAP_TOOL_NAMES,
    PREDICATE_HELP,
    classifier_gap_node,
)
from dpi_agents.runtime import Agent
from dpi_agents.schemas import NewAppCandidate, parse_new_app_candidate
from dpi_agents.tools import McpToolPort
from dpi_agents.trace import Trace
from dpi_engine.flow_features import FlowFeatures
from dpi_engine.proposals import common_predicates
from dpi_engine.run_store import FlowFilter, RunStore
from dpi_engine.signatures import (
    LIST_FIELDS,
    SCALAR_FIELDS,
    Predicate,
    Signature,
    SignatureTable,
)
from dpi_engine.types import AppType, FiveTuple, FlowRecord
from golden.corpus import ExpectedFlow, GoldenCase, GoldenClass, write_case

#: A port the engine does not classify by number, so a ClientHello whose SNI
#: extension carries no name stays `UNKNOWN` instead of being guessed `HTTPS`.
#: `sni_to_app_type` maps an unrecognised *non-empty* SNI to `HTTPS` by design,
#: so a genuine TLS gap is a client that offers a fingerprint and no hostname --
#: the extension is present (`sni_present` is `True`), but it names nothing.
GAP_PORT = 8443

#: The Chrome JA4 that `T5-04`'s table already claims. A proposal that uses it
#: for a synthetic client is the overreach the verifier exists to refuse.
FOREIGN_JA4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"


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
    src_port: int = 41000,
    app: str = AppType.UNKNOWN.name,
) -> FlowRecord:
    return FlowRecord(
        src_ip=167772161,
        dst_ip=167772162,
        src_port=src_port,
        dst_port=443,
        protocol=6,
        app=app,
        state="ESTABLISHED",
        hostname="c2.gap.example",
        features=features,
    )


_FLOW_A = _flow(_features(), src_port=41000)
_FLOW_B = _flow(_features(), src_port=41002)
_FLOWS = (_FLOW_A, _FLOW_B)


def _cite(flow: FlowRecord) -> dict[str, int]:
    """A flow's five-tuple, in the wire shape a citation takes."""
    return {
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
    }


def _candidate(**overrides: Any) -> dict[str, Any]:
    """A proposal that the two fixture flows genuinely support."""
    base: dict[str, Any] = {
        "name": "SYNTHETIC-CLIENT",
        "evidence": ["both flows offered the same ClientHello"],
        "confidence": 0.6,
        "proposed_patterns": [
            {"field": "ja4", "value": "ja4-a"},
            {"field": "sni_present", "value": True},
        ],
        "citations": [_cite(_FLOW_A), _cite(_FLOW_B)],
    }
    base.update(overrides)
    return base


def _parse(payload: dict[str, Any], *, flows: Sequence[FlowRecord] = _FLOWS) -> NewAppCandidate:
    return parse_new_app_candidate(json.dumps(payload), flows=flows)


# ---------------------------------------------------------------------------
# The engine's half: what a set of unknown flows supports in common
# ---------------------------------------------------------------------------


class TestCommonPredicates:
    def test_two_identical_flows_support_their_whole_observation(self) -> None:
        """The order is part of the answer: a signature is diffed, not just matched."""
        assert common_predicates(_FLOWS) == (
            Predicate("ja3", "ja3-a"),
            Predicate("ja4", "ja4-a"),
            Predicate("sni_present", True),
            Predicate("client_version", 771),
            Predicate("cipher_suites", 4865),
            Predicate("extensions", 0),
            Predicate("alpn", "h2"),
        )

    def test_a_scalar_the_flows_disagree_on_is_not_proposed(self) -> None:
        other = _flow(_features(client_version=772), src_port=41002)

        fields = [predicate.field for predicate in common_predicates((_FLOW_A, other))]

        assert "client_version" not in fields
        # A disagreement in one field does not silence the rest.
        assert "ja4" in fields

    def test_a_list_element_only_one_flow_offers_is_not_proposed(self) -> None:
        other = _flow(_features(alpn=("http/1.1",)), src_port=41002)

        proposed = common_predicates((_FLOW_A, other))

        assert Predicate("alpn", "http/1.1") not in proposed
        assert all(predicate.field != "alpn" for predicate in proposed), (
            "the intersection of ('h2',) and ('http/1.1',) is empty, so ALPN says nothing"
        )
        assert Predicate("cipher_suites", 4865) in proposed

    def test_a_list_element_both_flows_offer_is_proposed_in_wire_order(self) -> None:
        first = _flow(_features(cipher_suites=(4866, 4865, 4867)), src_port=41000)
        second = _flow(_features(cipher_suites=(4867, 4866, 4865)), src_port=41002)

        proposed = common_predicates((first, second))

        assert [p for p in proposed if p.field == "cipher_suites"] == [
            Predicate("cipher_suites", 4865),
            Predicate("cipher_suites", 4866),
            Predicate("cipher_suites", 4867),
        ], "list facts are ordered by value, so the same flows produce the same signature"

    def test_an_absence_is_not_a_fact(self) -> None:
        """`\"\"`/`None` are what an unobserved field reads as; a pattern on one is a trap."""
        observed = common_predicates(_FLOWS)

        fields = {predicate.field for predicate in observed}
        for field in ("ja3s", "ja4s", "selected_alpn", "http2_settings"):
            assert field not in fields, f"{field} was never observed but was proposed"
        assert "certificate.issuer" not in fields
        assert "certificate.subject" not in fields

    def test_no_sni_is_a_fact_rather_than_an_absence(self) -> None:
        """`sni_present: false` is something the client did, and it identifies."""
        quiet = _flow(_features(sni_present=False, ja3="", ja4="", client_version=None,
                                cipher_suites=(), extensions=(), alpn=()),
                      src_port=41000)
        twin = _flow(_features(sni_present=False, ja3="", ja4="", client_version=None,
                               cipher_suites=(), extensions=(), alpn=()),
                     src_port=41002)

        assert common_predicates((quiet, twin)) == (Predicate("sni_present", False),)

    def test_a_flow_that_showed_nothing_supports_nothing(self) -> None:
        assert common_predicates((_flow(FlowFeatures()), _flow(FlowFeatures(), src_port=41002))) == ()

    def test_one_unobserved_flow_erases_a_fact_the_others_share(self) -> None:
        assert common_predicates((_FLOW_A, _flow(FlowFeatures(), src_port=41002))) == (), (
            "a fact has to be shown by every flow; one silent flow makes the claim unproven"
        )

    def test_no_flows_is_refused_rather_than_answered_vacuously(self) -> None:
        with pytest.raises(ValueError, match="at least one flow"):
            common_predicates(())

    def test_a_known_app_is_not_part_of_the_gap(self) -> None:
        known = _flow(_features(), src_port=41002, app=AppType.GOOGLE.name)

        with pytest.raises(ValueError, match="not UNKNOWN"):
            common_predicates((_FLOW_A, known))

    def test_the_conjunction_matches_every_flow_it_came_from(self) -> None:
        """The property the whole task rests on, asserted rather than assumed."""
        flows = (
            _FLOW_A,
            _flow(_features(cipher_suites=(4865, 4866), alpn=("h2", "http/1.1")), src_port=41002),
        )
        signature = SignatureTable(
            signatures=(
                # A table entry needs a name; the name is the model's job, not this
                # function's, so the test supplies one.
                Signature(id="derived", app="GAP", all_of=common_predicates(flows)),
            )
        )

        for flow in flows:
            assert signature.identify(flow.features).app == "GAP"

    def test_the_derivation_does_not_depend_on_flow_order(self) -> None:
        first = _flow(_features(cipher_suites=(4865, 4866)), src_port=41000)
        second = _flow(_features(cipher_suites=(4866, 4865)), src_port=41002)

        assert common_predicates((first, second)) == common_predicates((second, first))


# ---------------------------------------------------------------------------
# The claim: shape, citations, and the support it has to earn
# ---------------------------------------------------------------------------


class TestTheCandidate:
    def test_a_supported_candidate_is_accepted(self) -> None:
        candidate = _parse(_candidate())

        assert candidate.name == "SYNTHETIC-CLIENT"
        assert candidate.evidence == ("both flows offered the same ClientHello",)
        assert candidate.confidence == 0.6
        assert candidate.proposed_patterns == (
            Predicate("ja4", "ja4-a"),
            Predicate("sni_present", True),
        )
        assert candidate.citations == (_FLOW_A.five_tuple, _FLOW_B.five_tuple)

    def test_the_wire_format_round_trips_through_the_parser(self) -> None:
        candidate = _parse(_candidate())

        again = parse_new_app_candidate(json.dumps(candidate.to_json()), flows=_FLOWS)

        assert again == candidate

    def test_the_wire_format_flattens_a_citation_like_a_row(self) -> None:
        """A citation is a five-tuple, so a `query_flows` row can be cited as it came."""
        payload = _candidate(citations=[{**_cite(_FLOW_A), "app": "UNKNOWN", "hostname": "x"}])

        candidate = _parse(payload)

        assert candidate.citations == (_FLOW_A.five_tuple,)
        assert candidate.to_json()["citations"] == [_cite(_FLOW_A)]

    def test_the_candidate_becomes_a_signature_that_identifies_its_flows(self) -> None:
        """The gate, made literal: propose a signature, then use it as one."""
        candidate = _parse(_candidate())

        signature = candidate.to_signature("gap-01")
        table = SignatureTable(signatures=(signature,))

        assert signature.app == candidate.name
        assert signature.all_of == candidate.proposed_patterns, (
            "the signature must carry every pattern the proposal argued for, not a prefix"
        )
        for flow in _FLOWS:
            assert table.identify(flow.features).app == "SYNTHETIC-CLIENT"

    def test_a_pattern_the_cited_flows_do_not_support_is_refused(self) -> None:
        payload = _candidate(
            proposed_patterns=[{"field": "ja4", "value": FOREIGN_JA4}]
        )

        with pytest.raises(ValueError, match="not supported"):
            _parse(payload)

    def test_a_pattern_that_holds_on_one_cited_flow_but_not_the_other_is_refused(self) -> None:
        other = _flow(_features(client_version=772), src_port=41002)
        payload = _candidate(
            proposed_patterns=[{"field": "client_version", "value": 771}],
            citations=[_cite(_FLOW_A), _cite(other)],
        )

        with pytest.raises(ValueError, match="not supported"):
            _parse(payload, flows=(_FLOW_A, other))

    def test_a_pattern_from_an_uncited_flow_is_refused(self) -> None:
        other = _flow(_features(ja4="ja4-b"), src_port=41002)
        payload = _candidate(
            proposed_patterns=[{"field": "ja4", "value": "ja4-b"}],
            citations=[_cite(_FLOW_A)],
        )

        with pytest.raises(ValueError, match="not supported"):
            _parse(payload, flows=(_FLOW_A, other))

    def test_a_citation_the_proposal_was_not_given_is_refused(self) -> None:
        fabricated = FiveTuple(src_ip=1, dst_ip=2, src_port=3, dst_port=4, protocol=6)
        payload = _candidate(
            citations=[
                {"src_ip": fabricated.src_ip, "dst_ip": fabricated.dst_ip,
                 "src_port": fabricated.src_port, "dst_port": fabricated.dst_port,
                 "protocol": fabricated.protocol}
            ]
        )

        with pytest.raises(ValueError, match="not one of the flows"):
            _parse(payload)

    def test_a_supplied_known_flow_is_refused_even_when_it_is_not_cited(self) -> None:
        known = _flow(_features(), src_port=41002, app=AppType.GOOGLE.name)

        with pytest.raises(ValueError, match="UNKNOWN"):
            _parse(_candidate(), flows=(_FLOW_A, known))

    def test_a_proposal_with_no_flows_to_be_checked_against_is_refused(self) -> None:
        with pytest.raises(ValueError, match="none were supplied"):
            _parse(_candidate(), flows=())

    @pytest.mark.parametrize(
        ("overrides", "reason"),
        [
            pytest.param({"citations": []}, "cites no flow", id="no-citation"),
            pytest.param(
                {"citations": [_cite(_FLOW_A), _cite(_FLOW_A)]}, "twice", id="duplicate-citation"
            ),
            pytest.param({"proposed_patterns": []}, "empty conjunction", id="no-pattern"),
            pytest.param(
                {
                    "proposed_patterns": [
                        {"field": "ja4", "value": "ja4-a"},
                        {"field": "ja4", "value": "ja4-a"},
                    ]
                },
                "twice",
                id="duplicate-pattern",
            ),
            pytest.param({"name": ""}, "name", id="empty-name"),
            pytest.param({"name": "   "}, "name", id="blank-name"),
            pytest.param({"evidence": []}, "evidence", id="no-evidence"),
            pytest.param({"evidence": ["  "]}, "evidence", id="blank-evidence"),
            pytest.param({"confidence": -0.1}, "confidence", id="negative-confidence"),
            pytest.param({"confidence": 1.1}, "confidence", id="overconfident"),
        ],
    )
    def test_a_claim_that_cannot_be_checked_is_refused(
        self, overrides: dict[str, Any], reason: str
    ) -> None:
        with pytest.raises(ValueError, match=reason):
            _parse(_candidate(**overrides))

    @pytest.mark.parametrize("key", ["name", "evidence", "confidence", "proposed_patterns", "citations"])
    def test_a_missing_key_is_refused_rather_than_defaulted(self, key: str) -> None:
        payload = _candidate()
        del payload[key]

        with pytest.raises(ValueError, match=key):
            _parse(payload)

    @pytest.mark.parametrize(
        ("overrides", "reason"),
        [
            pytest.param({"name": 7}, "name", id="name-is-not-text"),
            pytest.param({"evidence": "because"}, "evidence", id="evidence-is-not-a-list"),
            pytest.param({"evidence": [7]}, "evidence", id="evidence-item-is-not-text"),
            pytest.param({"confidence": "0.5"}, "confidence", id="confidence-is-text"),
            pytest.param({"confidence": True}, "confidence", id="confidence-is-a-bool"),
            pytest.param({"proposed_patterns": {}}, "must be a list", id="patterns-not-a-list"),
            pytest.param(
                {"proposed_patterns": ["ja4"]}, "must be an object", id="pattern-not-an-object"
            ),
            pytest.param(
                {"proposed_patterns": [{"field": "ja4"}]}, "value", id="pattern-has-no-value"
            ),
            pytest.param(
                {"proposed_patterns": [{"field": "nonsense", "value": 1}]},
                "not a feature",
                id="pattern-field-unknown",
            ),
            pytest.param(
                {"proposed_patterns": [{"field": "ja4", "value": None}]},
                "null",
                id="pattern-value-null",
            ),
            pytest.param({"citations": {}}, "citations", id="citations-not-a-list"),
            pytest.param({"citations": [7]}, "must be an object", id="citation-not-an-object"),
            pytest.param(
                {"citations": [{"src_ip": 1}]}, "missing", id="citation-incomplete"
            ),
            pytest.param(
                {
                    "citations": [
                        {"src_ip": "x", "dst_ip": 2, "src_port": 3, "dst_port": 4, "protocol": 6}
                    ]
                },
                "integer",
                id="citation-field-not-an-integer",
            ),
            pytest.param({"app": "GOOGLE"}, "unknown key", id="unknown-key"),
        ],
    )
    def test_a_malformed_claim_is_refused(self, overrides: dict[str, Any], reason: str) -> None:
        with pytest.raises(ValueError, match=reason):
            _parse(_candidate(**overrides))

    @pytest.mark.parametrize(
        ("text", "reason"),
        [
            pytest.param("not json", "JSON", id="not-json"),
            pytest.param("[]", "object", id="not-an-object"),
        ],
    )
    def test_the_answer_must_be_a_json_object(self, text: str, reason: str) -> None:
        with pytest.raises(ValueError, match=reason):
            parse_new_app_candidate(text, flows=_FLOWS)

    def test_a_candidate_is_immutable(self) -> None:
        candidate = _parse(_candidate())

        with pytest.raises(AttributeError):
            candidate.name = "OTHER"  # type: ignore[misc]

    def test_the_candidate_validates_itself_when_built_in_memory(self) -> None:
        """`T5-04`'s lesson: an invariant enforced only by the parser is not one."""
        pattern = Predicate("ja4", "ja4-a")

        with pytest.raises(ValueError, match="evidence"):
            NewAppCandidate(
                name="X", evidence=(), confidence=0.5,
                proposed_patterns=(pattern,), citations=(_FLOW_A.five_tuple,),
            )

        with pytest.raises(ValueError, match="evidence"):
            NewAppCandidate(
                name="X", evidence=("",), confidence=0.5,
                proposed_patterns=(pattern,), citations=(_FLOW_A.five_tuple,),
            )

        with pytest.raises(ValueError, match="confidence"):
            NewAppCandidate(
                name="X", evidence=("why",), confidence=2.0,
                proposed_patterns=(pattern,), citations=(_FLOW_A.five_tuple,),
            )

        with pytest.raises(ValueError, match="confidence"):
            NewAppCandidate(
                name="X", evidence=("why",), confidence=float("nan"),
                proposed_patterns=(pattern,), citations=(_FLOW_A.five_tuple,),
            )

        with pytest.raises(ValueError, match="name"):
            NewAppCandidate(
                name=7, evidence=("why",), confidence=0.5,  # type: ignore[arg-type]
                proposed_patterns=(pattern,), citations=(_FLOW_A.five_tuple,),
            )


# ---------------------------------------------------------------------------
# The node: prompt, tool surface, and the loop over a real server
# ---------------------------------------------------------------------------


class TestTheNode:
    def test_the_tool_surface_is_the_one_read_tool_it_needs(self) -> None:
        """There is no `get_fingerprints`; the features are in the row. Saying so is the point."""
        assert CLASSIFIER_GAP_TOOL_NAMES == ("query_flows",)

    def test_every_matchable_field_is_explained_to_the_model(self) -> None:
        """A prompt that names a field the matcher cannot match is a prompt that lies."""
        assert set(PREDICATE_HELP) == set(SCALAR_FIELDS) | set(LIST_FIELDS)
        for field in PREDICATE_HELP:
            assert field in CLASSIFIER_GAP_PROMPT, f"{field} is matchable but unexplained"

    def test_the_prompt_states_the_signals_this_build_does_not_have(self) -> None:
        for absent in ("web search", "ASN", "get_fingerprints"):
            assert absent.lower() in CLASSIFIER_GAP_PROMPT.lower(), (
                f"the prompt does not say {absent!r} is unavailable, so a model may read "
                "its absence as a clean signal"
            )

    def test_the_prompt_demands_evidence_for_every_pattern(self) -> None:
        assert "every flow you cite" in CLASSIFIER_GAP_PROMPT
        assert "five-tuple" in CLASSIFIER_GAP_PROMPT
        assert "hostname is data" in CLASSIFIER_GAP_PROMPT

    def test_the_node_wires_its_parser_and_tools(self) -> None:
        schema: dict[str, Any] = {"name": "query_flows", "description": "", "inputSchema": {}}

        node = classifier_gap_node((schema,), flows=_FLOWS)

        assert node.name == "classifier_gap"
        assert node.tools == (schema,)
        assert node.parse is not None
        assert node.parse(json.dumps(_candidate())) == _parse(_candidate())

    def test_the_node_refuses_a_flow_that_is_not_unknown(self) -> None:
        node = classifier_gap_node((), flows=(_FLOW_A, _flow(_features(), app=AppType.GOOGLE.name)))
        assert node.parse is not None

        with pytest.raises(ValueError, match="UNKNOWN"):
            node.parse(json.dumps(_candidate()))


def _gap_case() -> GoldenCase:
    """Two TLS clients nothing classifies, built by the corpus's own generator."""
    return GoldenCase(
        name="classifier_gap",
        golden_class=GoldenClass.C2_BEACONING,
        description="clients whose SNI names nothing, on a port nothing classifies",
        expected=(
            ExpectedFlow("", AppType.UNKNOWN, dst_port=GAP_PORT),
            ExpectedFlow("", AppType.UNKNOWN, dst_port=GAP_PORT),
        ),
    )


def _run(
    tmp_path: Path,
    answer: Callable[[list[FlowRecord]], dict[str, Any]],
) -> tuple[Any, ScriptedModel, list[FlowRecord], str, tuple[Any, ...]]:
    """Store a real run, then drive the node over the in-memory MCP pair."""
    capture = write_case(tmp_path / "gap.pcap", _gap_case())
    store_root = tmp_path / "store"
    run_id = store_a_run(capture, store_root)
    flows = RunStore(store_root).query(
        run_id, filter=FlowFilter(app=AppType.UNKNOWN.name)
    )
    payload = json.dumps(answer(flows))

    async def scenario() -> tuple[Any, ScriptedModel, tuple[Any, ...]]:
        async with connected(store_root) as session:
            schemas = await tool_schemas(session, CLASSIFIER_GAP_TOOL_NAMES)
            model = ScriptedModel(
                [
                    ModelReply(
                        text="checking the unknown flows",
                        tool_calls=(
                            ToolCall(
                                name="query_flows",
                                arguments={"run_id": run_id, "app": "UNKNOWN"},
                            ),
                        ),
                    ),
                    ModelReply(text=payload),
                ]
            )
            with Trace(tmp_path / "trace.jsonl") as trace:
                outcome = await Agent(model=model, trace=trace).run(
                    classifier_gap_node(schemas, flows=flows), tools=McpToolPort(session)
                )
        return outcome, model, schemas

    outcome, model, schemas = asyncio.run(scenario())
    return outcome, model, flows, run_id, schemas


def _fingerprinted(flows: Sequence[FlowRecord]) -> list[FlowRecord]:
    """The flows that actually showed a ClientHello, in a stable order."""
    return [flow for flow in flows if flow.features.ja4]


def _proposal(flows: list[FlowRecord]) -> dict[str, Any]:
    clients = _fingerprinted(flows)
    return {
        "name": "GAP-TLS-CLIENT",
        "evidence": ["both flows offered one ClientHello with the same JA4"],
        "confidence": 0.55,
        "proposed_patterns": [
            {"field": "ja4", "value": clients[0].features.ja4},
            {"field": "sni_present", "value": True},
            {"field": "client_version", "value": clients[0].features.client_version},
        ],
        "citations": [_cite(client) for client in clients],
    }


class TestTheAgentOverARealRun:
    def test_it_proposes_a_signature_for_the_unknown_flows(self, tmp_path: Path) -> None:
        outcome, _model, flows, run_id, schemas = _run(tmp_path, _proposal)

        assert len(schemas) == 1, "the server did not declare query_flows"
        assert outcome.reason == "verdict", outcome.error
        candidate = outcome.verdict
        assert isinstance(candidate, NewAppCandidate)
        assert candidate.name == "GAP-TLS-CLIENT"
        assert candidate.confidence == 0.55

        # The proposal names the run's own flows: a citation the run cannot match
        # would make the evidence unciteable.
        stored = RunStore(tmp_path / "store").query(run_id)
        assert set(candidate.citations) <= {flow.five_tuple for flow in stored}
        assert len(candidate.citations) == 2

        # And it is a signature: it identifies every flow it came from.
        signature = candidate.to_signature("gap-01")
        cited = [flow for flow in flows if flow.five_tuple in candidate.citations]
        assert len(cited) == 2
        for flow in cited:
            assert signature.matches(flow.features), (
                f"the proposal does not match {flow.five_tuple}, a flow it cites"
            )

    def test_the_model_is_told_the_flows_are_data(self, tmp_path: Path) -> None:
        _outcome, model, _flows, _run_id, _schemas = _run(tmp_path, _proposal)

        observation = model.requests[1].messages[0]
        assert observation.role == "tool"
        assert observation.content.startswith("<untrusted_capture_data>")

    def test_a_proposal_the_flows_do_not_support_is_an_invalid_verdict(
        self, tmp_path: Path
    ) -> None:
        def overreach(flows: list[FlowRecord]) -> dict[str, Any]:
            return _proposal(flows) | {
                "proposed_patterns": [{"field": "ja4", "value": FOREIGN_JA4}]
            }

        outcome, _model, _flows, _run_id, _schemas = _run(tmp_path, overreach)

        assert outcome.reason == "invalid verdict"
        assert outcome.verdict is None
        assert outcome.error is not None and "not supported" in outcome.error

    def test_a_citation_the_run_does_not_have_is_an_invalid_verdict(
        self, tmp_path: Path
    ) -> None:
        def fabricated(flows: list[FlowRecord]) -> dict[str, Any]:
            return _proposal(flows) | {
                "citations": [
                    {"src_ip": 1, "dst_ip": 2, "src_port": 3, "dst_port": 4, "protocol": 6}
                ]
            }

        outcome, _model, _flows, _run_id, _schemas = _run(tmp_path, fabricated)

        assert outcome.reason == "invalid verdict"
        assert outcome.error is not None and "not one of the flows" in outcome.error
