"""`T6-03`: the Policy agent — read-only, simulation-only, and no write tool.

**The first agent whose answer is a rule.** Every node before this one answers
with a verdict *about* a run. This one answers with a *change to the policy*,
and that difference is the whole of Phase 6's risk. So the file is organised
around what the agent cannot do:

* **It cannot write.** Its surface is `query_flows` and `simulate_ruleset`, the
  simulation writes two scratch pcaps and nothing else, and the module has no
  path to `RuleStore`.
* **It cannot choose its own provenance, versions or parent.** The draft parser
  accepts exactly four keys; provenance, the three versions and the parent are
  the agent's, because a model that can name its own author can launder a
  change.
* **It cannot cite a flow the run does not hold.** The draft names flows by
  five-tuple; `Proposal.build` resolves each one against the store before a
  proposal exists, so a fabricated citation is refused rather than queued.
* **It cannot hand back a plausible-looking change.** The answer is built by
  `Proposal.build`, never constructed directly, so the document is the engine's
  canonical form and both ids are the engine's arithmetic.

The last layer runs the node over the real MCP pair and a real capture: the
tool call, the dry run and the citation are exercised, not described.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
from pathlib import Path
from typing import Any

import pytest

from agent_harness import connected, store_a_run, tool_schemas
from conftest import TEST_DPI_PCAP
from dpi_agents.model import ModelReply, ScriptedModel, ToolCall
from dpi_agents.nodes import policy as policy_module
from dpi_agents.nodes.policy import (
    AGENT_VERSION,
    POLICY_PROMPT,
    POLICY_PROMPT_VERSION,
    POLICY_TOOL_NAMES,
    StoreResolver,
    policy_node,
    policy_system,
)
from dpi_agents.runtime import Agent
from dpi_agents.schemas import PolicyDraft, parse_policy_draft
from dpi_agents.tools import McpToolPort
from dpi_agents.trace import Trace
from dpi_engine.proposal import Citation, Proposal, ProposalError
from dpi_engine.rule_store import PolicyKind, version_id_for
from dpi_engine.run_store import RunStore
from dpi_engine.types import FiveTuple, FlowRecord

RUN_ID = "0123456789abcdef"
MODEL_VERSION = "scripted/1"

_FLOW = FiveTuple(src_ip=10, dst_ip=20, src_port=30, dst_port=40, protocol=6)
_OTHER = FiveTuple(src_ip=10, dst_ip=20, src_port=31, dst_port=40, protocol=6)


def _flow(five_tuple: FiveTuple = _FLOW, app: str = "TIKTOK") -> FlowRecord:
    return FlowRecord(
        src_ip=five_tuple.src_ip,
        dst_ip=five_tuple.dst_ip,
        src_port=five_tuple.src_port,
        dst_port=five_tuple.dst_port,
        protocol=five_tuple.protocol,
        app=app,
        state="CLASSIFIED",
        hostname="www.tiktok.com",
        packets=1,
        bytes=100,
    )


def _payload(**overrides: Any) -> dict[str, Any]:
    """A draft the fixture flow genuinely supports."""
    base: dict[str, Any] = {
        "kind": "ruleset",
        "document": {"blocked_apps": ["TIKTOK"]},
        "note": "TikTok is the only app this run shows that the policy allows.",
        "citations": [dict(_FLOW._asdict())],
    }
    base.update(overrides)
    return base


def _parse(payload: dict[str, Any]) -> PolicyDraft:
    return parse_policy_draft(json.dumps(payload))


class FakeResolver:
    """The `CitationResolver` port, backed by one in-memory run."""

    def __init__(self, *flows: FlowRecord, run_id: str = RUN_ID) -> None:
        self.run_id = run_id
        self.by_flow = {flow.five_tuple: flow for flow in flows}

    def resolve(self, cited: Citation) -> FlowRecord | None:
        if cited.run_id != self.run_id:
            return None
        return self.by_flow.get(cited.five_tuple)


def _node(*, resolver: Any = None, parent: str | None = None) -> Any:
    return policy_node(
        (),
        run_id=RUN_ID,
        capture=Path("capture.pcap"),
        simulation_dir=Path("policy-scratch"),
        resolver=FakeResolver(_flow()) if resolver is None else resolver,
        model_version=MODEL_VERSION,
        parent=parent,
    )


def _build(node: Any, payload: dict[str, Any]) -> Proposal:
    assert node.parse is not None
    proposal = node.parse(json.dumps(payload))
    assert isinstance(proposal, Proposal)
    return proposal


# ---------------------------------------------------------------------------
# The draft: exactly four keys, every one of them checked
# ---------------------------------------------------------------------------


class TestTheDraft:
    def test_a_well_formed_draft_parses(self) -> None:
        draft = _parse(_payload())

        assert draft.kind is PolicyKind.RULESET
        assert draft.document == {"blocked_apps": ["TIKTOK"]}
        assert draft.note.startswith("TikTok")
        assert draft.citations == (_FLOW,)

    def test_both_policy_kinds_are_accepted(self) -> None:
        assert _parse(_payload(kind="signatures")).kind is PolicyKind.SIGNATURES

    def test_an_unknown_kind_is_refused_with_the_vocabulary(self) -> None:
        with pytest.raises(ValueError, match="unknown policy kind"):
            _parse(_payload(kind="firewall"))

    def test_not_json_is_refused(self) -> None:
        with pytest.raises(ValueError, match="must be JSON"):
            parse_policy_draft("not json")

    def test_a_non_object_is_refused(self) -> None:
        with pytest.raises(ValueError, match="must be a JSON object"):
            parse_policy_draft("[]")

    def test_an_unknown_key_is_refused(self) -> None:
        with pytest.raises(ValueError, match="unknown key 'rationale'"):
            _parse(_payload(rationale="because"))

    @pytest.mark.parametrize(
        "key",
        [
            "provenance",
            "agent_version",
            "prompt_version",
            "model_version",
            "parent",
        ],
    )
    def test_the_model_cannot_choose_provenance_versions_or_parent(
        self, key: str
    ) -> None:
        """These are the agent's, not the model's: a model that names its own author can launder a change."""
        with pytest.raises(ValueError, match="unknown key"):
            _parse(_payload(**{key: "chosen-by-the-model"}))

    def test_a_missing_key_is_refused(self) -> None:
        payload = _payload()
        del payload["citations"]

        with pytest.raises(ValueError, match="missing the 'citations' key"):
            _parse(payload)

    def test_a_document_that_is_not_an_object_is_refused(self) -> None:
        with pytest.raises(ValueError, match="document must be an object"):
            _parse(_payload(document=[]))

    def test_a_blank_note_is_refused(self) -> None:
        """A policy change with no stated reason is a diff, not a proposal."""
        with pytest.raises(ValueError, match="must say why"):
            _parse(_payload(note="   "))

    def test_no_citation_is_refused(self) -> None:
        with pytest.raises(ValueError, match="cite at least one flow"):
            _parse(_payload(citations=[]))

    def test_a_duplicate_citation_is_refused(self) -> None:
        with pytest.raises(ValueError, match="same flow twice"):
            _parse(_payload(citations=[dict(_FLOW._asdict())] * 2))

    def test_a_citation_that_is_not_a_five_tuple_is_refused(self) -> None:
        with pytest.raises(ValueError, match="missing"):
            _parse(_payload(citations=[{"src_ip": 10}]))

    def test_a_citation_that_is_not_a_list_is_refused(self) -> None:
        with pytest.raises(ValueError, match="citations must be a list"):
            _parse(_payload(citations=dict(_FLOW._asdict())))


class TestTheDraftInvariants:
    """The dataclass's own door, not only the parser's.

    A draft is also built in memory by the node, so an invariant that holds
    only when a value arrives through the parser does not hold. These cases
    are the same refusals the parser tests above make, asserted at the type.
    """

    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"kind": "ruleset"}, "must be a PolicyKind"),
            ({"document": []}, "must be an object"),
            ({"note": "  "}, "must say why"),
            ({"citations": ()}, "cite at least one flow"),
            ({"citations": (_FLOW, _FLOW)}, "same flow twice"),
        ],
    )
    def test_the_type_refuses_a_draft_the_parser_would_refuse(
        self, overrides: dict[str, Any], message: str
    ) -> None:
        fields: dict[str, Any] = {
            "kind": PolicyKind.RULESET,
            "document": {},
            "note": "why",
            "citations": (_FLOW,),
        }
        fields.update(overrides)

        with pytest.raises(ValueError, match=message):
            PolicyDraft(**fields)


# ---------------------------------------------------------------------------
# The node: the surface it grants, and the prompt that describes it
# ---------------------------------------------------------------------------


class TestTheNode:
    def test_the_surface_is_the_query_and_the_dry_run(self) -> None:
        assert POLICY_TOOL_NAMES == ("query_flows", "simulate_ruleset")

    def test_the_surface_has_no_tool_that_writes(self) -> None:
        """`run_dpi` and `stream_dpi_events` write files; neither is granted."""
        writing = {"run_dpi", "stream_dpi_events"}

        assert not writing & set(POLICY_TOOL_NAMES), (
            "the policy agent may not be granted a tool that writes a capture"
        )

    def test_the_prompt_explains_both_tools_and_what_each_is_for(self) -> None:
        for tool in POLICY_TOOL_NAMES:
            assert f"`{tool}`" in POLICY_PROMPT, f"{tool} is granted but unexplained"

    def test_the_prompt_says_the_simulation_is_a_counterfactual_not_an_apply(self) -> None:
        lowered = POLICY_PROMPT.lower()

        assert "counterfactual" in lowered
        assert "does not apply" in lowered or "nothing is applied" in lowered

    def test_the_prompt_says_a_human_reviews_the_proposal(self) -> None:
        """The one sentence that keeps the model from claiming a change is live.

        Asserted as a sentence, not as the words `human` and `review` somewhere
        in the prompt: both appear elsewhere, so a word-level assertion would
        survive the sentence being deleted.
        """
        lowered = POLICY_PROMPT.lower()

        assert "reviewed by a human" in lowered
        assert "only then applied" in lowered

    def test_the_prompt_gives_the_complete_ruleset_shape(self) -> None:
        for key in (
            "blocked_apps",
            "blocked_domains",
            "domain_patterns",
            "blocked_ips",
            "blocked_cidrs",
            "blocked_ports",
        ):
            assert key in POLICY_PROMPT, f"the ruleset key {key} is not explained"

    def test_the_prompt_gives_the_complete_signature_shape(self) -> None:
        for key in ("signatures", "all_of", "id", "app", "field", "value"):
            assert key in POLICY_PROMPT, f"the signature key {key} is not explained"

    def test_the_prompt_says_a_document_is_the_whole_policy_not_a_delta(self) -> None:
        lowered = POLICY_PROMPT.lower()

        assert "complete" in lowered
        assert "not a list of additions" in lowered or "replaces" in lowered

    def test_the_prompt_names_the_app_vocabulary_the_engine_accepts(self) -> None:
        """A prompt that names an app the loader refuses is a prompt that lies."""
        for app in ("TIKTOK", "YOUTUBE", "GITHUB"):
            assert app in POLICY_PROMPT, f"{app} is a valid app but is not named"

    def test_the_prompt_states_the_tools_this_build_does_not_have(self) -> None:
        for absent in ("propose_rule", "diff_runs"):
            assert absent in POLICY_PROMPT, (
                f"the design grants {absent}; this build does not, and silence "
                "would let the model read its absence as a clean result"
            )

    def test_the_prompt_treats_capture_text_as_data(self) -> None:
        lowered = POLICY_PROMPT.lower()

        assert "hostname" in lowered
        assert "data" in lowered and "instruction" in lowered

    def test_the_prompt_demands_a_citation_for_every_claim(self) -> None:
        lowered = POLICY_PROMPT.lower()

        assert "five-tuple" in lowered
        assert "cite" in lowered

    def test_the_context_names_the_run_the_capture_and_the_simulation_directory(
        self,
    ) -> None:
        system = policy_system(
            run_id=RUN_ID,
            capture=Path("evidence.pcap"),
            simulation_dir=Path("policy-scratch"),
        )

        assert RUN_ID in system
        assert "evidence.pcap" in system
        assert "policy-scratch" in system

    def test_the_node_carries_that_context_in_its_system_prompt(self) -> None:
        node = _node()

        assert node.name == "policy"
        assert RUN_ID in node.system
        assert "capture.pcap" in node.system
        assert "policy-scratch" in node.system

    def test_the_node_wires_its_parser_and_tools(self) -> None:
        schema: dict[str, Any] = {
            "name": "query_flows",
            "description": "",
            "inputSchema": {},
        }

        node = policy_node(
            (schema,),
            run_id=RUN_ID,
            capture=Path("capture.pcap"),
            simulation_dir=Path("simulation"),
            resolver=FakeResolver(_flow()),
            model_version=MODEL_VERSION,
        )

        assert node.tools == (schema,)
        assert node.parse is not None

    def test_the_module_has_no_path_to_the_policy_store(self) -> None:
        """The gate is "a proposal is a value, not an installed rule", asserted structurally."""
        tree = ast.parse(inspect.getsource(policy_module))
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }

        assert "RuleStore" not in vars(policy_module), (
            "the policy node must not be able to publish"
        )
        assert not calls & {"commit", "publish", "restore"}, (
            f"the policy node calls a store-writing method: {calls}"
        )
        assert not hasattr(Proposal, "commit")


# ---------------------------------------------------------------------------
# The proposal the node builds: engine-owned facts, engine-computed ids
# ---------------------------------------------------------------------------


class TestTheProposal:
    def test_a_supported_draft_builds_a_proposal(self) -> None:
        proposal = _build(_node(), _payload())

        assert proposal.kind is PolicyKind.RULESET
        assert proposal.document["blocked_apps"] == ["TIKTOK"]
        assert proposal.note.startswith("TikTok")
        assert proposal.citations == (Citation(RUN_ID, _FLOW),)

    def test_provenance_is_the_agents_not_the_models(self) -> None:
        proposal = _build(_node(), _payload())

        assert proposal.provenance.source == "agent:policy"
        assert proposal.provenance.author == AGENT_VERSION
        assert str(proposal.provenance.created_at), "a proposal with no time is an orphan"

    def test_the_three_versions_are_recorded(self) -> None:
        """The audit trail asks which agent, which prompt, which model."""
        proposal = _build(_node(), _payload())

        assert proposal.agent_version == AGENT_VERSION
        assert proposal.prompt_version == POLICY_PROMPT_VERSION
        assert proposal.model_version == MODEL_VERSION

    def test_the_parent_is_the_nodes_choice_and_binds_the_digest(self) -> None:
        parent = version_id_for(PolicyKind.RULESET, document={"blocked_apps": ["GITHUB"]})
        proposal = _build(_node(parent=parent), _payload())

        assert proposal.parent == parent
        assert proposal.version_id == version_id_for(
            proposal.kind,
            document=proposal.document,
            provenance=proposal.provenance,
            note=proposal.note,
            parent=parent,
        )

    def test_the_version_id_is_the_version_the_store_would_mint(self) -> None:
        proposal = _build(_node(), _payload())

        assert proposal.version_id == version_id_for(
            proposal.kind,
            document=proposal.document,
            provenance=proposal.provenance,
            note=proposal.note,
            parent=proposal.parent,
        )

    def test_the_digest_recomputes_from_the_record(self) -> None:
        proposal = _build(_node(), _payload())

        assert proposal.digest == proposal.computed_digest

    def test_the_document_is_the_engine_canonical_form(self) -> None:
        proposal = _build(_node(), _payload())

        assert proposal.document["blocked_domains"] == []
        assert "version" not in proposal.document

    def test_a_citation_the_run_does_not_hold_is_refused(self) -> None:
        payload = _payload(citations=[dict(_OTHER._asdict())])

        with pytest.raises(ProposalError, match="cannot be resolved"):
            _build(_node(), payload)

    def test_a_document_the_loader_refuses_is_refused(self) -> None:
        payload = _payload(document={"blocked_ports": ["not-a-port"]})

        with pytest.raises(ProposalError, match="not valid"):
            _build(_node(), payload)

    def test_a_document_of_the_wrong_kind_is_refused(self) -> None:
        """The signatures loader is the one that runs; a ruleset shape is not a table."""
        payload = _payload(kind="signatures")

        with pytest.raises(ProposalError, match="signatures document is not valid"):
            _build(_node(), payload)


# ---------------------------------------------------------------------------
# The agent: a real capture, a real MCP server, a real dry run
# ---------------------------------------------------------------------------

_RULESET_NOTE = "TikTok is the only app this run shows that the policy allows."


def _tiktok(flows: list[FlowRecord]) -> FlowRecord:
    return next(
        flow
        for flow in flows
        if flow.app == "TIKTOK" and flow.hostname == "www.tiktok.com"
    )


def _ruleset_answer(flows: list[FlowRecord]) -> dict[str, Any]:
    flow = _tiktok(flows)
    return {
        "kind": "ruleset",
        "document": {
            "blocked_apps": ["TIKTOK"],
            "blocked_domains": ["www.tiktok.com"],
        },
        "note": _RULESET_NOTE,
        "citations": [dict(flow.five_tuple._asdict())],
    }


def _signature_answer(flows: list[FlowRecord]) -> dict[str, Any]:
    flow = _tiktok(flows)
    return {
        "kind": "signatures",
        "document": {
            "version": 1,
            "signatures": [
                {
                    "id": "sig-tiktok",
                    "app": "TIKTOK",
                    "all_of": [{"field": "sni_present", "value": True}],
                }
            ],
        },
        "note": "The TikTok client offered an SNI.",
        "citations": [dict(flow.five_tuple._asdict())],
    }


def _run(
    tmp_path: Path,
    answer: Any,
    *,
    simulate: bool = True,
    parent: str | None = None,
) -> tuple[Any, ScriptedModel, tuple[Any, ...], Any, str, Path]:
    """Store a real run, then drive the node over the in-memory MCP pair."""
    capture = Path(TEST_DPI_PCAP)
    store_root = tmp_path / "store"
    run_id = store_a_run(capture, store_root)
    flows = list(RunStore(store_root).query(run_id))
    payload = json.dumps(answer(flows))
    simulation_dir = tmp_path / "simulation"
    document = json.loads(payload)["document"]

    async def scenario() -> tuple[Any, ScriptedModel, tuple[Any, ...], Any]:
        async with connected(store_root) as session:
            schemas = await tool_schemas(session, POLICY_TOOL_NAMES)
            replies = [
                ModelReply(
                    text="reading the run",
                    tool_calls=(
                        ToolCall(
                            name="query_flows",
                            arguments={"run_id": run_id, "app": "TIKTOK"},
                        ),
                    ),
                )
            ]
            if simulate:
                replies.append(
                    ModelReply(
                        text="simulating the change",
                        tool_calls=(
                            ToolCall(
                                name="simulate_ruleset",
                                arguments={
                                    "capture": str(capture),
                                    "candidate": document,
                                    "output_dir": str(simulation_dir),
                                },
                            ),
                        ),
                    )
                )
            replies.append(ModelReply(text=payload))
            model = ScriptedModel(replies)
            node = policy_node(
                schemas,
                run_id=run_id,
                capture=capture,
                simulation_dir=simulation_dir,
                resolver=StoreResolver(RunStore(store_root)),
                model_version=MODEL_VERSION,
                parent=parent,
            )
            with Trace(tmp_path / "trace.jsonl") as trace:
                outcome = await Agent(model=model, trace=trace).run(
                    node, tools=McpToolPort(session)
                )
        return outcome, model, schemas, node

    outcome, model, schemas, node = asyncio.run(scenario())
    return outcome, model, schemas, node, run_id, simulation_dir


class TestTheAgentOverARealRun:
    def test_it_proposes_a_ruleset_from_the_run_it_read(self, tmp_path: Path) -> None:
        outcome, _model, schemas, _node, run_id, _simulation = _run(
            tmp_path, _ruleset_answer
        )

        assert len(schemas) == 2, "the server did not declare both policy tools"
        assert outcome.reason == "verdict", outcome.error
        proposal = outcome.verdict
        assert isinstance(proposal, Proposal)
        assert proposal.kind is PolicyKind.RULESET
        assert proposal.document["blocked_apps"] == ["TIKTOK"]
        assert proposal.note == _RULESET_NOTE

        # The citation is the run's own flow, resolved through the store.
        stored = RunStore(tmp_path / "store")
        assert len(proposal.citations) == 1
        cited = proposal.citations[0]
        assert cited.run_id == run_id
        assert stored.flow(run_id, cited.five_tuple) is not None

        # And the ids are the engine's, not a model's arithmetic.
        assert proposal.digest == proposal.computed_digest
        assert proposal.version_id == version_id_for(
            proposal.kind,
            document=proposal.document,
            provenance=proposal.provenance,
            note=proposal.note,
            parent=proposal.parent,
        )

    def test_the_dry_run_really_ran_and_is_framed_as_data(self, tmp_path: Path) -> None:
        _outcome, model, _schemas, _node, _run_id, simulation_dir = _run(
            tmp_path, _ruleset_answer
        )

        assert (simulation_dir / "candidate_sim.pcap").exists(), (
            "the simulation produced no capture, so the dry run was not a dry run"
        )
        observations = {
            message.name: message
            for message in model.requests[-1].messages
            if message.role == "tool"
        }
        report = observations["simulate_ruleset"].content
        assert report.startswith("<untrusted_capture_data>")
        assert '"total_loss"' in report

    def test_the_model_is_told_the_flows_are_data(self, tmp_path: Path) -> None:
        _outcome, model, _schemas, _node, _run_id, _simulation = _run(
            tmp_path, _ruleset_answer
        )

        observation = next(
            message
            for message in model.requests[-1].messages
            if message.role == "tool" and message.name == "query_flows"
        )
        assert observation.content.startswith("<untrusted_capture_data>")

    def test_a_signature_table_is_a_proposal_too(self, tmp_path: Path) -> None:
        outcome, _model, _schemas, _node, _run_id, _simulation = _run(
            tmp_path, _signature_answer, simulate=False
        )

        assert outcome.reason == "verdict", outcome.error
        proposal = outcome.verdict
        assert isinstance(proposal, Proposal)
        assert proposal.kind is PolicyKind.SIGNATURES
        assert proposal.document["version"] == 1
        assert proposal.document["signatures"][0]["id"] == "sig-tiktok"

    def test_the_parent_travels_from_the_node_into_the_proposal(
        self, tmp_path: Path
    ) -> None:
        parent = version_id_for(PolicyKind.RULESET, document={"blocked_apps": ["GITHUB"]})

        outcome, _model, _schemas, _node, _run_id, _simulation = _run(
            tmp_path, _ruleset_answer, simulate=False, parent=parent
        )

        assert outcome.reason == "verdict", outcome.error
        assert outcome.verdict.parent == parent

    def test_a_fabricated_citation_is_an_invalid_verdict(self, tmp_path: Path) -> None:
        def fabricated(flows: list[FlowRecord]) -> dict[str, Any]:
            return _ruleset_answer(flows) | {
                "citations": [
                    {
                        "src_ip": 1,
                        "dst_ip": 2,
                        "src_port": 3,
                        "dst_port": 4,
                        "protocol": 6,
                    }
                ]
            }

        outcome, _model, _schemas, _node, _run_id, _simulation = _run(
            tmp_path, fabricated, simulate=False
        )

        assert outcome.reason == "invalid verdict"
        assert outcome.verdict is None
        assert outcome.error is not None and "cannot be resolved" in outcome.error

    def test_an_invalid_document_is_an_invalid_verdict(self, tmp_path: Path) -> None:
        def broken(flows: list[FlowRecord]) -> dict[str, Any]:
            return _ruleset_answer(flows) | {
                "document": {"blocked_ports": ["not-a-port"]}
            }

        outcome, _model, _schemas, _node, _run_id, _simulation = _run(
            tmp_path, broken, simulate=False
        )

        assert outcome.reason == "invalid verdict"
        assert outcome.verdict is None
        assert outcome.error is not None and "not valid" in outcome.error

    def test_a_draft_naming_a_missing_key_is_an_invalid_verdict(
        self, tmp_path: Path
    ) -> None:
        def incomplete(flows: list[FlowRecord]) -> dict[str, Any]:
            answer = _ruleset_answer(flows)
            del answer["note"]
            return answer

        outcome, _model, _schemas, _node, _run_id, _simulation = _run(
            tmp_path, incomplete, simulate=False
        )

        assert outcome.reason == "invalid verdict"
        assert outcome.verdict is None
        assert outcome.error is not None and "missing the 'note' key" in outcome.error
