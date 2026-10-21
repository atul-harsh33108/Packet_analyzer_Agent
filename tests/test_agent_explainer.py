"""The Explainer (`T4-04`).

**A narrative is prose, so its evidence has to be structured.** "Every claim
cites what it rests on" is a property when the citation is a five-tuple the
reader can look up, and a hope when it is a sentence. So the claims carry
their flows and their apps, and the test checks them against the run.

What the test does **not** check is whether the cited flows *support* the claim
in the prose: that is a judgement, and it is `T4-06`'s job (citation-enforced
RAG). The boundary is stated rather than blurred \u2014 this layer guarantees the
citation is real, the next one guarantees it is apt.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from agent_harness import connected, store_a_run, tool_schemas
from conftest import TEST_DPI_PCAP
from dpi_agents.model import ModelReply, ScriptedModel, ToolCall
from dpi_agents.nodes.explainer import EXPLAINER_TOOL_NAMES, explainer_node
from dpi_agents.runtime import Agent
from dpi_agents.schemas import IncidentNarrative, NarrativeClaim
from dpi_agents.tools import McpToolPort
from dpi_agents.trace import Trace
from dpi_mcp.run_store import RunStore


def _narrative_json(flow: dict[str, int] | None = None) -> dict[str, Any]:
    """A narrative the fake model returns.

    It cites one flow by default, so the test has something to check against the
    run; the flow's values come from the run itself, so the citation is real.
    """
    citation = {
        "src_ip": flow["src_ip"],
        "dst_ip": flow["dst_ip"],
        "src_port": flow["src_port"],
        "dst_port": flow["dst_port"],
        "protocol": flow["protocol"],
    }
    return {
        "summary": "77 packets, one flow, nothing blocked.",
        "claims": [
            {
                "text": "one flow to a single destination, forwarded",
                "flows": [citation],
                "apps": ["TWITTER"],
            }
        ],
    }


def _a_flow(store_root: Path, run_id: str) -> dict[str, int]:
    """One of the run's own flows, in the shape a citation uses."""
    rows = RunStore(store_root).query(run_id)
    assert rows, "the run has no flows, so there is nothing to cite"
    flow = rows[0]
    return {
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
    }


class TestTheExplainer:
    def test_it_produces_a_narrative_whose_citations_can_be_checked(
        self, tmp_path: Path
    ) -> None:
        async def scenario() -> tuple[Any, RunStore, str]:
            store_root = tmp_path / "store"
            run_id = store_a_run(Path(TEST_DPI_PCAP), store_root)
            flow = _a_flow(store_root, run_id)
            async with connected(store_root) as session:
                schemas = await tool_schemas(session, EXPLAINER_TOOL_NAMES)
                model = ScriptedModel(
                    [
                        ModelReply(
                            text="let me look",
                            tool_calls=(
                                ToolCall(name="query_flows", arguments={"run_id": run_id}),
                            ),
                        ),
                        ModelReply(text=json.dumps(_narrative_json(flow))),
                    ]
                )
                with Trace(tmp_path / "trace.jsonl") as trace:
                    outcome = await Agent(model=model, trace=trace).run(
                        explainer_node(schemas), tools=McpToolPort(session)
                    )
            return outcome, RunStore(store_root), run_id

        outcome, store, run_id = asyncio.run(scenario())
        assert outcome.reason == "verdict", outcome.error
        narrative = outcome.verdict
        assert isinstance(narrative, IncidentNarrative)
        assert narrative.summary
        assert len(narrative.claims) == 1
        claim = narrative.claims[0]
        assert isinstance(claim, NarrativeClaim)
        assert claim.text
        assert claim.flows, "a claim that cites nothing is not a claim"
        assert claim.apps == ("TWITTER",)

        # The citation is real: the flow it names is one of the run's own.
        known = {
            (flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol)
            for flow in store.query(run_id)
        }
        for five_tuple in claim.flows:
            key = (
                five_tuple.src_ip,
                five_tuple.dst_ip,
                five_tuple.src_port,
                five_tuple.dst_port,
                five_tuple.protocol,
            )
            assert key in known, f"the narrative cites a flow the run does not have: {key}"

    def test_the_model_is_told_the_flows_are_data(self, tmp_path: Path) -> None:
        async def scenario() -> ScriptedModel:
            store_root = tmp_path / "store"
            run_id = store_a_run(Path(TEST_DPI_PCAP), store_root)
            async with connected(store_root) as session:
                schemas = await tool_schemas(session, EXPLAINER_TOOL_NAMES)
                model = ScriptedModel(
                    [
                        ModelReply(
                            text="looking",
                            tool_calls=(
                                ToolCall(name="query_flows", arguments={"run_id": run_id}),
                            ),
                        ),
                        ModelReply(text=json.dumps(_narrative_json(_a_flow(store_root, run_id)))),
                    ]
                )
                with Trace(tmp_path / "trace.jsonl") as trace:
                    await Agent(model=model, trace=trace).run(
                        explainer_node(schemas), tools=McpToolPort(session)
                    )
            return model

        model = asyncio.run(scenario())
        observation = model.requests[1].messages[0]
        assert observation.content.startswith("<untrusted_capture_data>")
        assert observation.content.rstrip().endswith("</untrusted_capture_data>")

    def test_a_narrative_with_nothing_to_say_is_still_a_narrative(
        self, tmp_path: Path
    ) -> None:
        """"Nothing notable" is a legitimate answer, and it is not a failure."""
        from dpi_agents.schemas import parse_incident_narrative

        narrative = parse_incident_narrative(
            json.dumps({"summary": "nothing notable in this run", "claims": []})
        )
        assert narrative.claims == ()


class TestTheExplainerIsReadOnly:
    def test_it_may_not_call_a_tool_that_writes(self) -> None:
        """An agent that can write is an agent that can cause harm.

        `simulate_ruleset` writes two output captures, so it is not a read tool
        and the Explainer does not get it. The policy agent's dry-run belongs to
        a node that is *about* policy.
        """
        assert "simulate_ruleset" not in EXPLAINER_TOOL_NAMES
        assert set(EXPLAINER_TOOL_NAMES) == {
            "inspect_capture",
            "query_flows",
            "get_flow_detail",
            "diff_runs",
        }

    def test_the_tools_it_may_call_are_the_ones_the_server_offers(self) -> None:
        """The node's tool list and the server's must agree.

        A node that names a tool the server does not have is a node whose model
        will be told to call something that cannot be called.
        """
        from dpi_mcp.registry import TOOL_SPECS

        offered = {spec.name for spec in TOOL_SPECS}
        assert set(EXPLAINER_TOOL_NAMES) <= offered


@pytest.mark.parametrize(
    "payload",
    [
        {"claims": []},
        {"summary": "", "claims": []},
        {"summary": "  ", "claims": []},
        {"summary": "ok", "claims": "not a list"},
        {"summary": "ok", "claims": ["not an object"]},
        {"summary": "ok", "claims": [{"flows": []}]},
        {"summary": "ok", "claims": [{"text": "x", "flows": {"a": 1}}]},
        {"summary": "ok", "claims": [{"text": "x", "flows": [{"src_ip": 1}]}]},
        {"summary": "ok", "claims": [{"text": "x", "flows": [], "apps": "TWITTER"}]},
        {"summary": "ok", "claims": [{"text": "x", "flows": [], "apps": [""]}]},
    ],
    ids=[
        "no summary",
        "empty summary",
        "blank summary",
        "claims is not a list",
        "a claim is not an object",
        "a claim has no text",
        "a claim's flows is not a list",
        "a flow is missing fields",
        "apps is not a list",
        "an app is empty",
    ],
)
def test_a_malformed_narrative_is_refused(payload: dict[str, Any]) -> None:
    """A citation that cannot be checked is worse than no citation: it looks
    like evidence."""
    from dpi_agents.schemas import parse_incident_narrative

    with pytest.raises(ValueError):
        parse_incident_narrative(json.dumps(payload))
