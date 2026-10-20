"""The agent runtime (`T4-01`).

The runtime is the keystone the other six Phase 4 tasks stand on, so what is
tested here is not "does it call the model" but the three properties the design
depends on:

* a node that asks for tools gets observations back, and can then answer;
* **every** way a run can fail to produce a verdict says so and produces *no*
  verdict -- a run that timed out must not return half an answer, because a
  half-verdict is how a security tool tells a story it did not earn;
* the trace is written as the run happens, and can be read back afterwards by
  something that is not the process that wrote it.

The model is the deterministic fake (`DEC-11`), so every assertion here is
reproducible and free.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from dpi_agents.model import ModelReply, ModelRequest, ModelUsage, ScriptedModel, ToolCall
from dpi_agents.runtime import Agent, Budgets, Graph, Node, ToolResult
from dpi_agents.trace import Trace


class FakeTools:
    """A tool port that answers from a script, and records what it was asked."""

    def __init__(self, answers: Mapping[str, str] | None = None) -> None:
        self._answers = dict(answers or {})
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call(self, name: str, arguments: Mapping[str, Any]) -> ToolResult:
        self.calls.append((name, dict(arguments)))
        return ToolResult(content=self._answers.get(name, f"{name} answered"))


def _parse_verdict(text: str) -> dict[str, Any]:
    """The node's parser: JSON, and it must be an object.

    Deterministic validation of the model's answer, which is Layer 7's rule
    applied to the verdict: garbage is caught by code, not by hope.
    """
    raw = json.loads(text)
    if not isinstance(raw, dict):
        raise ValueError(f"a verdict must be an object, got {type(raw).__name__}")
    return raw


def _node(**kwargs: Any) -> Node:
    defaults: dict[str, Any] = {
        "name": "triage",
        "system": "You are a triage agent.",
        "parse": _parse_verdict,
    }
    defaults.update(kwargs)
    return Node(**defaults)


class TestTheLoop:
    def test_a_node_that_asks_for_a_tool_gets_the_answer_back(
        self, tmp_path: Path
    ) -> None:
        model = ScriptedModel(
            [
                ModelReply(
                    text="I need the flows first.",
                    tool_calls=(ToolCall(name="query_flows", arguments={"run_id": "abc"}),),
                    usage=ModelUsage(input_tokens=10, output_tokens=5),
                ),
                ModelReply(text='{"severity": "high"}', usage=ModelUsage(output_tokens=3)),
            ]
        )
        tools = FakeTools({"query_flows": "27 flows"})
        with Trace(tmp_path / "trace.jsonl") as trace:
            outcome = asyncio.run(
                Agent(model=model, trace=trace).run(_node(), tools=tools)
            )

        assert outcome.reason == "verdict"
        assert outcome.verdict == {"severity": "high"}
        assert outcome.steps == 2
        assert outcome.tokens == 18
        assert tools.calls == [("query_flows", {"run_id": "abc"})]

        # The second request carries the tool's answer, so the model could act on it.
        second = model.requests[1]
        assert [m.role for m in second.messages] == ["tool", "assistant"]
        assert second.messages[0].content == "27 flows"
        assert second.messages[0].name == "query_flows"

    def test_a_tool_that_fails_is_an_observation_and_not_a_crash(
        self, tmp_path: Path
    ) -> None:
        """A failed tool call is information for the model, not an exception."""
        model = ScriptedModel(
            [
                ModelReply(
                    text="Let me look.",
                    tool_calls=(ToolCall(name="query_flows", arguments={}),),
                ),
                ModelReply(text='{"severity": "low"}'),
            ]
        )
        tools = FakeTools()
        tools._answers["query_flows"] = "no such run"

        class Failing:
            async def call(self, name: str, arguments: Mapping[str, Any]) -> ToolResult:
                return ToolResult(content="no such run", is_error=True)

        with Trace(tmp_path / "trace.jsonl") as trace:
            outcome = asyncio.run(Agent(model=model, trace=trace).run(_node(), tools=Failing()))
        assert outcome.reason == "verdict"
        assert outcome.verdict == {"severity": "low"}
        # The failure is recorded as a failure, not as a successful observation.
        steps = Trace.read(tmp_path / "trace.jsonl")
        tool_step = next(step for step in steps if step.kind == "tool")
        assert tool_step.payload["is_error"] is True

    def test_state_from_an_earlier_node_reaches_the_next_one(
        self, tmp_path: Path
    ) -> None:
        """The graph's state is passed down, as a message rather than as part of
        the system prompt -- so the prompt stays what its author wrote."""
        model = ScriptedModel([ModelReply(text='{"ok": true}')])
        with Trace(tmp_path / "trace.jsonl") as trace:
            asyncio.run(
                Agent(model=model, trace=trace).run(
                    _node(), tools=FakeTools(), state="earlier verdict: severity=high"
                )
            )
        request = model.requests[0]
        assert request.system == "You are a triage agent."
        assert request.messages[0].role == "user"
        assert request.messages[0].content == "earlier verdict: severity=high"


class TestTheGraph:
    def test_the_nodes_run_in_order_and_each_verdict_reaches_the_next(
        self, tmp_path: Path
    ) -> None:
        model = ScriptedModel(
            [
                ModelReply(text='{"severity": "high"}'),
                ModelReply(text='{"narrative": "it was bad"}'),
            ]
        )
        graph = Graph(
            nodes=(
                _node(name="triage"),
                _node(name="explainer", system="You explain things."),
            )
        )
        with Trace(tmp_path / "trace.jsonl") as trace:
            outcomes = asyncio.run(
                Agent(model=model, trace=trace).run_graph(graph, tools=FakeTools())
            )
        assert [outcome.reason for outcome in outcomes] == ["verdict", "verdict"]
        assert outcomes[0].verdict == {"severity": "high"}
        # The second node was told what the first one concluded.
        second = model.requests[1]
        assert "triage: " in second.messages[0].content
        assert "high" in second.messages[0].content
        assert second.system == "You explain things."

    def test_a_node_without_a_verdict_stops_the_graph(self, tmp_path: Path) -> None:
        """The nodes after it would be reasoning from a state that does not exist."""
        model = ScriptedModel([ModelReply(text="not json")])
        graph = Graph(nodes=(_node(name="triage"), _node(name="explainer")))
        with Trace(tmp_path / "trace.jsonl") as trace:
            outcomes = asyncio.run(
                Agent(model=model, trace=trace).run_graph(graph, tools=FakeTools())
            )
        assert len(outcomes) == 1
        assert outcomes[0].reason == "invalid verdict"
        assert len(model.requests) == 1


class TestTheBudgets:
    """A budget that cannot be counted is not a budget, and a run that stops for
    any reason has no verdict."""

    def test_the_step_budget_stops_a_loop_that_never_answers(
        self, tmp_path: Path
    ) -> None:
        model = ScriptedModel(
            [
                ModelReply(
                    text="again",
                    tool_calls=(ToolCall(name="query_flows", arguments={}),),
                )
                for _ in range(20)
            ]
        )
        with Trace(tmp_path / "trace.jsonl") as trace:
            outcome = asyncio.run(
                Agent(model=model, trace=trace, budgets=Budgets(max_steps=3)).run(
                    _node(), tools=FakeTools()
                )
            )
        assert outcome.reason == "step budget"
        assert outcome.verdict is None
        assert outcome.steps == 3

    def test_the_token_budget_stops_a_run_that_spends_too_much(
        self, tmp_path: Path
    ) -> None:
        model = ScriptedModel(
            [
                ModelReply(
                    text="thinking",
                    tool_calls=(ToolCall(name="query_flows", arguments={}),),
                    usage=ModelUsage(input_tokens=100, output_tokens=50),
                )
                for _ in range(10)
            ]
        )
        with Trace(tmp_path / "trace.jsonl") as trace:
            outcome = asyncio.run(
                Agent(model=model, trace=trace, budgets=Budgets(max_tokens=120)).run(
                    _node(), tools=FakeTools()
                )
            )
        assert outcome.reason == "token budget"
        assert outcome.verdict is None
        assert outcome.tokens > 120

    def test_the_wall_clock_budget_stops_a_run_that_takes_too_long(
        self, tmp_path: Path
    ) -> None:
        async def slow(_request: ModelRequest) -> ModelReply:
            await asyncio.sleep(0.05)
            return ModelReply(text="finally", tool_calls=(ToolCall(name="x", arguments={}),))

        model = ScriptedModel([slow for _ in range(10)])
        with Trace(tmp_path / "trace.jsonl") as trace:
            outcome = asyncio.run(
                Agent(model=model, trace=trace, budgets=Budgets(max_seconds=0.01)).run(
                    _node(), tools=FakeTools()
                )
            )
        assert outcome.reason == "time budget"
        assert outcome.verdict is None

    def test_a_model_that_will_not_stop_gets_no_verdict_and_no_hang(
        self, tmp_path: Path
    ) -> None:
        """The script running out is a bug in the script, and it says so."""
        model = ScriptedModel([])
        with Trace(tmp_path / "trace.jsonl") as trace:
            with pytest.raises(RuntimeError, match="no reply left"):
                asyncio.run(Agent(model=model, trace=trace).run(_node(), tools=FakeTools()))


class TestTheVerdict:
    def test_an_unparsable_answer_is_not_a_verdict(self, tmp_path: Path) -> None:
        model = ScriptedModel([ModelReply(text="I think it is probably fine")])
        with Trace(tmp_path / "trace.jsonl") as trace:
            outcome = asyncio.run(Agent(model=model, trace=trace).run(_node(), tools=FakeTools()))
        assert outcome.reason == "invalid verdict"
        assert outcome.verdict is None
        assert outcome.error is not None

    def test_a_node_without_a_parser_cannot_produce_a_verdict(
        self, tmp_path: Path
    ) -> None:
        model = ScriptedModel([ModelReply(text='{"severity": "high"}')])
        with Trace(tmp_path / "trace.jsonl") as trace:
            outcome = asyncio.run(
                Agent(model=model, trace=trace).run(_node(parse=None), tools=FakeTools())
            )
        assert outcome.reason == "no parser"
        assert outcome.verdict is None


class TestTheTrace:
    def test_it_is_written_as_the_run_happens_and_reads_back(
        self, tmp_path: Path
    ) -> None:
        model = ScriptedModel(
            [
                ModelReply(
                    text="looking",
                    tool_calls=(ToolCall(name="query_flows", arguments={"run_id": "abc"}),),
                ),
                ModelReply(text='{"severity": "high"}'),
            ]
        )
        path = tmp_path / "nested" / "trace.jsonl"
        with Trace(path) as trace:
            asyncio.run(Agent(model=model, trace=trace).run(_node(), tools=FakeTools()))
            # The trace is readable *during* the run, not only after it.
            assert path.exists()

        steps = Trace.read(path)
        assert [step.kind for step in steps] == ["model", "tool", "model", "verdict"]
        assert [step.index for step in steps] == [0, 1, 2, 3]
        assert steps[0].payload["text"] == "looking"
        assert steps[0].payload["tool_calls"] == [
            {"name": "query_flows", "arguments": {"run_id": "abc"}}
        ]
        assert steps[1].payload["name"] == "query_flows"
        assert steps[1].payload["arguments"] == {"run_id": "abc"}
        assert steps[3].payload["parsed"] is True

    def test_a_failed_run_leaves_the_steps_that_did_happen(self, tmp_path: Path) -> None:
        """A run that dies leaves its trace: that is the point of a durable one."""
        path = tmp_path / "trace.jsonl"
        model = ScriptedModel([ModelReply(text="not json", tool_calls=())])
        with Trace(path) as trace:
            outcome = asyncio.run(Agent(model=model, trace=trace).run(_node(), tools=FakeTools()))
        assert outcome.reason == "invalid verdict"
        steps = Trace.read(path)
        assert [step.kind for step in steps] == ["model", "verdict"]
        assert steps[-1].payload["parsed"] is False
