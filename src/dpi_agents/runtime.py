"""The agent runtime: a ReAct loop with three budgets, and a durable trace.

**What this is.** A node is a prompt, a set of tools it may call, and a typed
verdict it must end with. The runtime asks the model, runs the tools the model
asked for, feeds the answers back, and repeats -- until the model answers, or
one of the three budgets runs out. Every step is written to the trace as it
happens.

**Why a loop and not a chain.** The design's Layer 3 is a ReAct loop per node:
thought, tool call, observation, reflect, repeat. A chain would be a pipeline
of prompts, and it cannot decide to look at one more flow before answering --
which is the whole difference between an agent and a template.

**Why the three budgets.** Layer 7's "budget bounds", and they are the reason
this is safe to run unattended: a step budget, a token budget, and a wall-clock
timeout. A pathological capture must not be able to burn an afternoon and a
fortune. A budget that cannot be *counted* is not a budget, which is why the
model's usage is part of the port rather than an afterthought.

**Why the verdict is parsed, not trusted.** Layer 7 again: *deterministic
validation of every proposal*. Garbage is caught by code, not by hope. The
runtime does not know what a verdict looks like -- the node's parser does -- but
it does insist that the parser *succeeds*, and it records the failure rather
than letting a malformed answer look like a verdict.
"""

from __future__ import annotations

import dataclasses
import json
import time
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from dpi_agents.framing import PROMPT_VERSION, system_prompt
from dpi_agents.model import Model, ModelMessage, ModelReply, ModelRequest, ToolCall
from dpi_agents.trace import Trace

__all__ = [
    "Agent",
    "Budgets",
    "Graph",
    "Node",
    "Outcome",
    "ToolPort",
    "ToolResult",
]

@dataclasses.dataclass(frozen=True, slots=True)
class ToolResult:
    """What a tool answered.

    `is_error` is part of the answer rather than an exception, because a failed
    tool call is *information for the model*: "that run id does not exist" is
    something the model can act on, and the design's ReAct loop expects
    observations, not crashes.
    """

    content: str
    is_error: bool = False


class ToolPort(Protocol):
    """The tools a node may call."""

    async def call(self, name: str, arguments: Mapping[str, Any]) -> ToolResult:
        """Run one tool."""
        ...


@dataclasses.dataclass(frozen=True, slots=True)
class Budgets:
    """The three bounds a run may not exceed.

    The defaults are deliberately small: a node that cannot answer in a dozen
    steps and a couple of minutes is a node whose *prompt* is wrong, and the
    budget is how that becomes visible instead of expensive.
    """

    max_steps: int = 12
    max_tokens: int = 20_000
    max_seconds: float = 120.0


@dataclasses.dataclass(frozen=True, slots=True)
class Node:
    """One step of the graph: a prompt, the tools it may call, and how to parse
    its verdict.

    `parse` is supplied by the node rather than being inferred from a type, so
    the runtime stays generic and the *validation* lives with the verdict it
    validates.
    """

    name: str
    system: str
    tools: tuple[Mapping[str, Any], ...] = ()
    parse: Callable[[str], Any] | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class Graph:
    """An explicit sequence of nodes.

    Not a conversation between agents: state must be inspectable, resumable and
    pausable on a human decision, so the graph is a list and the state is the
    list of verdicts so far.
    """

    nodes: tuple[Node, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class Outcome[VerdictT]:
    """How a run ended.

    `reason` is `"verdict"` when the model produced a parsable answer, and
    otherwise which budget stopped it. A run that ended for any other reason
    has **no verdict**, and that is stated rather than implied: a run that
    timed out and returned half a verdict is how a security tool tells a story
    it did not earn.
    """

    verdict: VerdictT | None
    reason: str
    steps: int
    tokens: int
    elapsed_seconds: float
    error: str | None = None


class Agent:
    """Runs a node, and records what it did."""

    def __init__(
        self,
        *,
        model: Model,
        trace: Trace,
        budgets: Budgets | None = None,
    ) -> None:
        self._model = model
        self._trace = trace
        self._budgets = budgets if budgets is not None else Budgets()

    async def run(
        self,
        node: Node,
        *,
        tools: ToolPort,
        state: str = "",
    ) -> Outcome[Any]:
        """Run one node to a verdict, or to a budget.

        `state` is the context handed down from the nodes before this one: the
        verdicts so far, rendered. It is passed as a message rather than
        concatenated into the system prompt, so the prompt stays what the author
        wrote and the state stays inspectable.
        """
        messages: list[ModelMessage] = []
        if state:
            messages.append(ModelMessage(role="user", content=state))
        tokens = 0
        started = time.monotonic()

        for step in range(self._budgets.max_steps):
            elapsed = time.monotonic() - started
            if elapsed > self._budgets.max_seconds:
                return self._no_verdict(node, "time budget", step, tokens, elapsed)
            if tokens > self._budgets.max_tokens:
                return self._no_verdict(node, "token budget", step, tokens, elapsed)

            request = ModelRequest(
                system=system_prompt(node.system),
                messages=tuple(messages),
                tools=node.tools,
            )
            reply = await self._model.complete(request)
            tokens += reply.usage.total_tokens
            self._record_model(reply, request)

            if not reply.tool_calls:
                return self._finish(node, reply, step, tokens, started)

            for call in reply.tool_calls:
                result = await tools.call(call.name, call.arguments)
                self._record_tool(call, result)
                messages.append(
                    ModelMessage(role="tool", content=result.content, name=call.name)
                )
            messages.append(ModelMessage(role="assistant", content=reply.text))

        elapsed = time.monotonic() - started
        return self._no_verdict(node, "step budget", self._budgets.max_steps, tokens, elapsed)

    async def run_graph(
        self,
        graph: Graph,
        *,
        tools: ToolPort,
    ) -> list[Outcome[Any]]:
        """Run the graph's nodes in order, passing each verdict to the next.

        A node that ends **without** a verdict stops the graph: the nodes after
        it would be reasoning from a state that does not exist, and the honest
        thing is to return the outcomes so far and let the caller see where it
        stopped. That is what makes the state inspectable, which is the reason
        the design wants a graph and not a conversation between agents.
        """
        outcomes: list[Outcome[Any]] = []
        state: list[str] = []
        for node in graph.nodes:
            outcome = await self.run(node, tools=tools, state="\n".join(state))
            outcomes.append(outcome)
            if outcome.verdict is None:
                break
            state.append(f"{node.name}: {json.dumps(outcome.verdict, default=str)}")
        return outcomes

    # -- recording ---------------------------------------------------------

    def _record_model(self, reply: ModelReply, request: ModelRequest) -> None:
        """Record what was asked and what came back.

        The **system prompt is recorded too**, with its version. A trace that
        cannot say which prompt produced a verdict cannot be replayed against
        it, and the design asks for prompts to be versioned in git and
        eval-gated \u2014 which is only meaningful if the version travels with the
        answer.
        """
        self._trace.record(
            "model",
            {
                "text": reply.text,
                "system": request.system,
                "prompt_version": PROMPT_VERSION,
                "tool_calls": [
                    {"name": call.name, "arguments": dict(call.arguments)}
                    for call in reply.tool_calls
                ],
                "usage": {
                    "input_tokens": reply.usage.input_tokens,
                    "output_tokens": reply.usage.output_tokens,
                },
            },
        )

    def _record_tool(self, call: ToolCall, result: ToolResult) -> None:
        self._trace.record(
            "tool",
            {
                "name": call.name,
                "arguments": dict(call.arguments),
                "content": result.content,
                "is_error": result.is_error,
            },
        )

    # -- endings -----------------------------------------------------------

    def _finish(
        self,
        node: Node,
        reply: ModelReply,
        step: int,
        tokens: int,
        started: float,
    ) -> Outcome[Any]:
        """The model answered: parse it, and record whether it was usable."""
        elapsed = time.monotonic() - started
        if node.parse is None:
            self._trace.record("verdict", {"text": reply.text, "parsed": False})
            return Outcome(
                verdict=None,
                reason="no parser",
                steps=step + 1,
                tokens=tokens,
                elapsed_seconds=elapsed,
                error=f"node {node.name!r} has no parser, so its answer cannot be a verdict",
            )
        try:
            verdict = node.parse(reply.text)
        except Exception as exc:
            self._trace.record(
                "verdict", {"text": reply.text, "parsed": False, "error": str(exc)}
            )
            return Outcome(
                verdict=None,
                reason="invalid verdict",
                steps=step + 1,
                tokens=tokens,
                elapsed_seconds=elapsed,
                error=f"{type(exc).__name__}: {exc}",
            )
        self._trace.record("verdict", {"text": reply.text, "parsed": True})
        return Outcome(
            verdict=verdict,
            reason="verdict",
            steps=step + 1,
            tokens=tokens,
            elapsed_seconds=elapsed,
        )

    def _no_verdict(
        self,
        node: Node,
        reason: str,
        steps: int,
        tokens: int,
        elapsed: float,
    ) -> Outcome[Any]:
        """A budget stopped the run, so there is no verdict."""
        self._trace.record("outcome", {"reason": reason, "node": node.name})
        return Outcome(
            verdict=None,
            reason=reason,
            steps=steps,
            tokens=tokens,
            elapsed_seconds=elapsed,
        )
