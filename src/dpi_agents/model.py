"""The model port, and the deterministic fake that implements it (`DEC-11`).

**A port, not a class.** The runtime depends on this protocol and on nothing
else, so the agent package never imports a provider. That is what makes the
runtime `OFFLINE_CORE` -- and *provably* so, rather than by review. The real
client lives in its own package at `NETWORKED_AGENT` (`T4-07`), so the only
code in this package that could reach a network cannot.

**The fake is not a mock.** It is the CI's model: deterministic, free, and it
*records the requests it was given*, which is what lets a test assert what the
prompt actually contained. A test that cannot see the prompt cannot test the
prompt -- and the prompt is where the untrusted-data framing lives (`T4-02`).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, Protocol

__all__ = [
    "Model",
    "ModelMessage",
    "ModelReply",
    "ModelRequest",
    "ModelUsage",
    "ScriptedModel",
    "ToolCall",
]


@dataclasses.dataclass(frozen=True, slots=True)
class ToolCall:
    """A tool the model asked for.

    `arguments` is a mapping because that is what JSON gives, and the tool
    adapter validates it before anything acts on it -- an agent's arguments are
    input, not instruction.
    """

    name: str
    arguments: Mapping[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True, slots=True)
class ModelUsage:
    """What a call cost.

    Counted, because a budget that cannot be counted is not a budget.
    """

    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclasses.dataclass(frozen=True, slots=True)
class ModelMessage:
    """One turn of the conversation.

    `role` is one of `"user"`, `"assistant"` or `"tool"`. A `"tool"` message
    names the tool it answers.
    """

    role: str
    content: str
    name: str | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class ModelRequest:
    """What a node asks the model for.

    `tools` carries the tool *schemas* the model may call, in the shape the
    provider expects. The runtime does not interpret them: it hands them over.
    """

    system: str
    messages: tuple[ModelMessage, ...] = ()
    tools: tuple[Mapping[str, Any], ...] = ()
    max_output_tokens: int = 0


@dataclasses.dataclass(frozen=True, slots=True)
class ModelReply:
    """What the model said.

    A reply with no tool calls is the model finishing: its `text` is the
    answer. A reply with tool calls is the model asking for observation.
    """

    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    usage: ModelUsage = dataclasses.field(default_factory=ModelUsage)
    stop_reason: str = "end_turn"


class Model(Protocol):
    """The port every model implements."""

    async def complete(self, request: ModelRequest) -> ModelReply:
        """Answer one request."""
        ...


class ScriptedModel:
    """A model that replays a script, and records what it was asked.

    The replies are consumed in order. A reply may be a callable, so a script
    can *look at the request* before answering -- which is how a test drives a
    loop that depends on what the model was told.
    """

    def __init__(
        self,
        replies: Sequence[ModelReply | Callable[[ModelRequest], ModelReply | Awaitable[ModelReply]]],
    ) -> None:
        self._replies = list(replies)
        self._requests: list[ModelRequest] = []

    async def complete(self, request: ModelRequest) -> ModelReply:
        self._requests.append(request)
        if not self._replies:
            raise RuntimeError(
                "the scripted model has no reply left: the run asked for more turns "
                "than the script has. A script that runs out is a bug in the script, "
                "not a timeout."
            )
        scripted = self._replies.pop(0)
        if not callable(scripted):
            return scripted
        answer = scripted(request)
        # A script may want to *look* at the request before answering, and looking
        # can mean waiting -- so an async script is awaited rather than returned.
        if isinstance(answer, Awaitable):
            return await answer
        return answer

    @property
    def requests(self) -> tuple[ModelRequest, ...]:
        """Every request the model was given, in order."""
        return tuple(self._requests)

    def remaining(self) -> int:
        """How many scripted replies are left."""
        return len(self._replies)
