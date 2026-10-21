"""Typed wrappers over the MCP tool surface (`T4-03`).

**The agent drives the tools through the protocol**, not by importing them. That
is the design's Layer 2 -> Layer 3 boundary, and it is not ceremony: the
protocol is where the *schema* lives, so a call with an argument the schema does
not have is refused before it runs rather than being a `TypeError` deep inside
a call. The wrapper is transport-agnostic \u2014 it needs a session and nothing else \u2014
so the same code serves the in-memory transport a test uses and the stdio
transport a host application uses.

**Every capture-derived string a tool returns is screened and framed before it
reaches the model**, and what was withheld is *recorded*. Two things follow from
that, and both are the point:

* The **framing** (`T4-02`) tells the model the content is data. The whole
  answer is one block: it is derived from the capture, so the whole of it is
  data.
* The **screening** refuses a hostile string and replaces it with a marker. The
  marker is in the answer, so the agent can see that a value was withheld and
  why \u2014 a quiet exclusion would make the agent's view wrong without saying so,
  and an agent that does not know a hostname was withheld will read the absence
  as the truth.

**The screening is generic**, walking the answer and refusing *any* string that
looks hostile. It does not name the fields to check, because a list of field
names is a second copy of the tool's shape: rename a field and the copy goes
quietly stale, and the field that stops being screened is the one an attacker
was counting on. Walking every string costs a little and cannot be forgotten.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from mcp import ClientSession
from mcp.types import TextContent

from dpi_agents.framing import frame
from dpi_agents.injection import classify
from dpi_agents.runtime import ToolResult

__all__ = ["McpToolPort", "screen_value", "withheld_marker"]


def withheld_marker(rule: str) -> str:
    """What a refused string is replaced with.

    It says **that** a value was withheld and **which rule** matched, and it
    does not carry the text: the text is what the rule caught, and putting it
    back into the answer would put it straight back in front of the model.
    """
    return f"[withheld: refused by the {rule} rule]"


def _screen(value: Any) -> tuple[Any, tuple[str, ...]]:
    """Screen one value, recursively.

    Returns the value to pass on, and what was withheld (the rule and the text,
    for the trace). Strings are the only thing that can be hostile; numbers,
    booleans and null are the engine's own vocabulary and pass through.
    """
    if isinstance(value, str):
        verdict = classify(value)
        if verdict.suspicious:
            assert verdict.rule is not None  # a refusal always names its rule
            return withheld_marker(verdict.rule), (f"{verdict.rule}: {value}",)
        return value, ()
    if isinstance(value, Mapping):
        screened: dict[str, Any] = {}
        withheld: list[str] = []
        for key, item in value.items():
            new_item, item_withheld = _screen(item)
            screened[str(key)] = new_item
            withheld.extend(item_withheld)
        return screened, tuple(withheld)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        items: list[Any] = []
        withheld = []
        for item in value:
            new_item, item_withheld = _screen(item)
            items.append(new_item)
            withheld.extend(item_withheld)
        return items, tuple(withheld)
    return value, ()


def screen_value(value: Any) -> tuple[Any, tuple[str, ...]]:
    """Screen a value on its way to the model.

    The public name for the recursive walk, so a caller can screen something the
    wrapper did not produce (a prompt fragment, a document) with the same rules
    the wrapper used.
    """
    return _screen(value)


class McpToolPort:
    """The agent's view of the MCP tool surface.

    Implements the runtime's `ToolPort`, so the runtime knows nothing about
    MCP: it asks for a tool, and gets an answer that is already safe to put in
    front of a model.
    """

    def __init__(self, session: ClientSession) -> None:
        self._session = session

    async def call(self, name: str, arguments: Mapping[str, Any]) -> ToolResult:
        """Call one tool, and screen what comes back."""
        result = await self._session.call_tool(name, dict(arguments))
        text = "".join(
            block.text for block in result.content if isinstance(block, TextContent)
        )
        if result.is_error:
            # An error message is model-bound text too: a tool that echoes the
            # argument it was given can echo a hostile hostname back.
            screened, withheld = screen_value(text)
            return ToolResult(
                content=frame(str(screened)),
                is_error=True,
                withheld=withheld,
            )
        try:
            payload: Any = json.loads(text)
        except json.JSONDecodeError:
            payload = text
        screened, withheld = screen_value(payload)
        return ToolResult(
            content=frame(json.dumps(screened, indent=2, default=str)),
            is_error=False,
            withheld=withheld,
        )
