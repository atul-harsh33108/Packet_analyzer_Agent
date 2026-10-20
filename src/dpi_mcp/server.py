"""The MCP wiring boundary (`T3-05`, `DEC-09`).

**This is the only module in `dpi_mcp` that imports the `mcp` SDK.** The tools
stay plain typed Python that can be read, tested and used with no protocol
library installed; this file is where they become a protocol. That separation is
the discipline `AGENTIC_ARCHITECTURE.md` says MCP forces -- explicit, typed,
documented tool contracts -- and it is only real if the contracts do not depend
on the transport to be testable.

**stdio only, and that is now enforced rather than asserted** (`DEC-09`). The
SDK's HTTP transports are never imported here, the ASGI stack is never called,
and `tests/test_agent_safety_envelope.py` checks both: the envelope scanner
treats `uvicorn.run`, `starlette` and the HTTP clients as network calls, and a
separate import-level test asserts that this file imports nothing from the SDK
except its stdio, server and types modules. A server that could open a port
would be a different product, not a flag.

The server binds **one** store root, chosen by the operator when the server
starts. The agent is given a `run_id`, never a path: it cannot point a tool at
a directory nobody chose, and the store validates a run id before it touches the
filesystem.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import traceback
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolResult,
    ListResourcesResult,
    ListResourceTemplatesResult,
    ListToolsResult,
    ReadResourceResult,
    Resource,
    ResourceTemplate,
    TextContent,
    TextResourceContents,
    Tool,
)

from dpi_engine.events import event_to_dict
from dpi_mcp.registry import RESOURCE_TEMPLATES, TOOL_SPECS, ServerContext
from dpi_mcp.tools.streaming import DEFAULT_QUEUE_SIZE

__all__ = ["build_server", "main"]

_SERVER_NAME = "dpi-engine"

#: The catalogue, by name. A tool the server does not have is a protocol error,
#: not a missing key: the request names something that does not exist, and the
#: answer has to say so rather than raise `KeyError` at the agent.
_SPECS_BY_NAME = {spec.name: spec for spec in TOOL_SPECS}


def _server_version() -> str:
    """The installed package version, or `unknown`.

    From the package metadata rather than `dpi_engine.__version__`, which is a
    literal in the source and has already fallen behind the distribution.
    """
    try:
        from importlib.metadata import version

        return version("dpi-engine")
    except Exception:  # pragma: no cover - only if the package is not installed
        return "unknown"


def _error(message: str) -> CallToolResult:
    """A failed tool call.

    Reported as a tool error rather than a protocol error: the agent sent a
    request it can retry with a different argument, and an exception that
    escapes as a protocol failure tells it only that something broke.
    """
    return CallToolResult(content=[TextContent(text=message)], is_error=True)


def _text_result(payload: Any) -> CallToolResult:
    """A successful tool call.

    The answer is JSON text. A structured field is available on the result too,
    but the text is the one every client renders, and a client that only reads
    text must not receive a blank.
    """
    return CallToolResult(
        content=[TextContent(text=json.dumps(payload, indent=2, sort_keys=False, default=str))]
    )


def build_server(*, store_root: str | Path) -> Server:
    """The MCP server, bound to one store.

    `store_root` is the operator's choice, made when the server starts. It is
    not a module global and not a tool argument: configuration that is ambient
    cannot be exercised twice in one process, and it hides where a read or a
    write goes.
    """
    context = ServerContext(store_root=Path(store_root))

    async def on_list_tools(
        _ctx: Any, _params: Any
    ) -> ListToolsResult:
        return ListToolsResult(
            tools=[
                Tool(
                    name=spec.name,
                    description=spec.description,
                    input_schema=spec.input_schema,
                )
                for spec in TOOL_SPECS
            ]
        )

    async def on_call_tool(_ctx: Any, params: Any) -> CallToolResult:
        spec = _SPECS_BY_NAME.get(params.name)
        if spec is None:
            return _error(f"no tool named {params.name!r}")

        arguments = dict(params.arguments or {})
        bound = {name: _bound_value(name, context) for name in spec.bound}
        if spec.kind == "stream":
            return await _run_stream(_ctx, spec, arguments, bound)
        try:
            # The engine is blocking and a pipeline run is measured in seconds.
            # On the event loop that would freeze the server's ability to answer
            # anything else -- including a cancellation. A thread cannot be
            # cancelled, so a client that gives up on a call leaves the work
            # running to completion; for `run_dpi` that means the run is still
            # stored, which is the honest outcome for work that already happened.
            result = await asyncio.to_thread(spec.handler, **arguments, **bound)
        except Exception as exc:
            # The traceback goes to stderr, which in a stdio server is the
            # operator's log and not the protocol stream. An agent gets the
            # message; an operator gets the stack.
            traceback.print_exc(file=sys.stderr)
            return _error(f"{type(exc).__name__}: {exc}")
        return _text_result(spec.encoder(result))

    async def on_list_resources(_ctx: Any, _params: Any) -> ListResourcesResult:
        return ListResourcesResult(
            resources=[
                Resource(
                    uri=spec.uri,
                    name=spec.name,
                    description=spec.description,
                    mime_type=spec.mime_type,
                )
                for spec in RESOURCE_TEMPLATES
                if "{" not in spec.uri
            ]
        )

    async def on_list_resource_templates(
        _ctx: Any, _params: Any
    ) -> ListResourceTemplatesResult:
        return ListResourceTemplatesResult(
            resource_templates=[
                ResourceTemplate(
                    uri_template=spec.uri,
                    name=spec.name,
                    description=spec.description,
                    mime_type=spec.mime_type,
                )
                for spec in RESOURCE_TEMPLATES
                if "{" in spec.uri
            ]
        )

    async def on_read_resource(_ctx: Any, params: Any) -> ReadResourceResult:
        uri = str(params.uri)
        for spec in RESOURCE_TEMPLATES:
            value = _match_resource(spec.uri, uri)
            if value is None:
                continue
            try:
                payload = spec.reader(context, value)
            except Exception:
                traceback.print_exc(file=sys.stderr)
                raise
            return ReadResourceResult(
                contents=[
                    TextResourceContents(
                        uri=uri,
                        mime_type=spec.mime_type,
                        text=json.dumps(payload, indent=2, sort_keys=False, default=str),
                    )
                ]
            )
        raise ValueError(f"no resource at {uri!r}")

    return Server(
        _SERVER_NAME,
        version=_server_version(),
        instructions=(
            "The DPI engine's analysis tools. `run_dpi` classifies a capture and "
            "stores the run; `query_flows`, `get_flow_detail` and `diff_runs` ask "
            "questions about stored runs. The stored runs are also browsable as "
            "the `dpi://runs` resource."
        ),
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
        on_list_resources=on_list_resources,
        on_list_resource_templates=on_list_resource_templates,
        on_read_resource=on_read_resource,
    )


def _bound_value(name: str, context: ServerContext) -> Any:
    """The value of a server-bound parameter.

    The bound names are the server's to choose. `store_root` is where runs live;
    `with_flow_table` is forced on because the store refuses a run with no flow
    table, and an empty table would read as a capture with no flows;
    `queue_size` is how many events may wait for a consumer before the producer
    starts dropping them (`DEC-10`).
    """
    if name == "store_root":
        return context.store_root
    if name == "with_flow_table":
        return True
    if name == "queue_size":
        return DEFAULT_QUEUE_SIZE
    raise KeyError(f"no server-bound parameter named {name!r}")


def _progress_requested(ctx: Any) -> bool:
    """Whether the caller asked for progress notifications.

    Measured, not assumed: the SDK's `report_progress` is a **no-op** when the
    caller did not request progress, so a streaming tool that sent events
    without checking would report a delivery that never happened.
    """
    meta = getattr(ctx, "meta", None)
    return isinstance(meta, dict) and meta.get("progress_token") is not None


async def _run_stream(
    ctx: Any, spec: Any, arguments: dict[str, Any], bound: dict[str, Any]
) -> CallToolResult:
    """Drive a streaming tool, and deliver its events as progress notifications.

    The events are the tool's; the *delivery* is the protocol's, and the two are
    reported separately. `events_delivered` is what the **client** received, so a
    client that never asked for progress is told it saw nothing rather than
    being left to infer it from an empty stream.
    """
    stream = spec.handler(**arguments, **bound)
    progress_requested = _progress_requested(ctx)
    delivered = 0
    stream.start()
    try:
        async for event in stream.events():
            if progress_requested:
                await ctx.session.report_progress(
                    delivered + 1, message=json.dumps(event_to_dict(event))
                )
            delivered += 1
        outcome = await stream.finish()
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return _error(f"{type(exc).__name__}: {exc}")

    payload = outcome.to_json()
    payload["events_delivered"] = delivered if progress_requested else 0
    payload["progress_requested"] = progress_requested
    return _text_result(payload)


def _match_resource(template: str, uri: str) -> str | None:
    """The parameter in `uri` for `template`, or `None` if it does not match.

    `dpi://runs/{run_id}` matches `dpi://runs/abc123` with the value `abc123`.
    A template with more than one placeholder is not supported, and says so
    rather than matching the wrong thing.
    """
    if "{" not in template:
        return "" if template == uri else None
    prefix, _, rest = template.partition("{")
    name, _, tail = rest.partition("}")
    if not name or "{" in tail:
        raise ValueError(f"unsupported resource template {template!r}")
    if not uri.startswith(prefix) or not uri.endswith(tail):
        return None
    value = uri[len(prefix) : len(uri) - len(tail)] if tail else uri[len(prefix) :]
    return value


async def _serve(store_root: Path) -> None:
    """Serve over stdio until the client closes the pipes."""
    server = build_server(store_root=store_root)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main(argv: list[str] | None = None) -> int:
    """The `dpi-mcp` entry point."""
    parser = argparse.ArgumentParser(
        prog="dpi-mcp",
        description=(
            "Serve the DPI engine's MCP tools over stdio. The store root is the "
            "server's, not the agent's: the agent is given run ids."
        ),
    )
    parser.add_argument(
        "--store-root",
        required=True,
        type=Path,
        help="Directory holding the stored runs.",
    )
    args = parser.parse_args(argv)
    try:
        asyncio.run(_serve(args.store_root))
    except KeyboardInterrupt:  # pragma: no cover - the client's business
        return 130
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
