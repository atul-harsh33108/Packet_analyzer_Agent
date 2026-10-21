"""The harness the agent tests share (`T4-03`, `T4-04`).

**One copy, because two copies drift.** The MCP connection, the store fixture
and the tool-schema selection are the same in both agent test files, and a
helper that exists twice is a helper that exists once in one file and
differently in the other.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.shared.memory import create_client_server_memory_streams

from dpi_engine.pipeline import run_pipeline
from dpi_engine.rule_manager import RuleManager
from dpi_mcp.run_store import RunStore, record_from_result
from dpi_mcp.server import build_server

__all__ = ["connected", "store_a_run", "tool_schemas"]


def store_a_run(capture: Path, store_root: Path) -> str:
    """Run the engine over `capture` and store the run. Returns the run id.

    The engine's output capture goes next to the **store**, never next to the
    capture: the shared fixture lives in the repository, and a test that writes
    beside it leaves a file in the tree \u2014 which happened once, and was
    committed.
    """
    result = run_pipeline(
        str(capture),
        store_root.parent / "forwarded.pcap",
        RuleManager(),
        with_flow_table=True,
    )
    record = record_from_result(result, capture_path=capture, commit="test")
    RunStore(store_root).save(record)
    return record.run_id


@asynccontextmanager
async def connected(store_root: Path) -> AsyncIterator[ClientSession]:
    """A client session talking to a real MCP server, over the in-memory pair.

    The protocol is genuinely spoken \u2014 the server is the one `T3-05` built \u2014
    without spawning a process per test.
    """
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        server = build_server(store_root=store_root)
        task = asyncio.create_task(
            server.run(
                server_streams[0],
                server_streams[1],
                server.create_initialization_options(),
            )
        )
        try:
            async with ClientSession(client_streams[0], client_streams[1]) as session:
                await session.initialize()
                yield session
        finally:
            task.cancel()


async def tool_schemas(
    session: ClientSession, names: tuple[str, ...]
) -> tuple[Mapping[str, Any], ...]:
    """The schemas the **server** declares for the named tools.

    From the server rather than from a copy in the test: the schema's home is
    the server's, and a copy here would be a second one.
    """
    listed = await session.list_tools()
    return tuple(
        {
            "name": tool.name,
            "description": tool.description or "",
            "inputSchema": tool.input_schema,
        }
        for tool in listed.tools
        if tool.name in names
    )
