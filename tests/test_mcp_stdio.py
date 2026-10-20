"""The MCP server, exercised by a real client over real pipes (`T3-05`).

**Not a mock.** A mock proves the mock: it proves that the code calls the
functions the test author expected, which is not the same as proving that a
client can start a server, complete a handshake, list the tools and get an
answer back. So these tests spawn `python -m dpi_mcp.server` as a subprocess and
talk to it with the SDK's own stdio client, over the same inherited pipes a
host application would use.

Two of the things being checked are contracts rather than behaviour, and both
exist because a second copy of a fact is a thing that drifts:

* **The schema/signature guard.** Every tool's JSON Schema is hand-written, so it
  is a second list of the tool's parameters. The guard compares each schema
  against `inspect.signature` of the function it describes, so a parameter that
  exists in Python and not on the wire (or the other way round) fails the suite.
* **The declared tool set.** The client's list is compared against a pinned set,
  so adding or dropping a tool is a deliberate act with a failing test attached.

The `mcp` SDK is a **dev dependency and an optional extra** (`DEC-09`), and it is
installed here -- so these tests are not skipped for want of a dependency, and a
skip that reads as a pass is exactly the failure this project keeps meeting.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from conftest import TEST_DPI_PCAP
from dpi_mcp.registry import RESOURCE_TEMPLATES, TOOL_SPECS

#: The tools this server offers. Pinned rather than derived, so adding or
#: dropping one is a deliberate act with a failing test attached -- the same
#: treatment `QUERY_KEYS` and `FLOW_KEYS` got in `T3-04`.
#:
#: These are `DEC-08`'s seven. `stream_dpi_events` was the last of them
#: (`T3-07`); the four tools `DEC-08` deferred stay absent rather than stubbed,
#: because a tool that returns "not implemented" is worse than an absent one.
DECLARED_TOOLS = {
    "inspect_capture",
    "run_dpi",
    "simulate_ruleset",
    "query_flows",
    "get_flow_detail",
    "diff_runs",
    "stream_dpi_events",
}

#: The resources this server offers.
DECLARED_RESOURCES = {"dpi://runs"}


def _server_parameters(store_root: Path) -> StdioServerParameters:
    """How to start the server: this interpreter, this module, this store."""
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "dpi_mcp.server", "--store-root", str(store_root)],
    )


def _payload(result: Any) -> Any:
    """The JSON a tool call returned.

    The answer is JSON text, so it is parsed here rather than read as an object:
    a client that only reads text must not receive a blank, and parsing it is
    what proves it is well-formed JSON.
    """
    assert not result.is_error, f"the call failed: {result.content}"
    text = result.content[0].text
    return json.loads(text)


async def _with_session(store_root: Path, body: Any) -> Any:
    """Run `body(session)` against a freshly started server."""
    async with stdio_client(_server_parameters(store_root)) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            return await body(session)


# ---------------------------------------------------------------------------
# The catalogue, checked against the code it describes
# ---------------------------------------------------------------------------


class TestTheSchemasMatchTheCode:
    """A schema that has drifted from its function is a lie to every agent."""

    def test_every_tool_names_the_parameters_its_function_has(self) -> None:
        for spec in TOOL_SPECS:
            parameters = inspect.signature(spec.signature_source).parameters
            agent_parameters = {name for name in parameters if name not in spec.bound}
            schema_parameters = set(spec.input_schema["properties"])
            assert schema_parameters == agent_parameters, (
                f"{spec.name}: the schema names {sorted(schema_parameters)} but the function "
                f"takes {sorted(agent_parameters)}. A parameter the agent cannot see is a "
                "parameter it cannot set; one it can set and the function does not take is "
                "a call that fails at the boundary."
            )

    def test_every_required_parameter_is_one_the_function_demands(self) -> None:
        for spec in TOOL_SPECS:
            parameters = inspect.signature(spec.signature_source).parameters
            demanded = {
                name
                for name, parameter in parameters.items()
                if name not in spec.bound
                and parameter.default is inspect.Parameter.empty
                and parameter.kind
                in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
            }
            required = set(spec.input_schema.get("required", []))
            assert required == demanded, (
                f"{spec.name}: required {sorted(required)} but the function demands "
                f"{sorted(demanded)}. Marking an optional parameter required makes the "
                "client invent a value; failing to mark a demanded one makes a valid "
                "call look malformed."
            )

    def test_a_server_bound_parameter_is_never_in_the_schema(self) -> None:
        """The agent must not be able to choose where the server reads or writes."""
        for spec in TOOL_SPECS:
            for name in spec.bound:
                assert name not in spec.input_schema["properties"], (
                    f"{spec.name}: {name!r} is the server's to choose, and the agent is "
                    "not offered it"
                )

    def test_the_declared_tool_set_is_the_one_the_catalogue_holds(self) -> None:
        assert {spec.name for spec in TOOL_SPECS} == DECLARED_TOOLS

    def test_every_tool_has_a_description(self) -> None:
        """A tool with no description is a tool an agent has to guess at."""
        for spec in TOOL_SPECS:
            assert spec.description.strip(), f"{spec.name} has no description"
            for name, fragment in spec.input_schema["properties"].items():
                assert fragment.get("description", "").strip(), (
                    f"{spec.name}.{name} has no description"
                )


# ---------------------------------------------------------------------------
# The handshake, over real pipes
# ---------------------------------------------------------------------------


class TestTheHandshake:
    def test_a_real_client_lists_every_declared_tool(self, tmp_path: Path) -> None:
        """The gate `T3-05` was written for: a real client, a real handshake."""

        async def scenario(session: ClientSession) -> None:
            listed = await session.list_tools()
            assert {tool.name for tool in listed.tools} == DECLARED_TOOLS
            for tool in listed.tools:
                assert tool.description, f"{tool.name} arrived with no description"
                assert tool.input_schema["type"] == "object"

        asyncio.run(_with_session(tmp_path / "store", scenario))

    def test_the_server_answers_a_call_over_the_protocol(self, tmp_path: Path) -> None:
        async def scenario(session: ClientSession) -> None:
            result = await session.call_tool("inspect_capture", {"capture": str(TEST_DPI_PCAP)})
            payload = _payload(result)
            assert payload["packet_count"] == 77
            assert payload["path"] == str(TEST_DPI_PCAP)

        asyncio.run(_with_session(tmp_path / "store", scenario))

    def test_a_bad_argument_is_a_tool_error_and_not_a_broken_session(
        self, tmp_path: Path
    ) -> None:
        """An error the agent can fix must come back as an error, and the session
        must survive it: a crashed server is not a conversation."""

        async def scenario(session: ClientSession) -> None:
            bad = await session.call_tool("query_flows", {"run_id": "not-a-run-id"})
            assert bad.is_error, "an unknown run id must not read as an empty result"
            assert "not-a-run-id" in bad.content[0].text

            # The session is still usable, which is the point.
            after = await session.call_tool("inspect_capture", {"capture": str(TEST_DPI_PCAP)})
            assert not after.is_error

        asyncio.run(_with_session(tmp_path / "store", scenario))


# ---------------------------------------------------------------------------
# The workflow the tools are for
# ---------------------------------------------------------------------------


class TestTheWholeWorkflow:
    def test_a_run_is_stored_and_can_then_be_queried(self, tmp_path: Path) -> None:
        """Run, store, query, look up, diff -- over the protocol, not in-process.

        This is the sequence an agent actually performs, and it is the only thing
        that proves the pieces fit: a `run_dpi` that returns a run id is worth
        nothing if `query_flows` cannot find that run afterwards.
        """

        async def scenario(session: ClientSession) -> None:
            output = tmp_path / "forwarded.pcap"
            run = _payload(
                await session.call_tool(
                    "run_dpi",
                    {"capture": str(TEST_DPI_PCAP), "output": str(output)},
                )
            )
            assert output.exists(), "run_dpi did not write its output capture"
            run_id = run["run_id"]
            assert run_id
            assert run["stats"]["total_packets"] == 77
            assert "flows" not in run, "the run's flows belong to query_flows, not to the answer"

            flows = _payload(await session.call_tool("query_flows", {"run_id": run_id}))
            assert flows["matched"] == flows["returned"] > 0
            first = flows["flows"][0]
            assert set(first) >= {"src_ip", "dst_ip", "src_port", "dst_port", "protocol"}

            detail = _payload(
                await session.call_tool(
                    "get_flow_detail", {"run_id": run_id, "flow": first}
                )
            )
            assert detail["found"] is True
            assert detail["flow"]["src_ip"] == first["src_ip"]

            # A flow the run never saw is an answer, not an error.
            absent = _payload(
                await session.call_tool(
                    "get_flow_detail",
                    {
                        "run_id": run_id,
                        "flow": {
                            "src_ip": 1,
                            "dst_ip": 2,
                            "src_port": 3,
                            "dst_port": 4,
                            "protocol": 6,
                        },
                    },
                )
            )
            assert absent["found"] is False

            # The stored runs are browsable as a resource, and the run is one of them.
            resources = await session.list_resources()
            assert {str(resource.uri) for resource in resources.resources} == DECLARED_RESOURCES

            catalog = await session.read_resource("dpi://runs")
            assert json.loads(catalog.contents[0].text)["count"] == 1

            one = await session.read_resource(f"dpi://runs/{run_id}")
            assert json.loads(one.contents[0].text)["run_id"] == run_id

        asyncio.run(_with_session(tmp_path / "store", scenario))

    def test_two_runs_can_be_compared_through_the_protocol(self, tmp_path: Path) -> None:
        async def scenario(session: ClientSession) -> None:
            first = _payload(
                await session.call_tool(
                    "run_dpi",
                    {
                        "capture": str(TEST_DPI_PCAP),
                        "output": str(tmp_path / "a.pcap"),
                        "ruleset": {"blocked_apps": ["TWITTER"]},
                    },
                )
            )
            second = _payload(
                await session.call_tool(
                    "run_dpi",
                    {
                        "capture": str(TEST_DPI_PCAP),
                        "output": str(tmp_path / "b.pcap"),
                        "ruleset": {"blocked_apps": ["TWITTER", "FACEBOOK"]},
                    },
                )
            )
            assert first["run_id"] != second["run_id"]

            diff = _payload(
                await session.call_tool(
                    "diff_runs", {"run_a": first["run_id"], "run_b": second["run_id"]}
                )
            )
            assert diff["run_a"] == first["run_id"]
            assert "drop_rate_change_percent" in diff["counters"] or "counters" in diff

        asyncio.run(_with_session(tmp_path / "store", scenario))

    def test_a_ruleset_can_be_simulated_through_the_protocol(self, tmp_path: Path) -> None:
        async def scenario(session: ClientSession) -> None:
            report = _payload(
                await session.call_tool(
                    "simulate_ruleset",
                    {
                        "capture": str(TEST_DPI_PCAP),
                        "candidate": {"blocked_apps": ["TWITTER"]},
                        "output_dir": str(tmp_path / "sim"),
                    },
                )
            )
            assert report["candidate_blocked"] >= report["baseline_blocked"]
            assert report["drop_rate_change_percent"] >= 0

        asyncio.run(_with_session(tmp_path / "store", scenario))


class TestTheStreamingTool:
    """`T3-07`: the events arrive as progress notifications, over the protocol."""

    def test_events_arrive_as_progress_notifications(self, tmp_path: Path) -> None:
        """A real client, a real notification stream.

        The events travel in the notification's `message`, which is the only
        channel MCP gives a server for out-of-band data, and they are the
        engine's own -- `CaptureOpened`, `PacketParsed` and the rest.
        """

        async def scenario(session: ClientSession) -> tuple[list[str], dict[str, Any]]:
            seen: list[str] = []

            async def on_progress(
                progress: float, total: float | None, message: str | None
            ) -> None:
                assert total is None
                assert progress > 0
                if message is not None:
                    seen.append(message)

            result = await session.call_tool(
                "stream_dpi_events",
                {
                    "capture": str(TEST_DPI_PCAP),
                    "output": str(tmp_path / "streamed.pcap"),
                },
                progress_callback=on_progress,
            )
            return seen, _payload(result)

        seen, payload = asyncio.run(_with_session(tmp_path / "store", scenario))
        assert seen, "no progress notifications arrived"
        kinds = {json.loads(message)["kind"] for message in seen}
        assert "CaptureOpened" in kinds
        assert "PacketParsed" in kinds
        assert payload["progress_requested"] is True
        assert payload["events_delivered"] == len(seen)
        assert payload["events_produced"] >= len(seen)
        assert payload["run_id"]
        assert (tmp_path / "streamed.pcap").exists()

    def test_a_client_that_asked_for_no_progress_is_told_it_saw_nothing(
        self, tmp_path: Path
    ) -> None:
        """The honest answer when the channel was never opened.

        The SDK's `report_progress` is a no-op when the caller did not request
        progress, so a client that did not ask would otherwise be left to infer
        from an empty stream that the run produced nothing.
        """

        async def scenario(session: ClientSession) -> dict[str, Any]:
            result = await session.call_tool(
                "stream_dpi_events",
                {
                    "capture": str(TEST_DPI_PCAP),
                    "output": str(tmp_path / "streamed.pcap"),
                },
            )
            return _payload(result)

        payload = asyncio.run(_with_session(tmp_path / "store", scenario))
        assert payload["progress_requested"] is False
        assert payload["events_delivered"] == 0
        assert payload["events_produced"] > 0, "the run did produce events"
        assert payload["run_id"]


# ---------------------------------------------------------------------------
# What the server must not be
# ---------------------------------------------------------------------------


def test_the_sdk_is_actually_installed_here() -> None:
    """`T3-03`'s "the tools work without the SDK" proof is only evidence if the
    SDK *could* have been imported.

    `DEC-09` made the SDK a dev dependency, so the proof in
    `tests/test_tools_single_run.py` -- a subprocess in which `import mcp` fails,
    running the tool layer anyway -- is no longer vacuous. Without this
    assertion, a broken install would make that proof pass for the wrong
    reason: the same vacuous-pass trap the project keeps meeting.
    """
    import mcp

    assert mcp is not None
    assert Path(mcp.__file__ or "").exists()


def test_the_resource_templates_are_declared() -> None:
    templates = {spec.uri for spec in RESOURCE_TEMPLATES if "{" in spec.uri}
    assert templates == {"dpi://runs/{run_id}"}
