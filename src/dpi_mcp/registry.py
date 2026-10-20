"""The tool and resource catalogue (`T3-05`).

**Nothing here imports the `mcp` SDK.** The catalogue is plain data and plain
callables, so the contracts can be read, tested and checked against the Python
signatures they describe without a protocol library installed. `server.py` is the
only module in the package that imports the SDK, and the reason is the same one
`dpi_mcp/__init__.py` gives: a tool contract that cannot be tested without its
transport is a contract nobody tests.

Three things live here, and each is deliberately owned by exactly one place:

* **The schemas.** A JSON Schema per tool, hand-written, because a schema is the
  tool's *description* to an agent and a generated one describes the types rather
  than the meaning. The price of hand-writing is a second copy of the parameter
  list, so `tests/test_mcp_stdio.py` checks every schema against
  `inspect.signature` of the function it describes: a parameter that exists in
  Python and not in the schema (or the other way round) fails the suite. That is
  the `D-16` failure mode -- two homes for one fact -- caught before it ships.
* **The bounds.** Some parameters are the *server's* to choose, not the agent's:
  which store to read, and whether the run keeps its flow table. They are listed
  in `ToolSpec.bound`, they are absent from the schema, and the server supplies
  them. The agent gets a `run_id`, never a path.
* **The encoders.** Every tool answer is built from a projection the owner already
  publishes -- the engine's `CaptureProfile.to_dict`, the store's
  `RunRecord.to_json`, the simulator's `SimulationReport.to_dict`. This module
  does not invent a wire shape of its own.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dpi_engine.capture_profile import CaptureProfile
from dpi_engine.pcap_io import DEFAULT_MAX_PACKET_SIZE, DEFAULT_MAX_TOTAL_PACKETS
from dpi_engine.rules.simulator import SimulationReport
from dpi_mcp.run_store import RunStore, record_from_result
from dpi_mcp.tools.runs import (
    diff_runs,
    get_flow_detail,
    query_flows,
    ruleset_fingerprint,
    run_outcome,
)
from dpi_mcp.tools.single_run import (
    RunMode,
    inspect_capture,
    run_dpi,
    simulate_ruleset,
)
from dpi_mcp.tools.streaming import stream_dpi_events

__all__ = [
    "RESOURCE_TEMPLATES",
    "TOOL_SPECS",
    "ResourceSpec",
    "ServerContext",
    "ToolSpec",
    "run_outcome",
    "tool_names",
]


# ---------------------------------------------------------------------------
# The catalogue's shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ServerContext:
    """What the server binds and the agent does not choose.

    `store_root` is here rather than in a module global for the reason `T3-04`
    gave: configuration that is ambient cannot be exercised twice in one process,
    and it hides where a read or a write goes. The agent is given a `run_id`; the
    path is the operator's decision, made when the server was started.
    """

    store_root: Path


@dataclass(frozen=True)
class ToolSpec:
    """One tool: its name, its wire schema, and the callable behind it.

    `handler` is called with keyword arguments: the agent's arguments, plus the
    ones named in `bound`. `bound` parameters never appear in `input_schema`, so
    an agent cannot supply them even by accident.

    `kind` is `"call"` for a tool that answers with a value, and `"stream"` for
    one that produces events while it runs. The difference is not cosmetic: a
    streaming tool's answer arrives *after* its events, and the server has to
    drive it rather than call it.
    """

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[..., Any]
    bound: tuple[str, ...] = ()
    kind: str = "call"
    #: The function whose signature `input_schema` describes, when it is not the
    #: handler. `run_dpi`'s handler is a composition (it also stores the run), so
    #: the schema describes the *tool*, not the composition. Checked by
    #: `tests/test_mcp_stdio.py`, which compares every schema against
    #: `inspect.signature` of this function.
    described: Callable[..., Any] | None = None
    #: How the tool's answer becomes JSON-ready data, when the tool does not
    #: already return a dict. It is always a projection the *owner* publishes --
    #: the engine's `CaptureProfile.to_dict`, the simulator's
    #: `SimulationReport.to_dict` -- and never one written here, because a second
    #: copy of those fields is a second home for them (`D-16`).
    encode: Callable[[Any], Any] | None = None

    @property
    def signature_source(self) -> Callable[..., Any]:
        """The function whose parameters the schema must list."""
        return self.described if self.described is not None else self.handler

    @property
    def encoder(self) -> Callable[[Any], Any]:
        """The tool's answer, as JSON-ready data."""
        return self.encode if self.encode is not None else _identity


@dataclass(frozen=True)
class ResourceSpec:
    """One readable resource.

    `reader` takes the server context and the URI's own parts, and returns
    JSON-ready data.
    """

    uri: str
    name: str
    description: str
    mime_type: str
    reader: Callable[[ServerContext, str], Any]


# ---------------------------------------------------------------------------
# Shared schema fragments
# ---------------------------------------------------------------------------


def _identity(value: Any) -> Any:
    """The default encoder: the tool already returned JSON-ready data."""
    return value


def _object(properties: dict[str, Any], required: list[str], *, strict: bool = True) -> dict[str, Any]:
    """A JSON Schema for an object.

    `strict` forbids properties that are not listed. That is the right default
    for a tool's arguments: an unknown key is a typo, and a typo that is
    silently ignored becomes an agent that believes it asked for something it did
    not. The one exception is the five-tuple, which is documented to accept a
    whole flow row as input, so it allows extras.
    """
    schema: dict[str, Any] = {"type": "object", "properties": properties, "required": required}
    if strict:
        schema["additionalProperties"] = False
    return schema


_RULES_DOCUMENT = _object(
    {
        "blocked_ips": {
            "type": "array",
            "items": {"type": "string"},
            "description": "IP addresses to block, one per entry.",
        },
        "blocked_apps": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Application names to block, as the engine's names them (for example "
                "`TWITTER`, `FACEBOOK`). A name is matched as a bare substring, so "
                "`FACEBOOK` also matches `cdn.facebook.example`."
            ),
        },
        "blocked_domains": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Exact hostnames to block, one per entry.",
        },
        "blocked_ports": {
            "type": "array",
            "items": {"type": "integer"},
            "description": "Destination ports to block.",
        },
        "domain_patterns": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Wildcard domain rules, anchored at a domain boundary.",
        },
        "blocked_cidrs": {
            "type": "array",
            "items": {"type": "string"},
            "description": "CIDR ranges to block, in dotted-quad form.",
        },
    },
    [],
)

_FIVE_TUPLE = _object(
    {
        "src_ip": {"type": "integer", "description": "Source address as an integer."},
        "dst_ip": {"type": "integer", "description": "Destination address as an integer."},
        "src_port": {"type": "integer", "description": "Source port."},
        "dst_port": {"type": "integer", "description": "Destination port."},
        "protocol": {
            "type": "integer",
            "description": "IP protocol number: 6 for TCP, 17 for UDP.",
        },
    },
    ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"],
    strict=False,
)


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


def _run_dpi_and_store(**arguments: Any) -> dict[str, Any]:
    """`run_dpi`, and then the storing that makes the run-store tools able to answer.

    The composition lives here rather than in the server, because it is a policy
    about *runs* and not a fact about the protocol: a run that produced a flow
    table is stored, and the answer is the run's id. Without it, three of the
    tools have nothing to query -- the store would be populated by nothing but
    tests.

    `with_flow_table` is forced on: the store refuses to record a run with no
    flow table, because an empty table is indistinguishable from a capture with
    no flows.
    """
    store_root = arguments.pop("store_root")
    with_flow_table = arguments.pop("with_flow_table")
    capture = arguments["capture"]
    output = arguments["output"]
    ruleset = arguments.get("ruleset")

    result = run_dpi(**arguments, with_flow_table=with_flow_table)
    record = record_from_result(
        result,
        capture_path=capture,
        ruleset=ruleset_fingerprint(ruleset),
    )
    RunStore(store_root).save(record)
    return run_outcome(record, output=output)


# ---------------------------------------------------------------------------
# The tools
# ---------------------------------------------------------------------------

TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="inspect_capture",
        description=(
            "Describe a capture without inspecting any of it: identity, link type, "
            "snaplen, packet and byte counts, and the packet-length range. Use it to "
            "decide whether a file is worth running before running it."
        ),
        input_schema=_object(
            {
                "capture": {
                    "type": "string",
                    "description": "Path to the pcap file to describe.",
                },
                "max_packet_size": {
                    "type": "integer",
                    "description": "Largest record to accept, in bytes.",
                    "default": DEFAULT_MAX_PACKET_SIZE,
                },
                "max_total_packets": {
                    "type": "integer",
                    "description": "Largest number of records to read.",
                    "default": DEFAULT_MAX_TOTAL_PACKETS,
                },
            },
            ["capture"],
        ),
        handler=inspect_capture,
        encode=CaptureProfile.to_dict,
    ),
    ToolSpec(
        name="run_dpi",
        description=(
            "Classify a capture, write the forwarded packets to an output pcap, and "
            "store the run. The answer is the run's id, its counters, the apps and "
            "domains it found, and the flows it blocked; the run's flows are queried "
            "separately with `query_flows`."
        ),
        input_schema=_object(
            {
                "capture": {
                    "type": "string",
                    "description": "Path to the pcap file to classify.",
                },
                "output": {
                    "type": "string",
                    "description": "Path to write the forwarded packets to.",
                },
                "ruleset": {
                    **(_RULES_DOCUMENT),
                    "description": "The policy in force. Omit for no rules at all.",
                },
                "mode": {
                    "type": "string",
                    "enum": [mode.value for mode in RunMode],
                    "description": "Which engine entry point to run.",
                    "default": RunMode.SINGLE.value,
                },
                "workers": {
                    "type": "integer",
                    "description": "Worker processes, for the multiprocess modes.",
                    "default": 4,
                },
                "load_balancers": {
                    "type": "integer",
                    "description": "Load balancers, for the staged mode.",
                    "default": 2,
                },
                "fps_per_lb": {
                    "type": "integer",
                    "description": "Fast paths per load balancer, for the staged mode.",
                    "default": 2,
                },
                "enable_quic": {
                    "type": "boolean",
                    "description": "Decrypt QUIC Initial packets to read their SNI.",
                    "default": True,
                },
                "fold_bidirectional": {
                    "type": "boolean",
                    "description": (
                        "Fold a connection's two directions into one flow. On by "
                        "default: a block then applies to both directions."
                    ),
                    "default": True,
                },
                "max_packet_size": {
                    "type": "integer",
                    "description": "Largest record to accept, in bytes.",
                    "default": DEFAULT_MAX_PACKET_SIZE,
                },
                "max_total_packets": {
                    "type": "integer",
                    "description": "Largest number of records to read.",
                    "default": DEFAULT_MAX_TOTAL_PACKETS,
                },
            },
            ["capture", "output"],
        ),
        handler=_run_dpi_and_store,
        bound=("store_root", "with_flow_table"),
        described=run_dpi,
    ),
    ToolSpec(
        name="stream_dpi_events",
        description=(
            "Classify a capture and deliver the engine's events as they happen, as "
            "progress notifications. The events are the engine's own: one per packet "
            "parsed, and one per flow created, classified, blocked or evicted. The "
            "answer, when the run ends, is the run's id and its results. **The events "
            "arrive only if the client asked for progress notifications**; a client "
            "that did not is told so, rather than left to assume it saw them. "
            "Single-process only: the engine's other two modes publish one aggregated "
            "result each rather than a live stream."
        ),
        input_schema=_object(
            {
                "capture": {
                    "type": "string",
                    "description": "Path to the pcap file to classify.",
                },
                "output": {
                    "type": "string",
                    "description": "Path to write the forwarded packets to.",
                },
                "ruleset": {
                    **(_RULES_DOCUMENT),
                    "description": "The policy in force. Omit for no rules at all.",
                },
                "enable_quic": {
                    "type": "boolean",
                    "description": "Decrypt QUIC Initial packets to read their SNI.",
                    "default": True,
                },
                "fold_bidirectional": {
                    "type": "boolean",
                    "description": (
                        "Fold a connection's two directions into one flow. On by "
                        "default: a block then applies to both directions."
                    ),
                    "default": True,
                },
                "max_packet_size": {
                    "type": "integer",
                    "description": "Largest record to accept, in bytes.",
                    "default": DEFAULT_MAX_PACKET_SIZE,
                },
                "max_total_packets": {
                    "type": "integer",
                    "description": "Largest number of records to read.",
                    "default": DEFAULT_MAX_TOTAL_PACKETS,
                },
            },
            ["capture", "output"],
        ),
        handler=stream_dpi_events,
        bound=("store_root", "queue_size"),
        kind="stream",
    ),
    ToolSpec(
        name="simulate_ruleset",
        description=(
            "Report what a candidate ruleset would change about a capture, relative "
            "to the policy in force. Nothing is applied: this is the check to run "
            "before a policy change, not after it."
        ),
        input_schema=_object(
            {
                "capture": {
                    "type": "string",
                    "description": "Path to the pcap file to analyse.",
                },
                "candidate": {
                    **(_RULES_DOCUMENT),
                    "description": "The ruleset being considered.",
                },
                "output_dir": {
                    "type": "string",
                    "description": (
                        "Directory to write the two simulated output captures into. "
                        "It must be named: a tool that writes files nobody can find "
                        "is worse than one that writes them where you said."
                    ),
                },
                "baseline": {
                    **(_RULES_DOCUMENT),
                    "description": (
                        "The policy to compare against. Omit for no rules, which is "
                        "the policy usually in force."
                    ),
                },
                "enable_quic": {
                    "type": "boolean",
                    "description": "Decrypt QUIC Initial packets to read their SNI.",
                    "default": True,
                },
                "fold_bidirectional": {
                    "type": "boolean",
                    "description": "Fold a connection's two directions into one flow.",
                    "default": True,
                },
            },
            ["capture", "candidate", "output_dir"],
        ),
        handler=simulate_ruleset,
        encode=SimulationReport.to_dict,
    ),
    ToolSpec(
        name="query_flows",
        description=(
            "The stored flows of one run, filtered and capped. The answer carries "
            "both the number of flows that matched and the number returned, so a "
            "capped answer is visibly partial rather than apparently complete."
        ),
        input_schema=_object(
            {
                "run_id": {
                    "type": "string",
                    "description": "The run to query, as `run_dpi` returned it.",
                },
                "app": {
                    "type": ["string", "null"],
                    "description": "Keep only flows of this app, by engine name.",
                },
                "state": {
                    "type": ["string", "null"],
                    "description": "Keep only flows in this state, by engine name.",
                },
                "hostname": {
                    "type": ["string", "null"],
                    "description": "Keep only flows with this exact hostname.",
                },
                "ip": {
                    "type": ["string", "null"],
                    "description": (
                        "Keep only flows with this address on **either** endpoint, "
                        "in dotted-quad form."
                    ),
                },
                "protocol": {
                    "type": ["integer", "null"],
                    "description": "Keep only flows with this IP protocol number.",
                },
                "action": {
                    "type": ["string", "null"],
                    "description": "Keep only flows with this action, `FORWARD` or `BLOCK`.",
                },
                "min_bytes": {
                    "type": ["integer", "null"],
                    "description": "Keep only flows with at least this many bytes.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of flows to return. 0 means no cap.",
                    "default": 0,
                },
            },
            ["run_id"],
        ),
        handler=query_flows,
        bound=("store_root",),
    ),
    ToolSpec(
        name="get_flow_detail",
        description=(
            "One stored flow, addressed by its five-tuple. A flow the run never saw "
            "is reported as not found, which is a different answer from an error."
        ),
        input_schema=_object(
            {
                "run_id": {
                    "type": "string",
                    "description": "The run to look in, as `run_dpi` returned it.",
                },
                "flow": {
                    **_FIVE_TUPLE,
                    "description": (
                        "The flow's five-tuple. A whole row from `query_flows` is "
                        "accepted too, so one tool's output is the other's input."
                    ),
                },
            },
            ["run_id", "flow"],
        ),
        handler=get_flow_detail,
        bound=("store_root",),
    ),
    ToolSpec(
        name="diff_runs",
        description=(
            "What changed between two stored runs: the counters, and the flows that "
            "differ. The figures are signed and in the direction of the arguments."
        ),
        input_schema=_object(
            {
                "run_a": {
                    "type": "string",
                    "description": "The run to compare from.",
                },
                "run_b": {
                    "type": "string",
                    "description": "The run to compare to.",
                },
            },
            ["run_a", "run_b"],
        ),
        handler=diff_runs,
        bound=("store_root",),
    ),
)


def tool_names() -> tuple[str, ...]:
    """The tool names, in catalogue order."""
    return tuple(spec.name for spec in TOOL_SPECS)


# ---------------------------------------------------------------------------
# The resources
# ---------------------------------------------------------------------------
#
# Two, and both are the server's own state: what runs exist, and what one of them
# contains. The flows are deliberately *not* a resource -- they are a query, and
# `query_flows` is the query, with filters and a cap. A resource is for browsing;
# a tool is for asking.
#
# The scheme is `dpi://`, and the ids are the store's own: a run id is 16 hex
# characters, and the store validates it before it touches the filesystem, so a
# URI cannot walk out of the store's directory.


def _read_run_catalog(context: ServerContext, _uri: str) -> dict[str, Any]:
    summaries = RunStore(context.store_root).list_runs()
    return {
        "count": len(summaries),
        "runs": [summary.to_json() for summary in summaries],
    }


def _read_run(context: ServerContext, run_id: str) -> dict[str, Any]:
    return run_outcome(RunStore(context.store_root).load(run_id))


RESOURCE_TEMPLATES: tuple[ResourceSpec, ...] = (
    ResourceSpec(
        uri="dpi://runs",
        name="stored runs",
        description="Every run this server has stored, oldest first.",
        mime_type="application/json",
        reader=_read_run_catalog,
    ),
    ResourceSpec(
        uri="dpi://runs/{run_id}",
        name="a stored run",
        description=(
            "One stored run: its counters, the apps and domains it found, and the "
            "flows it blocked. Its flow table is queried with `query_flows`."
        ),
        mime_type="application/json",
        reader=_read_run,
    ),
)
