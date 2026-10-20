"""Run store: persist and query a finished run's flows, stats and events (`T3-02`).

**Why this exists.** `T3-06` made a *live* `PipelineResult` carry per-flow rows, but a
`PipelineResult` dies with the process that produced it. Three of Phase 3's seven tools
(`query_flows`, `get_flow_detail`, `diff_runs`) answer questions an agent asks *after*
the run, often in a later tool call, and Phase 4's Triage and ClassifierGap agents both
start from `query_flows`. Without a store, those tools have nothing to read.

## Four decisions that shape this module

**1. The run id is content-addressed, not a timestamp.** It hashes what the run
*observed* -- capture digest, engine commit, optional ruleset fingerprint, and the
canonical result payload -- so the same observation always gets the same id. That has
two consequences worth stating:

- Re-saving a run is idempotent, and the stored `created_at` is the *first* observation
  rather than being rewritten on every save.
- If the same id is ever re-saved with a **different** payload, `save` raises. Given a
  deterministic engine that can only mean a hash collision or genuine nondeterminism,
  and both are things a caller must not be told about by silence.

The id identifies an *observation*, not a configuration. Two different rulesets that
produce byte-identical output collapse onto one id unless the caller supplies a
`ruleset` fingerprint -- documented on `record_from_result`, because "these runs differ"
is exactly what `diff_runs` is asked to answer and it must not be wrong in the
direction of reporting a difference that is not there.

**2. Events are stored at flow scale, and what is dropped is counted.** `FlowClassified`
is emitted **once per inspected packet**, not once per flow (see `events.py`), so a
naive "persist the event stream" design is O(packets) rather than O(flows) and would
reintroduce the unbounded-retention problem `D-01`/`D-02` went to some trouble to
remove. Only the flow- and run-scale events are kept; `events_omitted` records, by type,
exactly how many were not. `len(event_log) + sum(events_omitted.values())` equals the
number of events offered, so a reader can *prove* the log is partial instead of
assuming it is complete. The retained `sequence` numbers are positions in the original
stream, so the gaps are visible rather than silently closed up.

**3. Malformed data raises. It never reads as an empty result.** This is the house rule
from `tests/eval/history.py`, and it matters more here: `query_flows` returning `[]`
because a file was truncated is indistinguishable from a genuine "this capture had no
matching flows". A schema mismatch raises with the version it found.

**4. Writes are atomic.** A run is written to a temporary file in the same directory and
then `os.replace`d into position, so a crash mid-write cannot leave a half-JSON file
that a later `load` would have to guess about.

**Safety envelope:** `OFFLINE_CORE`. This module reads and writes local files and does
nothing else -- no network, no subprocess, no dynamic execution. The safety suite scans
it like any other shipped source.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dpi_engine.capture_profile import capture_digest
from dpi_engine.events import (
    CaptureClosed,
    CaptureOpened,
    Event,
    FlowBlocked,
    FlowCreated,
    FlowEvicted,
    LimitExceeded,
)
from dpi_engine.pipeline import PipelineResult
from dpi_engine.types import AppType, ConnectionState, FiveTuple, FlowRecord

__all__ = [
    "SCHEMA",
    "BlockedFlow",
    "CounterDelta",
    "FlowChange",
    "FlowFilter",
    "RunDiff",
    "RunEvent",
    "RunRecord",
    "RunStats",
    "RunStore",
    "RunSummary",
    "capture_digest",
    "diff_records",
    "flow_from_json",
    "flow_to_json",
    "record_from_result",
]

#: Bumped when the on-disk shape changes incompatibly. `load` refuses a mismatch
#: rather than interpreting old data through new field meanings.
SCHEMA = "dpi-run/v1"

#: Run ids address a file, so they are validated before use. An agent supplies the id
#: in a later tool call; without this, `load("../../etc/passwd")` would be a path
#: traversal rather than a bad argument.
#:
#: Checked against an explicit character allowlist rather than a regex. Partly because
#: an allowlist is the more obviously correct shape -- every character this store ever
#: writes into an id comes from `hexdigest()[:16]` -- and partly because `re.compile` is
#: itself reported as `dynamic_exec` by the safety envelope's secondary regex net
#: (`D-28`), so a regex here would mean the store could only stay inside `OFFLINE_CORE`
#: by avoiding a stdlib module it has every reason to use.
_RUN_ID_LENGTH = 16
_RUN_ID_ALPHABET = frozenset("0123456789abcdef")


def _is_run_id(value: str) -> bool:
    """True when `value` is exactly 16 lowercase hex characters."""
    return len(value) == _RUN_ID_LENGTH and all(char in _RUN_ID_ALPHABET for char in value)


_APP_NAMES = frozenset(app.name for app in AppType)
_STATE_NAMES = frozenset(state.name for state in ConnectionState)


# ---------------------------------------------------------------------------
# Small JSON helpers, so every decode has one place to be strict
# ---------------------------------------------------------------------------


def _opt_int(raw: Mapping[str, Any], key: str) -> int | None:
    """Decodes `int | None`, where `None` means "not measured" rather than zero.

    The distinction is load-bearing: a run that did not compute `global_stats` has not
    measured its connection totals, and reporting `0` would be a claim about the capture
    rather than a statement about the run.
    """
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{key} must be an integer or null, got {value!r}")
    return value


def _int(raw: Mapping[str, Any], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{key} must be an integer, got {value!r}")
    return value


def _str(raw: Mapping[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string, got {value!r}")
    return value


def _list(raw: Mapping[str, Any], key: str) -> list[Any]:
    value = raw.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a list, got {type(value).__name__}")
    return value


def _canonical(payload: Mapping[str, Any]) -> str:
    """One spelling of a payload, so a digest does not depend on key order."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RunStats:
    """The counters a stored run reports.

    Deliberately a *copy* of the engine's counters rather than a live `DPIStats`:
    a stored run must not change when the process that produced it moves on, and
    `DPIStats` is mutable by design.
    """

    total_packets: int = 0
    total_bytes: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    other_packets: int = 0
    active_connections: int = 0
    #: `None` when the run did not compute `global_stats`. See `_opt_int`.
    total_connections_seen: int | None = None
    classified_connections: int | None = None
    blocked_connections: int | None = None

    @classmethod
    def from_result(cls, result: PipelineResult) -> RunStats:
        stats = result.stats
        global_stats = result.global_stats
        return cls(
            total_packets=stats.total_packets,
            total_bytes=stats.total_bytes,
            forwarded_packets=stats.forwarded_packets,
            dropped_packets=stats.dropped_packets,
            tcp_packets=stats.tcp_packets,
            udp_packets=stats.udp_packets,
            other_packets=stats.other_packets,
            active_connections=stats.active_connections,
            total_connections_seen=(
                None if global_stats is None else global_stats.total_connections_seen
            ),
            classified_connections=(
                None if global_stats is None else global_stats.classified_connections
            ),
            blocked_connections=(
                None if global_stats is None else global_stats.blocked_connections
            ),
        )

    @property
    def drop_rate_percent(self) -> float:
        """Dropped packets as a percentage of *inspected* (TCP/UDP) packets.

        Same denominator as `PipelineResult.drop_rate_percent`, and the same reason:
        frames no rule could ever have matched must not dilute the figure.
        """
        inspected = self.tcp_packets + self.udp_packets
        if inspected == 0:
            return 0.0
        return 100.0 * self.dropped_packets / inspected

    def to_json(self) -> dict[str, Any]:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "forwarded_packets": self.forwarded_packets,
            "dropped_packets": self.dropped_packets,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "other_packets": self.other_packets,
            "active_connections": self.active_connections,
            "total_connections_seen": self.total_connections_seen,
            "classified_connections": self.classified_connections,
            "blocked_connections": self.blocked_connections,
        }

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> RunStats:
        return cls(
            total_packets=_int(raw, "total_packets"),
            total_bytes=_int(raw, "total_bytes"),
            forwarded_packets=_int(raw, "forwarded_packets"),
            dropped_packets=_int(raw, "dropped_packets"),
            tcp_packets=_int(raw, "tcp_packets"),
            udp_packets=_int(raw, "udp_packets"),
            other_packets=_int(raw, "other_packets"),
            active_connections=_int(raw, "active_connections"),
            total_connections_seen=_opt_int(raw, "total_connections_seen"),
            classified_connections=_opt_int(raw, "classified_connections"),
            blocked_connections=_opt_int(raw, "blocked_connections"),
        )


@dataclass(frozen=True, slots=True)
class BlockedFlow:
    """One flow a rule blocked, as `PipelineResult.blocked_flows` describes it."""

    five_tuple: FiveTuple
    app: str
    hostname: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "src_ip": self.five_tuple.src_ip,
            "dst_ip": self.five_tuple.dst_ip,
            "src_port": self.five_tuple.src_port,
            "dst_port": self.five_tuple.dst_port,
            "protocol": self.five_tuple.protocol,
            "app": self.app,
            "hostname": self.hostname,
        }

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> BlockedFlow:
        return cls(
            five_tuple=FiveTuple(
                src_ip=_int(raw, "src_ip"),
                dst_ip=_int(raw, "dst_ip"),
                src_port=_int(raw, "src_port"),
                dst_port=_int(raw, "dst_port"),
                protocol=_int(raw, "protocol"),
            ),
            app=_str(raw, "app"),
            hostname=_str(raw, "hostname"),
        )


@dataclass(frozen=True, slots=True)
class RunEvent:
    """One retained event from a run's stream.

    `sequence` is the event's position in the **original** stream, not in this log.
    A log containing events 0, 3 and 9 is therefore visibly a sample of a longer
    stream instead of an apparently complete three-event run.
    """

    sequence: int
    kind: str
    five_tuple: FiveTuple | None = None
    app: str = ""
    hostname: str = ""
    detail: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "kind": self.kind,
            "five_tuple": None if self.five_tuple is None else list(self.five_tuple),
            "app": self.app,
            "hostname": self.hostname,
            "detail": self.detail,
        }

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> RunEvent:
        raw_tuple = raw.get("five_tuple")
        five_tuple: FiveTuple | None = None
        if raw_tuple is not None:
            if not isinstance(raw_tuple, list) or len(raw_tuple) != 5:
                raise ValueError(f"five_tuple must be a 5-element list, got {raw_tuple!r}")
            five_tuple = FiveTuple(
                src_ip=_int({"v": raw_tuple[0]}, "v"),
                dst_ip=_int({"v": raw_tuple[1]}, "v"),
                src_port=_int({"v": raw_tuple[2]}, "v"),
                dst_port=_int({"v": raw_tuple[3]}, "v"),
                protocol=_int({"v": raw_tuple[4]}, "v"),
            )
        return cls(
            sequence=_int(raw, "sequence"),
            kind=_str(raw, "kind"),
            five_tuple=five_tuple,
            app=_str(raw, "app"),
            hostname=_str(raw, "hostname"),
            detail=_str(raw, "detail"),
        )


@dataclass(frozen=True, slots=True)
class RunRecord:
    """One finished run, as stored.

    Immutable and fully comparable: two records are equal exactly when every field is,
    which is what lets `RunStore.save` detect that a re-save disagrees with what is
    already on disk.
    """

    run_id: str
    capture_path: str
    capture_sha256: str
    capture_bytes: int
    created_at: str
    commit: str
    stats: RunStats
    #: Sorted `(AppType.name, count)` pairs. `app_counts` in the engine is a per-packet
    #: tally keyed by enum; both properties are lost by storing a bare dict, and the
    #: sort makes the on-disk payload order-independent.
    app_counts: tuple[tuple[str, int], ...] = ()
    #: Sorted `(hostname, AppType.name)` pairs.
    detected_domains: tuple[tuple[str, str], ...] = ()
    #: Sorted by five-tuple.
    blocked_flows: tuple[BlockedFlow, ...] = ()
    #: Sorted by five-tuple, exactly as `to_flow_records` produced them (`T3-06`).
    flows: tuple[FlowRecord, ...] = ()
    #: `None` when the caller did not offer an event stream. Distinct from `()`: an
    #: empty log that was *collected* means the run emitted no retainable events, which
    #: is a claim about the run, not about the caller.
    event_log: tuple[RunEvent, ...] | None = None
    #: Event type name -> how many events of that type were deliberately not stored.
    events_omitted: tuple[tuple[str, int], ...] = ()
    #: Caller-supplied fingerprint of the ruleset used. Empty when not supplied; see the
    #: module docstring on why this is not inferred.
    ruleset: str = ""
    schema: str = SCHEMA

    # -- identity ---------------------------------------------------------

    def fingerprint_payload(self) -> dict[str, Any]:
        """The part of a record that identifies the *observation*.

        Excludes `run_id` (derived from this), `created_at` (when it was stored, not
        what was seen), `event_log`/`events_omitted` (derived from the same run and
        bounded differently depending on whether a caller offered them), and `schema`
        (a storage concern, not an observation).
        """
        return {
            "capture_sha256": self.capture_sha256,
            "commit": self.commit,
            "ruleset": self.ruleset,
            "stats": self.stats.to_json(),
            "app_counts": [list(pair) for pair in self.app_counts],
            "detected_domains": [list(pair) for pair in self.detected_domains],
            "blocked_flows": [flow.to_json() for flow in self.blocked_flows],
            "flows": [flow_to_json(flow) for flow in self.flows],
        }

    def computed_run_id(self) -> str:
        return hashlib.sha256(_canonical(self.fingerprint_payload()).encode("utf-8")).hexdigest()[
            :16
        ]

    # -- serialisation ----------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "run_id": self.run_id,
            "capture_path": self.capture_path,
            "capture_sha256": self.capture_sha256,
            "capture_bytes": self.capture_bytes,
            "created_at": self.created_at,
            "commit": self.commit,
            "ruleset": self.ruleset,
            "stats": self.stats.to_json(),
            "app_counts": [list(pair) for pair in self.app_counts],
            "detected_domains": [list(pair) for pair in self.detected_domains],
            "blocked_flows": [flow.to_json() for flow in self.blocked_flows],
            "flows": [flow_to_json(flow) for flow in self.flows],
            "event_log": (
                None if self.event_log is None else [event.to_json() for event in self.event_log]
            ),
            "events_omitted": [list(pair) for pair in self.events_omitted],
        }

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> RunRecord:
        found = raw.get("schema")
        if found != SCHEMA:
            raise ValueError(
                f"this record is schema {found!r}, but this build reads {SCHEMA!r}. "
                "Refusing to interpret old data through new field meanings; re-record "
                "the run with the current engine instead."
            )

        raw_event_log = raw.get("event_log")
        event_log: tuple[RunEvent, ...] | None = None
        if raw_event_log is not None:
            event_log = tuple(
                RunEvent.from_json(item) for item in _list_of_mapping(raw, "event_log")
            )

        return cls(
            run_id=_str(raw, "run_id"),
            capture_path=_str(raw, "capture_path"),
            capture_sha256=_str(raw, "capture_sha256"),
            capture_bytes=_int(raw, "capture_bytes"),
            created_at=_str(raw, "created_at"),
            commit=_str(raw, "commit"),
            ruleset=_str(raw, "ruleset"),
            stats=RunStats.from_json(_mapping(raw, "stats")),
            app_counts=_pairs_int(_list(raw, "app_counts"), "app_counts"),
            detected_domains=_pairs_str(_list(raw, "detected_domains"), "detected_domains"),
            blocked_flows=tuple(
                BlockedFlow.from_json(item) for item in _list_of_mapping(raw, "blocked_flows")
            ),
            flows=tuple(
                flow_from_json(item) for item in _list_of_mapping(raw, "flows")
            ),
            event_log=event_log,
            events_omitted=_pairs_int(_list(raw, "events_omitted"), "events_omitted"),
            schema=SCHEMA,
        )

    # -- views ------------------------------------------------------------

    def summary(self) -> RunSummary:
        return RunSummary(
            run_id=self.run_id,
            capture_path=self.capture_path,
            created_at=self.created_at,
            commit=self.commit,
            total_packets=self.stats.total_packets,
            dropped_packets=self.stats.dropped_packets,
            flow_count=len(self.flows),
        )


@dataclass(frozen=True, slots=True)
class RunSummary:
    """The cheap header `list_runs` returns, without the flow table.

    A separate type because `list_runs` is a directory listing, not a data transfer: it
    must not look like it has flows, or a caller will index into it and find none.
    """

    run_id: str
    capture_path: str
    created_at: str
    commit: str
    total_packets: int
    dropped_packets: int
    flow_count: int

    def to_json(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "capture_path": self.capture_path,
            "created_at": self.created_at,
            "commit": self.commit,
            "total_packets": self.total_packets,
            "dropped_packets": self.dropped_packets,
            "flow_count": self.flow_count,
        }


# ---------------------------------------------------------------------------
# Flow codec
#
# Kept here rather than on `FlowRecord` because the wire format belongs to the store.
# `types.py` is the engine's vocabulary and has no notion of persistence; putting a
# JSON codec on the type would make the engine own a storage decision.
#
# Public since `T3-04`: the run-store tools answer with the same rows this writes, and
# `get_flow_detail` reads its argument back through the same projection. A second
# copy of the field list would be a second place for the two to drift apart.
# ---------------------------------------------------------------------------


def flow_to_json(flow: FlowRecord) -> dict[str, Any]:
    return {
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "app": flow.app,
        "state": flow.state,
        "hostname": flow.hostname,
        "packets": flow.packets,
        "bytes": flow.bytes,
        "action": flow.action,
    }


def flow_from_json(raw: Mapping[str, Any]) -> FlowRecord:
    return FlowRecord(
        src_ip=_int(raw, "src_ip"),
        dst_ip=_int(raw, "dst_ip"),
        src_port=_int(raw, "src_port"),
        dst_port=_int(raw, "dst_port"),
        protocol=_int(raw, "protocol"),
        app=_str(raw, "app"),
        state=_str(raw, "state"),
        hostname=_str(raw, "hostname"),
        packets=_int(raw, "packets"),
        bytes=_int(raw, "bytes"),
        action=_str(raw, "action"),
    )


# ---------------------------------------------------------------------------
# Decoding helpers for nested containers
# ---------------------------------------------------------------------------


def _mapping(raw: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be an object, got {type(value).__name__}")
    return value


def _list_of_mapping(raw: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    items = _list(raw, key)
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"{key}[{index}] must be an object, got {type(item).__name__}")
    return items


def _pairs_int(items: list[Any], key: str) -> tuple[tuple[str, int], ...]:
    pairs: list[tuple[str, int]] = []
    for index, item in enumerate(items):
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError(f"{key}[{index}] must be a 2-element list, got {item!r}")
        name, value = item
        if not isinstance(name, str) or not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{key}[{index}] must be [str, int], got {item!r}")
        pairs.append((name, value))
    return tuple(pairs)


def _pairs_str(items: list[Any], key: str) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for index, item in enumerate(items):
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError(f"{key}[{index}] must be a 2-element list, got {item!r}")
        name, value = item
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError(f"{key}[{index}] must be [str, str], got {item!r}")
        pairs.append((name, value))
    return tuple(pairs)


# ---------------------------------------------------------------------------
# Capture identity
# ---------------------------------------------------------------------------

# `capture_digest` is imported from `dpi_engine.capture_profile` and re-exported here
# (`T3-03`). It used to be defined in this module, but a capture's digest is a property
# of the *capture*, and `inspect_capture` has to report the same value -- so the
# definition moved to the engine and this module keeps the name working for callers and
# for `test_run_store.py`. Two implementations of "sha256 of the capture" could disagree
# about truncation, and a run id that disagrees with the profile it was built from is
# worse than either being wrong alone.


# ---------------------------------------------------------------------------
# Building a record from a live result
# ---------------------------------------------------------------------------


def _event_to_record(sequence: int, event: Event) -> RunEvent | None:
    """The stored form of `event`, or `None` if this log does not represent it.

    `None` rather than an exception, and not an allowlist checked by the caller: the
    decision about what is representable belongs next to the representation, and the
    caller's job is only to count what came back empty-handed.

    There is deliberately no allowlist tuple here, which means a **future event type is
    counted in `events_omitted` by default** rather than silently dropped -- the safe
    direction for a log that is already known to be partial.

    Only flow- and run-scale events are represented. `PacketParsed` and `FlowClassified`
    are both emitted once per inspected packet, and their aggregates are already on the
    record (`RunStats`, `RunRecord.app_counts`), so retaining them would be O(packets)
    and would undo the bounded retention `D-01`/`D-02` established.
    """
    if isinstance(event, FlowBlocked):
        return RunEvent(
            sequence=sequence,
            kind="FlowBlocked",
            five_tuple=event.five_tuple,
            app=event.app_type.name,
            hostname=event.sni,
        )
    if isinstance(event, (FlowCreated, FlowEvicted)):
        return RunEvent(
            sequence=sequence, kind=type(event).__name__, five_tuple=event.five_tuple
        )
    if isinstance(event, CaptureOpened):
        return RunEvent(
            sequence=sequence, kind="CaptureOpened", detail=f"linktype={event.linktype}"
        )
    if isinstance(event, CaptureClosed):
        return RunEvent(sequence=sequence, kind="CaptureClosed")
    if isinstance(event, LimitExceeded):
        return RunEvent(
            sequence=sequence, kind="LimitExceeded", detail=f"{event.kind}: {event.detail}"
        )
    # `PacketParsed` and `FlowClassified` (per packet -- their aggregates are already on
    # the record), `WorkerFinished`/`LoadBalancerFinished` (carry live engine objects and
    # no figure the stats do not already hold), and any future event type.
    return None


def record_from_result(
    result: PipelineResult,
    *,
    capture_path: str | Path,
    events: Iterable[Event] | None = None,
    commit: str = "",
    ruleset: str = "",
    created_at: str | None = None,
) -> RunRecord:
    """Freezes a finished run into a `RunRecord`.

    `result.flow_table` must not be `None`: this raises if the run was produced without
    `with_flow_table=True`, rather than storing an empty table. An empty flow table is
    indistinguishable from "this capture had no flows", which would make `query_flows`
    answer a question it was never given the data for -- the silent-empty trap this
    project keeps meeting.

    `ruleset` is the caller's fingerprint of the policy used. It is not inferred here:
    the engine does not compute one, and inventing a hash of whatever the caller happened
    to load would look authoritative while being unable to see rules added to a live
    `RuleManager` during the run.
    """
    if result.flow_table is None:
        raise ValueError(
            "this run has no flow table, so there is nothing for query_flows to answer "
            "with. Re-run the pipeline with `with_flow_table=True` (see T3-06) and pass "
            "the result here. Refusing to store an empty table, because it would read "
            "as 'this capture had no flows'."
        )

    digest, size = capture_digest(capture_path)

    event_log: tuple[RunEvent, ...] | None = None
    events_omitted: tuple[tuple[str, int], ...] = ()
    if events is not None:
        retained: list[RunEvent] = []
        omitted: dict[str, int] = {}
        for sequence, event in enumerate(events):
            converted = _event_to_record(sequence, event)
            if converted is None:
                omitted[type(event).__name__] = omitted.get(type(event).__name__, 0) + 1
            else:
                retained.append(converted)
        event_log = tuple(retained)
        events_omitted = tuple(sorted(omitted.items()))

    record = RunRecord(
        run_id="",
        capture_path=str(capture_path),
        capture_sha256=digest,
        capture_bytes=size,
        created_at=created_at or datetime.now(UTC).isoformat(timespec="seconds"),
        commit=commit,
        ruleset=ruleset,
        stats=RunStats.from_result(result),
        app_counts=tuple(
            sorted((app.name, count) for app, count in result.app_counts.items())
        ),
        detected_domains=tuple(
            sorted((host, app.name) for host, app in result.detected_domains.items())
        ),
        blocked_flows=tuple(
            sorted(
                (
                    BlockedFlow(five_tuple=tuple_, app=app.name, hostname=hostname)
                    for tuple_, app, hostname in result.blocked_flows
                ),
                key=lambda blocked: blocked.five_tuple,
            )
        ),
        flows=tuple(sorted(result.flow_table, key=_flow_key)),
        event_log=event_log,
        events_omitted=events_omitted,
    )
    return _with_computed_id(record)


def _flow_key(flow: FlowRecord) -> tuple[int, int, int, int, int]:
    return (flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol)


def _with_computed_id(record: RunRecord) -> RunRecord:
    """Returns `record` with `run_id` set to its content hash."""
    return RunRecord(
        run_id=record.computed_run_id(),
        capture_path=record.capture_path,
        capture_sha256=record.capture_sha256,
        capture_bytes=record.capture_bytes,
        created_at=record.created_at,
        commit=record.commit,
        ruleset=record.ruleset,
        stats=record.stats,
        app_counts=record.app_counts,
        detected_domains=record.detected_domains,
        blocked_flows=record.blocked_flows,
        flows=record.flows,
        event_log=record.event_log,
        events_omitted=record.events_omitted,
    )


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FlowFilter:
    """A conjunctive filter over stored flows. Absent fields do not constrain.

    `app` and `state` are validated against the engine's own enum names and normalised
    to upper case. An unknown name raises instead of matching nothing: a typo would
    otherwise be reported as "no flows matched", which reads as a fact about the capture
    rather than a mistake in the query.

    `hostname` is an **exact**, case-insensitive match. Deliberately not a substring:
    `D-27` established that bare-substring matching produces confident wrong answers,
    and a filter an agent uses to narrow a result set is the last place to reintroduce
    it. The agent has the exact hostname from the flow it just read.

    `ip` accepts a dotted-quad and must parse, for the same reason.
    """

    app: str | None = None
    state: str | None = None
    hostname: str | None = None
    ip: str | None = None
    protocol: int | None = None
    action: str | None = None
    min_bytes: int | None = None

    def __post_init__(self) -> None:
        if self.app is not None:
            normalised = self.app.upper()
            if normalised not in _APP_NAMES:
                raise ValueError(
                    f"unknown app {self.app!r}; expected one of {sorted(_APP_NAMES)}"
                )
            object.__setattr__(self, "app", normalised)
        if self.state is not None:
            normalised_state = self.state.upper()
            if normalised_state not in _STATE_NAMES:
                raise ValueError(
                    f"unknown state {self.state!r}; expected one of "
                    f"{sorted(_STATE_NAMES)}"
                )
            object.__setattr__(self, "state", normalised_state)
        if self.action is not None:
            object.__setattr__(self, "action", self.action.upper())
        if self.ip is not None:
            # Parsed eagerly so a malformed address fails here rather than silently
            # matching nothing.
            self._ip_value()

    def _ip_value(self) -> int | None:
        if self.ip is None:
            return None
        try:
            return int(ipaddress.IPv4Address(self.ip))
        except ipaddress.AddressValueError as exc:
            raise ValueError(
                f"{self.ip!r} is not a valid IPv4 address: {exc}. The engine tracks "
                "IPv4 flows only."
            ) from exc

    def matches(self, flow: FlowRecord) -> bool:
        if self.app is not None and flow.app != self.app:
            return False
        if self.state is not None and flow.state != self.state:
            return False
        if self.hostname is not None and flow.hostname.lower() != self.hostname.lower():
            return False
        if self.action is not None and flow.action != self.action:
            return False
        if self.protocol is not None and flow.protocol != self.protocol:
            return False
        if self.min_bytes is not None and flow.bytes < self.min_bytes:
            return False
        ip_value = self._ip_value()
        return ip_value is None or ip_value in (flow.src_ip, flow.dst_ip)


# ---------------------------------------------------------------------------
# Diffing
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CounterDelta:
    """One counter's movement between two runs. Signed, and never clamped."""

    name: str
    before: int
    after: int

    @property
    def change(self) -> int:
        return self.after - self.before

    @property
    def increased(self) -> bool:
        return self.after > self.before

    @property
    def decreased(self) -> bool:
        return self.after < self.before

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "before": self.before,
            "after": self.after,
            "change": self.change,
        }


@dataclass(frozen=True, slots=True)
class FlowChange:
    """A flow present in both runs whose stored fields differ."""

    before: FlowRecord
    after: FlowRecord
    #: The names of the fields that differ, sorted. Derived so a caller cannot claim a
    #: change set that disagrees with the two rows it is describing.
    changed_fields: tuple[str, ...]

    @property
    def five_tuple(self) -> FiveTuple:
        return self.after.five_tuple

    def to_json(self) -> dict[str, Any]:
        return {
            "five_tuple": list(self.five_tuple),
            "changed_fields": list(self.changed_fields),
            "before": flow_to_json(self.before),
            "after": flow_to_json(self.after),
        }


@dataclass(frozen=True, slots=True)
class RunDiff:
    """What changed between two stored runs.

    Reports movement rather than judging it. `dropped_packets` rising is not
    automatically worse -- it can mean the capture carried more of a blocked app -- so
    the only interpretation offered is a signed `change` plus the drop-rate delta, and
    the caller (or `T3-04`'s tool) decides what it means.
    """

    run_a: str
    run_b: str
    added: tuple[FlowRecord, ...]
    removed: tuple[FlowRecord, ...]
    changed: tuple[FlowChange, ...]
    counters: tuple[CounterDelta, ...]
    drop_rate_change_percent: float

    @property
    def flows_changed(self) -> int:
        """Flows that appeared, disappeared, or changed in place."""
        return len(self.added) + len(self.removed) + len(self.changed)

    def counter(self, name: str) -> CounterDelta:
        for delta in self.counters:
            if delta.name == name:
                return delta
        raise KeyError(
            f"no counter named {name!r} in this diff; have "
            f"{sorted(delta.name for delta in self.counters)}"
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "run_a": self.run_a,
            "run_b": self.run_b,
            "added": [flow_to_json(flow) for flow in self.added],
            "removed": [flow_to_json(flow) for flow in self.removed],
            "changed": [change.to_json() for change in self.changed],
            "counters": [delta.to_json() for delta in self.counters],
            "flows_changed": self.flows_changed,
            "drop_rate_change_percent": self.drop_rate_change_percent,
        }


_COUNTER_NAMES = (
    "total_packets",
    "total_bytes",
    "forwarded_packets",
    "dropped_packets",
    "tcp_packets",
    "udp_packets",
    "other_packets",
    "active_connections",
)


def diff_records(before: RunRecord, after: RunRecord) -> RunDiff:
    """Compares two records by five-tuple and by counter.

    Flows are keyed by their exact five-tuple, matching how the engine keys its own
    table. Direction folding (`DEC-05`) happens upstream, in the tracker, so a stored
    row already carries the folded key and this comparison does not need to know
    whether folding was on.
    """
    before_by_key = {_flow_key(flow): flow for flow in before.flows}
    after_by_key = {_flow_key(flow): flow for flow in after.flows}

    added = tuple(after_by_key[key] for key in sorted(after_by_key.keys() - before_by_key.keys()))
    removed = tuple(
        before_by_key[key] for key in sorted(before_by_key.keys() - after_by_key.keys())
    )

    changed: list[FlowChange] = []
    for key in sorted(before_by_key.keys() & after_by_key.keys()):
        old, new = before_by_key[key], after_by_key[key]
        moved = tuple(
            sorted(field.name for field in fields(FlowRecord) if getattr(old, field.name) != getattr(new, field.name))
        )
        if moved:
            changed.append(FlowChange(before=old, after=new, changed_fields=moved))

    return RunDiff(
        run_a=before.run_id,
        run_b=after.run_id,
        added=added,
        removed=removed,
        changed=tuple(changed),
        counters=tuple(
            CounterDelta(name, getattr(before.stats, name), getattr(after.stats, name))
            for name in _COUNTER_NAMES
        ),
        drop_rate_change_percent=(
            after.stats.drop_rate_percent - before.stats.drop_rate_percent
        ),
    )


# ---------------------------------------------------------------------------
# The store
# ---------------------------------------------------------------------------


class RunStore:
    """A directory of `RunRecord`s, one JSON file per run.

    One file per run rather than an index plus blobs: a run is written once and read
    whole, so a file is the natural unit, and `os.replace` gives an atomic publish
    without a journal. `list_runs` reads every file to build its summaries -- acceptable
    at the scale a single analyst's runs reach, and called out here because it is the
    one operation whose cost grows with the number of stored runs rather than with what
    was asked for.
    """

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)

    @property
    def root(self) -> Path:
        return self._root

    # -- addressing -------------------------------------------------------

    def path_for(self, run_id: str) -> Path:
        """The file backing `run_id`, validated against traversal.

        The id arrives from an agent in a later tool call, so it is data, not a
        trusted path component.
        """
        if not _is_run_id(run_id):
            raise ValueError(
                f"{run_id!r} is not a run id. Expected 16 lowercase hex characters, as "
                "returned by `save` or `list_runs`."
            )
        return self._root / f"{run_id}.json"

    # -- writing ----------------------------------------------------------

    def save(self, record: RunRecord) -> Path:
        """Stores `record` atomically and returns its path.

        Idempotent: re-saving an identical observation returns the existing file and
        keeps its original `created_at`. A re-save whose payload differs raises -- with
        a deterministic engine that is a hash collision or nondeterminism, and neither
        should be discovered later by reading a quietly overwritten record.
        """
        path = self.path_for(record.run_id)
        self._root.mkdir(parents=True, exist_ok=True)

        if path.exists():
            existing = self.load(record.run_id)
            if existing.fingerprint_payload() != record.fingerprint_payload():
                raise ValueError(
                    f"run {record.run_id} is already stored with a different payload. "
                    "Run ids are content-addressed, so this means either a hash "
                    "collision or a nondeterministic engine. Neither can be resolved by "
                    "overwriting, and doing so would hide it; investigate before "
                    "storing this run under a different id."
                )
            return path

        temporary = path.with_name(f"{path.name}.tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record.to_json(), indent=2, sort_keys=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        return path

    # -- reading ----------------------------------------------------------

    def load(self, run_id: str) -> RunRecord:
        path = self.path_for(run_id)
        if not path.exists():
            raise FileNotFoundError(
                f"no run {run_id} in {self._root}. Call `list_runs` to see what is stored."
            )
        try:
            raw: Any = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{path} is not valid JSON: {exc}. A stored run is written atomically, so "
                "a truncated file means it was corrupted outside this store rather than "
                "left behind by a failed write."
            ) from exc
        if not isinstance(raw, dict):
            raise ValueError(f"{path} does not contain a JSON object")
        try:
            record = RunRecord.from_json(raw)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"{path} is not a valid {SCHEMA} record: {exc}") from exc

        # A stored id must agree with its content, or the directory and the payload
        # disagree about which observation this file is.
        computed = record.computed_run_id()
        if computed != record.run_id:
            raise ValueError(
                f"{path} claims run id {record.run_id}, but its contents hash to "
                f"{computed}. The file has been edited or written by another version of "
                "this store; trusting either id would make diff_runs compare the wrong "
                "pair of runs."
            )
        return record

    def list_runs(self) -> tuple[RunSummary, ...]:
        """Every stored run's header, oldest first. Raises on any unreadable file.

        Skipping a bad file would make the store look tidier than it is, and a caller
        asking "what runs do I have" would silently get a shorter answer than the truth.
        """
        if not self._root.exists():
            return ()
        summaries = [
            self.load(path.stem).summary()
            for path in sorted(self._root.glob("*.json"))
        ]
        return tuple(sorted(summaries, key=lambda summary: (summary.created_at, summary.run_id)))

    # -- querying ---------------------------------------------------------

    def query(
        self,
        run_id: str,
        *,
        filter: FlowFilter | None = None,
        limit: int = 0,
    ) -> tuple[FlowRecord, ...]:
        """Stored flows matching `filter`, capped at `limit` (`0` means no cap).

        `limit=0` for "all" follows `report.render_detected_domains`'s convention rather
        than inventing a second meaning for zero.
        """
        if limit < 0:
            raise ValueError(f"limit must be >= 0, got {limit}")
        record = self.load(run_id)
        selected = (
            record.flows
            if filter is None
            else tuple(flow for flow in record.flows if filter.matches(flow))
        )
        return selected if limit == 0 else selected[:limit]

    def flow(self, run_id: str, five_tuple: FiveTuple) -> FlowRecord | None:
        """The stored row for one five-tuple, or `None` if the run never saw it.

        `None` rather than an exception because "this flow is not in that run" is a
        legitimate answer; `T3-04`'s tool decides how an agent should see it.
        """
        key = (
            five_tuple.src_ip,
            five_tuple.dst_ip,
            five_tuple.src_port,
            five_tuple.dst_port,
            five_tuple.protocol,
        )
        for flow in self.load(run_id).flows:
            if _flow_key(flow) == key:
                return flow
        return None

    def diff(self, run_a: str, run_b: str) -> RunDiff:
        return diff_records(self.load(run_a), self.load(run_b))
