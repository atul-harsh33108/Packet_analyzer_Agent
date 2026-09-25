"""Per-process worker for the hash-partitioned multiprocessing pipeline.

Ports the original's FastPath (fast_path.h/fast_path.cpp) role to a Python
`multiprocessing.Process` target function, fixing the shutdown/drain bug
identified in the original (see DESIGN_DECISIONS.md "Bugs fixed during the
port" and "Architecture").

Each worker:
- Owns a private ConnectionTracker (mirrors the original: "each FP thread
  has its own ConnectionTracker instance, no sharing needed since
  connections are consistently hashed to the same FP").
- Receives an immutable RuleManager snapshot at startup (pickled across the
  process boundary) -- see rule_manager.py's module docstring for why this
  requires no locking.
- Pulls WorkItem objects from its input multiprocessing.Queue until it
  receives the sentinel (None), classifies and rule-checks each packet
  using the exact same logic as the single-process pipeline
  (dpi_engine.pipeline.classify_flow_from_packet /
  RuleManager.should_block), and returns a WorkerResult with everything
  the main process needs to reassemble the output pcap and report.

Shutdown/drain fix: the original's LoadBalancer/FastPath stop() sequence
called `input_queue_.shutdown()` immediately, which woke any blocked
`push()` caller and made it silently drop the item being pushed (see the
prior C++ analysis: "packets can vanish silently on every shutdown").
This port never shuts a queue down while items might still be pushed to
it -- the reader (pipeline.py) pushes every packet, THEN pushes exactly one
sentinel per worker, and each worker's loop is a plain `while True: get()
...; if item is None: break`. There is no shutdown() call and no timeout-
based polling that could race with a producer; queue.Queue/multiprocessing
.Queue's blocking get() simply waits until the sentinel (or a real item)
arrives. Every packet dispatched by the reader is guaranteed to be
processed by exactly one worker before that worker exits.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from multiprocessing import Queue
from typing import Optional

from dpi_engine.connection_tracker import ConnectionTracker, TrackerStats
from dpi_engine.packet_parser import ParsedPacket, parse_packet
from dpi_engine.pcap_io import RawPacket
from dpi_engine.rule_manager import RuleManager
from dpi_engine.types import AppType, Connection, FiveTuple
from dpi_engine.pipeline import classify_flow_from_packet

# Sentinel signaling "no more input" for a worker's queue. A plain `None`
# is used (not a sentinel object) since WorkItem is never None itself, so
# there's no ambiguity, and None pickles trivially across the process
# boundary.
SHUTDOWN_SENTINEL = None

# Test-only hook: when set, injects an artificial per-packet delay inside
# each worker process. Used exclusively by
# tests/test_worker_stress.py::test_no_packet_loss_under_artificially_slowed_worker_processing
# to stress the shutdown/drain protocol's timing under conditions where
# workers are guaranteed to still have a large backlog when shutdown
# sentinels are sent. Reading an environment variable (rather than a
# monkeypatch) is necessary because Windows' multiprocessing "spawn" start
# method re-imports this module fresh in each child process rather than
# inheriting the parent test process's in-memory patched state -- but
# environment variables ARE inherited by spawned children, so this is the
# one mechanism that reliably reaches them. Never read or set in
# production code paths.
_TEST_DELAY_MS_ENV_VAR = "DPI_ENGINE_TEST_WORKER_DELAY_MS"


def _maybe_apply_test_delay() -> None:
    delay_ms = os.environ.get(_TEST_DELAY_MS_ENV_VAR)
    if delay_ms:
        time.sleep(float(delay_ms) / 1000.0)


@dataclass(slots=True)
class WorkItem:
    """A single packet dispatched from the reader to a worker, tagged with
    its original sequence index so the main process can restore input
    order in the output pcap even though workers may finish packets out of
    that order relative to each other (only relative order *within* a
    single five-tuple's packets is guaranteed by hash-partitioning, since
    they always land on the same worker and that worker processes its
    queue strictly in FIFO order)."""

    sequence_index: int
    raw: RawPacket
    parsed: ParsedPacket
    five_tuple: FiveTuple


@dataclass(slots=True)
class ProcessedPacket:
    """A single packet's outcome, returned from a worker to the main
    process for output-pcap assembly."""

    sequence_index: int
    raw: RawPacket
    forwarded: bool


@dataclass(slots=True)
class WorkerResult:
    """Everything a worker sends back to the main process after draining
    its input queue and receiving the shutdown sentinel."""

    worker_id: int
    tracker_stats: TrackerStats
    connections: list[Connection] = field(default_factory=list)
    processed_packets: list[ProcessedPacket] = field(default_factory=list)
    app_counts: dict[AppType, int] = field(default_factory=dict)
    blocked_flows: list[tuple[FiveTuple, AppType, str]] = field(default_factory=list)
    tcp_count: int = 0
    udp_count: int = 0


def worker_main(
    worker_id: int,
    input_queue: "Queue[Optional[WorkItem]]",
    output_queue: "Queue[WorkerResult]",
    rule_manager: RuleManager,
    max_connections: int,
) -> None:
    """Entry point for a worker process (multiprocessing.Process target).

    Pure compute: never touches the filesystem or network (see
    DESIGN_DECISIONS.md "Safety constraints" -- workers are pure compute).
    All I/O (reading the input pcap, writing the output pcap) happens in
    the main process (pipeline.py).
    """
    tracker = ConnectionTracker(fp_id=worker_id, max_connections=max_connections)
    blocked_tuples: set[FiveTuple] = set()

    processed_packets: list[ProcessedPacket] = []
    app_counts: dict[AppType, int] = {}
    blocked_flows: list[tuple[FiveTuple, AppType, str]] = []
    tcp_count = 0
    udp_count = 0

    while True:
        item = input_queue.get()
        if item is SHUTDOWN_SENTINEL:
            break

        assert item is not None  # narrows type for the type checker; sentinel handled above
        parsed = item.parsed
        five_tuple = item.five_tuple

        if parsed.has_tcp:
            tcp_count += 1
        elif parsed.has_udp:
            udp_count += 1

        _maybe_apply_test_delay()

        conn = tracker.get_or_create_connection(five_tuple)
        tracker.update_connection(conn, item.raw.orig_len, is_outbound=True)

        new_app, new_sni, confirmed = classify_flow_from_packet(parsed, conn.app_type, conn.sni)
        if new_app != conn.app_type or new_sni != conn.sni:
            tracker.classify_connection(conn, new_app, new_sni, confirmed=confirmed)

        if five_tuple not in blocked_tuples:
            reason = rule_manager.should_block(
                src_ip=parsed.src_ip_str,
                dst_port=parsed.dst_port,
                app=conn.app_type,
                domain=conn.sni,
            )
            if reason is not None:
                blocked_tuples.add(five_tuple)
                tracker.block_connection(conn)
                blocked_flows.append((five_tuple, conn.app_type, conn.sni))

        app_counts[conn.app_type] = app_counts.get(conn.app_type, 0) + 1

        forwarded = five_tuple not in blocked_tuples
        processed_packets.append(
            ProcessedPacket(sequence_index=item.sequence_index, raw=item.raw, forwarded=forwarded)
        )

    result = WorkerResult(
        worker_id=worker_id,
        tracker_stats=tracker.get_stats(),
        connections=tracker.get_all_connections(),
        processed_packets=processed_packets,
        app_counts=app_counts,
        blocked_flows=blocked_flows,
        tcp_count=tcp_count,
        udp_count=udp_count,
    )
    output_queue.put(result)
