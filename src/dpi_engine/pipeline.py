"""DPI pipelines: single-process, single-tier multiprocessing, and two-tier
staged (reader -> load balancers -> fast paths).

Ports OSC/src/main_working.cpp (the reference single-threaded implementation)
and OSC's reader/LB/FP tiering (dpi_engine.cpp, load_balancer.cpp,
fast_path.cpp).

=============================================================================
The three entry points
=============================================================================
`run_pipeline`
    One process, no IPC. Parses, classifies, rule-checks and writes the output
    pcap in a single loop. Always produces the same result as the others for
    the same input and rules; it is the reference the other two are tested
    against, and the right choice for small captures.

`run_pipeline_multiprocess`
    The parent reads *and parses* every packet, then dispatches to N fast-path
    worker processes by `hash(five_tuple) % N`. One IPC hop. Use when parsing
    is not the bottleneck.

`run_pipeline_staged`
    The parent only reads bytes and writes the output pcap. K load-balancer
    processes do the parsing and hash-based routing; each feeds M fast-path
    processes that own the flow tables. Two IPC hops, and the parse cost
    actually parallelises. Use for large captures on a many-core host; the
    extra process startup is not worth it for small inputs.

All three share `_FlowEngine`, so the per-packet decision logic cannot drift
between them. That is the property that matters: the whole reason the
multiprocessing variants are trustworthy is that they are not separate
implementations.

=============================================================================
Known behavioural quirks carried forward from the original
=============================================================================
- Flows are keyed by the packet's *exact* five-tuple, not folded with the
  reverse direction. The client->server direction of a connection (which
  carries the ClientHello / HTTP request, and gets classified and potentially
  blocked) and the server->client direction are therefore two independent
  flow-table entries, and a block decision on one does not apply to the
  other. This matches `main_working.cpp` exactly (it never calls
  `FiveTuple::reverse()` in its main loop) and is preserved deliberately:
  folding directions would change blocking scope beyond what the documented
  bug-fix list asks for. `ConnectionTracker.get_connection` does implement
  reverse lookup for callers that want it; the pipeline just does not use it.

- DNS is resolved to a name and classified by app, which `main_working.cpp`
  did not do (it only ever tagged port-53 traffic as flat `DNS`, even though
  `DNSExtractor` existed and worked). This is a functional improvement, and
  it has a visible consequence: an app-based block now also catches that app's
  DNS query. Pinned as an expected delta in the differential suite.

- `is_outbound=True` is passed for every packet, as in every OSC code path:
  the original had no notion of which side of a capture was "the user", and
  neither does an offline pcap file. `packets_out`/`bytes_out` therefore mean
  "all traffic"; `packets_in`/`bytes_in` stay at zero.
"""

from __future__ import annotations

import contextlib
import multiprocessing as mp
import queue as queue_module
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from multiprocessing import Queue
from pathlib import Path
from typing import Any

from dpi_engine.connection_tracker import (
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_REAP_INTERVAL_PACKETS,
    DEFAULT_STALE_TIMEOUT_SECONDS,
    ConnectionTracker,
    GlobalStats,
    TrackerStats,
    combine_tracker_reports,
)
from dpi_engine.load_balancer import (
    SHUTDOWN_SENTINEL,
    FastPathStats,
    LoadBalancer,
    LoadBalancerStats,
    build_pipeline_graph,
    hash_select,
)
from dpi_engine.packet_parser import ParsedPacket, parse_packet
from dpi_engine.pcap_io import (
    DEFAULT_MAX_PACKET_SIZE,
    DEFAULT_MAX_TOTAL_PACKETS,
    PcapReader,
    PcapWriter,
    RawPacket,
)
from dpi_engine.rule_manager import RuleManager, RuleSnapshot
from dpi_engine.types import AppType, DPIStats, FiveTuple
from dpi_engine.worker import (
    FixedRuleSource,
    FlowProcessor,
    ProcessedPacket,
    RuleSource,
    WorkerResult,
    WorkItem,
    worker_main,
)

__all__ = [
    "PipelineResult",
    "RuleBroadcaster",
    "run_pipeline",
    "run_pipeline_multiprocess",
    "run_pipeline_staged",
]


@dataclass(slots=True)
class PipelineResult:
    """Everything the CLI and the tests need after a pipeline run."""

    stats: DPIStats
    app_counts: dict[AppType, int] = field(default_factory=dict)
    detected_domains: dict[str, AppType] = field(default_factory=dict)
    blocked_flows: list[tuple[FiveTuple, AppType, str]] = field(default_factory=list)
    #: Per-execution-context packet counts, in context-id order. Populated for
    #: the multiprocessing variants (fast-path id for the single-tier
    #: pipeline, load-balancer id for the staged one), which is the analogue of
    #: the original's "LB0 dispatched / FP0 processed" report section.
    per_worker_packet_counts: list[int] = field(default_factory=list)
    #: Aggregated fast-path counters. Empty for the single-process pipeline
    #: unless `with_fast_path_stats=True` was requested.
    fast_path_stats: FastPathStats | None = None
    load_balancer_stats: LoadBalancerStats | None = None
    #: UDP packets recognised as QUIC, and how many of those we could not
    #: decrypt. `quic_undecryptable > 0` with `quic_packets > 0` means QUIC
    #: was seen but its SNI was not readable -- distinct from "no QUIC".
    quic_packets: int = 0
    quic_undecryptable: int = 0
    #: Cross-worker flow aggregation. Populated when
    #: `with_global_stats=True`, so the report can show top domains and
    #: per-flow state counts. This is what consumes each tracker's immutable
    #: snapshot, replacing OSC's racy GlobalConnectionTable.
    global_stats: GlobalStats | None = None

    @property
    def drop_rate_percent(self) -> float:
        """Dropped packets as a percentage of inspected (TCP/UDP) packets.

        The denominator is *inspected* packets, not all packets read: ARP,
        IPv6 and other non-TCP/UDP frames were never candidates for a rule, so
        counting them would understate the drop rate.
        """
        inspected = self.stats.tcp_packets + self.stats.udp_packets
        if inspected == 0:
            return 0.0
        return 100.0 * self.stats.dropped_packets / inspected


# ---------------------------------------------------------------------------
# Live rule updates
# ---------------------------------------------------------------------------


class RuleBroadcaster:
    """Publishes `RuleSnapshot` updates from the parent to every worker.

    This is the mechanism behind "change rules while a run is in progress",
    the capability OSC's `DPIEngine` exposed (dpi_engine.cpp:335-402) via a
    shared, mutex-guarded `RuleManager`.

    What is different, and why it is safer:

    * OSC mutated *live* containers that FP threads were reading, under a
      `shared_mutex`. Here the parent only ever sends an **immutable**
      snapshot. A worker swaps its reference; it never mutates shared state,
      so there is no reader/writer race to reason about and no lock on the
      packet path.
    * Updates are published on a separate control queue, never mixed into the
      packet queue, so a rule change can never be mistaken for a packet or
      reordered relative to one.
    * Newest-wins: workers drain the whole control queue before each packet, so
      a burst of rapid changes collapses to the latest state.

    Deliberately *not* implemented: version-based acknowledgement or rollback.
    If a worker dies mid-run the update is simply lost with it, and the parent
    reports the failure. That is honest and simple; a two-phase commit here
    would add real complexity for a batch tool.

    The *initial* rule set is not published here: workers receive it as a
    constructor argument at startup, and this channel carries changes only.
    That is why `publish()` is a no-op until something actually mutates.
    """

    def __init__(self, rule_manager: RuleManager) -> None:
        self._rule_manager = rule_manager
        self._queues: list[Queue[RuleSnapshot]] = []
        self._published_version = rule_manager.version

    def register(self, queue: Queue[RuleSnapshot]) -> None:
        """Adds a control queue to publish to."""
        self._queues.append(queue)

    def publish(self) -> bool:
        """Ships the current snapshot to every registered worker if it changed
        since the last publish. Returns True if anything was sent."""
        current = self._rule_manager.snapshot()
        if current.version == self._published_version:
            return False
        self._published_version = current.version
        for q in self._queues:
            q.put(current)
        return True


# ---------------------------------------------------------------------------
# Shared single-context engine
# ---------------------------------------------------------------------------


class _FlowEngine:
    """The per-packet decision loop, with no multiprocessing knowledge.

    `run_pipeline` drives this directly in-process; the fast-path worker
    processes drive the same `FlowProcessor` over a queue. Keeping the
    decision logic in `FlowProcessor` (worker.py) is what guarantees the
    single-process and multiprocessing results are identical.
    """

    def __init__(
        self,
        rule_source: RuleSource,
        *,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        stale_timeout_seconds: float | None = DEFAULT_STALE_TIMEOUT_SECONDS,
        reap_interval_packets: int = DEFAULT_REAP_INTERVAL_PACKETS,
        enable_quic: bool = True,
        context_id: int = 0,
    ) -> None:
        self.processor = FlowProcessor(
            tracker=ConnectionTracker(
                fp_id=context_id,
                max_connections=max_connections,
                stale_timeout_seconds=stale_timeout_seconds,
                reap_interval_packets=reap_interval_packets,
            ),
            rule_source=rule_source,
            enable_quic=enable_quic,
            fp_id=context_id,
        )

    def submit(self, item: WorkItem) -> ProcessedPacket:
        return self.processor.process(item)

    def result(self, processed: Sequence[ProcessedPacket]) -> WorkerResult:
        res = self.processor.finalize()
        res.processed_packets = list(processed)
        return res


def _make_five_tuple(parsed: ParsedPacket) -> FiveTuple:
    return FiveTuple(
        src_ip=parsed.src_ip,
        dst_ip=parsed.dst_ip,
        src_port=parsed.src_port,
        dst_port=parsed.dst_port,
        protocol=parsed.protocol,
    )


#: One packet handed to a fast-path, tagged with its original position in the
#: input file.
InspectableItem = tuple[int, RawPacket, ParsedPacket, FiveTuple]


def _iter_inspectable(
    reader: PcapReader,
    stats: DPIStats,
) -> Iterable[InspectableItem]:
    """Yields (sequence_index, raw, parsed, five_tuple) for every packet that
    is worth inspecting, accumulating the read-level counters into `stats`.

    Non-IPv4 frames, non-TCP/UDP payloads, and unparseable frames are counted
    in `stats.other_packets` and skipped -- never an error, just nothing to do.
    """
    for sequence_index, raw in enumerate(reader):
        stats.total_packets += 1
        # `len(data)`, not `raw.orig_len` -- see the note in
        # `worker.FlowProcessor.process`. Byte totals report what was read from
        # the capture, matching the C++ original's `raw.data.size()`.
        stats.total_bytes += len(raw.data)

        parsed = parse_packet(raw)
        if parsed is None or not parsed.has_ip or not (parsed.has_tcp or parsed.has_udp):
            stats.other_packets += 1
            continue

        if parsed.has_tcp:
            stats.tcp_packets += 1
        else:
            stats.udp_packets += 1

        yield sequence_index, raw, parsed, _make_five_tuple(parsed)


def _accumulate(
    stats: DPIStats,
    results: Sequence[WorkerResult],
) -> tuple[
    dict[AppType, int],
    dict[str, AppType],
    list[tuple[FiveTuple, AppType, str]],
    GlobalStats,
    int,
    int,
]:
    """Merges worker results into the run-level totals.

    Does NOT write the output pcap: the caller owns the writer, because the
    single-process variant streams packets as it goes while the multiprocessing
    variants can only write after every worker has reported. Does NOT touch
    `stats.tcp_packets`/`udp_packets` either -- those are set from whichever
    stage actually parsed (the reader, or the load balancers), and each
    variant does that itself so the two tallies stay cross-checkable.

    Returns (app_counts, detected_domains, blocked_flows, global_stats,
    quic_packets, quic_undecryptable).
    """
    app_counts: dict[AppType, int] = {}
    detected_domains: dict[str, AppType] = {}
    blocked_flows: list[tuple[FiveTuple, AppType, str]] = []
    quic_packets = 0
    quic_undecryptable = 0

    for result in results:
        blocked_flows.extend(result.blocked_flows)
        quic_packets += result.quic_packets
        quic_undecryptable += result.quic_undecryptable
        for app, count in result.app_counts.items():
            app_counts[app] = app_counts.get(app, 0) + count
        for domain, app in result.detected_domains.items():
            detected_domains[domain] = app

    combined = TrackerStats()
    for r in results:
        combined = combined.combine(r.tracker_stats)
    stats.active_connections = combined.active_connections

    # Each tracker's immutable snapshot is aggregated here, which is what
    # replaces OSC's racy GlobalConnectionTable (which read other threads'
    # live trackers). See connection_tracker.combine_tracker_reports.
    global_stats = combine_tracker_reports(
        [(r.tracker_stats, r.connections) for r in results]
    )

    return app_counts, detected_domains, blocked_flows, global_stats, quic_packets, quic_undecryptable


def _combine_fast_path_stats(results: Sequence[WorkerResult]) -> FastPathStats:
    total = FastPathStats()
    for r in results:
        total = total.combine([r.fp_stats])
    return total


# ---------------------------------------------------------------------------
# 1. Single process
# ---------------------------------------------------------------------------


def run_pipeline(
    input_path: str | Path,
    output_path: str | Path,
    rule_manager: RuleManager | None = None,
    *,
    max_connections: int = DEFAULT_MAX_CONNECTIONS,
    max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
    max_total_packets: int = DEFAULT_MAX_TOTAL_PACKETS,
    stale_timeout_seconds: float | None = DEFAULT_STALE_TIMEOUT_SECONDS,
    reap_interval_packets: int = DEFAULT_REAP_INTERVAL_PACKETS,
    enable_quic: bool = True,
    with_global_stats: bool = True,
    rule_broadcaster: RuleBroadcaster | None = None,
) -> PipelineResult:
    """Runs the full pipeline in one process, with no IPC.

    Raises PcapError on I/O problems with the input/output files (the caller
    decides how to report it); never raises on malformed *packet* content --
    that is handled by the parser/extractor layers returning None.

    `rule_broadcaster`, if given, is polled each packet, which is what makes
    live rule mutation work in the single-process path too. Passing it is
    optional because the common case is "rules never change during a run".

    The resource bounds are forwarded explicitly (rather than only defaulted
    deep inside PcapReader/ConnectionTracker) so callers, including the CLI,
    can raise them for an unusually large legitimate capture without editing
    source, while still getting a safe default against adversarial input.
    """
    rules = FixedRuleSource(
        (rule_manager if rule_manager is not None else RuleManager()).snapshot()
    )
    engine = _FlowEngine(
        rules,
        max_connections=max_connections,
        stale_timeout_seconds=stale_timeout_seconds,
        reap_interval_packets=reap_interval_packets,
        enable_quic=enable_quic,
    )

    stats = DPIStats()
    processed: list[ProcessedPacket] = []

    with PcapReader(
        input_path, max_packet_size=max_packet_size, max_total_packets=max_total_packets
    ) as reader, PcapWriter(output_path, source_path=input_path) as writer:
        for sequence_index, raw, parsed, tuple_ in _iter_inspectable(reader, stats):
            if rule_broadcaster is not None:
                rule_broadcaster.publish()
            outcome = engine.submit(
                WorkItem(
                    sequence_index=sequence_index,
                    raw=raw,
                    parsed=parsed,
                    five_tuple=tuple_,
                )
            )
            processed.append(outcome)
            if outcome.forwarded:
                stats.forwarded_packets += 1
                writer.write(raw)
            else:
                stats.dropped_packets += 1

    result = engine.result(processed)
    stats.tcp_packets = result.tcp_count
    stats.udp_packets = result.udp_count

    (
        app_counts,
        detected_domains,
        blocked_flows,
        global_stats,
        quic_packets,
        quic_undecryptable,
    ) = _accumulate(stats, [result])

    return PipelineResult(
        stats=stats,
        app_counts=app_counts,
        detected_domains=detected_domains,
        blocked_flows=blocked_flows,
        per_worker_packet_counts=[result.fp_stats.packets_processed],
        fast_path_stats=result.fp_stats,
        quic_packets=quic_packets,
        quic_undecryptable=quic_undecryptable,
        global_stats=global_stats if with_global_stats else None,
    )


# ---------------------------------------------------------------------------
# 2. Single-tier multiprocessing
# ---------------------------------------------------------------------------


def run_pipeline_multiprocess(
    input_path: str | Path,
    output_path: str | Path,
    rule_manager: RuleManager | None = None,
    *,
    num_workers: int = 4,
    max_connections: int = DEFAULT_MAX_CONNECTIONS,
    max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
    max_total_packets: int = DEFAULT_MAX_TOTAL_PACKETS,
    stale_timeout_seconds: float | None = DEFAULT_STALE_TIMEOUT_SECONDS,
    reap_interval_packets: int = DEFAULT_REAP_INTERVAL_PACKETS,
    enable_quic: bool = True,
    live_rules: bool = False,
) -> PipelineResult:
    """Reader-parses, hash-partitioned fast-path workers.

    Mirrors the original's LB->FP consistent-hashing design collapsed to a
    single hop: the reader parses every packet and dispatches it to
    `hash(five_tuple) % num_workers`, so every packet of a given connection
    lands on the same worker and per-flow state stays correct.

    Produces IDENTICAL results to `run_pipeline` on the same input and rules
    (verified field-by-field in tests/test_worker.py). The output pcap's packet
    order is explicitly restored to match the input order via each item's
    sequence_index, so the two are indistinguishable from outside.

    `live_rules=True` opens a per-worker control channel and polls the
    caller's `RuleManager` version each packet, so rules can be changed while
    the run is in progress. Off by default because it costs one non-blocking
    queue drain per packet per worker.

    Safety: workers are pure compute; only this function (in the parent) ever
    touches the filesystem.
    """
    if num_workers < 1:
        raise ValueError(f"num_workers must be >= 1, got {num_workers}")

    manager = rule_manager if rule_manager is not None else RuleManager()
    rule_source = FixedRuleSource(manager.snapshot())
    broadcaster = RuleBroadcaster(manager) if live_rules else None

    input_queues: list[Queue[WorkItem | None]] = [mp.Queue() for _ in range(num_workers)]
    output_queue: Queue[WorkerResult] = mp.Queue()
    control_queues: list[Queue[RuleSnapshot]] = (
        [mp.Queue() for _ in range(num_workers)] if live_rules else []
    )
    if broadcaster is not None:
        for control_queue in control_queues:
            broadcaster.register(control_queue)

    processes = [
        mp.Process(
            target=worker_main,
            args=(worker_id, input_queues[worker_id], output_queue, rule_source, max_connections),
            kwargs={
                "stale_timeout_seconds": stale_timeout_seconds,
                "reap_interval_packets": reap_interval_packets,
                "control_queue": control_queues[worker_id] if live_rules else None,
                "enable_quic": enable_quic,
            },
            name=f"dpi-fp-{worker_id}",
        )
        for worker_id in range(num_workers)
    ]
    for p in processes:
        p.start()

    stats = DPIStats()
    dispatch_succeeded = False

    try:
        with PcapReader(
            input_path, max_packet_size=max_packet_size, max_total_packets=max_total_packets
        ) as reader, PcapWriter(output_path, source_path=input_path) as writer:
            for sequence_index, raw, parsed, tuple_ in _iter_inspectable(reader, stats):
                if broadcaster is not None:
                    broadcaster.publish()
                input_queues[hash_select(tuple_, num_workers)].put(
                    WorkItem(
                        sequence_index=sequence_index,
                        raw=raw,
                        parsed=parsed,
                        five_tuple=tuple_,
                    )
                )
        dispatch_succeeded = True
    finally:
        # This MUST run whether dispatch succeeded or raised (e.g.
        # PcapLimitExceededError partway through). The workers are already
        # started and blocked on input_queue.get(); if they were not sent a
        # sentinel and terminated here on the exception path they would hang
        # forever -- a bug this shutdown protocol exists to prevent. On the
        # exception path we cannot trust partially-dispatched workers to
        # produce a coherent result anyway, so they are terminated directly.
        if dispatch_succeeded:
            for packet_queue in input_queues:
                packet_queue.put(SHUTDOWN_SENTINEL)
        else:
            _terminate(processes, [*input_queues, *control_queues, output_queue])

    if not dispatch_succeeded:
        # Unreachable: the try block either completes and sets the flag, or
        # raises and propagates out past this `finally`. Kept so a static
        # reader can see this function can never return a bogus result after a
        # dispatch failure.
        raise AssertionError("unreachable: dispatch failure must propagate its exception")

    results = _collect(output_queue, num_workers)
    for process in processes:
        process.join()
    for queue_ in [*input_queues, *control_queues, output_queue]:
        _close_quietly(queue_)

    results.sort(key=lambda r: r.worker_id)
    stats.tcp_packets = sum(r.tcp_count for r in results)
    stats.udp_packets = sum(r.udp_count for r in results)
    (
        app_counts,
        detected_domains,
        blocked_flows,
        global_stats,
        quic_packets,
        quic_undecryptable,
    ) = _accumulate(stats, results)

    with PcapWriter(output_path, source_path=input_path) as writer:
        _write_forwarded(stats, results, writer)

    return PipelineResult(
        stats=stats,
        app_counts=app_counts,
        detected_domains=detected_domains,
        blocked_flows=blocked_flows,
        per_worker_packet_counts=[r.fp_stats.packets_processed for r in results],
        fast_path_stats=_combine_fast_path_stats(results),
        quic_packets=quic_packets,
        quic_undecryptable=quic_undecryptable,
        global_stats=global_stats,
    )


# ---------------------------------------------------------------------------
# 3. Two-tier staged: reader -> load balancers -> fast paths
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _LoadBalancerResult:
    """What one load-balancer process returns to the parent."""

    stats: LoadBalancerStats


def _lb_main(
    input_queue: Queue[WorkItem | None],
    lb: LoadBalancer,
    output_queue: Queue[_LoadBalancerResult],
) -> None:
    """`multiprocessing.Process` target for one load-balancer stage.

    Exactly OSC's `LoadBalancer::run` (load_balancer.cpp:49-69): pop a packet,
    hash-select one of *this LB's own* fast-paths, push it there. It holds no
    flow state, needs no reaping, and cannot re-classify anything -- the whole
    point of the shard.

    Shutdown ordering is the part that matters: this function drains its own
    queue to exhaustion first, and only then sends a sentinel to each fast-path
    it feeds. Sending the sentinel early would make a fast-path exit while
    items were still in flight -- exactly the silent packet loss the sentinel
    protocol exists to prevent.

    Pure compute: no filesystem, no network.
    """
    stats = LoadBalancerStats(lb_id=lb.lb_id)

    while True:
        item = input_queue.get()
        if item is SHUTDOWN_SENTINEL:
            break

        stats.packets_received += 1
        fast_path = lb.select_fp(item.five_tuple)
        stats.per_fp_packets[fast_path.fp_id] = (
            stats.per_fp_packets.get(fast_path.fp_id, 0) + 1
        )
        stats.packets_dispatched += 1
        fast_path.input_queue.put(item)

    for fast_path in lb.fps:
        fast_path.input_queue.put(SHUTDOWN_SENTINEL)

    output_queue.put(_LoadBalancerResult(stats=stats))


def run_pipeline_staged(
    input_path: str | Path,
    output_path: str | Path,
    rule_manager: RuleManager | None = None,
    *,
    num_load_balancers: int = 2,
    fps_per_lb: int = 2,
    max_connections: int = DEFAULT_MAX_CONNECTIONS,
    max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
    max_total_packets: int = DEFAULT_MAX_TOTAL_PACKETS,
    stale_timeout_seconds: float | None = DEFAULT_STALE_TIMEOUT_SECONDS,
    reap_interval_packets: int = DEFAULT_REAP_INTERVAL_PACKETS,
    enable_quic: bool = True,
    live_rules: bool = False,
) -> PipelineResult:
    """Two-tier staged pipeline: reader -> load balancers -> fast paths.

    Reproduces OSC's `reader -> LB* -> FP* -> output` topology
    (dpi_engine.cpp:47-56 builds exactly this graph, with
    `num_load_balancers * fps_per_lb` fast-paths, and
    `LBManager::getLBForPacket` + `LoadBalancer::selectFP` do the two hash
    steps), and reports both tiers' counters as OSC's
    `DPIEngine::generateReport` did.

    Why the reader still parses
    ----------------------------
    The tempting alternative -- let the load-balancer stage parse, so the parse
    cost parallelises too -- is **wrong**, and demonstrably so: a stateless
    reader can only hand raw frames to load balancers by round-robin, so the
    two halves of one connection land in different shards, and the flow's
    state gets split across two fast-paths. (Measured on the sample capture:
    61 tracked "connections" for 43 real ones, with per-flow classification
    half-applied.) Routing by five-tuple requires parsing first, which is
    exactly what OSC's reader did, so this is the faithful topology.

    Consequently the LB tier is a queue-decoupling / backpressure-isolation
    construct here, not a throughput win: the reader's parse is the serial
    stage in this design just as it is in `run_pipeline_multiprocess`, and
    the extra hop makes the two-tier path slightly *slower* than the
    single-tier one. Use this variant for architecture parity and for
    per-shard observability; use `run_pipeline_multiprocess` for speed.

    Produces the same decisions as `run_pipeline` for the same input and rules
    (asserted in tests/test_staged_pipeline.py, which also asserts the
    per-flow partitioning invariant that the round-robin variant violated).

    `live_rules=True` opens a per-fast-path control channel and polls the
    caller's `RuleManager` version each packet, exactly as
    `run_pipeline_multiprocess` does. This parameter did not exist until D-03:
    `cli._execute` assembled one kwargs dict for whichever variant it selected
    and omitted `live_rules` from it, so `--live-rules` was accepted by the
    parser and then dropped on the floor whenever `--load-balancers` was given
    -- silently, with a plausible-looking result. There is one control queue
    per fast path (`num_load_balancers * fps_per_lb`), all registered with a
    single broadcaster the parent polls during dispatch. Off by default
    because it costs one non-blocking queue drain per packet per fast path.
    """
    if num_load_balancers < 1:
        raise ValueError(f"num_load_balancers must be >= 1, got {num_load_balancers}")
    if fps_per_lb < 1:
        raise ValueError(f"fps_per_lb must be >= 1, got {fps_per_lb}")

    manager = rule_manager if rule_manager is not None else RuleManager()
    rule_source = FixedRuleSource(manager.snapshot())
    broadcaster = RuleBroadcaster(manager) if live_rules else None

    lbs, all_fps = build_pipeline_graph(
        num_load_balancers, fps_per_lb, queue_factory=mp.Queue
    )
    lb_output_queue: Queue[_LoadBalancerResult] = mp.Queue()
    fp_output_queue: Queue[WorkerResult] = mp.Queue()

    # One control queue per *fast path*, not per load balancer: the workers that
    # read rules are the FPs, and the LB tier never touches a RuleSnapshot.
    # Indexing must therefore be over `all_fps`, or later shards silently keep
    # reading the startup snapshot forever.
    control_queues: list[Queue[RuleSnapshot]] = (
        [mp.Queue() for _ in all_fps] if live_rules else []
    )
    if broadcaster is not None:
        for control_queue in control_queues:
            broadcaster.register(control_queue)

    lb_processes = [
        mp.Process(
            target=_lb_main,
            args=(lb.input_queue, lb, lb_output_queue),
            name=f"dpi-lb-{lb.lb_id}",
        )
        for lb in lbs
    ]

    fp_processes = [
        mp.Process(
            target=worker_main,
            args=(fp.fp_id, fp.input_queue, fp_output_queue, rule_source, max_connections),
            kwargs={
                "stale_timeout_seconds": stale_timeout_seconds,
                "reap_interval_packets": reap_interval_packets,
                "control_queue": control_queues[fp.fp_id] if live_rules else None,
                "enable_quic": enable_quic,
            },
            name=f"dpi-fp-{fp.fp_id}",
        )
        for fp in all_fps
    ]

    for p in [*lb_processes, *fp_processes]:
        p.start()

    stats = DPIStats()
    dispatch_succeeded = False

    try:
        with PcapReader(
            input_path, max_packet_size=max_packet_size, max_total_packets=max_total_packets
        ) as reader:
            for sequence_index, raw, parsed, tuple_ in _iter_inspectable(reader, stats):
                if broadcaster is not None:
                    broadcaster.publish()
                # OSC's first hash step: pick the owning load balancer from the
                # five-tuple, so all of a flow's packets go to the same shard.
                lbs[hash_select(tuple_, num_load_balancers)].input_queue.put(
                    WorkItem(
                        sequence_index=sequence_index,
                        raw=raw,
                        parsed=parsed,
                        five_tuple=tuple_,
                    )
                )
        dispatch_succeeded = True
    finally:
        if dispatch_succeeded:
            for lb in lbs:
                lb.input_queue.put(SHUTDOWN_SENTINEL)
        else:
            _terminate(
                [*lb_processes, *fp_processes],
                [lb.input_queue for lb in lbs]
                + [fp.input_queue for fp in all_fps]
                + [*control_queues, lb_output_queue, fp_output_queue],
            )

    if not dispatch_succeeded:
        raise AssertionError("unreachable: dispatch failure must propagate its exception")

    lb_results = _collect(lb_output_queue, num_load_balancers)
    fp_results = _collect(fp_output_queue, len(all_fps))
    for p in [*lb_processes, *fp_processes]:
        p.join()
    for q in [
        *[lb.input_queue for lb in lbs],
        *[fp.input_queue for fp in all_fps],
        *control_queues,
        lb_output_queue,
        fp_output_queue,
    ]:
        _close_quietly(q)

    fp_results.sort(key=lambda r: r.worker_id)
    stats.tcp_packets = sum(r.tcp_count for r in fp_results)
    stats.udp_packets = sum(r.udp_count for r in fp_results)
    (
        app_counts,
        detected_domains,
        blocked_flows,
        global_stats,
        quic_packets,
        quic_undecryptable,
    ) = _accumulate(stats, fp_results)

    with PcapWriter(output_path, source_path=input_path) as writer:
        _write_forwarded(stats, fp_results, writer)

    lb_stats = LoadBalancerStats().combine([r.stats for r in lb_results])

    return PipelineResult(
        stats=stats,
        app_counts=app_counts,
        detected_domains=detected_domains,
        blocked_flows=blocked_flows,
        per_worker_packet_counts=[r.stats.packets_dispatched for r in lb_results],
        fast_path_stats=_combine_fast_path_stats(fp_results),
        load_balancer_stats=lb_stats,
        quic_packets=quic_packets,
        quic_undecryptable=quic_undecryptable,
        global_stats=global_stats,
    )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _write_forwarded(
    stats: DPIStats, results: Sequence[WorkerResult], writer: PcapWriter
) -> None:
    """Writes every forwarded packet, in input order, counting drops. Used by
    the multiprocessing variants, where the parent holds the decisions but not
    the streaming writer."""
    packets: list[ProcessedPacket] = [pp for r in results for pp in r.processed_packets]
    packets.sort(key=lambda pp: pp.sequence_index)
    for pp in packets:
        if pp.forwarded:
            stats.forwarded_packets += 1
            writer.write(pp.raw)
        else:
            stats.dropped_packets += 1


def _collect[T](output_queue: Queue[T], expected: int) -> list[T]:
    """Reads exactly `expected` results off a queue.

    Bounded by a timeout so a lost worker surfaces as a clear error instead of
    an indefinite hang -- the failure mode this whole shutdown protocol exists
    to avoid, so it should not be able to reintroduce one silently.
    """
    results: list[T] = []
    try:
        for _ in range(expected):
            results.append(output_queue.get(timeout=_RESULT_TIMEOUT_SECONDS))
    except queue_module.Empty:
        raise RuntimeError(
            f"Timed out after {_RESULT_TIMEOUT_SECONDS}s waiting for a worker "
            f"result (got {len(results)} of {expected}). A worker process "
            "appears to have died; re-run with --workers 1 for a diagnostic."
        ) from None
    return results


#: Generous, because a worker may still be draining a large backlog. It exists
#: to convert a hang into a diagnosable error, not to bound normal work.
_RESULT_TIMEOUT_SECONDS = 120.0


def _terminate(
    processes: Sequence[mp.process.BaseProcess], queues: Sequence[Any]
) -> None:
    """Best-effort teardown for the failure path: no sentinel is coming, so
    terminate rather than wait, then close the queues.

    The queue parameter is deliberately untyped: the payload type is
    irrelevant to teardown, and the callers mix packet, control and result
    queues in one list.
    """
    for p in processes:
        if p.is_alive():
            p.terminate()
    for p in processes:
        p.join(timeout=5)
    for q in queues:
        _close_quietly(q)


def _close_quietly(queue: Any) -> None:
    """Best-effort teardown of a multiprocessing queue.

    Runs on the failure path and during normal cleanup, where the queue may
    already be closed or half-initialised. Every method is therefore
    optional and every exception is swallowed: raising here would mask the
    original error that triggered teardown, which is the one thing the caller
    actually needs to see.
    """
    for method in ("close", "cancel_join_thread", "join_thread"):
        fn = getattr(queue, method, None)
        if fn is None:
            continue
        with contextlib.suppress(OSError, ValueError, AssertionError):
            fn()
