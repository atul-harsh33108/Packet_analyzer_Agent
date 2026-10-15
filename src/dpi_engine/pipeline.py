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
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from multiprocessing import Queue
from pathlib import Path
from typing import Any

from dpi_engine.cap_source import CapSource
from dpi_engine.connection_tracker import (
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_REAP_INTERVAL_PACKETS,
    DEFAULT_STALE_TIMEOUT_SECONDS,
    ConnectionTracker,
    GlobalStats,
    TrackerStats,
    combine_tracker_reports,
)
from dpi_engine.events import (
    CaptureClosed,
    CaptureOpened,
    Event,
    EventBus,
    FlowBlocked,
    FlowClassified,
    FlowCreated,
    FlowEvicted,
    LimitExceeded,
    LoadBalancerFinished,
    PacketParsed,
    WorkerFinished,
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
    ETHERNET_LINKTYPE,
    PcapLimitExceededError,
    PcapReader,
    PcapWriter,
    RawPacket,
)
from dpi_engine.rule_manager import RuleManager, RuleSnapshot
from dpi_engine.types import (
    AppType,
    Connection,
    ConnectionState,
    DPIStats,
    FiveTuple,
    canonical_flow_key,
)
from dpi_engine.worker import (
    FixedRuleSource,
    FlowProcessor,
    PacketDecision,
    RuleSource,
    WorkerMessage,
    WorkerResult,
    WorkItem,
    is_forwarded,
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
    #: Aggregated fast-path counters. Populated by all three variants: the
    #: single-process path uses the one engine's own `fp_stats`, and the two
    #: multiprocess variants fold the per-worker counters together with
    #: `_combine_fast_path_stats`. (An earlier version of this comment claimed
    #: the field was empty for the single-process pipeline unless a
    #: `with_fast_path_stats=True` parameter was passed. No such parameter has
    #: ever existed, and the field is in fact always populated -- S-03.)
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


#: Default `DEC-01` reorder window, in packets.
#:
#: Sized to absorb the spread between the fastest and slowest *worker*, which is
#: what hash-partitioned dispatch actually produces -- not the spread between
#: individual packets, which is small. 1024 in flight is at most 64 MiB at the
#: default `max_packet_size`, the same arithmetic that sizes `_QUEUE_MAXSIZE`.
#:
#: The counter to watch is `ReorderBuffer.out_of_order_emissions`: it is the
#: direct measurement of the window being too small for a given capture, and the
#: only reason to spend more memory here.
DEFAULT_REORDER_WINDOW = 1024


# ---------------------------------------------------------------------------
# The fold
# ---------------------------------------------------------------------------


def fold_events(events: Iterable[Event]) -> PipelineResult:
    """Derives `PipelineResult` by folding an event stream.

    This is the *only* place `PipelineResult` is constructed from a run's
    behaviour once the pipeline emits events, and it must agree exactly with
    what the batch path computed -- that is the guarantee
    `tests/test_event_bus.py::test_the_fold_reproduces_the_batch_result`
    asserts. Where the two would disagree, the fold is wrong, not the batch
    path: the batch path is the specification until streaming replaces it.

    Composition rules, mirroring `_accumulate`:
      * `PacketParsed` builds `DPIStats`;
      * `FlowClassified` builds `app_counts` and `detected_domains`, with
        last-write-wins on a repeated domain, matching the batch dict merge;
      * `FlowBlocked` appends to `blocked_flows` in arrival order;
      * `WorkerFinished` contributes `per_worker_packet_counts`, its share of
        `fast_path_stats`, its `quic_*` counters, and its tracker report;
      * `LoadBalancerFinished` contributes `load_balancer_stats`.

    `active_connections` and `flows_reaped` come from the tracker reports, not
    from `FlowEvicted`, because eviction is a *tracker* judgement the fold has
    no second source for.
    """
    stats = DPIStats()
    app_counts: dict[AppType, int] = {}
    detected_domains: dict[str, AppType] = {}
    blocked_flows: list[tuple[FiveTuple, AppType, str]] = []
    worker_results: list[WorkerResult] = []
    lb_results = []
    quic_packets = 0
    quic_undecryptable = 0

    for event in events:
        if isinstance(event, PacketParsed):
            stats.total_packets += 1
            stats.total_bytes += event.byte_len
            if event.is_tcp:
                stats.tcp_packets += 1
            elif event.is_udp:
                stats.udp_packets += 1
            else:
                stats.other_packets += 1
            if event.forwarded:
                stats.forwarded_packets += 1
            else:
                stats.dropped_packets += 1

        elif isinstance(event, FlowClassified):
            app_counts[event.app_type] = app_counts.get(event.app_type, 0) + 1
            if event.sni:
                detected_domains[event.sni] = event.app_type

        elif isinstance(event, FlowBlocked):
            blocked_flows.append((event.five_tuple, event.app_type, event.sni))

        elif isinstance(event, WorkerFinished):
            worker_results.append(event.result)
            quic_packets += event.result.quic_packets
            quic_undecryptable += event.result.quic_undecryptable

        elif isinstance(event, LoadBalancerFinished):
            lb_results.append(event.result)

        # CaptureOpened / CaptureClosed / FlowCreated / FlowEvicted /
        # LimitExceeded carry no figure the fold needs; see module docstring.

    stats.active_connections = _combined_active(worker_results)
    result = PipelineResult(
        stats=stats,
        app_counts=app_counts,
        detected_domains=detected_domains,
        blocked_flows=blocked_flows,
        per_worker_packet_counts=[r.fp_stats.packets_processed for r in worker_results],
        fast_path_stats=_combined_fast_path(worker_results),
        load_balancer_stats=_combined_lb_stats(lb_results),
        quic_packets=quic_packets,
        quic_undecryptable=quic_undecryptable,
        global_stats=_combined_global(worker_results),
    )
    return result


def _combined_active(results: list[WorkerResult]) -> int:
    """`active_connections` across every tracker that reported."""
    from dpi_engine.connection_tracker import TrackerStats

    total = TrackerStats()
    for r in results:
        total = total.combine(r.tracker_stats)
    return total.active_connections


def _combined_global(results: list[WorkerResult]) -> GlobalStats | None:
    """`combine_tracker_reports` over the reported trackers, or None if none."""
    if not results:
        return None
    from dpi_engine.connection_tracker import combine_tracker_reports

    return combine_tracker_reports(
        [(r.tracker_stats, r.connections) for r in results]
    )


def _combined_fast_path(results: list[WorkerResult]) -> FastPathStats | None:
    """Folds every reported `FastPathStats`, or None if no worker reported."""
    if not results:
        return None
    from dpi_engine.load_balancer import FastPathStats

    total = FastPathStats(fp_id=results[0].fp_stats.fp_id)
    for r in results:
        total = total.combine([r.fp_stats])
    return total


def _combined_lb_stats(
    results: list[_LoadBalancerResult],
) -> LoadBalancerStats | None:
    """Folds every load-balancer stat, or None if none reported."""
    if not results:
        return None
    from dpi_engine.load_balancer import LoadBalancerStats

    total = LoadBalancerStats()
    for r in results:
        total = total.combine([r.stats])
    return total


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
        fold_bidirectional: bool = True,
        on_evicted: Callable[[FiveTuple], None] | None = None,
    ) -> None:
        self.processor = FlowProcessor(
            tracker=ConnectionTracker(
                fp_id=context_id,
                max_connections=max_connections,
                stale_timeout_seconds=stale_timeout_seconds,
                reap_interval_packets=reap_interval_packets,
                fold_bidirectional=fold_bidirectional,
                on_evicted=on_evicted,
            ),
            rule_source=rule_source,
            enable_quic=enable_quic,
            fp_id=context_id,
            # Must match the tracker's, or the side tables would key differently
            # from the flow table -- a blocked flow's reverse direction would then
            # look unblocked to `blocked_tuples`.
            fold_bidirectional=fold_bidirectional,
        )

    def submit(self, item: WorkItem) -> bool:
        """Decides one packet; returns whether it is forwarded.

        Only the decision comes back, never the packet. The single-process path
        writes from its own loop variable and the multiprocess paths read the
        bytes back out of the input file, so nothing needs the payload (D-01).
        """
        return self.processor.process(item)

    def result(self) -> WorkerResult:
        return self.processor.finalize()


def _emit_lifecycle_events(
    bus: EventBus,
    engine: _FlowEngine,
    tuple_: FiveTuple,
    conn_before: Connection | None,
    existed_before: bool,
    was_blocked: bool,
) -> None:
    """Emits the flow-lifecycle events for a packet, after it has been decided.

    Deliberately *after* `engine.submit`, not before. An earlier version emitted
    `FlowCreated` before the decision and then returned, on the reasoning that a
    brand-new flow has no classification yet -- which under-counted `app_counts`
    by exactly the number of distinct flows, because the batch path tallies
    `_record_stats` for every packet including the first. The guarantee test
    caught it. Emitting after the decision means the connection exists and its
    classification is the real one.

    `existed_before` is an **exact-tuple** containment check, not
    `get_connection(tuple_) is None`. That matters: `ConnectionTracker.
    get_connection` also matches the *reverse* five-tuple, so a flow whose
    reverse direction was already tracked would look "not new" and never emit
    `FlowCreated` -- while the entry for this exact tuple did not exist.
    `test_flow_created_precedes_flow_classified` caught that one.

    `FlowBlocked` compares `was_blocked` to the post-decision state, which is
    what makes it fire exactly once per flow rather than once per packet.
    """
    conn = engine.processor.tracker.get_connection(tuple_)
    if conn is None:
        return  # unreachable for an inspectable packet, but cheap to be safe
    if not existed_before:
        bus.emit(FlowCreated(five_tuple=tuple_))
    bus.emit(FlowClassified(five_tuple=tuple_, app_type=conn.app_type, sni=conn.sni))
    if not was_blocked and conn.state is ConnectionState.BLOCKED:
        bus.emit(FlowBlocked(five_tuple=tuple_, app_type=conn.app_type, sni=conn.sni))


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


def _closing(reader: Iterable[RawPacket]) -> contextlib.AbstractContextManager[Iterable[RawPacket]]:
    """Closes `reader` if it is a context manager, else yields it unchanged.

    Only `PcapReader` (the path branch) owns an open file handle. A `CapSource` is
    an arbitrary iterable and closing it here would be closing something the caller
    handed us -- a live stream, most of all. So the type is checked rather than the
    caller's intent assumed.
    """
    if isinstance(reader, PcapReader):
        return reader
    return contextlib.nullcontext(reader)


def _iter_inspectable(
    reader: Iterable[RawPacket],
    stats: DPIStats,
    *,
    bus: EventBus | None = None,
    on_skipped: Callable[[int], None] | None = None,
) -> Iterable[InspectableItem]:
    """Yields (sequence_index, raw, parsed, five_tuple) for every packet that
    is worth inspecting, accumulating the read-level counters into `stats`.

    Non-IPv4 frames, non-TCP/UDP payloads, and unparseable frames are counted
    in `stats.other_packets` and skipped -- never an error, just nothing to do.

    When `bus` is given, a `PacketParsed` event is emitted for *every* packet,
    including the skipped ones with `inspected=False`. The fold needs those:
    `stats.total_packets` and `stats.total_bytes` count them, so an event
    stream that omitted them could never reproduce the batch totals. Emission
    is opt-in so that per-packet cost is paid only by callers who asked for the
    stream.
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
            if bus is not None:
                bus.emit(
                    PacketParsed(
                        sequence_index=sequence_index,
                        byte_len=len(raw.data),
                        inspected=False,
                        is_tcp=False,
                        is_udp=False,
                        # Nothing was considered, so nothing was dropped.
                        forwarded=True,
                    )
                )
            if on_skipped is not None:
                on_skipped(sequence_index)
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
    input_path: str | Path | CapSource,
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
    bus: EventBus | None = None,
    fold_bidirectional: bool = True,
) -> PipelineResult:
    """Runs the full pipeline in one process, with no IPC.

    Raises PcapError on I/O problems with the input/output files (the caller
    decides how to report it); never raises on malformed *packet* content --
    that is handled by the parser/extractor layers returning None.

    `rule_broadcaster`, if given, is polled each packet, which is what makes
    live rule mutation work in the single-process path too.

    **The CLI never supplies it**, and that is deliberate rather than an
    oversight. A one-shot `run` owns its `RuleManager` for the duration of the
    process and nothing else can mutate it, so opening the channel would cost a
    per-packet check for a capability nothing could use -- the same reasoning
    that keeps `--live-rules` a no-op in single-process mode. The parameter
    exists for embedding callers that *do* hold a long-lived `RuleManager` and
    want rules changed mid-run without a second pass over the capture. It was
    reachable only from tests, which made it read as dead API surface rather
    than an embedding hook (`D-26`); the docstring is what was missing, not the
    parameter. The multiprocess variants do use it, via
    `run_pipeline_multiprocess(live_rules=True)` and `run_pipeline_staged`.

    The resource bounds are forwarded explicitly (rather than only defaulted
    deep inside PcapReader/ConnectionTracker) so callers, including the CLI,
    can raise them for an unusually large legitimate capture without editing
    source, while still getting a safe default against adversarial input.
    """
    # `T1-02`. `input_path` may now be a `CapSource` (a stream, or a directory
    # watcher) instead of a filesystem path.
    #
    # A path still goes through `PcapReader`, because that is where the parsing
    # lives and where `reader.linktype` comes from. A `CapSource` is already an
    # iterable of `RawPacket` -- it *delegated* to `PcapReader` to produce them --
    # so it is iterated directly and the same bounds are applied by that reader
    # inside the source. Wrapping a source in a second `PcapReader` would mean
    # parsing packets as if they were bytes, so the two are kept distinct here.
    #
    # `source_path` is the one thing that cannot be generic: `PcapWriter` needs a
    # path to refuse overwriting it. A source reports `None` when it has no single
    # file (a stream cannot be re-opened, a watcher spans a directory), and the
    # guard is then skipped rather than fed a fabricated path.
    if isinstance(input_path, (str, Path)):
        pcap_reader = PcapReader(
            input_path, max_packet_size=max_packet_size, max_total_packets=max_total_packets
        )
        reader: Iterable[RawPacket] = pcap_reader
        linktype = pcap_reader.linktype
        source_path: Path | None = Path(input_path)
        capture_label = str(input_path)
    else:
        # A source validates its own linktype inside the `PcapReader` it delegates
        # to, so this branch has no reader to ask. The value here is what the
        # `CaptureOpened` event reports for a non-file capture.
        reader = input_path
        linktype = ETHERNET_LINKTYPE
        source_path = input_path.path
        capture_label = input_path.describe()

    rules = FixedRuleSource(
        (rule_manager if rule_manager is not None else RuleManager()).snapshot()
    )
    engine = _FlowEngine(
        rules,
        max_connections=max_connections,
        stale_timeout_seconds=stale_timeout_seconds,
        reap_interval_packets=reap_interval_packets,
        enable_quic=enable_quic,
        fold_bidirectional=fold_bidirectional,
        # `FlowEvicted` is published from the tracker's departure hook rather
        # than by polling it afterwards, so the tracker stays ignorant of the
        # event vocabulary and eviction costs one truthiness check when no bus is
        # attached. A closure over `bus` rather than a method, so `_FlowEngine`
        # never has to learn what an event is.
        on_evicted=(
            (lambda t: bus.emit(FlowEvicted(five_tuple=t))) if bus is not None else None
        ),
    )

    stats = DPIStats()

    with _closing(reader), PcapWriter(output_path, source_path=source_path) as writer:
        if bus is not None:
            bus.emit(CaptureOpened(path=capture_label, linktype=linktype))
        try:
            for sequence_index, raw, parsed, tuple_ in _iter_inspectable(reader, stats, bus=bus):
                if rule_broadcaster is not None:
                    rule_broadcaster.publish()

                # `tuple_ in tracker`, not `get_connection(tuple_) is None`:
                # `get_connection` also matches the *reverse* five-tuple, so a
                # flow whose reverse direction was already tracked would look
                # "not new" and never emit FlowCreated -- while the connection
                # for this exact tuple did not exist. The exact-tuple containment
                # check is the one that means what "this flow is new" means.
                conn_before = engine.processor.tracker.get_connection(tuple_)
                # Both checks go through the tracker, which canonicalises under
                # `DEC-05`, so a flow's reverse direction counts as already
                # created and already tracked.
                existed_before = tuple_ in engine.processor.tracker
                # NOT bare `tuple_ in blocked_tuples`: that set is a plain
                # `set[FiveTuple]`, so its membership test hashes the tuple
                # itself and does *not* canonicalise the way
                # `ConnectionTracker.__contains__` does. Probing it with the
                # packet's own tuple reports "not blocked" for every
                # reverse-direction packet of a flow whose canonical key is the
                # forward one -- and then `conn.state is BLOCKED` is true and
                # FlowBlocked fires again. That asymmetry produced three
                # FlowBlocked events for one flow on the sample capture, which
                # is what broke the fold's reproduction of `blocked_flows`.
                was_blocked = (
                    engine.processor.tracker.flow_key(tuple_)
                    in engine.processor.blocked_tuples
                )
                forwarded = engine.submit(
                    WorkItem(
                        sequence_index=sequence_index,
                        raw=raw,
                        parsed=parsed,
                        five_tuple=tuple_,
                    )
                )
                if bus is not None:
                    _emit_lifecycle_events(
                        bus, engine, tuple_, conn_before, existed_before, was_blocked
                    )
                    bus.emit(
                        PacketParsed(
                            sequence_index=sequence_index,
                            byte_len=len(raw.data),
                            inspected=True,
                            is_tcp=parsed.has_tcp,
                            is_udp=parsed.has_udp,
                            forwarded=forwarded,
                        )
                    )

                if forwarded:
                    stats.forwarded_packets += 1
                    writer.write(raw)
                else:
                    stats.dropped_packets += 1
        except PcapLimitExceededError as exc:
            # The one resource bound that ends a run mid-capture. It is a
            # failure the caller already sees as a raised exception; emitting it
            # is what makes a stream consumer able to tell "the capture ended"
            # from "the capture hit a bound", which are otherwise the same thing
            # from the outside.
            if bus is not None:
                bus.emit(
                    LimitExceeded(kind=type(exc).__name__, detail=str(exc))
                )
            raise

    result = engine.result()
    if bus is not None:
        bus.emit(WorkerFinished(worker_id=0, result=result))
        bus.emit(CaptureClosed())
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
    fold_bidirectional: bool = True,
    reorder_window: int | None = DEFAULT_REORDER_WINDOW,
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

    # Bounded: the parent parses faster than the workers can decide, so an
    # unbounded queue here just accumulates the whole capture in memory (`D-02`).
    input_queues: list[Queue[WorkItem | None]] = [
        mp.Queue(maxsize=_QUEUE_MAXSIZE) for _ in range(num_workers)
    ]
    output_queue: Queue[WorkerMessage] = mp.Queue()
    control_queues: list[Queue[RuleSnapshot]] = (
        [mp.Queue() for _ in range(num_workers)] if live_rules else []
    )
    if broadcaster is not None:
        for control_queue in control_queues:
            broadcaster.register(control_queue)

    # Streaming mode is what makes the reorder window meaningful: without
    # per-packet verdicts the parent has nothing to reorder and would have to
    # fall back to the second input pass.
    streaming = reorder_window is not None
    # Decisions and aggregates share one queue, so this holds whichever worker
    # aggregates have already arrived by the time dispatch finishes.
    stream_results: list[WorkerResult] = []

    processes = [
        mp.Process(
            target=worker_main,
            args=(worker_id, input_queues[worker_id], output_queue, rule_source, max_connections),
            kwargs={
                "stale_timeout_seconds": stale_timeout_seconds,
                "reap_interval_packets": reap_interval_packets,
                "control_queue": control_queues[worker_id] if live_rules else None,
                "enable_quic": enable_quic,
                "emit_decisions": streaming,
                "fold_bidirectional": fold_bidirectional,
            },
            name=f"dpi-fp-{worker_id}",
        )
        for worker_id in range(num_workers)
    ]
    for p in processes:
        p.start()

    stats = DPIStats()
    dispatch_succeeded = False
    reorder_buffer: ReorderBuffer | None = None

    try:
        with PcapReader(
            input_path, max_packet_size=max_packet_size, max_total_packets=max_total_packets
        ) as reader, PcapWriter(output_path, source_path=input_path) as writer:
            reorder_buffer = (
                ReorderBuffer(writer, reorder_window) if reorder_window is not None else None
            )
            for sequence_index, raw, parsed, tuple_ in _iter_inspectable(
                reader,
                stats,
                on_skipped=reorder_buffer.offer_skipped if reorder_buffer is not None else None,
            ):
                if broadcaster is not None:
                    broadcaster.publish()
                if reorder_buffer is not None:
                    # Take whatever the workers have already decided, then hold
                    # this packet until its own verdict lands. Backpressure
                    # rather than eviction: the window bounds memory, and a
                    # packet is never dropped or guessed at to make room.
                    _pump_worker_messages(output_queue, reorder_buffer, stream_results)
                    while reorder_buffer.full():
                        _await_space(
                            output_queue, reorder_buffer, stream_results, processes
                        )
                    reorder_buffer.offer(sequence_index, raw)
                # `DEC-05`. The hash must be over the *canonical* key, or the
                # two directions of one conversation land on different workers
                # and each tracker folds only the half it receives -- which is
                # strictly worse than not folding at all.
                worker_id = hash_select(
                    canonical_flow_key(tuple_, fold_bidirectional), num_workers
                )
                _put_bounded(
                    input_queues[worker_id],
                    WorkItem(
                        sequence_index=sequence_index,
                        raw=raw,
                        parsed=parsed,
                        five_tuple=tuple_,
                    ),
                    process=processes[worker_id],
                )
            # Everything has been dispatched, so the workers can be told to
            # finish. Each puts its decisions on the output queue as it makes
            # them and its aggregate last, so this is also what makes the
            # remaining decisions -- and then the aggregates -- arrive.
            for packet_queue in input_queues:
                packet_queue.put(SHUTDOWN_SENTINEL)
            dispatch_succeeded = True

            # Collection stays inside the `with`. In streaming mode the buffer
            # is still writing packets as verdicts arrive, so closing the writer
            # first would have it writing to a closed file -- which is exactly
            # what happened when this ran after the `with` block.
            all_queues = [*input_queues, *control_queues, output_queue]
            try:
                # Every worker puts its decisions ahead of its aggregate on the
                # same FIFO queue, so once all `num_workers` aggregates are in,
                # every decision is in too. That is what makes the buffer's
                # final flush safe here.
                results = _collect_streaming(
                    output_queue, num_workers, reorder_buffer, stream_results, processes
                )
                for process in processes:
                    process.join()
            finally:
                _terminate(processes, all_queues)

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

            if reorder_buffer is not None:
                # Written during dispatch, so there is no second pass to run.
                # The counts come from the buffer, the only place that saw the
                # decisions in the order they were applied.
                stats.forwarded_packets = reorder_buffer.forwarded_packets
                stats.dropped_packets = reorder_buffer.dropped_packets
            else:
                # Legacy path: no per-packet verdicts were emitted, so the
                # decisions exist only as the workers' bitmaps and the packets
                # have to be re-read in order to be written.
                _write_forwarded(
                    stats,
                    results,
                    writer,
                    input_path,
                    max_packet_size=max_packet_size,
                    max_total_packets=max_total_packets,
                )

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
    finally:
        # This MUST run whether dispatch succeeded or raised (e.g.
        # PcapLimitExceededError partway through). The workers are already
        # started and blocked on input_queue.get(); if they were not sent a
        # sentinel and terminated here on the exception path they would hang
        # forever -- a bug this shutdown protocol exists to prevent. On the
        # exception path we cannot trust partially-dispatched workers to
        # produce a coherent result anyway, so they are terminated directly.
        # On the happy path they have already been joined and terminated inside
        # the `with`, so this is a no-op.
        if not dispatch_succeeded:
            _terminate(processes, [*input_queues, *control_queues, output_queue])


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
        # No `process=` handle: the fast paths are this load balancer's own children,
        # spawned in a different process, so it cannot check their liveness. An
        # overrun here stays bounded by the parent's `_RESULT_TIMEOUT_SECONDS`.
        _put_bounded(fast_path.input_queue, item)

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
    fold_bidirectional: bool = True,
    reorder_window: int | None = DEFAULT_REORDER_WINDOW,
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
        num_load_balancers,
        fps_per_lb,
        queue_factory=_bounded_queue_factory,
        fold_bidirectional=fold_bidirectional,
    )
    lb_output_queue: Queue[_LoadBalancerResult] = mp.Queue()
    # Typed as the union because streaming mode interleaves per-packet
    # `PacketDecision`s with the fast paths' aggregates on this one queue.
    fp_output_queue: Queue[WorkerMessage] = mp.Queue()

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

    # Streaming mode is what makes the reorder window meaningful: without
    # per-packet verdicts the parent has nothing to reorder and would have to
    # fall back to the second input pass. Defined before the process list
    # because the fast paths' kwargs reference it.
    streaming = reorder_window is not None
    # Per-packet decisions and the fast paths' aggregates share one queue, so
    # this holds whichever aggregates arrived by the end of dispatch.
    stream_results: list[WorkerResult] = []

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
                "emit_decisions": streaming,
                "fold_bidirectional": fold_bidirectional,
            },
            name=f"dpi-fp-{fp.fp_id}",
        )
        for fp in all_fps
    ]

    for p in [*lb_processes, *fp_processes]:
        p.start()

    stats = DPIStats()
    dispatch_succeeded = False
    reorder_buffer: ReorderBuffer | None = None

    try:
        with PcapReader(
            input_path, max_packet_size=max_packet_size, max_total_packets=max_total_packets
        ) as reader, PcapWriter(output_path, source_path=input_path) as writer:
            # `streaming` is defined above the process list: the fast paths'
            # kwargs need it before this point.
            reorder_buffer = (
                ReorderBuffer(writer, reorder_window) if reorder_window is not None else None
            )
            for sequence_index, raw, parsed, tuple_ in _iter_inspectable(
                reader,
                stats,
                on_skipped=reorder_buffer.offer_skipped if reorder_buffer is not None else None,
            ):
                if broadcaster is not None:
                    broadcaster.publish()
                if reorder_buffer is not None:
                    # The fast paths publish verdicts on `fp_output_queue`
                    # directly -- the load-balancer tier only forwards *input*,
                    # so streaming needs no changes below this point.
                    _pump_worker_messages(fp_output_queue, reorder_buffer, stream_results)
                    while reorder_buffer.full():
                        _await_space(
                            fp_output_queue,
                            reorder_buffer,
                            stream_results,
                            [*lb_processes, *fp_processes],
                        )
                    reorder_buffer.offer(sequence_index, raw)
                # OSC's first hash step, over the canonical key (`DEC-05`). Both
                # halves of a conversation are one flow, so both must reach the
                # same load balancer -- otherwise the shard splits the flow
                # before the fast path ever sees it.
                lb_id = hash_select(
                    canonical_flow_key(tuple_, fold_bidirectional), num_load_balancers
                )
                _put_bounded(
                    lbs[lb_id].input_queue,
                    WorkItem(
                        sequence_index=sequence_index,
                        raw=raw,
                        parsed=parsed,
                        five_tuple=tuple_,
                    ),
                    process=lb_processes[lb_id],
                )

            # Everything has been dispatched, so the load balancers can be told to
            # finish. Each drains its own queue to exhaustion first and only then
            # sends the sentinel to the fast paths it feeds, which is what stops a
            # fast path exiting while items are still in flight.
            for lb in lbs:
                lb.input_queue.put(SHUTDOWN_SENTINEL)
            dispatch_succeeded = True

            # Collection stays inside the `with`, because in streaming mode the
            # buffer is still writing packets as verdicts arrive -- closing the
            # writer first would have it writing to a closed file.
            teardown_queues = [
                *[lb.input_queue for lb in lbs],
                *[fp.input_queue for fp in all_fps],
                *control_queues,
                lb_output_queue,
                fp_output_queue,
            ]
            all_processes = [*lb_processes, *fp_processes]
            try:
                # A fast path puts each decision on the queue as it makes it and
                # its aggregate last, so once all `len(all_fps)` aggregates are in
                # every decision is in too and the final flush is safe.
                fp_results = _collect_streaming(
                    fp_output_queue, len(all_fps), reorder_buffer, stream_results, all_processes
                )
                lb_results = _collect(lb_output_queue, num_load_balancers)
                for p in all_processes:
                    p.join()
            finally:
                _terminate(all_processes, teardown_queues)

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

            if reorder_buffer is not None:
                # Written during dispatch, so there is no second pass to run.
                stats.forwarded_packets = reorder_buffer.forwarded_packets
                stats.dropped_packets = reorder_buffer.dropped_packets
            else:
                # Legacy path: no per-packet verdicts were emitted, so the
                # decisions exist only as the fast paths' bitmaps and the packets
                # have to be re-read in order to be written.
                _write_forwarded(
                    stats,
                    fp_results,
                    writer,
                    input_path,
                    max_packet_size=max_packet_size,
                    max_total_packets=max_total_packets,
                )

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
    finally:
        # Teardown must be unconditional (D-12). `_collect` raises `RuntimeError`
        # on a tier that never reports, and `_accumulate` / `PcapWriter` /
        # `_write_forwarded` can raise after it; any of those used to leave LB and
        # FP processes alive and queues unclosed. On the happy path both tiers
        # have already been joined and terminated inside the `with`, so this is a
        # no-op.
        if not dispatch_succeeded:
            _terminate(
                [*lb_processes, *fp_processes],
                [lb.input_queue for lb in lbs]
                + [fp.input_queue for fp in all_fps]
                + [*control_queues, lb_output_queue, fp_output_queue],
            )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Bounded reorder window (DEC-01)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Pending:
    """One packet waiting for its worker's verdict."""

    #: `None` only for a packet the reader skipped, which has no bytes to write.
    raw: RawPacket | None
    #: `None` until a worker decides. Always `False` for a skipped packet, which
    #: is resolved the moment it is offered.
    forwarded: bool | None
    #: Whether this packet was ever offered to a worker. A skipped frame is
    #: neither written nor counted as a drop, because the drop total is derived
    #: from `total_packets - other_packets` exactly as `_write_forwarded` derives
    #: it -- counting it here too would double-subtract it.
    offered: bool
    #: Set once the packet has gone out from under `next_expected`, i.e. it was
    #: emitted while an *earlier* packet was still undecided. The entry is kept
    #: (without its bytes) precisely so `_advance` can step over the hole it
    #: leaves; dropping it outright would strand `next_expected` there forever
    #: and turn every later packet into an out-of-order emission.
    emitted: bool = False


class ReorderBuffer:
    """Emits packets in input order within a window, and out of order beyond it.

    This is the mechanism that replaces `T0-11`'s second sequential input pass.
    That pass was correct and cheap, and it deferred the *whole* cost to the end:
    nothing was written until the entire capture had been read and dispatched.
    This buffer writes packet N as soon as worker N has decided it, which is what
    makes the pipeline streaming rather than batch.

    **What "the same result" means here (`DEC-01`).** Output is deterministic and
    in input order for as long as a packet's decision arrives while it is still
    inside the window. Beyond that, the buffer emits out of order under the
    policy below. So byte-identical parity with the second-pass path is
    *conditional on the window being large enough*, and the tests pin both sides
    of that boundary rather than one golden output.

    **The late-packet policy.** Workers decide at different speeds and dispatch
    is hash-partitioned, so the packet at `next_expected` is often the one still
    in flight while a hundred later ones have already been decided. Two ways to
    handle that:

      * Block until it arrives. Simple, in-order, and it serialises the whole run
        on whichever worker happened to receive the slowest flow -- the second
        pass had exactly this property and it is why it was slow to produce
        anything.
      * Emit what is ready, out of order, and let the straggler land late.

    The buffer does the first by default and the second only under pressure,
    because order is worth preserving when it is free. When the window is full
    *and* the packet at `next_expected` still has no verdict, `flush_out_of_order`
    writes the lowest-index packet that is decided, freeing the space. That is
    the only circumstance in which order is given up.

    What is never given up is the **decision**: a packet is only ever written
    from a worker's actual verdict. The buffer never guesses, never forwards an
    undecided packet, and never drops one to make room. `out_of_order_emissions`
    counts every departure from input order so a caller can tell how often the
    policy fired, and `late_decisions` counts verdicts that arrived after their
    packet had already gone -- which is the one case where the two paths can
    disagree about a packet and is reported rather than hidden.

    Only the multiprocessing variants need this. `run_pipeline` already writes
    inline as it decides, in input order, with no buffer at all.
    """

    __slots__ = (
        "_store",
        "_writer",
        "dropped_packets",
        "forwarded_packets",
        "late_decisions",
        "next_expected",
        "out_of_order_emissions",
        "window",
    )

    def __init__(self, writer: PcapWriter, window: int) -> None:
        if window < 1:
            raise ValueError(f"window must be >= 1, got {window}")
        self._writer = writer
        self.window = window
        self._store: dict[int, _Pending] = {}
        #: Lowest sequence index not yet emitted. Every contiguous run of
        #: resolved packets is flushed from here upward.
        self.next_expected = 0
        self.forwarded_packets = 0
        self.dropped_packets = 0
        self.out_of_order_emissions = 0
        self.late_decisions = 0

    # -- feeding ----------------------------------------------------------

    def offer(self, sequence_index: int, raw: RawPacket) -> None:
        """Takes custody of one packet, awaiting its decision."""
        self._store[sequence_index] = _Pending(raw=raw, forwarded=None, offered=True)

    def offer_skipped(self, sequence_index: int) -> None:
        """Accounts for a packet the reader declined to inspect.

        Resolved immediately, since nothing will decide it: it is neither
        written nor counted. It still has to occupy its index, or `next_expected`
        would stall forever on a hole no worker is ever going to fill.

        Deliberately does *not* advance the cursor itself. A skipped entry is
        already resolved, so the next `decide` or the final `finish` will step
        over it in the same way it steps over anything else resolved -- calling
        `_advance` here would be unobservable, and a line no test can make fail
        is a line nobody will notice rotting.
        """
        self._store[sequence_index] = _Pending(raw=None, forwarded=False, offered=False)

    def decide(self, sequence_index: int, forwarded: bool) -> None:
        """Applies one worker's verdict, flushing whatever that unblocks."""
        pending = self._store.get(sequence_index)
        if pending is None:
            # Its packet has already gone. Either it was flushed out of order
            # while this verdict was still in flight, or the index was never
            # offered -- both are worth counting, and neither can be repaired
            # by writing it now.
            self.late_decisions += 1
            return
        pending.forwarded = forwarded
        self._advance()

    # -- querying ---------------------------------------------------------

    def _held(self) -> int:
        """Packets whose bytes are still in memory."""
        return sum(1 for pending in self._store.values() if pending.raw is not None)

    def full(self) -> bool:
        """True when no further packet can be held without exceeding the window."""
        return self._held() >= self.window

    def pending(self) -> int:
        """Packets still waiting on a verdict. Zero means the run can finish."""
        return sum(1 for pending in self._store.values() if pending.forwarded is None)

    def flush_out_of_order(self) -> bool:
        """Emits one decided packet that is stuck behind an undecided one.

        Returns True if it emitted anything, so a caller can loop until the
        window has space or nothing is left to emit. Deliberately emits only the
        *lowest* such index, so that when several candidates exist the output
        stays as close to input order as the policy allows.
        """
        for index in sorted(self._store):
            pending = self._store[index]
            if pending.forwarded is None or pending.emitted:
                continue
            # No `index == next_expected` case to exclude: `decide` and
            # `offer_skipped` both call `_advance` before returning, and it
            # drains every decided entry from `next_expected` upward. A decided
            # packet at the cursor cannot therefore still be in the store here,
            # so there is nothing to skip over and no reason to special-case it.
            self._emit(pending)
            # The entry is kept as a tombstone but its bytes are released: the
            # slot it held against the window is what the caller was trying to
            # free, and `_advance` needs the marker to step over the hole.
            pending.emitted = True
            pending.raw = None
            self.out_of_order_emissions += 1
            return True
        return False

    def finish(self) -> None:
        """Flushes everything resolvable. Anything left has no verdict yet."""
        self._advance()
        while self.flush_out_of_order():
            pass

    # -- internals --------------------------------------------------------

    def _advance(self) -> None:
        """Emits the contiguous run of resolved packets from `next_expected`.

        Steps *over* entries that were already emitted out of order rather than
        stopping at them. Such an entry leaves a hole, and `next_expected` has to
        move past it: otherwise the straggler that finally resolves it leaves the
        cursor stranded one short, and every subsequent packet is treated as
        stuck behind something that left long ago -- silently degrading the whole
        rest of the capture to out-of-order emission.
        """
        while True:
            pending = self._store.get(self.next_expected)
            if pending is None or pending.forwarded is None:
                return
            del self._store[self.next_expected]
            if not pending.emitted:
                self._emit(pending)
            self.next_expected += 1

    def _emit(self, pending: _Pending) -> None:
        if pending.forwarded and pending.raw is not None:
            self._writer.write(pending.raw)
            self.forwarded_packets += 1
        elif pending.offered:
            self.dropped_packets += 1


def _pump_worker_messages(
    output_queue: Queue[WorkerMessage],
    buffer: ReorderBuffer | None,
    results: list[WorkerResult],
) -> int:
    """Handles every message currently waiting, without blocking.

    Returns how many were handled, so a caller under backpressure can tell
    progress from a stall. Both message kinds share one queue, so a parent that
    only understood `WorkerResult` would silently discard every per-packet
    decision -- the reason this function exists rather than being inlined twice.
    """
    handled = 0
    while True:
        try:
            message = output_queue.get_nowait()
        except queue_module.Empty:
            return handled
        if isinstance(message, PacketDecision):
            if buffer is not None:
                buffer.decide(message.sequence_index, message.forwarded)
        else:
            results.append(message)
        handled += 1


def _await_space(
    output_queue: Queue[WorkerMessage],
    buffer: ReorderBuffer,
    results: list[WorkerResult],
    processes: Sequence[mp.Process],
) -> None:
    """Blocks until the reorder window has room again, or fails loudly.

    Called when the buffer is full, which means the packet at `next_expected` has
    no verdict and later packets are stacked up behind it. Waiting is correct --
    the alternative is guessing, which `ReorderBuffer` never does -- but an
    unbounded wait is how a dead worker turns into a hung run, which is the exact
    failure `D-12`'s teardown protocol exists to prevent. So the wait is bounded
    and it re-checks whether the workers are still alive.
    """
    while buffer.full():
        _pump_worker_messages(output_queue, buffer, results)
        if not buffer.full():
            return
        try:
            message = output_queue.get(timeout=_RESULT_TIMEOUT_SECONDS)
        except queue_module.Empty:
            raise RuntimeError(
                f"reorder window of {buffer.window} stayed full for "
                f"{_RESULT_TIMEOUT_SECONDS}s with no worker making progress"
            ) from None
        if isinstance(message, PacketDecision):
            buffer.decide(message.sequence_index, message.forwarded)
        else:
            results.append(message)
        # A worker that died leaves its packets undecided forever, so without
        # this the stall would look like a slow one right up to the timeout.
        _ensure_alive(processes)


def _ensure_alive(processes: Sequence[mp.Process]) -> None:
    """Raises naming every worker that died abnormally, so a stall cannot
    masquerade as slowness.

    Abnormal specifically: a worker that has finished its queue and exited
    cleanly is *not* dead, it is done -- and with more workers than a small
    capture has flows, that is the common case, not the exceptional one. Only a
    non-zero exit (a crash, or a signal) means the run cannot make progress.
    """
    broken = [
        p.name for p in processes if not p.is_alive() and p.exitcode not in (0, None)
    ]
    if broken:
        raise RuntimeError(
            f"worker(s) exited abnormally without reporting: {', '.join(broken)}"
        )


def _collect_streaming(
    output_queue: Queue[WorkerMessage],
    expected: int,
    buffer: ReorderBuffer | None,
    results: list[WorkerResult],
    processes: Sequence[mp.Process],
) -> list[WorkerResult]:
    """Reads the queue until `expected` worker aggregates have arrived.

    Streaming mode's counterpart to `_collect`. The two share a queue, so a
    collector that assumed every message was an aggregate would consume the
    per-packet decisions and hand them to nothing -- the reorder buffer would
    then never see a verdict and the window would fill and stall. This is why
    the drain is one function and not two.

    Waiting for the *aggregates* rather than for a decision count is what makes
    the final flush correct: a worker puts each decision on the queue as it
    makes it and its aggregate last, so once all `expected` aggregates are in,
    every decision is in too and nothing is left undecided.

    Returns `results` extended in place, which already holds whatever dispatch
    managed to drain.
    """
    deadline = time.monotonic() + _RESULT_TIMEOUT_SECONDS
    while len(results) < expected:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(
                f"only {len(results)} of {expected} workers reported within "
                f"{_RESULT_TIMEOUT_SECONDS}s"
            )
        try:
            # Wait in slices rather than for the whole budget, so liveness is
            # re-checked while a stall is in progress.
            message = output_queue.get(timeout=min(_LIVENESS_POLL_SECONDS, remaining))
        except queue_module.Empty:
            # `D-13`. The processes may not be slow at all -- they may be dead. A
            # dead load balancer sends no sentinel to its fast paths (`_lb_main` is
            # the only thing that does), so its fast paths block on
            # `input_queue.get()` forever and never report. Blocking for the whole
            # budget would burn 120 s discovering it and then blame the fast paths,
            # which are innocent: the operator would go and look at the wrong tier.
            _ensure_alive(processes)
            continue
        if isinstance(message, PacketDecision):
            if buffer is not None:
                buffer.decide(message.sequence_index, message.forwarded)
        else:
            results.append(message)
        _ensure_alive(processes)

    if buffer is not None:
        buffer.finish()
    return results


def _write_forwarded(
    stats: DPIStats,
    results: Sequence[WorkerResult],
    writer: PcapWriter,
    input_path: str | Path,
    *,
    max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
    max_total_packets: int = DEFAULT_MAX_TOTAL_PACKETS,
) -> None:
    """Writes every forwarded packet, in input order, counting drops.

    Used by the multiprocessing variants, where the workers hold the decisions
    but the parent holds the bytes.

    The parent makes a second sequential pass over the input file and writes
    packet *N* wherever bit *N* is set in the union of the workers' decision
    bitmaps. Before this, each worker shipped every packet's bytes back to the
    parent, which materialised the lot and sorted it by `sequence_index` -- the
    unbounded accumulation of D-01, and the reason output order was only
    deterministic *because* of that materialisation.

    Re-reading the input removes the materialisation *and* the sort at once,
    because the second pass is already sequential over the input. Output is
    byte-identical to the old path, and it is why the plan's `DEC-01` question
    does not need answering first: byte-order determinism is preserved outright
    rather than traded away.

    Drop counts come from arithmetic rather than a second bitmap. `stats` was
    filled by the dispatch pass, where `total_packets` counts every packet read
    and `other_packets` the ones skipped as uninspectable, so
    `total_packets - other_packets` is exactly the number of packets a worker
    decided -- and every decided packet either forwarded or dropped.
    """
    bits = bytearray()
    for result in results:
        worker_bits = result.forwarded_bits
        if len(worker_bits) > len(bits):
            bits.extend(bytes(len(worker_bits) - len(bits)))
        for i, byte in enumerate(worker_bits):
            bits[i] |= byte

    forwarded = 0
    with PcapReader(
        input_path, max_packet_size=max_packet_size, max_total_packets=max_total_packets
    ) as reader:
        for sequence_index, raw in enumerate(reader):
            if is_forwarded(bits, sequence_index):
                writer.write(raw)
                forwarded += 1

    stats.forwarded_packets += forwarded
    stats.dropped_packets += (stats.total_packets - stats.other_packets) - forwarded


#: Items a packet queue may hold before the dispatcher blocks. The queues carry
#: `WorkItem`s, each holding a whole packet, so an unbounded queue is a memory
#: bound in name only: the parent would read the entire capture into the queues
#: as fast as it could parse, which is `D-02` in everything but spelling. Bounding
#: them makes the read loop apply backpressure to itself, so peak memory becomes
#: a function of this number rather than of the capture's size.
#:
#: Sized for throughput headroom, not for a tight memory cap: at the default
#: `max_packet_size` of 64 KiB, 1024 in-flight items per worker is at most
#: 64 MiB per worker, and in practice far less because most packets are ~100
#: bytes. Raise it if a future measurement shows queueing is the bottleneck.
_QUEUE_MAXSIZE = 1024

#: How long a single bounded `put` waits before the consumer is re-checked.
#: Long enough that a merely-busy worker is never mistaken for a dead one.
_QUEUE_PUT_TIMEOUT_SECONDS = 30.0


def _bounded_queue_factory() -> Any:
    """The queue factory `build_pipeline_graph` uses for the staged pipeline.

    Every queue it creates carries `WorkItem`s -- both the parent-to-load-balancer
    hop and the load-balancer-to-fast-path hop -- so all of them are bounded. The
    LB tier spawning the FP queues here is what makes `D-02` apply to the staged
    pipeline as well as the single-tier one.
    """
    return mp.Queue(maxsize=_QUEUE_MAXSIZE)


def _put_bounded(
    queue: Queue[Any], item: Any, *, process: mp.process.BaseProcess | None = None
) -> None:
    """Puts to a bounded packet queue, converting a stuck consumer into an error.

    A bounded queue makes the dispatcher wait instead of growing without limit
    (`D-02`), but a plain blocking `put` would turn a *dead* consumer into an
    indefinite hang -- exactly the failure mode `_collect`'s timeout exists to
    avoid, just moved earlier in the pipeline. So each wait is bounded, and on
    expiry we check whether the consumer is still alive: if it died, raise rather
    than block forever on a queue nobody will ever drain; if it is merely slow,
    keep waiting rather than give up on a healthy worker.

    `process` is omitted only where the caller has no handle to the consumer (the
    load balancer feeding its fast paths -- those are its own children, spawned in
    a different process). There an overrun stays bounded by
    `_RESULT_TIMEOUT_SECONDS`, because the parent is still waiting on that tier's
    result and will time out with a diagnosable message.
    """
    while True:
        try:
            queue.put(item, timeout=_QUEUE_PUT_TIMEOUT_SECONDS)
            return
        except queue_module.Full:
            if process is not None and not process.is_alive():
                raise RuntimeError(
                    "a packet queue is full and its consumer process has died; "
                    "the run cannot make progress"
                ) from None


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

#: How long a single `get` on a result queue waits before liveness is re-checked.
#: `D-13`. A dead worker is reported within this many seconds rather than after the
#: full `_RESULT_TIMEOUT_SECONDS`, while a healthy-but-slow worker is still given
#: the entire budget to finish. Kept well under the budget so the slicing is
#: unobservable for a run that is merely slow.
_LIVENESS_POLL_SECONDS = 1.0


def _terminate(
    processes: Sequence[mp.process.BaseProcess], queues: Sequence[Any]
) -> None:
    """Best-effort teardown for every exit path: terminate what is still alive,
    then join, then close the queues.

    Used unconditionally from a `finally` in both multiprocess variants, so it
    runs on the happy path too. That is safe and idempotent: a process that has
    already been joined is not `is_alive()`, so `terminate()` is skipped, the
    join returns immediately, and the queue closes are the same ones the old
    explicit `_close_quietly` loop performed. Centralising it here is what stops
    the two variants drifting apart again.

    On the failure path no sentinel is coming, so terminate rather than wait.

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
