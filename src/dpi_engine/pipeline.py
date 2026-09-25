"""Single-process DPI pipeline: read -> parse -> track -> classify ->
rule-check -> write filtered output pcap + classification report.

Ports OSC/src/main_working.cpp to Python (the most complete single-threaded
reference implementation -- see DESIGN_DECISIONS.md). This is the Task 8
vertical slice: no multiprocessing yet (that's Task 10's worker.py), just
the full per-packet decision logic wired together and proven correct in
one process first, so pipeline-logic bugs and multiprocessing bugs are
never conflated (see DESIGN_DECISIONS.md "Testing strategy").

Per-packet decision flow (mirrors main_working.cpp's main loop):
1. Parse the packet; skip anything without IP or without TCP/UDP.
2. Look up or create the flow for this packet's exact five-tuple.
3. If the flow isn't yet confirmed-classified, try SNI (port 443) / HTTP
   Host (port 80) extraction; fall back to a DNS or port-based guess.
4. Once a flow is marked blocked, it stays blocked (checked once per flow,
   not re-evaluated every packet -- matches the original).
5. Forward (write to output) or drop (count only) based on the flow's
   blocked state.

Known behavioral quirk carried forward from the original (not a bug, not
fixed -- see DESIGN_DECISIONS.md): flows are keyed by the packet's *exact*
five-tuple, not folded with the reverse direction. This means the
client->server direction of a connection (which carries the ClientHello/
HTTP request and gets classified and potentially blocked) and the
server->client direction are tracked as two independent flow-table entries.
A block decision made on one direction does NOT automatically apply to the
other direction. This matches main_working.cpp exactly (it never calls
FiveTuple::reverse() anywhere in its main loop) and is preserved as-is
since "fixing" it would change blocking scope/behavior beyond what the
bug-fix list in DESIGN_DECISIONS.md calls for.
"""

from __future__ import annotations

import multiprocessing as mp
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dpi_engine.connection_tracker import DEFAULT_MAX_CONNECTIONS, ConnectionTracker
from dpi_engine.packet_parser import ParsedPacket, parse_packet
from dpi_engine.pcap_io import (
    DEFAULT_MAX_PACKET_SIZE,
    DEFAULT_MAX_TOTAL_PACKETS,
    PcapError,
    PcapReader,
    PcapWriter,
)
from dpi_engine.rule_manager import RuleManager
from dpi_engine.sni_extractor import extract_dns_query, extract_http_host, extract_sni
from dpi_engine.types import AppType, DPIStats, FiveTuple, sni_to_app_type

# Minimum bytes needed for a TLS record header to even be worth trying to
# parse (matches main_working.cpp's "payload_len > 5" guard).
_MIN_TLS_PAYLOAD_LEN = 5


@dataclass(slots=True)
class PipelineResult:
    """Everything the CLI / tests need after a pipeline run."""

    stats: DPIStats
    app_counts: dict[AppType, int] = field(default_factory=dict)
    detected_domains: dict[str, AppType] = field(default_factory=dict)
    blocked_flows: list[tuple[FiveTuple, AppType, str]] = field(default_factory=list)
    # Populated only by run_pipeline_multiprocess: packet counts dispatched
    # to each worker, in worker-id order (mirrors the original's per-thread
    # "LB0 dispatched / FP0 processed" style report section).
    per_worker_packet_counts: list[int] = field(default_factory=list)


def classify_flow_from_packet(
    parsed: ParsedPacket,
    app_type: AppType,
    sni: str,
) -> tuple[AppType, str, bool]:
    """Attempts to (re)classify a flow using this single packet's payload.

    Returns (new_app_type, new_sni, confirmed). If nothing new could be
    determined, returns the flow's existing (app_type, sni) unchanged with
    confirmed=False (a no-op update).
    """
    # Only attempt SNI extraction if not already confirmed-classified with
    # a specific app (mirrors main_working.cpp: retries while UNKNOWN or
    # still-generic HTTPS/HTTP, matching the "confirmed" concept from
    # connection_tracker.py -- generic HTTPS/HTTP fallbacks are guesses).
    retry_ok = app_type in (AppType.UNKNOWN, AppType.HTTPS) and not sni

    if retry_ok and parsed.has_tcp and parsed.dst_port == 443:
        if len(parsed.payload) > _MIN_TLS_PAYLOAD_LEN:
            found = extract_sni(parsed.payload)
            if found:
                return sni_to_app_type(found), found, True

    retry_ok_http = app_type in (AppType.UNKNOWN, AppType.HTTP) and not sni
    if retry_ok_http and parsed.has_tcp and parsed.dst_port == 80:
        found = extract_http_host(parsed.payload)
        if found:
            return sni_to_app_type(found), found, True

    if app_type == AppType.UNKNOWN and parsed.has_udp and (
        parsed.dst_port == 53 or parsed.src_port == 53
    ):
        query = extract_dns_query(parsed.payload) if parsed.payload else None
        if query:
            return sni_to_app_type(query), query, True
        return AppType.DNS, sni, False

    if app_type == AppType.UNKNOWN:
        if parsed.has_tcp and parsed.dst_port == 443:
            return AppType.HTTPS, sni, False
        if parsed.has_tcp and parsed.dst_port == 80:
            return AppType.HTTP, sni, False

    return app_type, sni, False


def run_pipeline(
    input_path: str | Path,
    output_path: str | Path,
    rule_manager: Optional[RuleManager] = None,
    *,
    max_connections: int = DEFAULT_MAX_CONNECTIONS,
    max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
    max_total_packets: int = DEFAULT_MAX_TOTAL_PACKETS,
) -> PipelineResult:
    """Runs the full single-process pipeline. Raises PcapError on I/O
    problems with the input/output files (caller/CLI decides how to report
    it); never crashes on malformed *packet* content -- that's handled by
    the parser/extractor layers returning None instead of raising.

    max_connections/max_packet_size/max_total_packets are the resource
    bounds required by DESIGN_DECISIONS.md "Safety constraints" --
    explicitly forwarded here (not just defaulted deep inside PcapReader/
    ConnectionTracker) so callers, including the CLI, can override them for
    unusually large legitimate captures without editing source, while
    still getting a safe default against adversarial input out of the box.
    """
    if rule_manager is None:
        rule_manager = RuleManager()

    tracker = ConnectionTracker(fp_id=0, max_connections=max_connections)
    blocked_tuples: set[FiveTuple] = set()

    stats = DPIStats()
    app_counts: dict[AppType, int] = {}
    detected_domains: dict[str, AppType] = {}
    blocked_flows: list[tuple[FiveTuple, AppType, str]] = []

    with PcapReader(
        input_path, max_packet_size=max_packet_size, max_total_packets=max_total_packets
    ) as reader:
        with PcapWriter(output_path, source_path=input_path) as writer:
            for raw in reader:
                stats.total_packets += 1
                stats.total_bytes += raw.orig_len

                parsed = parse_packet(raw)
                if parsed is None or not parsed.has_ip or not (parsed.has_tcp or parsed.has_udp):
                    stats.other_packets += 1
                    continue

                if parsed.has_tcp:
                    stats.tcp_packets += 1
                else:
                    stats.udp_packets += 1

                five_tuple = FiveTuple(
                    src_ip=parsed.src_ip,
                    dst_ip=parsed.dst_ip,
                    src_port=parsed.src_port,
                    dst_port=parsed.dst_port,
                    protocol=parsed.protocol,
                )

                conn = tracker.get_or_create_connection(five_tuple)
                tracker.update_connection(conn, raw.orig_len, is_outbound=True)

                new_app, new_sni, confirmed = classify_flow_from_packet(
                    parsed, conn.app_type, conn.sni
                )
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
                if conn.sni:
                    detected_domains[conn.sni] = conn.app_type

                if five_tuple in blocked_tuples:
                    stats.dropped_packets += 1
                else:
                    stats.forwarded_packets += 1
                    writer.write(raw)

    tracker_stats = tracker.get_stats()
    stats.active_connections = tracker_stats.active_connections

    return PipelineResult(
        stats=stats,
        app_counts=app_counts,
        detected_domains=detected_domains,
        blocked_flows=blocked_flows,
    )


def run_pipeline_multiprocess(
    input_path: str | Path,
    output_path: str | Path,
    rule_manager: Optional[RuleManager] = None,
    *,
    num_workers: int = 4,
    max_connections: int = DEFAULT_MAX_CONNECTIONS,
    max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
    max_total_packets: int = DEFAULT_MAX_TOTAL_PACKETS,
) -> PipelineResult:
    """Hash-partitioned multiprocessing pipeline (Task 10).

    Mirrors the original's LB->FP consistent-hashing design (see
    DESIGN_DECISIONS.md "Architecture"): the reader (this function, running
    in the main process) parses every packet and dispatches it to
    `hash(five_tuple) % num_workers`, guaranteeing every packet of a given
    connection lands on the same worker process, so per-flow classification
    state stays correct exactly as it does in the single-process pipeline.

    Produces IDENTICAL results to run_pipeline() on the same input/rules
    (see DESIGN_DECISIONS.md "Testing strategy" -- this is verified
    directly in tests/test_worker.py by re-running the same fixture through
    both and comparing every field of PipelineResult). The only difference
    is that packets may be interleaved differently across five-tuples in
    the internal processing order (each worker processes its own queue in
    strict FIFO order, but workers run concurrently) -- the OUTPUT PCAP'S
    packet order is explicitly restored to match the input order before
    writing, using each WorkItem's sequence_index, so from the outside
    (output pcap contents, stats, classification) the two pipelines are
    indistinguishable.

    Safety: worker processes are pure compute (see worker.py) -- only this
    function (running in the main process) ever touches the filesystem.
    """
    if num_workers < 1:
        raise ValueError(f"num_workers must be >= 1, got {num_workers}")

    if rule_manager is None:
        rule_manager = RuleManager()

    # Local import to avoid a module-level circular dependency (worker.py
    # imports classify_flow_from_packet from this module).
    from dpi_engine.worker import SHUTDOWN_SENTINEL, WorkItem, worker_main

    input_queues: list[mp.Queue] = [mp.Queue() for _ in range(num_workers)]
    output_queue: mp.Queue = mp.Queue()

    processes = [
        mp.Process(
            target=worker_main,
            args=(worker_id, input_queues[worker_id], output_queue, rule_manager, max_connections),
            name=f"dpi-worker-{worker_id}",
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
        ) as reader:
            for sequence_index, raw in enumerate(reader):
                stats.total_packets += 1
                stats.total_bytes += raw.orig_len

                parsed = parse_packet(raw)
                if parsed is None or not parsed.has_ip or not (parsed.has_tcp or parsed.has_udp):
                    stats.other_packets += 1
                    continue

                five_tuple = FiveTuple(
                    src_ip=parsed.src_ip,
                    dst_ip=parsed.dst_ip,
                    src_port=parsed.src_port,
                    dst_port=parsed.dst_port,
                    protocol=parsed.protocol,
                )
                worker_id = hash(five_tuple) % num_workers
                input_queues[worker_id].put(
                    WorkItem(
                        sequence_index=sequence_index,
                        raw=raw,
                        parsed=parsed,
                        five_tuple=five_tuple,
                    )
                )
        dispatch_succeeded = True
    finally:
        # This MUST run whether dispatch succeeded or raised (e.g.
        # PcapLimitExceededError partway through the file) -- worker
        # processes are already started and blocked on input_queue.get();
        # if we didn't send a sentinel and terminate them here on the
        # exception path, they would hang forever, exactly the kind of
        # "workers left running, never signaled to shut down" bug this
        # port's shutdown protocol is designed to prevent (see worker.py's
        # module docstring). On the exception path we cannot trust
        # partially-dispatched workers to produce a coherent PipelineResult
        # anyway, so we terminate them directly rather than trying to
        # drain and collect results that will never be used.
        if dispatch_succeeded:
            # Every packet has now been dispatched. Send exactly one
            # shutdown sentinel per worker -- see worker.py's module
            # docstring for why this ordering (dispatch everything, THEN
            # signal shutdown) guarantees no packet is ever dropped,
            # unlike the original's shutdown-races-with-push bug.
            for q in input_queues:
                q.put(SHUTDOWN_SENTINEL)
        else:
            for p in processes:
                p.terminate()
            for p in processes:
                p.join(timeout=5)
            for q in input_queues:
                q.close()
            output_queue.close()

    if not dispatch_succeeded:
        # Unreachable in practice (the try block either completes and sets
        # dispatch_succeeded=True, or raises and propagates past this
        # function before reaching here) -- kept only so a static reader
        # can see this function never silently returns a bogus
        # PipelineResult after a dispatch failure. The actual re-raise
        # happens naturally: PcapReader's context manager propagates its
        # exception through the `with` block above, past the `finally`,
        # and out of this function.
        raise AssertionError("unreachable: dispatch failure must propagate its exception")

    results = [output_queue.get() for _ in range(num_workers)]
    for p in processes:
        p.join()

    results.sort(key=lambda r: r.worker_id)

    all_processed_packets = [pp for r in results for pp in r.processed_packets]
    all_processed_packets.sort(key=lambda pp: pp.sequence_index)

    app_counts: dict[AppType, int] = {}
    detected_domains: dict[str, AppType] = {}
    blocked_flows: list[tuple[FiveTuple, AppType, str]] = []
    per_worker_packet_counts: list[int] = []

    for r in results:
        per_worker_packet_counts.append(len(r.processed_packets))
        stats.tcp_packets += r.tcp_count
        stats.udp_packets += r.udp_count
        blocked_flows.extend(r.blocked_flows)
        for app, count in r.app_counts.items():
            app_counts[app] = app_counts.get(app, 0) + count
        for conn in r.connections:
            if conn.sni:
                detected_domains[conn.sni] = conn.app_type

    with PcapWriter(output_path, source_path=input_path) as writer:
        for pp in all_processed_packets:
            if pp.forwarded:
                stats.forwarded_packets += 1
                writer.write(pp.raw)
            else:
                stats.dropped_packets += 1

    combined_tracker_stats = None
    for r in results:
        combined_tracker_stats = (
            r.tracker_stats
            if combined_tracker_stats is None
            else combined_tracker_stats.combine(r.tracker_stats)
        )
    if combined_tracker_stats is not None:
        stats.active_connections = combined_tracker_stats.active_connections

    return PipelineResult(
        stats=stats,
        app_counts=app_counts,
        detected_domains=detected_domains,
        blocked_flows=blocked_flows,
        per_worker_packet_counts=per_worker_packet_counts,
    )
