"""Fast-path (FP) processing: the per-flow decision engine.

Ports OSC's `FastPathProcessor` (OSC/include/fast_path.h,
OSC/src/fast_path.cpp), and is also the body of the worker process used by
the single-tier multiprocessing pipeline.

=============================================================================
Structure
=============================================================================
The decision logic lives in `FlowProcessor`, a plain class with no knowledge
of multiprocessing. `worker_main` is a thin `multiprocessing.Process` target
that owns one `FlowProcessor` and pumps a queue through it. That split exists
so the exact same logic can be:

  * unit-tested directly, with no process spawning (most of the test suite
    does this);
  * run in-process, single-file, with no IPC at all (`run_pipeline`);
  * run in a worker process for the single-tier pipeline;
  * run in an FP process behind an LB stage for the two-tier pipeline.

=============================================================================
Shutdown/drain fix
=============================================================================
OSC's `LoadBalancer::stop` / `FastPathProcessor::stop` called
`input_queue_.shutdown()` immediately, which woke any blocked `push()` caller
and made it *silently drop the item being pushed* (thread_safe_queue.h:26 --
`if (shutdown_) return;`). Packets could vanish on every shutdown, and
nothing reported it.

This port never shuts a queue down while items might still be pushed to it.
The reader pushes every packet, THEN pushes exactly one sentinel per consumer
(worker.py's `SHUTDOWN_SENTINEL`, load_balancer.py's identical constant), and
each consumer's loop is a plain blocking `get()` that breaks on the sentinel.
No timeout-based polling can race with a producer, so every packet dispatched
is processed by exactly one consumer before it exits.
"""

from __future__ import annotations

import os
import queue as queue_module
import time
from dataclasses import dataclass, field
from multiprocessing import Queue
from typing import Protocol

from dpi_engine.connection_tracker import (
    DEFAULT_REAP_INTERVAL_PACKETS,
    DEFAULT_STALE_TIMEOUT_SECONDS,
    ConnectionTracker,
    TrackerStats,
)
from dpi_engine.load_balancer import SHUTDOWN_SENTINEL, FastPathStats
from dpi_engine.packet_parser import ParsedPacket
from dpi_engine.pcap_io import RawPacket
from dpi_engine.quic import QuicFlowInspector, is_quic, is_quic_initial
from dpi_engine.rule_manager import RuleSnapshot
from dpi_engine.sni_extractor import (
    extract_dns_query,
    extract_http_host,
    extract_sni,
)
from dpi_engine.types import AppType, Connection, ConnectionState, FiveTuple, sni_to_app_type

#: Minimum bytes worth attempting a TLS parse on (matches OSC's
#: "payload_len > 5" guard: a TLS record header is 5 bytes).
_MIN_TLS_PAYLOAD_LEN = 5

# Test-only hook: when set, injects an artificial per-packet delay inside each
# worker process. Used exclusively by
# tests/test_worker_stress.py to stress the shutdown/drain protocol's timing
# under conditions where workers are guaranteed to still have a large backlog
# when shutdown sentinels are sent. An environment variable (rather than a
# monkeypatch) is necessary because Windows' multiprocessing "spawn" start
# method re-imports this module fresh in each child process instead of
# inheriting the parent's in-memory patched state -- but environment variables
# ARE inherited by spawned children, so this is the one mechanism that
# reliably reaches them. Never read or set in production code paths.
_TEST_DELAY_MS_ENV_VAR = "DPI_ENGINE_TEST_WORKER_DELAY_MS"


def _maybe_apply_test_delay() -> None:
    delay_ms = os.environ.get(_TEST_DELAY_MS_ENV_VAR)
    if delay_ms:
        time.sleep(float(delay_ms) / 1000.0)


class RuleSource(Protocol):
    """Anything that can hand out an immutable `RuleSnapshot` plus a cheap
    version to poll.

    Implemented by `RuleManager` (the mutable admin front door) and by
    `pipeline.RuleBroadcaster.SnapshotHolder` (what a worker process uses
    after receiving updates over its control channel). Expressed as a
    Protocol so the processor does not care which it has.
    """

    @property
    def version(self) -> int: ...

    def snapshot(self) -> RuleSnapshot: ...


@dataclass(slots=True)
class WorkItem:
    """One packet handed to a fast-path, tagged with its original position in
    the input file.

    `sequence_index` is what lets the parent restore input order in the output
    pcap even though fast-paths finish packets out of order relative to each
    other. Relative order *within* one five-tuple is guaranteed anyway, because
    hash-partitioning sends all of a flow's packets to the same fast-path,
    which drains its own queue strictly FIFO.
    """

    sequence_index: int
    raw: RawPacket
    parsed: ParsedPacket
    five_tuple: FiveTuple


@dataclass(slots=True)
class ProcessedPacket:
    """One packet's outcome, returned from a fast-path to the parent for
    output-pcap assembly."""

    sequence_index: int
    raw: RawPacket
    forwarded: bool


@dataclass(slots=True)
class FlowProcessor:
    """Owns one bounded flow table and makes the per-packet decision.

    This is the port of `FastPathProcessor::processPacket` plus its
    `inspectPayload` / `tryExtractSNI` / `tryExtractHTTPHost` / `checkRules` /
    `updateTCPState` helpers, with the per-packet ordering made explicit (see
    `process`).
    """

    tracker: ConnectionTracker
    rule_source: RuleSource
    enable_quic: bool = True
    fp_id: int = 0
    #: The rule snapshot currently in force. Rebound (never mutated) when a
    #: newer snapshot arrives, so the hot path is one attribute read.
    _rules: RuleSnapshot = field(init=False)
    _rules_version: int = field(init=False)
    stats: FastPathStats = field(init=False)
    blocked_tuples: set[FiveTuple] = field(default_factory=set)
    blocked_flows: list[tuple[FiveTuple, AppType, str]] = field(default_factory=list)
    app_counts: dict[AppType, int] = field(default_factory=dict)
    detected_domains: dict[str, AppType] = field(default_factory=dict)
    quic_packets: int = 0
    quic_undecryptable: int = 0
    _quic_inspectors: dict[FiveTuple, QuicFlowInspector] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._rules = self.rule_source.snapshot()
        self._rules_version = self._rules.version
        self.stats = FastPathStats(fp_id=self.fp_id)

    # ------------------------------------------------------------------
    # Rule updates
    # ------------------------------------------------------------------

    def refresh_rules(self) -> bool:
        """Picks up a newer rule snapshot if the source has one.

        Returns True if the active snapshot changed. Cheap when nothing
        changed: one int comparison. Called once per packet, so this is the
        path that makes "change rules while a run is in progress" affordable
        -- the expensive part (pickling a snapshot across a process boundary)
        happens once per actual change, in the broadcaster, not here.
        """
        version = self.rule_source.version
        if version == self._rules_version:
            return False
        self.apply_snapshot(self.rule_source.snapshot())
        return True

    def apply_snapshot(self, snapshot: RuleSnapshot) -> None:
        """Installs `snapshot` as the active rules. Idempotent, and safe to
        call from a control channel mid-run: the old snapshot is simply
        released, and any in-flight decision already read the value it needs.
        """
        self._rules = snapshot
        self._rules_version = snapshot.version
        self.stats.rule_updates_applied += 1

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def classify(
        self,
        parsed: ParsedPacket,
        tuple_: FiveTuple,
        app_type: AppType,
        sni: str,
    ) -> tuple[AppType, str, bool]:
        """Attempts to (re)classify a flow using this packet's payload.

        Returns (app_type, sni, confirmed). `confirmed=True` means the result
        came from a directly observed name (TLS SNI, HTTP Host, DNS query
        name, decrypted QUIC SNI) and is therefore terminal; `confirmed=False`
        is a port-based guess that a later packet may still improve on.

        Ordering is the original's (fast_path.cpp:110-197): TLS first (most
        traffic is HTTPS), then HTTP Host, then DNS, then a port-based guess.
        The retry guards mirror `main_working.cpp`'s `(app == UNKNOWN || app ==
        HTTPS) && sni.empty()` conditions, i.e. keep trying while the current
        answer is generic and unconfirmed.
        """
        payload = parsed.payload
        unconfirmed = not sni

        if (
            unconfirmed
            and app_type in (AppType.UNKNOWN, AppType.HTTPS)
            and parsed.has_tcp
            and parsed.dst_port == 443
            and len(payload) > _MIN_TLS_PAYLOAD_LEN
        ):
            found = extract_sni(payload)
            if found:
                self.stats.sni_extractions += 1
                return self._named(found)

        if (
            unconfirmed
            and app_type in (AppType.UNKNOWN, AppType.HTTP)
            and parsed.has_tcp
            and parsed.dst_port == 80
        ):
            found = extract_http_host(payload)
            if found:
                self.stats.http_host_extractions += 1
                return self._named(found)

        # QUIC. Two separate questions, deliberately asked in order:
        #   1. Is this QUIC at all? (`is_quic` accepts any long-header packet.)
        #   2. If so, is it an Initial we can actually decrypt?
        # The port is deliberately NOT the gate -- a client may send a QUIC
        # packet from any port, and the long-header shape is a far more specific
        # signal than a port number.
        #
        # Answering (1) for every QUIC packet, not just Initials, is what keeps
        # coverage reporting honest: Handshake and 1-RTT packets are encrypted
        # by protocol design and can never be read by a passive observer, but
        # reporting them as "unknown" would make a capture full of modern
        # encrypted traffic look like a capture full of unrecognisable noise.
        if (
            self.enable_quic
            and unconfirmed
            and app_type in (AppType.UNKNOWN, AppType.QUIC, AppType.HTTPS)
            and parsed.has_udp
            and payload
            and is_quic(payload)
        ):
            self.quic_packets += 1
            found = None
            if is_quic_initial(payload):
                inspector = self._quic_inspectors.get(tuple_)
                if inspector is None:
                    inspector = QuicFlowInspector()
                    self._quic_inspectors[tuple_] = inspector
                found = inspector.feed(payload)
                if found:
                    self.stats.quic_extractions += 1
                    return self._named(found)
                if inspector.undecryptable_packets:
                    self.quic_undecryptable += 1
            else:
                # Not an Initial: correctly undecryptable, and we say so rather
                # than leaving it to look like a parsing miss.
                self.quic_undecryptable += 1
            return AppType.QUIC, sni, False

        if app_type is AppType.UNKNOWN and parsed.has_udp and (
            parsed.dst_port == 53 or parsed.src_port == 53
        ):
            query = extract_dns_query(payload) if payload else None
            if query:
                self.stats.dns_extractions += 1
                return self._named(query)
            return AppType.DNS, sni, False

        if app_type is AppType.UNKNOWN:
            if parsed.has_tcp and parsed.dst_port == 443:
                return AppType.HTTPS, sni, False
            if parsed.has_tcp and parsed.dst_port == 80:
                return AppType.HTTP, sni, False

        return app_type, sni, False

    def _named(self, name: str) -> tuple[AppType, str, bool]:
        """Maps an observed name to an app type and counts a classification
        hit. Mirrors OSC's `if (app != UNKNOWN && app != HTTPS) hits++`."""
        app = sni_to_app_type(name)
        if app not in (AppType.UNKNOWN, AppType.HTTPS):
            self.stats.classification_hits += 1
        return app, name, True

    # ------------------------------------------------------------------
    # The per-packet decision
    # ------------------------------------------------------------------

    def process(self, item: WorkItem) -> ProcessedPacket:
        """Runs the full per-packet decision and returns its outcome.

        The order below is deliberate and follows OSC's (fast_path.cpp:79-108),
        with the two states that can only ever be "already decided" handled up
        front so no work is wasted on them:

            1. refresh the rule snapshot if a new one was published
            2. look up / create the flow, and record the packet against it
            3. advance the TCP lifecycle (handshake / FIN / RST)
            4. BLOCKED flows: skip both classification and the rule check --
               both can only ever re-derive a decision already recorded, and
               re-checking is a measurable cost on a capture full of blocked
               traffic
            5. CLOSED flows: skip *classification* (a dead flow must not be
               re-classified -- an OSC bug) but still rule-check, so a policy
               that was added mid-connection is still enforced on the packets
               that remain
            6. otherwise classify from this packet's payload
            7. check the rules, unless this flow is already recorded as
               blocked (OSC's `flow.blocked` was sticky here too)
            8. record stats and return the forward/drop decision
        """
        self.refresh_rules()

        parsed = item.parsed
        tuple_ = item.five_tuple
        rules = self._rules
        tracker = self.tracker

        self.stats.packets_processed += 1
        if parsed.has_tcp:
            self.stats.tcp_packets += 1
        elif parsed.has_udp:
            self.stats.udp_packets += 1

        conn = tracker.get_or_create_connection(tuple_)
        # `len(data)`, not `raw.orig_len`. Byte counters report what was *read*
        # from the capture, which is the captured length (incl_len). The C++
        # original does the same -- `flow.bytes += raw.data.size()`
        # (main_working.cpp:184) -- and parity with it is enforced by the
        # differential suite. `orig_len` is the on-wire length and is larger on
        # a snaplen-truncated capture, so using it here would silently change
        # every byte total relative to the reference.
        tracker.update_connection(conn, len(item.raw.data), is_outbound=True)

        if parsed.has_tcp:
            tracker.update_tcp_state(conn, parsed.tcp_flags)

        blocked = tuple_ in self.blocked_tuples

        if conn.state is not ConnectionState.BLOCKED:
            if conn.state is not ConnectionState.CLOSED:
                new_app, new_sni, confirmed = self.classify(
                    parsed, tuple_, conn.app_type, conn.sni
                )
                if new_app is not conn.app_type or new_sni != conn.sni:
                    tracker.classify_connection(conn, new_app, new_sni, confirmed=confirmed)

            if not blocked:
                reason = rules.should_block(
                    src_ip=parsed.src_ip,
                    dst_port=parsed.dst_port,
                    app=conn.app_type,
                    domain=conn.sni,
                )
                if reason is not None:
                    self.blocked_tuples.add(tuple_)
                    tracker.block_connection(conn)
                    self.blocked_flows.append((tuple_, conn.app_type, conn.sni))
                    blocked = True

        self._record_stats(conn)

        if blocked:
            self.stats.packets_dropped += 1
        else:
            self.stats.packets_forwarded += 1
        return ProcessedPacket(
            sequence_index=item.sequence_index, raw=item.raw, forwarded=not blocked
        )

    def _record_stats(self, conn: Connection) -> None:
        self.app_counts[conn.app_type] = self.app_counts.get(conn.app_type, 0) + 1
        if conn.sni:
            self.detected_domains[conn.sni] = conn.app_type

    def finalize(self) -> WorkerResult:
        """Snapshots everything the parent process needs and packages it for
        transport. `processed_packets` is left empty; the caller fills it in
        from its own loop, because only the caller knows the items it fed."""
        self.stats.connections_tracked = self.tracker.get_active_count()
        self.stats.flows_reaped = self.tracker.reaped_total
        return WorkerResult(
            worker_id=self.fp_id,
            tracker_stats=self.tracker.get_stats(),
            connections=self.tracker.get_all_connections(),
            app_counts=self.app_counts,
            detected_domains=self.detected_domains,
            blocked_flows=self.blocked_flows,
            fp_stats=self.stats,
            quic_packets=self.quic_packets,
            quic_undecryptable=self.quic_undecryptable,
        )


@dataclass(slots=True)
class FixedRuleSource:
    """A `RuleSource` pinned to exactly one immutable snapshot.

    This is what a worker process starts with when rules are pushed to it over
    a control channel: it satisfies the `RuleSource` protocol, is trivially
    picklable, and never changes -- so the worker's steady-state cost is a
    single attribute read per packet.
    """

    _rules: RuleSnapshot

    @property
    def version(self) -> int:
        return self._rules.version

    def snapshot(self) -> RuleSnapshot:
        return self._rules


@dataclass(slots=True)
class WorkerResult:
    """Everything a fast-path sends back to the parent after draining its
    input queue and receiving the shutdown sentinel."""

    worker_id: int
    tracker_stats: TrackerStats
    connections: list[Connection] = field(default_factory=list)
    processed_packets: list[ProcessedPacket] = field(default_factory=list)
    app_counts: dict[AppType, int] = field(default_factory=dict)
    detected_domains: dict[str, AppType] = field(default_factory=dict)
    blocked_flows: list[tuple[FiveTuple, AppType, str]] = field(default_factory=list)
    fp_stats: FastPathStats = field(default_factory=FastPathStats)
    quic_packets: int = 0
    quic_undecryptable: int = 0

    @property
    def tcp_count(self) -> int:
        """Alias kept for readability at call sites that read protocol counts
        off a result. Backed by `fp_stats` so there is exactly one counter."""
        return self.fp_stats.tcp_packets

    @property
    def udp_count(self) -> int:
        return self.fp_stats.udp_packets


def worker_main(
    worker_id: int,
    input_queue: Queue[WorkItem | None],
    output_queue: Queue[WorkerResult],
    rule_source: RuleSource,
    max_connections: int,
    *,
    stale_timeout_seconds: float | None = DEFAULT_STALE_TIMEOUT_SECONDS,
    reap_interval_packets: int = DEFAULT_REAP_INTERVAL_PACKETS,
    control_queue: Queue[RuleSnapshot | None] | None = None,
    enable_quic: bool = True,
) -> None:
    """`multiprocessing.Process` target for a single-tier fast-path worker.

    Pulls WorkItems off `input_queue` until it receives the sentinel,
    processes each, and puts a single `WorkerResult` on `output_queue` before
    exiting.

    `control_queue` (optional) carries `RuleSnapshot` messages that replace the
    active rules mid-run. It is drained non-blockingly between packets, so a
    rule change takes effect on the next packet without ever blocking the
    packet path on control traffic.

    Safety: pure compute. Never touches the filesystem or network -- all file
    I/O happens in the parent (see DESIGN_DECISIONS.md "Safety constraints").
    """
    processor = FlowProcessor(
        tracker=ConnectionTracker(
            fp_id=worker_id,
            max_connections=max_connections,
            stale_timeout_seconds=stale_timeout_seconds,
            reap_interval_packets=reap_interval_packets,
        ),
        rule_source=rule_source,
        enable_quic=enable_quic,
        fp_id=worker_id,
    )

    processed: list[ProcessedPacket] = []

    while True:
        _drain_control(processor, control_queue)

        item = input_queue.get()
        if item is SHUTDOWN_SENTINEL:
            break

        assert item is not None  # sentinel handled above; narrows for the type checker
        _maybe_apply_test_delay()
        processed.append(processor.process(item))

    result = processor.finalize()
    result.processed_packets = processed
    output_queue.put(result)


def _drain_control(
    processor: FlowProcessor, control_queue: Queue[RuleSnapshot | None] | None
) -> None:
    """Applies every pending rule-snapshot message, newest-wins, without
    blocking.

    Never raises: a control-channel problem must not take down a worker
    mid-run. Anything that is not a recognisable rule-snapshot message is
    ignored, so an unexpected message cannot be mistaken for a policy change.

    The queue is typed as carrying `Optional[RuleSnapshot]` because the
    shutdown sentinel shares the same vocabulary as the packet queues. The
    parent never actually sends it on this channel, but tolerating it costs
    nothing and means a future teardown-ordering change cannot silently apply
    `None` as a rule set.
    """
    if control_queue is None:
        return
    while True:
        try:
            message = control_queue.get_nowait()
        except (queue_module.Empty, OSError, ValueError):
            # Empty queue (nothing pending), or the queue has been closed by
            # the parent during teardown. Either way, stop polling.
            return
        if message is SHUTDOWN_SENTINEL or not isinstance(message, RuleSnapshot):
            continue
        processor.apply_snapshot(message)
