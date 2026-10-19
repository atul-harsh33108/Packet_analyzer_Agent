"""Per-worker flow table: tracks connection state, classification, TCP
handshake/teardown, and byte/packet counters, with bounded O(1) LRU eviction
and bounded-cost stale-flow reaping.

Ports OSC/include/connection_tracker.h + OSC/src/connection_tracker.cpp to
Python.

=============================================================================
Fixes and additions relative to the original
=============================================================================
- O(1) LRU eviction: the original's `evictOldest()` did a full linear scan of
  every connection to find the least-recently-seen one whenever the table was
  full (connection_tracker.cpp:150-162), making flow creation O(n) once the
  table saturated -- a real availability risk under a flood of distinct
  five-tuples. This port uses `collections.OrderedDict` and moves an entry to
  the end on every use, so the least-recently-used entry is always the first
  item and eviction is O(1).

- Stale-flow reaping is actually wired in. The original called
  `cleanupStale(300s)` from `FastPathProcessor::run` on every idle poll
  (fast_path.cpp:56). The first version of this port *implemented*
  `cleanup_stale` but never called it from any production path, so idle
  flows were only ever reclaimed by LRU pressure. It is now invoked
  automatically by `get_or_create_connection` via `reap_if_due`, on a
  bounded cadence (see `DEFAULT_REAP_INTERVAL_PACKETS`) so the amortized
  cost stays negligible, and `cleanup_stale` remains public for callers that
  want an explicit sweep.

- TCP state machine: ports `FastPathProcessor::updateTCPState`
  (fast_path.cpp:246-277), which the first version of this port declared
  `syn_seen`/`syn_ack_seen`/`fin_seen` fields for but never drove. Now
  implemented as `update_tcp_state`, and called from every pipeline.

- Terminal states are sticky. OSC had no such guarantee: a flow that reached
  CLOSED (via FIN or RST) could still be re-inspected and re-classified by a
  later packet, and `classifyConnection` happily moved a BLOCKED flow back to
  CLASSIFIED because it only compared against CLASSIFIED, not BLOCKED. Here
  `ConnectionState.is_terminal` (see types.py) defines BLOCKED and CLOSED as
  absorbing, and every mutator here honours it.

- Classification lock-in: the original's `classifyConnection` only ever
  classified a connection `if conn->state != ConnectionState::CLASSIFIED`
  -- once *any* classification happened (even a low-confidence port-based
  guess, e.g. "port 443 => HTTPS"), the state became CLASSIFIED and no
  later, more accurate SNI-based classification could ever overwrite it.
  This port distinguishes a *guess* (low confidence, e.g. port-based
  fallback) from a *confirmed* classification (SNI/HTTP Host observed
  directly): only a confirmed classification is terminal. A guess can
  always be upgraded by either a later guess or a confirmed classification;
  a confirmed classification can never be downgraded or overwritten.

=============================================================================
Threading / multiprocessing model
=============================================================================
OSC's `GlobalConnectionTable` held raw, live pointers to each FP thread's
ConnectionTracker and read them concurrently while FP threads mutated the
same tracker -- a real data race. This port makes that pattern impossible by
construction: worker processes do not share memory, so there is nothing to
reach into. Each tracker produces immutable snapshots (`get_stats()`,
`get_all_connections()`) that are shipped back to the main process after the
worker finishes, and `combine_tracker_reports` merges them. There is nothing
to lock because nothing is shared.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from dpi_engine.types import (
    AppType,
    Connection,
    ConnectionState,
    FiveTuple,
    FlowRecord,
    PacketAction,
    canonical_flow_key,
)

DEFAULT_MAX_CONNECTIONS = 100_000

#: How many calls to get_or_create_connection() may pass between automatic
#: stale-flow sweeps. A sweep is O(live flows); at 65_536 packets between
#: sweeps the amortized cost is a small fraction of a percent even at the
#: 100k-flow table cap, while still reclaiming idle memory promptly on any
#: realistically-sized capture. Set to 0 to disable automatic reaping
#: (equivalent to the pre-reaper behaviour, where only LRU pressure reclaimed
#: anything). Exposed as `--reap-interval` so a short capture, or a test, can
#: ask for a more aggressive sweep.
DEFAULT_REAP_INTERVAL_PACKETS = 65_536

# Idle time after which a flow with no activity is considered stale and
# eligible for reaping. Mirrors OSC's cleanupStale default of 300s.
DEFAULT_STALE_TIMEOUT_SECONDS = 300.0

# TCP flag bits (packet_parser.h TCPFlags).
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


@dataclass(slots=True)
class TrackerStats:
    """Per-tracker counters. Mirrors OSC's ConnectionTracker::TrackerStats."""

    active_connections: int = 0
    total_connections_seen: int = 0
    classified_connections: int = 0
    blocked_connections: int = 0

    def combine(self, other: TrackerStats) -> TrackerStats:
        return TrackerStats(
            active_connections=self.active_connections + other.active_connections,
            total_connections_seen=self.total_connections_seen + other.total_connections_seen,
            classified_connections=self.classified_connections + other.classified_connections,
            blocked_connections=self.blocked_connections + other.blocked_connections,
        )


class ConnectionTracker:
    """A bounded, per-worker flow table.

    Not thread-safe by design, and it does not need to be: a tracker is owned
    by exactly one execution context (the single-process pipeline's main
    thread, or one worker/FP process). Cross-context aggregation happens by
    shipping snapshots out, never by sharing the tracker.
    """

    def __init__(
        self,
        fp_id: int = 0,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        *,
        stale_timeout_seconds: float | None = DEFAULT_STALE_TIMEOUT_SECONDS,
        reap_interval_packets: int = DEFAULT_REAP_INTERVAL_PACKETS,
        fold_bidirectional: bool = True,
        on_evicted: Callable[[FiveTuple], None] | None = None,
    ) -> None:
        if max_connections < 1:
            raise ValueError(f"max_connections must be >= 1, got {max_connections}")
        if stale_timeout_seconds is not None and stale_timeout_seconds <= 0:
            raise ValueError(
                f"stale_timeout_seconds must be positive or None, got {stale_timeout_seconds}"
            )
        if reap_interval_packets < 0:
            raise ValueError(
                f"reap_interval_packets must be >= 0, got {reap_interval_packets}"
            )

        self.fp_id = fp_id
        self.max_connections = max_connections
        self.stale_timeout_seconds = stale_timeout_seconds
        self.reap_interval_packets = reap_interval_packets

        # `DEC-05`. With folding on -- the default -- a flow and its reverse
        # direction are the same entry, so a SYN and the SYN-ACK answering it
        # share one `Connection`. That is what makes `packets_in`/`bytes_in`
        # derivable at all (`D-25`): there is finally a shared object to
        # attribute the second direction to.
        #
        # Differential mode passes False. The C++ original keys flows by exact
        # tuple and never calls `FiveTuple::reverse()`, so folding would show
        # up as a divergence in flow counts, in app counts, and in every
        # per-flow byte total. Off is the parity behaviour; on is the
        # product-correct one.
        self.fold_bidirectional = fold_bidirectional

        # `T1-01` follow-up: a hook fired when a flow leaves the table, so the
        # pipeline can publish `FlowEvicted` without the tracker importing the
        # event vocabulary. The tracker stays ignorant of reporting; the parent
        # decides what a departure means. None by default, so the hot path is a
        # single truthiness check.
        self.on_evicted = on_evicted

        # OrderedDict preserves insertion order; every *use* moves the entry to
        # the end, so the front is always the least-recently-used entry --
        # this is what makes eviction O(1). Note that `update_tcp_state` and
        # `update_connection` also refresh LRU position, so an actively-used
        # flow is never a reaping candidate.
        self._connections: OrderedDict[FiveTuple, Connection] = OrderedDict()

        # Connections classified by a low-confidence *guess* (e.g. a
        # port-based fallback) rather than a confirmed observation
        # (SNI/HTTP Host/DNS name). Only entries NOT in this set are treated
        # as terminal for classification purposes. Kept as a side set rather
        # than a Connection field so the Connection dataclass stays a pure
        # mirror of the original's struct.
        self._guessed: set[FiveTuple] = set()

        self._calls_since_reap = 0
        self._total_seen = 0
        self._classified_count = 0
        self._blocked_count = 0
        self._reaped_total = 0

    # ------------------------------------------------------------------
    # Lookup / creation
    # ------------------------------------------------------------------

    def flow_key(self, tuple_: FiveTuple) -> FiveTuple:
        """The canonical key for `tuple_`, which is what `_connections` is keyed by.

        Public because two other modules need exactly this mapping and must not
        reimplement it: `worker.FlowProcessor` keys its per-flow side tables by
        it, and the multiprocessing dispatcher hashes it so that both
        directions of a flow reach the same worker. A second, subtly different
        canonicalisation anywhere would silently split one flow across two
        trackers.

        `DEC-05`. Canonicalising by taking the lexicographically smaller of the
        tuple and its reverse makes the mapping a *projection*: both directions
        land on one key, and the choice is stable and total, so it does not
        depend on which direction happened to arrive first.

        `min` over a `NamedTuple` compares field by field, so the winner is the
        same on every call and in every process.

        With folding off this is the identity, and the tracker behaves exactly
        as the C++ original does.
        """
        return canonical_flow_key(tuple_, self.fold_bidirectional)

    def get_or_create_connection(self, tuple_: FiveTuple) -> Connection:
        """Returns the existing connection for `tuple_`, or creates one.

        Every call (whether it finds an existing entry or creates a new one)
        counts as a "use" for LRU purposes and moves the entry to the
        most-recently-used position. Also performs the opportunistic stale
        sweep; see `reap_if_due`.
        """
        self._calls_since_reap += 1
        if self._calls_since_reap >= self.reap_interval_packets:
            self._calls_since_reap = 0
            self.reap_if_due()

        key = self.flow_key(tuple_)
        existing = self._connections.get(key)
        if existing is not None:
            self._connections.move_to_end(key)
            return existing

        if len(self._connections) >= self.max_connections:
            self._evict_oldest()

        now = time.monotonic()
        # `Connection.tuple` is the *canonical* key, not the packet's own tuple.
        # `worker.FlowProcessor.process` tells the two apart with
        # `tuple_ == conn.tuple` to decide which direction a packet belongs to,
        # which is how `packets_in`/`bytes_in` become derivable (`D-25`). Storing
        # the packet's tuple instead would make that test always true and leave
        # both counters at zero again.
        conn = Connection(tuple=key, state=ConnectionState.NEW, first_seen=now, last_seen=now)
        self._connections[key] = conn
        self._total_seen += 1
        return conn

    def get_connection(self, tuple_: FiveTuple) -> Connection | None:
        """Looks up a connection without creating one, falling back to the
        reverse tuple (for the opposite direction of a bidirectional flow).
        Mirrors OSC's getConnection.

        Unlike `get_or_create_connection` this does *not* refresh LRU position
        or classify the flow as in-use: a read-only probe should not keep an
        idle flow alive. Callers that genuinely mean "this flow is active"
        should use `get_or_create_connection`.
        """
        existing = self._connections.get(self.flow_key(tuple_))
        if existing is not None or self.fold_bidirectional:
            # With folding on, the canonical key already spans both directions,
            # so there is nothing further to try.
            return existing
        # Folding off: the key is the exact tuple, so the reverse fallback is
        # still what gives this method its bidirectional behaviour -- and it is
        # the path differential mode exercises.
        return self._connections.get(tuple_.reverse())

    def __contains__(self, tuple_: FiveTuple) -> bool:
        return self.flow_key(tuple_) in self._connections

    def __len__(self) -> int:
        return len(self._connections)

    def __iter__(self) -> Iterator[Connection]:
        return iter(self._connections.values())

    # ------------------------------------------------------------------
    # Per-packet updates
    # ------------------------------------------------------------------

    def update_connection(self, conn: Connection, packet_size: int, is_outbound: bool = True) -> None:
        """Records one packet against `conn` and refreshes its activity
        timestamp and LRU position."""
        conn.last_seen = time.monotonic()
        if is_outbound:
            conn.packets_out += 1
            conn.bytes_out += packet_size
        else:
            conn.packets_in += 1
            conn.bytes_in += packet_size
        self._connections.move_to_end(conn.tuple, last=True)

    def update_tcp_state(self, conn: Connection, tcp_flags: int) -> None:
        """Advances `conn`'s TCP lifecycle from one packet's flag byte.

        Ports OSC's `FastPathProcessor::updateTCPState` (fast_path.cpp:246-277)
        and adds the invariants it lacked:

        - SYN+ACK sets `syn_ack_seen` (not `syn_seen`), so a half-open
          scan from the wrong direction stays distinguishable from a real
          client SYN.
        - A flow becomes ESTABLISHED once both handshake halves have been seen
          and an ACK is present, but only while it is still NEW -- a flow that
          has already been classified is not dragged backwards.
        - RST is treated as an unambiguous abort and closes the flow at once,
          rather than waiting for the FIN+ACK sequence OSC required.
        - CLOSED is absorbing for the transport lifecycle: once closed, no
          later packet re-opens it. (OSC had no such guarantee and would
          happily move an RST'd flow back to ESTABLISHED/CLASSIFIED.)

        State precedence is a strict total order, BLOCKED > CLOSED >
        CLASSIFIED/ESTABLISHED > NEW, so an observable state is never lost to
        a lower-priority one: an explicit policy block outranks a later
        transport close, because "this flow was blocked" is the more
        actionable fact to report. Deciding forward-vs-drop never depends on
        this ordering -- the pipeline keeps its own monotonic per-flow block
        set for that -- so this is purely about reporting fidelity.

        `tcp_flags` may be 0 (non-TCP flows), in which case this is a no-op.
        """
        if not tcp_flags:
            return

        self._connections.move_to_end(conn.tuple, last=True)

        if tcp_flags & TCP_SYN:
            if tcp_flags & TCP_ACK:
                conn.syn_ack_seen = True
            else:
                conn.syn_seen = True

        if (
            conn.syn_seen
            and conn.syn_ack_seen
            and (tcp_flags & TCP_ACK)
            and conn.state is ConnectionState.NEW
        ):
            conn.state = ConnectionState.ESTABLISHED

        if tcp_flags & TCP_FIN:
            conn.fin_seen = True

        if tcp_flags & TCP_RST:
            conn.rst_seen = True
            if conn.state is not ConnectionState.BLOCKED:
                conn.state = ConnectionState.CLOSED
            return

        if conn.fin_seen and (tcp_flags & TCP_ACK) and conn.state is not ConnectionState.BLOCKED:
            conn.state = ConnectionState.CLOSED

    def classify_connection(
        self,
        conn: Connection,
        app_type: AppType,
        sni: str,
        *,
        confirmed: bool,
    ) -> None:
        """Classifies a flow, fixing the original's lock-in bug.

        `confirmed=True` means this classification came from directly
        observing an SNI / HTTP Host header / DNS query name -- high
        confidence, and terminal: nothing can overwrite it afterwards.

        `confirmed=False` is a low-confidence guess (e.g. "this looks like
        HTTPS because it's on port 443, but we haven't seen a Client Hello
        yet"). A guess is always replaceable by a later guess or upgradeable
        by a later confirmed classification.

        Terminal states (BLOCKED, CLOSED) are never overwritten -- see
        `ConnectionState.is_terminal`.
        """
        if conn.state.is_terminal:
            return

        was_classified_before = conn.state is ConnectionState.CLASSIFIED
        # A confirmed classification is terminal; a guess is not.
        is_locked = was_classified_before and conn.tuple not in self._guessed
        if is_locked:
            return

        conn.app_type = app_type
        conn.sni = sni
        conn.state = ConnectionState.CLASSIFIED

        if confirmed:
            self._guessed.discard(conn.tuple)
        else:
            self._guessed.add(conn.tuple)

        if not was_classified_before:
            self._classified_count += 1

    def block_connection(self, conn: Connection) -> None:
        """Marks a flow as blocked. Idempotent -- re-blocking an already
        blocked flow does not double-count `blocked_connections`."""
        if conn.state is ConnectionState.BLOCKED:
            return
        conn.state = ConnectionState.BLOCKED
        conn.action = PacketAction.DROP
        self._blocked_count += 1

    def close_connection(self, tuple_: FiveTuple) -> None:
        conn = self._connections.get(tuple_)
        if conn is not None and not conn.state.is_terminal:
            conn.state = ConnectionState.CLOSED

    # ------------------------------------------------------------------
    # Reclamation
    # ------------------------------------------------------------------

    def cleanup_stale(self, timeout_seconds: float | None = None) -> int:
        """Removes flows idle for longer than `timeout_seconds` (default: the
        tracker's `stale_timeout_seconds`) or already in the CLOSED state.
        Returns the number removed."""
        if timeout_seconds is None:
            timeout_seconds = self.stale_timeout_seconds
        if timeout_seconds is None:
            # No timeout configured: only reap terminal flows, which is always
            # safe because they can never change again.
            timeout_seconds = float("inf")

        now = time.monotonic()
        stale = [
            t
            for t, conn in self._connections.items()
            if (now - conn.last_seen) > timeout_seconds or conn.state is ConnectionState.CLOSED
        ]
        for t in stale:
            del self._connections[t]
            self._guessed.discard(t)
            self._notify_evicted(t)
        self._reaped_total += len(stale)
        return len(stale)

    def reap_if_due(self) -> int:
        """Runs `cleanup_stale` only if the configured packet cadence says it
        is due. Called automatically by `get_or_create_connection`.

        Returns the number of flows reaped (0 when not due, or when automatic
        reaping is disabled via `reap_interval_packets=0`).

        Note that `stale_timeout_seconds=None` disables *idle* reaping only.
        Flows in the CLOSED state are still swept, because a closed flow can
        never change again, so reclaiming one is unconditionally safe and costs
        nothing. Sweeping is not skipped here just because the caller turned
        off idle timeouts -- that would silently leak every closed flow for the
        whole run.
        """
        if self.reap_interval_packets <= 0:
            return 0
        return self.cleanup_stale(self.stale_timeout_seconds)

    def clear(self) -> None:
        self._connections.clear()
        self._guessed.clear()

    @property
    def reaped_total(self) -> int:
        """Cumulative flows reclaimed by reaping over this tracker's life."""
        return self._reaped_total

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def get_all_connections(self) -> list[Connection]:
        return list(self._connections.values())

    def get_active_count(self) -> int:
        return len(self._connections)

    def get_stats(self) -> TrackerStats:
        return TrackerStats(
            active_connections=len(self._connections),
            total_connections_seen=self._total_seen,
            classified_connections=self._classified_count,
            blocked_connections=self._blocked_count,
        )

    def for_each(self, callback: Callable[[Connection], None]) -> None:
        for conn in self._connections.values():
            callback(conn)

    def _evict_oldest(self) -> None:
        """O(1): the least-recently-used entry is always the first item in the
        OrderedDict, since every use moves its entry to the end. Contrast with
        the original's evictOldest(), which scanned every connection's
        last_seen timestamp for the minimum -- O(n) per eviction."""
        if not self._connections:
            return
        oldest_tuple, _ = self._connections.popitem(last=False)
        self._guessed.discard(oldest_tuple)
        self._notify_evicted(oldest_tuple)

    def _notify_evicted(self, tuple_: FiveTuple) -> None:
        """Fires the `on_evicted` hook, if one is installed.

        Both eviction paths -- LRU pressure and the stale sweep -- funnel
        through here, so a subscriber sees every departure exactly once and
        cannot tell which mechanism caused it. That indistinguishability is
        deliberate: from a live view's perspective a flow leaving the table is
        one event with two causes, and splitting it would make consumers
        reimplement the tracker's policy.

        A hook that raises does not take the run down. Eviction happens inside
        `get_or_create_connection`, i.e. on the packet path, so letting a
        reporting bug propagate would turn a broken dashboard into a dropped
        capture -- the same reasoning as `EventBus.emit`.
        """
        if self.on_evicted is None:
            return
        try:
            self.on_evicted(tuple_)
        except Exception:  # a reporting bug must not break the packet path
            return


@dataclass(slots=True)
class GlobalStats:
    """Aggregated statistics across all per-worker trackers.

    Mirrors OSC's GlobalConnectionTable::GlobalStats, but is built by
    merging immutable snapshots rather than by reading other threads' live
    trackers (which is the data race this port removes).
    """

    total_active_connections: int = 0
    total_connections_seen: int = 0
    classified_connections: int = 0
    blocked_connections: int = 0
    app_distribution: dict[AppType, int] = field(default_factory=dict)
    top_domains: list[tuple[str, int]] = field(default_factory=list)
    unknown_connections: int = 0
    #: Histogram of live flows by lifecycle state. A histogram rather than one
    #: field per state, because the state set is open and because reporting
    #: "established" separately is misleading: a flow that completed its
    #: handshake and was then classified is CLASSIFIED, not ESTABLISHED, so
    #: almost every healthy flow would be invisible to a per-state counter.
    state_counts: dict[ConnectionState, int] = field(default_factory=dict)

    @property
    def total_connections(self) -> int:
        return sum(self.app_distribution.values())


def combine_tracker_reports(
    reports: list[tuple[TrackerStats, list[Connection]]],
    *,
    top_domains_limit: int = 20,
) -> GlobalStats:
    """Combines per-worker (TrackerStats, connections) snapshots into one
    GlobalStats, replacing OSC's GlobalConnectionTable.

    Each execution context calls `tracker.get_stats()` and
    `tracker.get_all_connections()` once, after finishing, and ships the
    snapshot to the main process (e.g. over a `multiprocessing.Queue`). This
    function runs in the main process over the collected list.

    `app_distribution` and `top_domains` are counted from the *flow* snapshot
    (one entry per live flow), not per packet -- matching OSC's
    getGlobalStats. Per-packet application counts are reported separately by
    the pipeline (`PipelineResult.app_counts`).
    """
    if top_domains_limit < 0:
        raise ValueError(f"top_domains_limit must be >= 0, got {top_domains_limit}")

    total_active = 0
    total_seen = 0
    classified = 0
    blocked = 0
    unknown = 0
    app_distribution: dict[AppType, int] = {}
    domain_counts: dict[str, int] = {}
    state_counts: dict[ConnectionState, int] = {}

    for stats, connections in reports:
        total_active += stats.active_connections
        total_seen += stats.total_connections_seen
        classified += stats.classified_connections
        blocked += stats.blocked_connections

        for conn in connections:
            app_distribution[conn.app_type] = app_distribution.get(conn.app_type, 0) + 1
            if conn.app_type is AppType.UNKNOWN:
                unknown += 1
            state_counts[conn.state] = state_counts.get(conn.state, 0) + 1
            if conn.sni:
                domain_counts[conn.sni] = domain_counts.get(conn.sni, 0) + 1

    # Ties broken by domain name so the ordering is deterministic across runs
    # (a plain sort on count alone is not stable for equal counts across dict
    # iteration order, which varies with worker completion order).
    top_domains = sorted(domain_counts.items(), key=lambda kv: (-kv[1], kv[0]))[
        :top_domains_limit
    ]

    return GlobalStats(
        total_active_connections=total_active,
        total_connections_seen=total_seen,
        classified_connections=classified,
        blocked_connections=blocked,
        app_distribution=app_distribution,
        top_domains=top_domains,
        unknown_connections=unknown,
        state_counts=state_counts,
    )


def to_flow_records(connections: list[Connection]) -> list[FlowRecord]:
    """Freezes live `Connection` state into rows that outlive the tracker (`T3-06`).

    Ordered deterministically by five-tuple, because the input arrives in whatever
    order the tracker's LRU happens to hold (which depends on packet arrival) and
    across workers in completion order. Two runs over the same capture must produce
    the same `flow_table` ordering, or `diff_runs` would report spurious churn that
    is really just worker scheduling.

    Enum fields become `.name` (`DEC-04`'s persistence rule), so a stored row is plain
    JSON with no codec. See `FlowRecord` for why volume is outbound-only.
    """
    return sorted(
        (
            FlowRecord(
                src_ip=c.tuple.src_ip,
                dst_ip=c.tuple.dst_ip,
                src_port=c.tuple.src_port,
                dst_port=c.tuple.dst_port,
                protocol=c.tuple.protocol,
                app=c.app_type.name,
                state=c.state.name,
                hostname=c.sni,
                packets=c.packets_out,
                bytes=c.bytes_out,
                action=c.action.name,
            )
            for c in connections
        ),
        key=lambda r: (r.src_ip, r.dst_ip, r.src_port, r.dst_port, r.protocol),
    )
