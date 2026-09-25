"""Per-worker flow table: tracks connection state, classification, and
byte/packet counters, with bounded O(1) LRU eviction.

Ports OSC/include/connection_tracker.h + OSC/src/connection_tracker.cpp to
Python.

Fixes applied during the port (see DESIGN_DECISIONS.md "Bugs fixed"):

- O(1) LRU eviction: the original's evictOldest() did a full linear scan of
  every connection to find the least-recently-seen one whenever the table
  was full (connection_tracker.cpp), making flow creation O(n) once the
  table saturates -- a real availability risk under a flood of distinct
  five-tuples. This port uses collections.OrderedDict and moves an entry to
  the end on every access (`move_to_end`), so the least-recently-used entry
  is always the first item and eviction is O(1) (`popitem(last=False)`).

- Classification lock-in: the original's classifyConnection() only ever
  classified a connection `if conn->state != ConnectionState::CLASSIFIED`
  -- once *any* classification happened (even a low-confidence port-based
  guess, e.g. "port 443 => HTTPS"), the state became CLASSIFIED and no
  later, more accurate SNI-based classification could ever overwrite it.
  This port distinguishes a *guess* (low confidence, e.g. port-based
  fallback) from a *confirmed* classification (SNI/HTTP Host observed
  directly): only a confirmed classification is terminal. A guess can
  always be upgraded by either a later guess (replacing the previous guess)
  or a confirmed classification; a confirmed classification can never be
  downgraded back to a guess or overwritten by a different confirmed value
  once set (matching the original's intent that classification should
  eventually stabilize, while actually achieving that only for high
  confidence results).

Threading/multiprocessing model note: the original's GlobalConnectionTable
held raw, live pointers to each FP thread's ConnectionTracker and read them
concurrently while FP threads mutated the same tracker -- a real, if
narrowly-triggered, data race (see DESIGN_DECISIONS.md / prior C++
analysis). This port's multiprocessing architecture (Task 10) makes that
pattern impossible by construction: worker processes do not share memory,
so there is no live tracker to reach into from another process. Instead,
each ConnectionTracker produces an immutable TrackerStats snapshot
(get_stats()) that is sent back to the main process (e.g. via a
multiprocessing.Queue) after the worker finishes, and combine_tracker_stats
merges those snapshots. There is nothing to lock because nothing is shared.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Optional

from dpi_engine.types import AppType, Connection, ConnectionState, FiveTuple, PacketAction

DEFAULT_MAX_CONNECTIONS = 100_000


@dataclass(slots=True)
class TrackerStats:
    """Mirrors OSC's ConnectionTracker::TrackerStats."""

    active_connections: int = 0
    total_connections_seen: int = 0
    classified_connections: int = 0
    blocked_connections: int = 0

    def combine(self, other: "TrackerStats") -> "TrackerStats":
        return TrackerStats(
            active_connections=self.active_connections + other.active_connections,
            total_connections_seen=self.total_connections_seen + other.total_connections_seen,
            classified_connections=self.classified_connections + other.classified_connections,
            blocked_connections=self.blocked_connections + other.blocked_connections,
        )


class ConnectionTracker:
    """A bounded, per-worker flow table.

    Mirrors OSC's ConnectionTracker, with O(1) LRU eviction (see module
    docstring) and a confirmed-vs-guessed classification distinction that
    fixes the original's classification lock-in bug.
    """

    def __init__(self, fp_id: int, max_connections: int = DEFAULT_MAX_CONNECTIONS) -> None:
        self.fp_id = fp_id
        self.max_connections = max_connections

        # OrderedDict preserves insertion order; every access moves the
        # entry to the end, so the front is always the least-recently-used
        # entry -- this is what makes eviction O(1).
        self._connections: OrderedDict[FiveTuple, Connection] = OrderedDict()

        # Tracks which connections were classified via a low-confidence
        # guess (e.g. port-based fallback) vs. a confirmed observation
        # (SNI/HTTP Host). Only entries NOT in this set are treated as
        # terminal/locked. Kept as a separate set (not a Connection field)
        # to avoid changing the Connection dataclass's shape from Task 4.
        self._guessed: set[FiveTuple] = set()

        self._total_seen = 0
        self._classified_count = 0
        self._blocked_count = 0

    def get_or_create_connection(self, tuple_: FiveTuple) -> Connection:
        """Returns the existing connection for `tuple_`, or creates one.

        Every call (whether it finds an existing entry or creates a new
        one) counts as a "use" for LRU purposes and moves the entry to the
        most-recently-used position.
        """
        existing = self._connections.get(tuple_)
        if existing is not None:
            self._connections.move_to_end(tuple_)
            return existing

        if len(self._connections) >= self.max_connections:
            self._evict_oldest()

        now = time.monotonic()
        conn = Connection(tuple=tuple_, state=ConnectionState.NEW, first_seen=now, last_seen=now)
        self._connections[tuple_] = conn
        self._total_seen += 1
        return conn

    def get_connection(self, tuple_: FiveTuple) -> Optional[Connection]:
        """Looks up a connection without creating one. Tries the reverse
        tuple as a fallback (for matching the opposite direction of a
        bidirectional flow), mirroring the original's getConnection.

        Note (matches original behavior, not a new bug): unlike
        get_or_create_connection, this does NOT move the found entry to the
        most-recently-used position, since a lookup that only reads
        (without the caller committing to "this flow is active") shouldn't
        necessarily refresh its LRU position. Callers that want LRU refresh
        on read should use get_or_create_connection.
        """
        existing = self._connections.get(tuple_)
        if existing is not None:
            return existing
        return self._connections.get(tuple_.reverse())

    def update_connection(self, conn: Connection, packet_size: int, is_outbound: bool) -> None:
        conn.last_seen = time.monotonic()
        if is_outbound:
            conn.packets_out += 1
            conn.bytes_out += packet_size
        else:
            conn.packets_in += 1
            conn.bytes_in += packet_size

    def classify_connection(
        self,
        conn: Connection,
        app_type: AppType,
        sni: str,
        *,
        confirmed: bool,
    ) -> None:
        """Classifies a connection, fixing the original's lock-in bug.

        `confirmed=True` means this classification came from directly
        observing the SNI/HTTP Host header -- high confidence, sets a
        terminal CLASSIFIED state that nothing can overwrite afterward.

        `confirmed=False` means this is a low-confidence guess (e.g. "this
        looks like HTTPS because it's on port 443, but we haven't seen a
        Client Hello yet"). A guess is always allowed to be replaced by a
        later guess or upgraded by a later confirmed classification. A
        connection already in a confirmed state is never touched by a
        subsequent call, regardless of the new call's confirmed flag --
        this matches the original's intent (classification should
        eventually stabilize) while actually achieving that only once a
        real signal (not just a port heuristic) has been observed.
        """
        was_classified_before = conn.state == ConnectionState.CLASSIFIED
        is_locked = was_classified_before and conn.tuple not in self._guessed

        if is_locked:
            return  # Confirmed classification is terminal; do not overwrite.

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
        conn.state = ConnectionState.BLOCKED
        conn.action = PacketAction.DROP
        self._blocked_count += 1

    def close_connection(self, tuple_: FiveTuple) -> None:
        conn = self._connections.get(tuple_)
        if conn is not None:
            conn.state = ConnectionState.CLOSED

    def cleanup_stale(self, timeout_seconds: float = 300.0) -> int:
        """Removes connections idle longer than `timeout_seconds`, or in the
        CLOSED state. Returns the number removed."""
        now = time.monotonic()
        stale_tuples = [
            t
            for t, conn in self._connections.items()
            if (now - conn.last_seen) > timeout_seconds or conn.state == ConnectionState.CLOSED
        ]
        for t in stale_tuples:
            del self._connections[t]
            self._guessed.discard(t)
        return len(stale_tuples)

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

    def clear(self) -> None:
        self._connections.clear()
        self._guessed.clear()

    def for_each(self, callback: Callable[[Connection], None]) -> None:
        for conn in self._connections.values():
            callback(conn)

    def _evict_oldest(self) -> None:
        """O(1): the least-recently-used entry is always the first item in
        the OrderedDict, since every access moves its entry to the end.
        Contrast with the original's evictOldest(), which scanned every
        connection's last_seen timestamp to find the minimum -- O(n) per
        eviction (see module docstring)."""
        if not self._connections:
            return
        oldest_tuple, _ = self._connections.popitem(last=False)
        self._guessed.discard(oldest_tuple)


@dataclass(slots=True)
class GlobalStats:
    """Mirrors OSC's GlobalConnectionTable::GlobalStats."""

    total_active_connections: int = 0
    total_connections_seen: int = 0
    app_distribution: dict[AppType, int] = field(default_factory=dict)
    top_domains: list[tuple[str, int]] = field(default_factory=list)


def combine_tracker_reports(
    reports: list[tuple[TrackerStats, list[Connection]]],
    *,
    top_domains_limit: int = 20,
) -> GlobalStats:
    """Combines per-worker (TrackerStats, connections) snapshots into a
    single GlobalStats, replacing OSC's GlobalConnectionTable (which held
    live cross-thread pointers into each FP's tracker -- see module
    docstring for why that pattern isn't reproduced here).

    Each worker (Task 10) calls tracker.get_stats() and
    tracker.get_all_connections() once, after it finishes processing, and
    sends that snapshot back to the main process. This function is called
    in the main process on the collected list of snapshots.
    """
    total_active = 0
    total_seen = 0
    app_distribution: dict[AppType, int] = {}
    domain_counts: dict[str, int] = {}

    for stats, connections in reports:
        total_active += stats.active_connections
        total_seen += stats.total_connections_seen

        for conn in connections:
            app_distribution[conn.app_type] = app_distribution.get(conn.app_type, 0) + 1
            if conn.sni:
                domain_counts[conn.sni] = domain_counts.get(conn.sni, 0) + 1

    top_domains = sorted(domain_counts.items(), key=lambda kv: kv[1], reverse=True)[
        :top_domains_limit
    ]

    return GlobalStats(
        total_active_connections=total_active,
        total_connections_seen=total_seen,
        app_distribution=app_distribution,
        top_domains=top_domains,
    )
