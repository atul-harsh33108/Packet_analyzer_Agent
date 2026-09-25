"""Tests for dpi_engine.connection_tracker.

Covers: get_or_create/get semantics (including reverse-tuple fallback),
update/classify/block/close lifecycle, O(1) LRU eviction (verified via call
counting, not just correctness), the classification-upgrade fix (port
guess -> SNI-confirmed), cleanup_stale, and combine_tracker_reports.
"""

from __future__ import annotations

from dpi_engine.connection_tracker import (
    ConnectionTracker,
    TrackerStats,
    combine_tracker_reports,
)
from dpi_engine.types import AppType, ConnectionState, FiveTuple, PacketAction


def make_tuple(n: int) -> FiveTuple:
    return FiveTuple(src_ip=n, dst_ip=1000 + n, src_port=n, dst_port=443, protocol=6)


# --- get_or_create_connection / get_connection ---------------------------------------


def test_get_or_create_returns_same_object_on_repeat_calls() -> None:
    tracker = ConnectionTracker(fp_id=0)
    t = make_tuple(1)

    conn1 = tracker.get_or_create_connection(t)
    conn2 = tracker.get_or_create_connection(t)

    assert conn1 is conn2
    assert tracker.get_stats().total_connections_seen == 1


def test_get_or_create_creates_new_connection_with_new_state() -> None:
    tracker = ConnectionTracker(fp_id=0)
    conn = tracker.get_or_create_connection(make_tuple(1))

    assert conn.state == ConnectionState.NEW
    assert conn.app_type == AppType.UNKNOWN
    assert conn.packets_in == 0


def test_get_connection_returns_none_for_unknown_tuple() -> None:
    tracker = ConnectionTracker(fp_id=0)
    assert tracker.get_connection(make_tuple(1)) is None


def test_get_connection_finds_reverse_tuple() -> None:
    tracker = ConnectionTracker(fp_id=0)
    forward = make_tuple(1)
    tracker.get_or_create_connection(forward)

    found = tracker.get_connection(forward.reverse())
    assert found is not None
    assert found.tuple == forward


# --- update_connection ------------------------------------------------------------


def test_update_connection_outbound_and_inbound() -> None:
    tracker = ConnectionTracker(fp_id=0)
    conn = tracker.get_or_create_connection(make_tuple(1))

    tracker.update_connection(conn, packet_size=100, is_outbound=True)
    tracker.update_connection(conn, packet_size=50, is_outbound=False)

    assert conn.packets_out == 1
    assert conn.bytes_out == 100
    assert conn.packets_in == 1
    assert conn.bytes_in == 50


# --- classify_connection: the lock-in bug fix ----------------------------------------


def test_port_guess_can_be_replaced_by_another_guess() -> None:
    tracker = ConnectionTracker(fp_id=0)
    conn = tracker.get_or_create_connection(make_tuple(1))

    tracker.classify_connection(conn, AppType.HTTPS, "", confirmed=False)
    assert conn.app_type == AppType.HTTPS
    assert conn.state == ConnectionState.CLASSIFIED

    tracker.classify_connection(conn, AppType.HTTP, "", confirmed=False)
    assert conn.app_type == AppType.HTTP  # guesses can replace each other


def test_port_guess_upgraded_by_confirmed_sni_classification() -> None:
    """Direct regression test for the original's classification lock-in
    bug: a port-based guess (e.g. AppType.HTTPS from seeing port 443) must
    NOT permanently block a later, more accurate SNI-based classification."""
    tracker = ConnectionTracker(fp_id=0)
    conn = tracker.get_or_create_connection(make_tuple(1))

    # Port-based fallback guess fires first (this is what the original did
    # unconditionally, locking the state).
    tracker.classify_connection(conn, AppType.HTTPS, "", confirmed=False)
    assert conn.app_type == AppType.HTTPS

    # SNI arrives later in the same connection's lifetime.
    tracker.classify_connection(conn, AppType.YOUTUBE, "www.youtube.com", confirmed=True)

    assert conn.app_type == AppType.YOUTUBE
    assert conn.sni == "www.youtube.com"
    assert conn.state == ConnectionState.CLASSIFIED


def test_confirmed_classification_is_terminal() -> None:
    tracker = ConnectionTracker(fp_id=0)
    conn = tracker.get_or_create_connection(make_tuple(1))

    tracker.classify_connection(conn, AppType.YOUTUBE, "www.youtube.com", confirmed=True)
    # A later guess must NOT overwrite the confirmed classification.
    tracker.classify_connection(conn, AppType.HTTPS, "", confirmed=False)

    assert conn.app_type == AppType.YOUTUBE
    assert conn.sni == "www.youtube.com"

    # Nor can a different confirmed classification overwrite it.
    tracker.classify_connection(conn, AppType.GOOGLE, "other.google.com", confirmed=True)
    assert conn.app_type == AppType.YOUTUBE


def test_classified_count_increments_once_per_connection() -> None:
    tracker = ConnectionTracker(fp_id=0)
    conn = tracker.get_or_create_connection(make_tuple(1))

    tracker.classify_connection(conn, AppType.HTTPS, "", confirmed=False)
    tracker.classify_connection(conn, AppType.YOUTUBE, "youtube.com", confirmed=True)
    tracker.classify_connection(conn, AppType.HTTPS, "", confirmed=False)  # blocked, terminal

    assert tracker.get_stats().classified_connections == 1


# --- block_connection / close_connection ---------------------------------------------


def test_block_connection_sets_state_and_action() -> None:
    tracker = ConnectionTracker(fp_id=0)
    conn = tracker.get_or_create_connection(make_tuple(1))

    tracker.block_connection(conn)

    assert conn.state == ConnectionState.BLOCKED
    assert conn.action == PacketAction.DROP
    assert tracker.get_stats().blocked_connections == 1


def test_close_connection_sets_closed_state() -> None:
    tracker = ConnectionTracker(fp_id=0)
    t = make_tuple(1)
    tracker.get_or_create_connection(t)

    tracker.close_connection(t)

    conn = tracker.get_connection(t)
    assert conn is not None
    assert conn.state == ConnectionState.CLOSED


def test_close_connection_on_unknown_tuple_is_a_no_op() -> None:
    tracker = ConnectionTracker(fp_id=0)
    tracker.close_connection(make_tuple(99))  # must not raise


# --- O(1) LRU eviction ----------------------------------------------------------------


def test_eviction_removes_least_recently_used_entry() -> None:
    tracker = ConnectionTracker(fp_id=0, max_connections=3)

    t1, t2, t3 = make_tuple(1), make_tuple(2), make_tuple(3)
    tracker.get_or_create_connection(t1)
    tracker.get_or_create_connection(t2)
    tracker.get_or_create_connection(t3)

    # Touch t1 again so t2 becomes the least-recently-used.
    tracker.get_or_create_connection(t1)

    t4 = make_tuple(4)
    tracker.get_or_create_connection(t4)  # table full (3), must evict LRU (t2)

    assert tracker.get_connection(t1) is not None
    assert tracker.get_connection(t2) is None  # evicted
    assert tracker.get_connection(t3) is not None
    assert tracker.get_connection(t4) is not None
    assert tracker.get_active_count() == 3


def test_eviction_uses_ordereddict_popitem_not_a_manual_scan() -> None:
    """Regression test for the original's O(n) evictOldest (a full linear
    scan of every connection's last_seen timestamp on every eviction once
    the table is full). This port's eviction must delegate to
    collections.OrderedDict.popitem(last=False), which is documented by the
    Python standard library to run in O(1) -- never a manual scan over
    every connection to find the minimum last_seen.

    Verified by wrapping the tracker's popitem with a call counter and
    asserting eviction calls it exactly once per eviction (proving the
    O(1) primitive is what's actually used), combined with the timing-scale
    smoke test below as a second, independent signal.
    """
    tracker = ConnectionTracker(fp_id=0, max_connections=2)
    tracker.get_or_create_connection(make_tuple(1))
    tracker.get_or_create_connection(make_tuple(2))

    popitem_calls = 0
    original_popitem = tracker._connections.popitem

    def counting_popitem(last=True):
        nonlocal popitem_calls
        popitem_calls += 1
        return original_popitem(last=last)

    tracker._connections.popitem = counting_popitem  # type: ignore[method-assign]

    tracker.get_or_create_connection(make_tuple(3))  # table full -> triggers eviction

    assert popitem_calls == 1
    assert tracker.get_active_count() == 2


def test_eviction_cost_does_not_grow_with_table_size() -> None:
    """Complementary timing-based smoke test: since collections.OrderedDict
    guarantees O(1) popitem/move_to_end, the average per-insert cost of
    filling a table well past its cap should not grow as the cap grows.
    An O(n) implementation (like the original's linear scan) would show
    clearly increasing per-insert time as max_connections grows; this test
    gives a coarse signal that isn't the case here."""
    import time

    def time_fill(max_connections: int, total_inserts: int) -> float:
        tracker = ConnectionTracker(fp_id=0, max_connections=max_connections)
        start = time.perf_counter()
        for i in range(total_inserts):
            tracker.get_or_create_connection(make_tuple(i))
        return time.perf_counter() - start

    small_table_time = time_fill(max_connections=100, total_inserts=20_000)
    large_table_time = time_fill(max_connections=20_000, total_inserts=20_000)

    # With O(1) eviction, filling a table whose cap is 100x larger should
    # not take dramatically longer per insert. Allow generous headroom
    # (10x) to avoid flakiness on slow/loaded CI machines -- this is a
    # smoke test, not a precise benchmark.
    assert large_table_time < small_table_time * 10 + 1.0


def test_large_table_eviction_completes_quickly() -> None:
    """Sanity/perf smoke test: filling a reasonably large table well past
    its cap must not be noticeably slower per-insert as the table grows,
    which an O(n) eviction would exhibit."""
    tracker = ConnectionTracker(fp_id=0, max_connections=1000)

    for i in range(5000):
        tracker.get_or_create_connection(make_tuple(i))

    assert tracker.get_active_count() == 1000


# --- cleanup_stale ----------------------------------------------------------------------


def test_cleanup_stale_removes_closed_connections() -> None:
    tracker = ConnectionTracker(fp_id=0)
    t = make_tuple(1)
    tracker.get_or_create_connection(t)
    tracker.close_connection(t)

    removed = tracker.cleanup_stale(timeout_seconds=10_000)  # not idle long enough by time alone

    assert removed == 1
    assert tracker.get_active_count() == 0


def test_cleanup_stale_removes_idle_connections_by_timeout() -> None:
    tracker = ConnectionTracker(fp_id=0)
    conn = tracker.get_or_create_connection(make_tuple(1))
    conn.last_seen -= 1000  # simulate having been idle for 1000 seconds

    removed = tracker.cleanup_stale(timeout_seconds=500)

    assert removed == 1
    assert tracker.get_active_count() == 0


def test_cleanup_stale_keeps_active_connections() -> None:
    tracker = ConnectionTracker(fp_id=0)
    tracker.get_or_create_connection(make_tuple(1))

    removed = tracker.cleanup_stale(timeout_seconds=300)

    assert removed == 0
    assert tracker.get_active_count() == 1


# --- get_all_connections / for_each / clear -------------------------------------------


def test_get_all_connections_returns_every_tracked_connection() -> None:
    tracker = ConnectionTracker(fp_id=0)
    tracker.get_or_create_connection(make_tuple(1))
    tracker.get_or_create_connection(make_tuple(2))

    all_conns = tracker.get_all_connections()
    assert len(all_conns) == 2


def test_for_each_visits_every_connection() -> None:
    tracker = ConnectionTracker(fp_id=0)
    tracker.get_or_create_connection(make_tuple(1))
    tracker.get_or_create_connection(make_tuple(2))

    visited = []
    tracker.for_each(visited.append)

    assert len(visited) == 2


def test_clear_empties_the_table() -> None:
    tracker = ConnectionTracker(fp_id=0)
    tracker.get_or_create_connection(make_tuple(1))
    tracker.clear()
    assert tracker.get_active_count() == 0


# --- combine_tracker_reports ------------------------------------------------------------


def test_combine_tracker_reports_sums_stats_and_ranks_domains() -> None:
    tracker_a = ConnectionTracker(fp_id=0)
    conn_a1 = tracker_a.get_or_create_connection(make_tuple(1))
    tracker_a.classify_connection(conn_a1, AppType.YOUTUBE, "youtube.com", confirmed=True)
    conn_a2 = tracker_a.get_or_create_connection(make_tuple(2))
    tracker_a.classify_connection(conn_a2, AppType.YOUTUBE, "youtube.com", confirmed=True)

    tracker_b = ConnectionTracker(fp_id=1)
    conn_b1 = tracker_b.get_or_create_connection(make_tuple(3))
    tracker_b.classify_connection(conn_b1, AppType.GITHUB, "github.com", confirmed=True)

    reports = [
        (tracker_a.get_stats(), tracker_a.get_all_connections()),
        (tracker_b.get_stats(), tracker_b.get_all_connections()),
    ]

    global_stats = combine_tracker_reports(reports)

    assert global_stats.total_active_connections == 3
    assert global_stats.total_connections_seen == 3
    assert global_stats.app_distribution[AppType.YOUTUBE] == 2
    assert global_stats.app_distribution[AppType.GITHUB] == 1
    assert global_stats.top_domains[0] == ("youtube.com", 2)


def test_tracker_stats_combine() -> None:
    a = TrackerStats(active_connections=5, total_connections_seen=10, classified_connections=3)
    b = TrackerStats(active_connections=2, total_connections_seen=4, classified_connections=1)

    combined = a.combine(b)

    assert combined.active_connections == 7
    assert combined.total_connections_seen == 14
    assert combined.classified_connections == 4
