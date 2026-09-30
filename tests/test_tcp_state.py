"""Tests for the TCP lifecycle state machine and the stale-flow reaper.

Covers `ConnectionTracker.update_tcp_state` (a port of
`FastPathProcessor::updateTCPState`, which the first version of this port
declared fields for but never drove) and the automatic reaping that
`get_or_create_connection` performs.
"""

from __future__ import annotations

import time

import pytest

from dpi_engine.connection_tracker import (
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    ConnectionTracker,
)
from dpi_engine.types import AppType, ConnectionState, FiveTuple, PacketAction

FIN, SYN, RST, PSH, ACK = TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK
SYN_ACK = SYN | ACK
FIN_ACK = FIN | ACK


def tup(n: int = 1) -> FiveTuple:
    return FiveTuple(0x0A000001, 0x0A000002, 1000 + n, 443, 6)


def fresh(**kwargs) -> tuple[ConnectionTracker, FiveTuple]:
    tracker = ConnectionTracker(fp_id=0, **kwargs)
    t = tup()
    return tracker, t


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------


def test_client_syn_sets_syn_seen_only() -> None:
    tracker, t = fresh()
    conn = tracker.get_or_create_connection(t)
    tracker.update_tcp_state(conn, SYN)
    assert conn.syn_seen is True
    assert conn.syn_ack_seen is False
    assert conn.state is ConnectionState.NEW


def test_syn_ack_sets_syn_ack_seen_not_syn_seen() -> None:
    tracker, t = fresh()
    conn = tracker.get_or_create_connection(t)
    tracker.update_tcp_state(conn, SYN_ACK)
    assert conn.syn_ack_seen is True
    assert conn.syn_seen is False
    # SYN+ACK alone is a half-open flow until the client's SYN has also been
    # seen, so it must not jump straight to ESTABLISHED.
    assert conn.state is ConnectionState.NEW


def test_full_handshake_reaches_established() -> None:
    tracker, t = fresh()
    conn = tracker.get_or_create_connection(t)
    for flags in (SYN, SYN_ACK, ACK):
        tracker.update_tcp_state(conn, flags)
    assert conn.state is ConnectionState.ESTABLISHED


def test_established_is_not_re_entered_once_classified() -> None:
    """The ESTABLISHED promotion only applies while a flow is NEW, so a late
    stray ACK cannot drag a classified flow backwards."""
    tracker, t = fresh()
    conn = tracker.get_or_create_connection(t)
    tracker.update_tcp_state(conn, SYN)
    tracker.update_tcp_state(conn, SYN_ACK)
    tracker.classify_connection(conn, AppType.YOUTUBE, "www.youtube.com", confirmed=True)
    assert conn.state is ConnectionState.CLASSIFIED

    tracker.update_tcp_state(conn, ACK)
    assert conn.state is ConnectionState.CLASSIFIED


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------


def test_fin_then_fin_ack_closes_the_flow() -> None:
    tracker, t = fresh()
    conn = tracker.get_or_create_connection(t)
    for flags in (SYN, SYN_ACK, ACK, FIN):
        tracker.update_tcp_state(conn, flags)
    assert conn.state is ConnectionState.ESTABLISHED
    assert conn.fin_seen is True

    tracker.update_tcp_state(conn, FIN_ACK)
    assert conn.state is ConnectionState.CLOSED


def test_rst_closes_immediately_without_waiting_for_fin() -> None:
    tracker, t = fresh()
    conn = tracker.get_or_create_connection(t)
    tracker.update_tcp_state(conn, SYN)
    tracker.update_tcp_state(conn, RST)
    assert conn.rst_seen is True
    assert conn.state is ConnectionState.CLOSED


def test_closed_is_absorbing() -> None:
    """A closed flow must not be re-opened by later packets (OSC had no such
    guarantee and would happily revive an RST'd flow)."""
    tracker, t = fresh()
    conn = tracker.get_or_create_connection(t)
    tracker.update_tcp_state(conn, RST)
    assert conn.state is ConnectionState.CLOSED

    tracker.update_tcp_state(conn, SYN)
    tracker.update_tcp_state(conn, SYN_ACK)
    assert conn.state is ConnectionState.CLOSED


def test_blocked_state_outranks_a_later_close() -> None:
    """State precedence is BLOCKED > CLOSED: a policy block is the more
    actionable fact to report than a transport teardown."""
    tracker, t = fresh()
    conn = tracker.get_or_create_connection(t)
    tracker.block_connection(conn)
    assert conn.state is ConnectionState.BLOCKED

    tracker.update_tcp_state(conn, RST)
    assert conn.state is ConnectionState.BLOCKED
    assert conn.action is PacketAction.DROP


def test_closed_flow_is_not_reclassified() -> None:
    tracker, t = fresh()
    conn = tracker.get_or_create_connection(t)
    tracker.update_tcp_state(conn, RST)

    tracker.classify_connection(conn, AppType.NETFLIX, "www.netflix.com", confirmed=True)
    assert conn.app_type is AppType.UNKNOWN
    assert conn.sni == ""


def test_zero_flags_is_a_no_op() -> None:
    """UDP flows have no flags; the call must do nothing at all (OSC's version
    touched last_seen even for non-TCP)."""
    tracker, t = fresh()
    conn = tracker.get_or_create_connection(t)
    before = (conn.syn_seen, conn.state, conn.fin_seen, conn.rst_seen)
    tracker.update_tcp_state(conn, 0)
    assert (conn.syn_seen, conn.state, conn.fin_seen, conn.rst_seen) == before


# ---------------------------------------------------------------------------
# Reaping
# ---------------------------------------------------------------------------


def test_reap_interval_zero_disables_automatic_reaping() -> None:
    """With reaping disabled, idle flows survive indefinitely -- the behaviour
    the first version of this port had, and the reason idle flows were only
    ever reclaimed under LRU pressure."""
    tracker, t = fresh(reap_interval_packets=0, stale_timeout_seconds=0.001)
    tracker.get_or_create_connection(t)
    time.sleep(0.01)

    for i in range(100):
        tracker.get_or_create_connection(tup(1000 + i))
    assert tracker.get_active_count() == 101


def test_automatic_reap_fires_on_the_configured_cadence() -> None:
    tracker, t = fresh(reap_interval_packets=10, stale_timeout_seconds=0.001)
    tracker.get_or_create_connection(t)
    time.sleep(0.01)

    for i in range(10):
        tracker.get_or_create_connection(tup(1000 + i))

    assert tracker.reaped_total >= 1
    assert tracker.get_active_count() < 11


def test_cleanup_stale_removes_closed_flows_regardless_of_age() -> None:
    tracker, t = fresh(stale_timeout_seconds=10_000, reap_interval_packets=0)
    tracker.get_or_create_connection(t)
    conn = tracker.get_or_create_connection(t)
    tracker.update_tcp_state(conn, RST)

    removed = tracker.cleanup_stale(10_000)
    assert removed == 1
    assert tracker.get_active_count() == 0


def test_cleanup_stale_respects_the_idle_timeout() -> None:
    tracker, t = fresh(stale_timeout_seconds=10_000, reap_interval_packets=0)
    tracker.get_or_create_connection(t)
    assert tracker.cleanup_stale(10_000) == 0

    time.sleep(0.01)
    assert tracker.cleanup_stale(0.001) == 1


def test_cleanup_stale_with_no_timeout_only_reaps_closed_flows() -> None:
    tracker, t = fresh(stale_timeout_seconds=None, reap_interval_packets=0)
    tracker.get_or_create_connection(t)
    assert tracker.cleanup_stale() == 0  # idle, but no timeout configured
    assert tracker.get_active_count() == 1


def test_reaping_also_drops_the_guessed_classification_set() -> None:
    """A reaped flow must not leave a dangling entry in the guess set, or a
    later flow reusing the tuple would be wrongly treated as confirmed."""
    tracker, t = fresh(stale_timeout_seconds=0.001, reap_interval_packets=1)
    conn = tracker.get_or_create_connection(t)
    tracker.classify_connection(conn, AppType.HTTPS, "", confirmed=False)
    assert t in tracker._guessed

    time.sleep(0.01)
    tracker.get_or_create_connection(tup(999))
    assert t not in tracker._guessed


# ---------------------------------------------------------------------------
# Construction guards
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_connections": 0},
        {"stale_timeout_seconds": 0},
        {"stale_timeout_seconds": -1},
        {"reap_interval_packets": -1},
    ],
)
def test_constructor_rejects_nonsensical_bounds(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        ConnectionTracker(fp_id=0, **kwargs)


# ---------------------------------------------------------------------------
# LRU interaction
# ---------------------------------------------------------------------------


def test_update_refreshes_lru_position_so_active_flows_are_never_reaped() -> None:
    """update_connection must count as a use, otherwise a busy long-lived flow
    sitting in the middle of the table would look idle to the reaper.

    Ages are set explicitly rather than slept for, so the test is
    deterministic instead of racing the wall clock.
    """
    tracker, t = fresh(stale_timeout_seconds=60.0, reap_interval_packets=0)
    active = tracker.get_or_create_connection(t)
    idle = [tracker.get_or_create_connection(tup(100 + i)) for i in range(5)]

    now = time.monotonic()
    for conn in idle:
        conn.last_seen = now - 3600  # idle for an hour
    active.last_seen = now

    # cleanup_stale directly, because reap_if_due is a deliberate no-op when
    # automatic reaping is disabled (reap_interval_packets=0).
    assert tracker.cleanup_stale(60.0) == 5
    assert t in tracker
    assert tracker.get_active_count() == 1


def test_a_flow_never_updated_looks_idle_even_when_created_first() -> None:
    """The complement: without the LRU refresh, insertion order alone would
    decide, and the oldest-created flow would be reaped first."""
    tracker, t = fresh(stale_timeout_seconds=60.0, reap_interval_packets=0)
    old = tracker.get_or_create_connection(t)
    busy = tracker.get_or_create_connection(tup(2))

    now = time.monotonic()
    old.last_seen = now - 3600
    busy.last_seen = now

    assert tracker.cleanup_stale(60.0) == 1
    assert t not in tracker
    assert old is not None
