"""Tests for the two-tier load-balancer / fast-path dispatch layer."""

from __future__ import annotations

import pytest

from dpi_engine.load_balancer import (
    SHUTDOWN_SENTINEL,
    FastPath,
    FastPathStats,
    LoadBalancer,
    LoadBalancerStats,
    build_pipeline_graph,
    flow_hash,
    hash_select,
)
from dpi_engine.types import FiveTuple


def tup(n: int = 1) -> FiveTuple:
    return FiveTuple(0x0A000001, 0x0A000002, 1000 + n, 443, 6)


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def test_flow_hash_is_stable_across_calls() -> None:
    """Partitioning depends on this being deterministic: an unstable hash would
    scatter a flow's packets across workers and corrupt its state."""
    t = tup()
    assert flow_hash(t) == flow_hash(t)
    assert flow_hash(t) == flow_hash(FiveTuple(*tuple(t)))


def test_flow_hash_ignores_the_salt_for_determinism_given_one() -> None:
    t = tup()
    assert flow_hash(t, salt=0) == flow_hash(t, salt=0)


def test_different_salts_give_different_selections() -> None:
    """The two tiers must not hash identically, which is what made the original
    permanently idle half its fast-paths."""
    tuples = [FiveTuple(0x0A000001, 0x0A000002, 1000 + n, 443, 6) for n in range(64)]
    same_at_every_bucket = all(
        hash_select(t, 2) == hash_select(t, 2, salt=0x85EBCA6B) for t in tuples
    )
    assert not same_at_every_bucket


def test_hash_select_covers_every_bucket() -> None:
    tuples = [FiveTuple(0x0A000001, 0x0A000002, 1000 + n, 443, 6) for n in range(400)]
    for n in (1, 2, 3, 4, 8):
        seen = {hash_select(t, n) for t in tuples}
        assert seen == set(range(n)), f"bucket {n} under-used: {seen}"


def test_hash_select_is_always_in_range() -> None:
    for n in range(1, 9):
        for i in range(200):
            assert 0 <= hash_select(tup(i), n) < n


def test_hash_select_rejects_zero_buckets() -> None:
    with pytest.raises(ValueError):
        hash_select(tup(), 0)


def test_hash_select_rejects_negative_buckets() -> None:
    with pytest.raises(ValueError):
        hash_select(tup(), -1)


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def test_build_graph_numbers_fast_paths_by_load_balancer() -> None:
    lbs, fps = build_pipeline_graph(2, 3, queue_factory=list)
    assert len(lbs) == 2
    assert [fp.fp_id for fp in fps] == [0, 1, 2, 3, 4, 5]
    assert [lb.lb_id for lb in lbs] == [0, 1]
    assert [fp.fp_id for fp in lbs[0].fps] == [0, 1, 2]
    assert [fp.fp_id for fp in lbs[1].fps] == [3, 4, 5]


def test_build_graph_wires_ownership_both_ways() -> None:
    lbs, fps = build_pipeline_graph(2, 2, queue_factory=list)
    for lb in lbs:
        for fp in lb.fps:
            assert fp.owner is lb
    assert {fp.owner.lb_id for fp in fps} == {0, 1}


def test_build_graph_gives_every_node_a_distinct_queue() -> None:
    lbs, fps = build_pipeline_graph(2, 2, queue_factory=list)
    queues = [lb.input_queue for lb in lbs] + [fp.input_queue for fp in fps]
    assert len(queues) == 6
    for i, a in enumerate(queues):
        for b in queues[i + 1 :]:
            assert a is not b


@pytest.mark.parametrize(
    "num_lbs,fps_per_lb", [(0, 2), (2, 0), (-1, 1), (1, -1)]
)
def test_build_graph_rejects_nonsensical_shapes(num_lbs: int, fps_per_lb: int) -> None:
    with pytest.raises(ValueError):
        build_pipeline_graph(num_lbs, fps_per_lb, queue_factory=list)


def test_load_balancer_rejects_an_empty_fast_path_set() -> None:
    with pytest.raises(ValueError):
        LoadBalancer(lb_id=0, input_queue=[], fps=[])


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


def test_select_fp_stays_inside_the_lb_s_own_shard() -> None:
    """A load balancer may only ever feed the fast-paths it owns; that
    disjointness is what makes per-shard backpressure meaningful."""
    lbs, _ = build_pipeline_graph(2, 2, queue_factory=list)
    lb = lbs[1]
    owned = {fp.fp_id for fp in lb.fps}
    assert owned == {2, 3}

    for i in range(100):
        assert lb.select_fp(tup(i)).fp_id in owned


def test_select_fp_is_deterministic_for_a_flow() -> None:
    lbs, _ = build_pipeline_graph(2, 2, queue_factory=list)
    lb = lbs[0]
    t = tup(7)
    assert lb.select_fp(t).fp_id == lb.select_fp(t).fp_id


def test_queue_for_returns_the_selected_queue() -> None:
    lbs, _ = build_pipeline_graph(1, 3, queue_factory=list)
    lb = lbs[0]
    assert lb.queue_for(tup()) is lb.select_fp(tup()).input_queue


def test_fast_path_holds_a_queue_directly() -> None:
    fp = FastPath(fp_id=7, input_queue=["q"])
    assert fp.fp_id == 7
    assert fp.owner is None


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def test_load_balancer_stats_combine_merges_per_fp_by_id() -> None:
    """Positional merging would conflate LB0's FP0 with LB1's FP0, so the
    counts are keyed by fast-path id."""
    lb0 = LoadBalancerStats(
        lb_id=0, packets_received=10, packets_dispatched=9, per_fp_packets={0: 5, 1: 4}
    )
    lb1 = LoadBalancerStats(
        lb_id=1, packets_received=7, packets_dispatched=7, per_fp_packets={2: 3, 3: 4}
    )

    combined = lb0.combine([lb1])
    assert combined.packets_received == 17
    assert combined.packets_dispatched == 16
    assert combined.per_fp_packets == {0: 5, 1: 4, 2: 3, 3: 4}


def test_load_balancer_stats_to_dict_sorts_per_fp_for_stability() -> None:
    stats = LoadBalancerStats(lb_id=0, per_fp_packets={3: 1, 0: 2, 2: 3})
    assert list(stats.to_dict()["per_fp_packets"]) == [0, 2, 3]


def test_fast_path_stats_combine_sums_every_field() -> None:
    a = FastPathStats(
        fp_id=0,
        packets_processed=10,
        packets_forwarded=7,
        packets_dropped=3,
        tcp_packets=6,
        udp_packets=4,
        connections_tracked=5,
        sni_extractions=2,
        http_host_extractions=1,
        dns_extractions=3,
        quic_extractions=1,
        classification_hits=6,
        flows_reaped=2,
        rule_updates_applied=1,
    )
    b = FastPathStats(
        fp_id=1,
        packets_processed=4,
        packets_forwarded=4,
        tcp_packets=4,
        connections_tracked=3,
        sni_extractions=1,
        classification_hits=1,
    )

    combined = a.combine([b])
    assert combined.packets_processed == 14
    assert combined.packets_forwarded == 11
    assert combined.packets_dropped == 3
    assert combined.tcp_packets == 10
    assert combined.udp_packets == 4
    assert combined.connections_tracked == 8
    assert combined.sni_extractions == 3
    assert combined.http_host_extractions == 1
    assert combined.dns_extractions == 3
    assert combined.quic_extractions == 1
    assert combined.classification_hits == 7
    assert combined.flows_reaped == 2
    assert combined.rule_updates_applied == 1


def test_fast_path_stats_to_dict_round_trips_all_fields() -> None:
    stats = FastPathStats(fp_id=3, packets_processed=9, quic_extractions=2)
    payload = stats.to_dict()
    assert payload["fp_id"] == 3
    assert payload["packets_processed"] == 9
    assert payload["quic_extractions"] == 2
    # Nothing may be missing, or a report section silently loses a counter.
    assert set(payload) == {
        "fp_id",
        "packets_processed",
        "packets_forwarded",
        "packets_dropped",
        "tcp_packets",
        "udp_packets",
        "connections_tracked",
        "sni_extractions",
        "http_host_extractions",
        "dns_extractions",
        "quic_extractions",
        "classification_hits",
        "flows_reaped",
        "rule_updates_applied",
    }


# ---------------------------------------------------------------------------
# Shutdown sentinel
# ---------------------------------------------------------------------------


def test_shutdown_sentinel_is_none_and_unambiguous() -> None:
    """A bare None can never collide with a real queue item, and pickles
    trivially across a process boundary."""
    import pickle

    assert SHUTDOWN_SENTINEL is None
    assert pickle.loads(pickle.dumps(SHUTDOWN_SENTINEL)) is None
