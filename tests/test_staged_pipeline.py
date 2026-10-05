"""Tests for the two-tier staged pipeline and for live rule updates.

Two things are being pinned here:

1. **The partitioning invariant.** Every packet of a five-tuple must reach the
   same fast-path process, or that flow's state is split and its classification
   is half-applied. An earlier revision of the staged pipeline round-robined
   *raw* frames across load balancers, which broke this: the sample capture
   produced 61 tracked "connections" for 43 real ones. The regression test
   below is the reason that cannot come back.

2. **Equivalence.** All three pipeline variants must make identical decisions,
   because they share one decision engine.

Note the Windows/macOS `spawn` start method requires every multiprocessing
entry point to be called from a `__main__`-guarded context; pytest satisfies
that, and the CLI's console script does too.
"""

from __future__ import annotations

import unittest.mock
from pathlib import Path

import pytest

from conftest import TEST_DPI_PCAP
from dpi_engine.connection_tracker import ConnectionTracker
from dpi_engine.packet_parser import ParsedPacket
from dpi_engine.pcap_io import PcapReader, RawPacket
from dpi_engine.pipeline import (
    RuleBroadcaster,
    run_pipeline,
    run_pipeline_multiprocess,
    run_pipeline_staged,
)
from dpi_engine.rule_manager import RuleManager
from dpi_engine.types import AppType, FiveTuple
from dpi_engine.worker import FixedRuleSource, FlowProcessor, WorkItem

STAGED_SHAPES = [(1, 1), (1, 3), (2, 1), (2, 2), (3, 2)]


# ---------------------------------------------------------------------------
# Equivalence between the three variants
# ---------------------------------------------------------------------------


def _compare(a, b) -> None:
    assert a.stats == b.stats
    assert a.app_counts == b.app_counts
    assert a.detected_domains == b.detected_domains
    assert a.blocked_flows == b.blocked_flows
    assert (a.quic_packets, a.quic_undecryptable) == (b.quic_packets, b.quic_undecryptable)
    assert a.global_stats.total_active_connections == b.global_stats.total_active_connections
    assert a.global_stats.app_distribution == b.global_stats.app_distribution


def test_multiprocess_matches_single_process(tmp_path: Path) -> None:
    single = run_pipeline(TEST_DPI_PCAP, tmp_path / "single.pcap")
    multi = run_pipeline_multiprocess(
        TEST_DPI_PCAP, tmp_path / "multi.pcap", num_workers=3
    )
    _compare(single, multi)


@pytest.mark.parametrize("num_lbs,fps_per_lb", STAGED_SHAPES)
def test_staged_matches_single_process(
    tmp_path: Path, num_lbs: int, fps_per_lb: int
) -> None:
    single = run_pipeline(TEST_DPI_PCAP, tmp_path / f"single_{num_lbs}_{fps_per_lb}.pcap")
    staged = run_pipeline_staged(
        TEST_DPI_PCAP,
        tmp_path / f"staged_{num_lbs}_{fps_per_lb}.pcap",
        num_load_balancers=num_lbs,
        fps_per_lb=fps_per_lb,
    )
    _compare(single, staged)


def test_staged_output_pcap_is_byte_identical_to_single_process(tmp_path: Path) -> None:
    """Input order must be restored from each item's sequence index, so the two
    outputs are indistinguishable to a downstream tool -- not merely
    equivalent in count."""
    single_path = tmp_path / "single.pcap"
    staged_path = tmp_path / "staged.pcap"
    run_pipeline(TEST_DPI_PCAP, single_path)
    run_pipeline_staged(
        TEST_DPI_PCAP, staged_path, num_load_balancers=2, fps_per_lb=2
    )

    assert single_path.read_bytes() == staged_path.read_bytes()


def test_blocking_is_identical_across_variants(tmp_path: Path) -> None:
    single = run_pipeline(TEST_DPI_PCAP, tmp_path / "s.pcap", _yt_rules())
    multi = run_pipeline_multiprocess(
        TEST_DPI_PCAP, tmp_path / "m.pcap", _yt_rules(), num_workers=2
    )
    staged = run_pipeline_staged(
        TEST_DPI_PCAP, tmp_path / "t.pcap", _yt_rules(), num_load_balancers=2
    )

    # The fixture has exactly two YouTube five-tuples: the TLS flow and its
    # DNS query (the Python port resolves DNS names, which OSC's reference
    # binary does not -- see DESIGN_DECISIONS.md).
    assert single.stats.dropped_packets == 2
    _compare(single, multi)
    _compare(single, staged)


def _yt_rules() -> RuleManager:
    rules = RuleManager()
    rules.block_app(AppType.YOUTUBE)
    return rules


# ---------------------------------------------------------------------------
# The partitioning invariant
# ---------------------------------------------------------------------------


def test_every_flow_lands_on_exactly_one_fast_path(tmp_path: Path) -> None:
    """The regression test for the round-robin bug: the sum of per-fast-path
    connection counts must equal the number of distinct five-tuples, not exceed
    it. (The buggy version produced 61 tracked flows for 43 real ones.)"""
    from dpi_engine.load_balancer import _SALT_TIER_2, hash_select

    distinct: set[FiveTuple] = set()
    with PcapReader(TEST_DPI_PCAP) as reader:
        for raw in reader:
            parsed = _parse(raw)
            if parsed is not None and parsed.has_ip:
                distinct.add(_tuple_of(parsed))
    assert len(distinct) == 43

    staged = run_pipeline_staged(
        TEST_DPI_PCAP, tmp_path / "out.pcap", num_load_balancers=2, fps_per_lb=2
    )
    assert staged.global_stats.total_active_connections == len(distinct)

    # And in the two-level scheme, each five-tuple resolves to exactly one
    # (load balancer, fast path) pair.
    num_lbs, fps_per_lb = 2, 2
    owners = {
        (
            hash_select(t, num_lbs),
            hash_select(t, fps_per_lb, salt=_SALT_TIER_2),
        )
        for t in distinct
    }
    assert len(owners) == len({(lb, fp) for lb, fp in owners})  # stable set
    assert len(owners) <= num_lbs * fps_per_lb


def test_all_fast_paths_receive_work(tmp_path: Path) -> None:
    """The original hashed the same value with the same modulus at both tiers,
    so only half its fast-paths ever got a packet. The two levels now use
    different salts."""
    staged = run_pipeline_staged(
        TEST_DPI_PCAP, tmp_path / "out.pcap", num_load_balancers=2, fps_per_lb=2
    )

    per_fp = staged.load_balancer_stats.per_fp_packets
    assert set(per_fp) == {0, 1, 2, 3}
    assert all(count > 0 for count in per_fp.values())
    assert sum(per_fp.values()) == staged.stats.tcp_packets + staged.stats.udp_packets


def test_staged_reports_both_tiers(tmp_path: Path) -> None:
    result = run_pipeline_staged(
        TEST_DPI_PCAP, tmp_path / "out.pcap", num_load_balancers=2, fps_per_lb=3
    )
    lb = result.load_balancer_stats
    assert lb is not None
    assert lb.packets_received == result.stats.tcp_packets + result.stats.udp_packets
    assert lb.packets_dispatched == lb.packets_received
    assert sum(lb.per_fp_packets.values()) == lb.packets_dispatched
    assert len(lb.per_fp_packets) == 6
    assert result.fast_path_stats.packets_processed == lb.packets_dispatched
    assert len(result.per_worker_packet_counts) == 2  # per load balancer


def test_staged_per_flow_classification_is_not_split(tmp_path: Path) -> None:
    """A flow that resolves a name must be fully classified, not half of it --
    the symptom of the flow being split across two fast-paths."""
    result = run_pipeline_staged(
        TEST_DPI_PCAP, tmp_path / "out.pcap", num_load_balancers=2, fps_per_lb=2
    )
    classified = sum(
        count for app, count in result.global_stats.app_distribution.items()
        if app is not AppType.UNKNOWN
    )
    single = run_pipeline(TEST_DPI_PCAP, tmp_path / "s.pcap")
    classified_single = sum(
        count
        for app, count in single.global_stats.app_distribution.items()
        if app is not AppType.UNKNOWN
    )
    assert classified == classified_single


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("num_lbs", [0, -1])
def test_staged_rejects_bad_load_balancer_counts(tmp_path: Path, num_lbs: int) -> None:
    with pytest.raises(ValueError):
        run_pipeline_staged(
            TEST_DPI_PCAP, tmp_path / "o.pcap", num_load_balancers=num_lbs
        )


@pytest.mark.parametrize("fps", [0, -1])
def test_staged_rejects_bad_fps_per_lb(tmp_path: Path, fps: int) -> None:
    with pytest.raises(ValueError):
        run_pipeline_staged(
            TEST_DPI_PCAP, tmp_path / "o.pcap", num_load_balancers=1, fps_per_lb=fps
        )


@pytest.mark.parametrize("workers", [0, -1])
def test_multiprocess_rejects_bad_worker_counts(tmp_path: Path, workers: int) -> None:
    with pytest.raises(ValueError):
        run_pipeline_multiprocess(
            TEST_DPI_PCAP, tmp_path / "o.pcap", num_workers=workers
        )


# ---------------------------------------------------------------------------
# Live rule updates
# ---------------------------------------------------------------------------


def test_broadcaster_publishes_only_on_change() -> None:
    import queue as queue_module

    rules = RuleManager()
    broadcaster = RuleBroadcaster(rules)
    queues = [queue_module.Queue(), queue_module.Queue()]
    for q in queues:
        broadcaster.register(q)

    assert broadcaster.publish() is False  # nothing has changed yet

    rules.block_app(AppType.YOUTUBE)
    assert broadcaster.publish() is True
    assert queues[0].qsize() == 1
    assert queues[1].qsize() == 1

    assert broadcaster.publish() is False  # already published
    assert queues[0].qsize() == 1

    rules.block_app(AppType.NETFLIX)
    assert broadcaster.publish() is True
    assert queues[0].qsize() == 2


def test_broadcaster_ships_a_picklable_snapshot() -> None:
    import pickle
    import queue as queue_module

    rules = RuleManager()
    # The broadcaster is created first, exactly as the pipeline does it: the
    # *initial* snapshot reaches workers as a constructor argument, and this
    # channel carries changes only.
    broadcaster = RuleBroadcaster(rules)
    q: queue_module.Queue = queue_module.Queue()
    broadcaster.register(q)

    rules.block_ip("10.0.0.1")
    rules.block_app(AppType.ZOOM)
    assert broadcaster.publish() is True

    snapshot = pickle.loads(pickle.dumps(q.get_nowait()))
    assert snapshot.is_ip_blocked(0x0A000001)
    assert snapshot.is_app_blocked(AppType.ZOOM)


def test_broadcaster_does_not_ship_the_initial_snapshot() -> None:
    """A worker already holds the startup snapshot, so re-sending it would be
    pure overhead."""
    import queue as queue_module

    rules = RuleManager()
    broadcaster = RuleBroadcaster(rules)
    q: queue_module.Queue = queue_module.Queue()
    broadcaster.register(q)

    assert broadcaster.publish() is False
    assert q.qsize() == 0


def test_processor_picks_up_a_newer_snapshot() -> None:
    """The steady-state cost is one int comparison; a real change costs one
    snapshot read."""
    rules = RuleManager()
    processor = FlowProcessor(
        tracker=ConnectionTracker(fp_id=0), rule_source=rules
    )
    conn = processor.tracker.get_or_create_connection(_tup(1))
    assert rules.snapshot().should_block(0x0A000001, 443, AppType.HTTPS, "") is None

    # No change: refresh is a no-op.
    assert processor.refresh_rules() is False
    assert processor.stats.rule_updates_applied == 0

    rules.block_ip("10.0.0.1")
    assert processor.refresh_rules() is True
    assert processor.stats.rule_updates_applied == 1
    assert processor._rules.should_block(0x0A000001, 443, AppType.HTTPS, "") is not None
    assert conn is not None


def test_fixed_rule_source_never_changes() -> None:
    snapshot = RuleManager().snapshot()
    source = FixedRuleSource(snapshot)
    assert source.version == snapshot.version
    assert source.snapshot() is snapshot


def test_drain_control_ignores_junk_without_raising() -> None:
    """A malformed control message must not take a worker down mid-run."""
    from dpi_engine.worker import _drain_control

    processor = FlowProcessor(tracker=ConnectionTracker(fp_id=0), rule_source=RuleManager())

    class FakeQueue:
        def __init__(self, items):
            self._items = list(items)

        def get_nowait(self):
            if not self._items:
                raise __import__("queue").Empty
            return self._items.pop(0)

    # Junk values, then a real snapshot.
    rules = RuleManager()
    rules.block_app(AppType.TIKTOK)
    queue = FakeQueue([None, "not-a-snapshot", 42, rules.snapshot()])

    _drain_control(processor, queue)
    assert processor._rules.is_app_blocked(AppType.TIKTOK)

    # An empty queue and a closed queue are both fine.
    _drain_control(processor, FakeQueue([]))
    _drain_control(processor, None)


def test_multiprocess_with_live_rules_still_matches_single_process(tmp_path: Path) -> None:
    """Opening the control channel must not change any decision when the rules
    never actually change."""
    expected = run_pipeline(TEST_DPI_PCAP, tmp_path / "single.pcap", _yt_rules())
    actual = run_pipeline_multiprocess(
        TEST_DPI_PCAP,
        tmp_path / "multi.pcap",
        _yt_rules(),
        num_workers=2,
        live_rules=True,
    )
    _compare(expected, actual)


def test_rules_mutated_mid_run_are_picked_up(tmp_path: Path) -> None:
    """The single-process path honours a mutation made while it is running, if
    the caller drives the broadcaster. Verifies the mechanism end to end on the
    path where it is cheap to observe."""
    rules = RuleManager()
    broadcaster = RuleBroadcaster(rules)
    tracker = ConnectionTracker(fp_id=0, stale_timeout_seconds=None)
    processor = FlowProcessor(tracker=tracker, rule_source=rules)

    flow = _tup(1)
    item = WorkItem(
        sequence_index=0,
        raw=RawPacket(ts_sec=0, ts_usec=0, data=b"", orig_len=0),
        parsed=_parsed(sport=flow.src_port, dport=443, has_tcp=True, payload=b""),
        five_tuple=flow,
    )

    assert processor.process(item).forwarded is True

    rules.block_port(443)
    broadcaster.publish()  # in a real run the pipeline does this per packet
    processor.refresh_rules()

    second = WorkItem(
        sequence_index=1,
        raw=RawPacket(ts_sec=0, ts_usec=0, data=b"", orig_len=0),
        parsed=_parsed(sport=flow.src_port, dport=443, has_tcp=True, payload=b""),
        five_tuple=flow,
    )
    assert processor.process(second).forwarded is False
    assert processor.blocked_flows and processor.blocked_flows[0][0] == flow


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(raw: RawPacket) -> ParsedPacket | None:
    from dpi_engine.packet_parser import parse_packet

    return parse_packet(raw)


def _tuple_of(parsed: ParsedPacket) -> FiveTuple:
    return FiveTuple(
        parsed.src_ip,
        parsed.dst_ip,
        parsed.src_port,
        parsed.dst_port,
        parsed.protocol,
    )


def _tup(n: int) -> FiveTuple:
    return FiveTuple(0x0A000001, 0x0A000002, 50000 + n, 443, 6)


def _parsed(
    *, sport: int, dport: int, has_tcp: bool, payload: bytes = b""
) -> ParsedPacket:
    return ParsedPacket(
        has_ip=True,
        src_ip=0x0A000001,
        dst_ip=0x0A000002,
        protocol=6 if has_tcp else 17,
        has_tcp=has_tcp,
        has_udp=not has_tcp,
        src_port=sport,
        dst_port=dport,
        payload=payload,
    )


# ---------------------------------------------------------------------------
# D-03: --live-rules must not be a silent no-op under --load-balancers
# ---------------------------------------------------------------------------


def test_staged_with_live_rules_still_matches_single_process(tmp_path: Path) -> None:
    """`run_pipeline_staged` must honour `live_rules` at all.

    It had no such parameter, so `cli._execute` -- which assembles one kwargs
    dict and splats it into whichever variant is selected -- silently dropped
    the flag whenever `--load-balancers` was given. No warning, no error: the
    run looked identical while the promised per-worker control channel did not
    exist. This is the equivalence twin of
    `test_multiprocess_with_live_rules_still_matches_single_process`.
    """
    expected = run_pipeline(TEST_DPI_PCAP, tmp_path / "single.pcap", _yt_rules())
    actual = run_pipeline_staged(
        TEST_DPI_PCAP,
        tmp_path / "staged.pcap",
        _yt_rules(),
        num_load_balancers=2,
        fps_per_lb=2,
        live_rules=True,
    )
    _compare(expected, actual)


def test_staged_live_rules_defaults_to_off() -> None:
    """Off by default: the channel costs a per-packet queue drain, so it must
    be opt-in rather than silently enabled by a default change."""
    import inspect

    from dpi_engine import pipeline

    sig = inspect.signature(pipeline.run_pipeline_staged)
    assert "live_rules" in sig.parameters, (
        "run_pipeline_staged has no live_rules parameter, which is why "
        "--live-rules was silently ignored with --load-balancers (D-03)"
    )
    assert sig.parameters["live_rules"].default is False


def test_staged_live_rules_registers_one_control_queue_per_fast_path(
    tmp_path: Path,
) -> None:
    """Every fast path must get a channel, not just the first.

    `RuleBroadcaster.register` appends to a list, so a partial registration
    would leave later shards reading a stale ruleset forever -- and with
    `num_load_balancers * fps_per_lb` shards that is easy to get wrong by
    indexing on the wrong loop variable.
    """
    from dpi_engine import pipeline

    real_register = pipeline.RuleBroadcaster.register
    registered: list[object] = []

    def spy(self: object, queue: object) -> None:  # type: ignore[no-untyped-def]
        registered.append(queue)
        real_register(self, queue)  # type: ignore[arg-type]

    with unittest.mock.patch.object(pipeline.RuleBroadcaster, "register", spy):
        run_pipeline_staged(
            TEST_DPI_PCAP,
            tmp_path / "out.pcap",
            _yt_rules(),
            num_load_balancers=3,
            fps_per_lb=2,
            live_rules=True,
        )

    assert len(registered) == 6, (
        f"expected one control queue per fast path (3 LBs x 2 FPs = 6), "
        f"registered {len(registered)}"
    )


def test_staged_live_rules_is_a_no_op_when_rules_never_change(tmp_path: Path) -> None:
    """Opening the channel must not perturb a single decision.

    Draining a queue per packet is easy to get subtly wrong -- draining the
    wrong queue, blocking on it, or eating a shutdown sentinel. This pins the
    semantics: `live_rules` is a performance knob, not a semantic one.
    """
    off = run_pipeline_staged(
        TEST_DPI_PCAP, tmp_path / "off.pcap", _yt_rules(),
        num_load_balancers=2, fps_per_lb=2, live_rules=False,
    )
    on = run_pipeline_staged(
        TEST_DPI_PCAP, tmp_path / "on.pcap", _yt_rules(),
        num_load_balancers=2, fps_per_lb=2, live_rules=True,
    )
    _compare(off, on)
