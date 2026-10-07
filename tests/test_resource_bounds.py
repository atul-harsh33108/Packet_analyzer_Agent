"""Task 11: resource-bound enforcement tests at the pipeline/CLI level.

Tasks 2 and 7 already unit-test the underlying primitives
(PcapReader's max_packet_size/max_total_packets, ConnectionTracker's
max_connections eviction) in isolation. This module verifies those bounds
are actually wired through run_pipeline/run_pipeline_multiprocess/the CLI
end-to-end (DESIGN_DECISIONS.md "Safety constraints": "Resource bounds
enforced at every untrusted-input boundary... must not be violated by any
earlier task's implementation" -- these tests catch it if a bound was
unit-tested but never actually connected to the real entry points).

Also includes an adversarial "many tiny packets" pcap that stays within a
generous but concrete time bound, demonstrating the tool doesn't hang or
degrade catastrophically on a flood of distinct flows (this is the
practical manifestation of the O(1) LRU eviction fix from Task 7 -- an
O(n) eviction implementation would show clearly superlinear growth here).
"""

from __future__ import annotations

import socket
import time
from pathlib import Path

import pytest

from dpi_engine.pcap_io import PcapLimitExceededError, PcapWriter, RawPacket
from dpi_engine.pipeline import run_pipeline, run_pipeline_multiprocess


def _build_tiny_tcp_packet(flow_id: int) -> bytes:
    eth = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    src_port = 20000 + (flow_id % 40000)
    tcp = (
        src_port.to_bytes(2, "big")
        + (443).to_bytes(2, "big")
        + (0).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + bytes([0x50, 0x02])
        + (65535).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
    )
    total_len = 20 + len(tcp)
    dst_ip = f"10.{(flow_id >> 16) & 0xFF}.{(flow_id >> 8) & 0xFF}.{flow_id & 0xFF}"
    ip = (
        bytes([0x45, 0x00])
        + total_len.to_bytes(2, "big")
        + b"\x00\x00"
        + b"\x40\x00"
        + bytes([64, 6])
        + b"\x00\x00"
        + socket.inet_aton("192.168.1.100")
        + socket.inet_aton(dst_ip)
    )
    return eth + ip + tcp


def _build_many_tiny_flows_pcap(path: Path, count: int) -> None:
    with PcapWriter(path) as writer:
        for i in range(count):
            data = _build_tiny_tcp_packet(i)
            writer.write(RawPacket(ts_sec=1700000000 + i, ts_usec=0, data=data, orig_len=len(data)))


def test_max_total_packets_is_enforced_through_run_pipeline(tmp_path: Path) -> None:
    input_pcap = tmp_path / "many.pcap"
    _build_many_tiny_flows_pcap(input_pcap, count=50)

    with pytest.raises(PcapLimitExceededError):
        run_pipeline(input_pcap, tmp_path / "out.pcap", max_total_packets=10)


def test_max_packet_size_is_enforced_through_run_pipeline(tmp_path: Path) -> None:
    input_pcap = tmp_path / "one_big.pcap"
    big_packet = _build_tiny_tcp_packet(1) + b"\x00" * 200
    with PcapWriter(input_pcap) as writer:
        writer.write(RawPacket(ts_sec=0, ts_usec=0, data=big_packet, orig_len=len(big_packet)))

    with pytest.raises(PcapLimitExceededError):
        run_pipeline(input_pcap, tmp_path / "out.pcap", max_packet_size=50)


def test_max_connections_bounds_memory_via_pipeline(tmp_path: Path) -> None:
    """With max_connections set well below the number of distinct flows in
    the input, the pipeline must still complete successfully (eviction
    kicks in rather than growing the flow table unbounded) -- this is the
    practical, end-to-end manifestation of Task 7's O(1) LRU eviction."""
    input_pcap = tmp_path / "many_flows.pcap"
    _build_many_tiny_flows_pcap(input_pcap, count=200)

    result = run_pipeline(input_pcap, tmp_path / "out.pcap", max_connections=10)

    assert result.stats.total_packets == 200
    assert result.stats.active_connections <= 10


def test_max_total_packets_enforced_through_multiprocess_pipeline(tmp_path: Path) -> None:
    input_pcap = tmp_path / "many.pcap"
    _build_many_tiny_flows_pcap(input_pcap, count=50)

    with pytest.raises(PcapLimitExceededError):
        run_pipeline_multiprocess(
            input_pcap, tmp_path / "out.pcap", num_workers=2, max_total_packets=10
        )


def test_many_tiny_flows_completes_within_generous_time_bound(tmp_path: Path) -> None:
    """Adversarial-shaped input: many distinct five-tuples (each its own
    flow), maximizing flow-table churn. Must complete well within a
    generous time bound -- if eviction ever regressed to O(n) (the
    original C++ bug being fixed in Task 7), this would visibly degrade as
    the flow count grows past max_connections."""
    input_pcap = tmp_path / "adversarial_many_flows.pcap"
    packet_count = 3000
    _build_many_tiny_flows_pcap(input_pcap, count=packet_count)

    start = time.perf_counter()
    result = run_pipeline(input_pcap, tmp_path / "out.pcap", max_connections=500)
    elapsed = time.perf_counter() - start

    assert result.stats.total_packets == packet_count
    assert result.stats.active_connections <= 500
    # Generous bound: this should take well under a few seconds on any
    # reasonable machine; a real O(n) eviction regression across 3000
    # flows / a 500-cap table would be dramatically slower than this.
    assert elapsed < 10.0, f"Processing {packet_count} tiny-flow packets took {elapsed:.2f}s"


# --- D-01 / D-22 reproduction (T0-03) ---------------------------------------------
#
# These are `xfail(strict=True)`: they document a defect that is NOT yet
# fixed, so they are expected to fail. strict=True means that if one starts
# PASSING, the suite fails -- so T0-11 cannot silently land without someone
# coming back and flipping the marker. That is the whole point: a failing
# regression test would break CI, so the honest encoding of "known broken" is
# xfail, not a red suite.
#
# The measurement is the pickled size of what the workers send back, because
# that is the quantity the defect is actually about. `worker_main` accumulates
# one `ProcessedPacket` -- which holds the packet's full bytes -- per input
# packet (worker.py:501,512), then pickles the whole list into a single
# `WorkerResult`. Measuring the pickle measures the memory that crosses the
# process boundary and pins it in the same unit.


def _worker_result_pickle_bytes(pcap: Path, tmp_path: Path, **kwargs: object) -> int:
    """Total pickled bytes of every WorkerResult the pipeline collects.

    `_collect` is the single point where the parent receives results, so
    hooking it captures them without changing pipeline behaviour.
    """
    import pickle

    import dpi_engine.pipeline as pipeline_module

    captured: list[int] = []
    original = pipeline_module._collect

    def _spy(output_queue: object, expected: int) -> list[object]:
        results = original(output_queue, expected)  # type: ignore[arg-type]
        captured.extend(len(pickle.dumps(r)) for r in results)
        return results

    pipeline_module._collect = _spy  # type: ignore[assignment]
    try:
        pipeline_module.run_pipeline_multiprocess(
            pcap, tmp_path / "out.pcap", num_workers=2, **kwargs
        )
    finally:
        pipeline_module._collect = original  # type: ignore[assignment]

    return sum(captured)


@pytest.mark.xfail(
    strict=True,
    reason="D-01: workers accumulate every packet's full bytes and pickle them "
    "back as one WorkerResult; fixed by T0-11",
)
def test_worker_results_do_not_carry_packet_payloads(tmp_path: Path) -> None:
    """A worker's result must not grow with the size of the capture.

    Before the fix the pickled results total roughly the size of the input
    file, because every packet's bytes ride back to the parent. At the
    documented defaults (10M packets x 65535 bytes) that is hundreds of GB,
    and it defeats every other resource bound in the codebase -- including
    the ones asserted above.
    """
    packet_count = 400
    input_pcap = tmp_path / "many.pcap"
    _build_many_tiny_flows_pcap(input_pcap, count=packet_count)
    capture_bytes = input_pcap.stat().st_size

    result_bytes = _worker_result_pickle_bytes(input_pcap, tmp_path)

    assert result_bytes < capture_bytes // 4, (
        f"worker results total {result_bytes} bytes for a {capture_bytes}-byte "
        "capture -- they are carrying the packet payloads back to the parent "
        "(D-01)"
    )


def test_processor_state_stays_bounded_by_max_connections() -> None:
    """`max_connections` bounds the flow table and nothing else.

    `_quic_inspectors` holds one per-flow QUIC reassembly buffer (each capped
    at MAX_CRYPTO_BUFFER = 64 KiB) and `blocked_tuples` grows monotonically;
    neither is pruned and neither is touched by the tracker's LRU. A stream
    with far more distinct flows than the bound should leave bounded state
    behind.

    Driven against `FlowProcessor` directly rather than through the pipeline:
    the processor is discarded when a worker exits, so only `WorkerResult`
    crosses the process boundary and these containers are invisible from
    outside. The defect is about *peak* memory during a run.
    """
    from dpi_engine.connection_tracker import ConnectionTracker
    from dpi_engine.packet_parser import parse_packet
    from dpi_engine.pcap_io import RawPacket
    from dpi_engine.rule_manager import RuleManager
    from dpi_engine.types import AppType, FiveTuple
    from dpi_engine.worker import FixedRuleSource, FlowProcessor, WorkItem

    max_connections = 50
    rules = RuleManager()
    rules.block_app(AppType.HTTPS)  # so most flows get blocked and land in the set
    processor = FlowProcessor(
        tracker=ConnectionTracker(fp_id=0, max_connections=max_connections),
        rule_source=FixedRuleSource(rules.snapshot()),
        enable_quic=False,
    )

    distinct_flows = 1000
    for i in range(distinct_flows):
        frame = _build_tiny_tcp_packet(i)
        raw = RawPacket(ts_sec=1700000000 + i, ts_usec=0, data=frame, orig_len=len(frame))
        parsed = parse_packet(raw)
        assert parsed is not None
        processor.process(
            WorkItem(
                sequence_index=i,
                raw=raw,
                parsed=parsed,
                five_tuple=FiveTuple(
                    src_ip=parsed.src_ip,
                    dst_ip=parsed.dst_ip,
                    src_port=parsed.src_port,
                    dst_port=parsed.dst_port,
                    protocol=parsed.protocol,
                ),
            )
        )

    assert len(processor.blocked_tuples) <= max_connections, (
        f"blocked_tuples holds {len(processor.blocked_tuples)} entries for "
        f"{distinct_flows} flows against a {max_connections}-connection bound"
    )
    assert len(processor._quic_inspectors) <= max_connections, (
        f"_quic_inspectors holds {len(processor._quic_inspectors)} entries for "
        f"{distinct_flows} flows against a {max_connections}-connection bound"
    )


def test_blocked_flow_is_still_dropped_after_its_tuple_is_pruned() -> None:
    """Pruning `blocked_tuples` must not let a blocked flow's packets through.

    This is the invariant that makes the `D-22` pruning safe, and it is easy to
    get wrong. `process` skips the rule check entirely once
    `conn.state is ConnectionState.BLOCKED`, so if `blocked` were read only from
    the pruned cache, a flow that the tracker still holds as blocked but whose
    tuple is no longer cached would take the "not blocked" branch and have its
    packets **forwarded**. The tracker is therefore consulted as well:

        blocked = tuple_ in self.blocked_tuples or conn.state is ConnectionState.BLOCKED

    Driven by emptying `blocked_tuples` directly, which is exactly the state a
    prune leaves behind for a flow the tracker has not evicted yet -- the window
    in which the bug would show.
    """
    from dpi_engine.connection_tracker import ConnectionTracker
    from dpi_engine.packet_parser import parse_packet
    from dpi_engine.pcap_io import RawPacket
    from dpi_engine.rule_manager import RuleManager
    from dpi_engine.types import AppType, FiveTuple
    from dpi_engine.worker import FixedRuleSource, FlowProcessor, WorkItem

    rules = RuleManager()
    rules.block_app(AppType.HTTPS)
    processor = FlowProcessor(
        tracker=ConnectionTracker(fp_id=0, max_connections=50),
        rule_source=FixedRuleSource(rules.snapshot()),
        enable_quic=False,
    )

    def send(index: int):
        frame = _build_tiny_tcp_packet(index)
        raw = RawPacket(ts_sec=1700000000 + index, ts_usec=0, data=frame, orig_len=len(frame))
        parsed = parse_packet(raw)
        assert parsed is not None
        tuple_ = FiveTuple(
            src_ip=parsed.src_ip, dst_ip=parsed.dst_ip,
            src_port=parsed.src_port, dst_port=parsed.dst_port,
            protocol=parsed.protocol,
        )
        return processor.process(
            WorkItem(sequence_index=index, raw=raw, parsed=parsed, five_tuple=tuple_)
        ), tuple_

    first, tuple_ = send(0)
    assert first.forwarded is False, "the rule set should have blocked this flow"
    assert tuple_ in processor.blocked_tuples

    # Simulate the state a prune produces for a flow the tracker still holds.
    processor.blocked_tuples.clear()
    assert tuple_ in processor.tracker, "precondition: the tracker still holds the flow"
    assert processor.tracker.get_connection(tuple_).state.name == "BLOCKED"

    second, _ = send(0)
    assert second.forwarded is False, (
        "a flow the tracker still holds as BLOCKED must keep dropping packets "
        "even when its tuple is no longer in the pruned blocked_tuples cache; "
        "forwarding it here would silently disable the blocking rule"
    )
