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
