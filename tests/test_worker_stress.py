"""Stress test for the multiprocessing pipeline's shutdown/drain safety
(Task 10): verifies no packet is ever lost across shutdown, including
under artificially slowed worker processing that maximizes the chance of
hitting a shutdown-vs-still-processing race if one existed.

This directly targets the bug class documented in DESIGN_DECISIONS.md
("packets can vanish silently on every shutdown" in the original's
load_balancer.cpp/fast_path.cpp/dpi_mt.cpp) and worker.py's module
docstring explaining the fix (dispatch everything, THEN send exactly one
shutdown sentinel per worker; no queue.shutdown()-style call that could
race with an in-flight push).
"""

from __future__ import annotations

import socket
import time
from pathlib import Path

from dpi_engine.pcap_io import PcapReader, PcapWriter, RawPacket
from dpi_engine.pipeline import run_pipeline_multiprocess


def _build_tcp_packet(seq_id: int, src_port: int, dst_port: int = 443) -> bytes:
    eth = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    tcp = (
        src_port.to_bytes(2, "big")
        + dst_port.to_bytes(2, "big")
        + (0).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + bytes([0x50, 0x18])
        + (65535).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + b"\x00" * 10  # tiny payload, nothing extractable
    )
    total_len = 20 + len(tcp)
    ip = (
        bytes([0x45, 0x00])
        + total_len.to_bytes(2, "big")
        + b"\x00\x00"
        + b"\x40\x00"
        + bytes([64, 6])
        + b"\x00\x00"
        + socket.inet_aton("192.168.1.100")
        + socket.inet_aton(f"10.{(seq_id >> 16) & 0xFF}.{(seq_id >> 8) & 0xFF}.{seq_id & 0xFF}")
    )
    return eth + ip + tcp


def build_large_interleaved_pcap(path: Path, num_flows: int, packets_per_flow: int) -> int:
    """Builds a pcap with `num_flows` distinct five-tuples, interleaving
    their packets round-robin (so consecutive packets in the file belong
    to different flows/workers -- maximizing dispatch interleaving across
    workers, which is what would expose a shutdown-ordering race if one
    existed). Returns the total packet count written."""
    total = 0
    with PcapWriter(path) as writer:
        for round_ in range(packets_per_flow):
            for flow_id in range(num_flows):
                src_port = 20000 + flow_id
                data = _build_tcp_packet(flow_id, src_port)
                writer.write(
                    RawPacket(
                        ts_sec=1700000000 + total,
                        ts_usec=0,
                        data=data,
                        orig_len=len(data),
                    )
                )
                total += 1
    return total


def test_no_packet_loss_across_shutdown_with_many_interleaved_flows(tmp_path: Path) -> None:
    input_pcap = tmp_path / "large_interleaved.pcap"
    total_written = build_large_interleaved_pcap(input_pcap, num_flows=50, packets_per_flow=20)
    assert total_written == 1000

    result = run_pipeline_multiprocess(
        input_pcap, tmp_path / "output.pcap", num_workers=6
    )

    assert result.stats.total_packets == total_written
    assert result.stats.forwarded_packets + result.stats.dropped_packets == total_written
    assert result.stats.forwarded_packets == total_written  # no rules -> everything forwarded

    with PcapReader(tmp_path / "output.pcap") as r:
        output_packets = list(r)
    assert len(output_packets) == total_written


def test_no_packet_loss_with_many_workers_and_few_packets(tmp_path: Path) -> None:
    """Edge case: more workers than packets. Every worker still must
    receive its shutdown sentinel and return cleanly, and no packet may be
    lost even though most workers get zero real work items."""
    input_pcap = tmp_path / "small.pcap"
    total_written = build_large_interleaved_pcap(input_pcap, num_flows=3, packets_per_flow=2)
    assert total_written == 6

    result = run_pipeline_multiprocess(
        input_pcap, tmp_path / "output.pcap", num_workers=16
    )

    assert result.stats.total_packets == total_written
    assert result.stats.forwarded_packets == total_written
    assert len(result.per_worker_packet_counts) == 16


def test_no_packet_loss_under_artificially_slowed_worker_processing(tmp_path: Path) -> None:
    """Directly stresses the shutdown-ordering fix: artificially slows down
    every packet's classification inside the actual worker PROCESSES (via
    an environment variable checked at worker startup -- see
    worker._maybe_apply_test_delay -- since a monkeypatch in this test
    process would NOT propagate to the spawned child processes on Windows,
    which re-import worker.py fresh rather than inheriting this process's
    patched state). This guarantees that, at the moment the main process
    finishes dispatching all packets and sends the shutdown sentinels,
    every worker still has a substantial backlog of unprocessed items in
    its queue. If the shutdown/drain protocol had the original's bug
    (shutting down a queue while items are still queued, causing in-flight
    pushes/pops to be dropped), this timing is exactly what would expose
    it. With the correct implementation (dispatch everything, THEN one
    sentinel per worker, workers drain via a plain blocking get() loop),
    slowing down processing changes nothing about correctness -- only how
    long the run takes.
    """
    import os

    input_pcap = tmp_path / "slow_stress.pcap"
    total_written = build_large_interleaved_pcap(input_pcap, num_flows=8, packets_per_flow=15)
    assert total_written == 120

    os.environ["DPI_ENGINE_TEST_WORKER_DELAY_MS"] = "2"
    try:
        start = time.perf_counter()
        result = run_pipeline_multiprocess(input_pcap, tmp_path / "output.pcap", num_workers=4)
        elapsed = time.perf_counter() - start
    finally:
        del os.environ["DPI_ENGINE_TEST_WORKER_DELAY_MS"]

    # Sanity: confirm the delay actually took effect (120 packets * 2ms /
    # 4 workers running concurrently ~= 60ms minimum, generously bounded
    # here to avoid flakiness while still catching "delay silently did
    # nothing" if the env var plumbing broke).
    assert elapsed > 0.03, (
        "Expected the artificial per-packet delay to measurably slow down "
        "processing -- if this fails, the delay isn't reaching the worker "
        "processes and this test isn't actually stressing anything."
    )

    assert result.stats.total_packets == total_written
    assert result.stats.forwarded_packets == total_written
    assert result.stats.dropped_packets == 0

    with PcapReader(tmp_path / "output.pcap") as r:
        output_packets = list(r)
    assert len(output_packets) == total_written


def test_repeated_runs_never_lose_packets(tmp_path: Path) -> None:
    """Runs the pipeline several times in a row against the same
    moderately large input -- if there were any nondeterministic
    race-driven packet loss, running multiple times increases the chance
    of observing it at least once."""
    input_pcap = tmp_path / "repeat.pcap"
    total_written = build_large_interleaved_pcap(input_pcap, num_flows=20, packets_per_flow=10)

    for i in range(5):
        result = run_pipeline_multiprocess(
            input_pcap, tmp_path / f"output_{i}.pcap", num_workers=4
        )
        assert result.stats.total_packets == total_written
        assert result.stats.forwarded_packets == total_written
        assert result.stats.dropped_packets == 0
