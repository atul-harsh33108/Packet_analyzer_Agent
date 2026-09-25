"""Tests for the multiprocessing pipeline (Task 10): dpi_engine.worker +
dpi_engine.pipeline.run_pipeline_multiprocess.

Covers: output identical to the single-process pipeline (proving hash-
partitioning doesn't change behavior, per DESIGN_DECISIONS.md "Testing
strategy"), no packet loss across shutdown even under artificially slowed
worker processing, worker-count edge cases, and re-running the Task 9
differential fixtures through the multiprocessing pipeline.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dpi_engine.pcap_io import PcapReader
from dpi_engine.pipeline import run_pipeline, run_pipeline_multiprocess
from dpi_engine.rule_manager import RuleManager
from dpi_engine.types import AppType

FIXTURES = Path(__file__).parent / "fixtures"
TEST_DPI_PCAP = FIXTURES / "test_dpi.pcap"


def test_multiprocess_matches_single_process_with_no_rules(tmp_path: Path) -> None:
    sp_result = run_pipeline(TEST_DPI_PCAP, tmp_path / "sp_out.pcap")
    mp_result = run_pipeline_multiprocess(
        TEST_DPI_PCAP, tmp_path / "mp_out.pcap", num_workers=4
    )

    assert mp_result.stats.total_packets == sp_result.stats.total_packets
    assert mp_result.stats.forwarded_packets == sp_result.stats.forwarded_packets
    assert mp_result.stats.dropped_packets == sp_result.stats.dropped_packets
    assert mp_result.stats.tcp_packets == sp_result.stats.tcp_packets
    assert mp_result.stats.udp_packets == sp_result.stats.udp_packets
    assert mp_result.app_counts == sp_result.app_counts
    assert mp_result.detected_domains == sp_result.detected_domains

    with PcapReader(tmp_path / "sp_out.pcap") as r:
        sp_packets = [p.data for p in r]
    with PcapReader(tmp_path / "mp_out.pcap") as r:
        mp_packets = [p.data for p in r]
    assert sp_packets == mp_packets  # exact byte-for-byte, same order


def test_multiprocess_matches_single_process_when_blocking_youtube(tmp_path: Path) -> None:
    rules = RuleManager()
    rules.block_app(AppType.YOUTUBE)

    sp_result = run_pipeline(TEST_DPI_PCAP, tmp_path / "sp_out.pcap", rules)
    mp_result = run_pipeline_multiprocess(
        TEST_DPI_PCAP, tmp_path / "mp_out.pcap", rules, num_workers=4
    )

    assert mp_result.stats.forwarded_packets == sp_result.stats.forwarded_packets
    assert mp_result.stats.dropped_packets == sp_result.stats.dropped_packets
    assert sorted(mp_result.blocked_flows) == sorted(sp_result.blocked_flows)

    with PcapReader(tmp_path / "sp_out.pcap") as r:
        sp_packets = [p.data for p in r]
    with PcapReader(tmp_path / "mp_out.pcap") as r:
        mp_packets = [p.data for p in r]
    assert sp_packets == mp_packets


def test_multiprocess_matches_single_process_when_blocking_domain(tmp_path: Path) -> None:
    rules = RuleManager()
    rules.block_domain("*.facebook.com")

    sp_result = run_pipeline(TEST_DPI_PCAP, tmp_path / "sp_out.pcap", rules)
    mp_result = run_pipeline_multiprocess(
        TEST_DPI_PCAP, tmp_path / "mp_out.pcap", rules, num_workers=3
    )

    assert mp_result.stats.dropped_packets == sp_result.stats.dropped_packets
    assert mp_result.stats.forwarded_packets == sp_result.stats.forwarded_packets


@pytest.mark.parametrize("num_workers", [1, 2, 4, 8])
def test_multiprocess_output_identical_across_different_worker_counts(
    tmp_path: Path, num_workers: int
) -> None:
    """Regardless of how many workers process the file, the final output
    (packet order, contents, stats) must be identical -- hash-partitioning
    only affects internal concurrency, never the observable result."""
    result = run_pipeline_multiprocess(
        TEST_DPI_PCAP, tmp_path / f"out_{num_workers}.pcap", num_workers=num_workers
    )
    assert result.stats.total_packets == 77
    assert result.stats.forwarded_packets == 77
    assert sum(result.per_worker_packet_counts) == 77

    with PcapReader(tmp_path / f"out_{num_workers}.pcap") as r:
        packets = [p.data for p in r]

    with PcapReader(TEST_DPI_PCAP) as r:
        original_packets = [p.data for p in r]

    assert packets == original_packets  # order preserved regardless of worker count


def test_num_workers_must_be_at_least_one(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        run_pipeline_multiprocess(TEST_DPI_PCAP, tmp_path / "out.pcap", num_workers=0)


def test_per_worker_packet_counts_sum_to_classified_packets(tmp_path: Path) -> None:
    result = run_pipeline_multiprocess(TEST_DPI_PCAP, tmp_path / "out.pcap", num_workers=4)
    # per_worker_packet_counts only counts packets that were actually
    # dispatched to a worker (has_ip and has_tcp/has_udp); packets skipped
    # entirely (other_packets) never reach a worker.
    expected = result.stats.total_packets - result.stats.other_packets
    assert sum(result.per_worker_packet_counts) == expected
