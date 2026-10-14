"""Re-runs the Task 9 differential fixtures through the multiprocessing
pipeline (Task 10), asserting IDENTICAL results to the single-process
pipeline's output on the same fixtures -- not a fresh comparison against
the C++ binary (that's what test_differential.py / test_differential_edge_cases.py
already do for the single-process pipeline). This proves hash-partitioning
across worker processes doesn't change behavior on the exact same
adversarial/edge-case inputs that were carefully verified against the real
C++ reference in Task 9.
"""

from __future__ import annotations

from pathlib import Path

from conftest import DIFFERENTIAL_FIXTURES as DIFF_FIXTURES
from conftest import TEST_DPI_PCAP
from dpi_engine.pcap_io import PcapReader

from .conftest import run_pipeline, run_pipeline_multiprocess

EDGE_CASE_FIXTURES = [
    "control_normal_capture.pcap",
    "truncated_client_hello.pcap",
    "truncated_tcp_header.pcap",
    "oversized_declared_lengths.pcap",
]


def _assert_pipelines_agree(fixture_path: Path, tmp_path: Path, num_workers: int = 4) -> None:
    sp_out = tmp_path / "sp_out.pcap"
    mp_out = tmp_path / "mp_out.pcap"

    sp_result = run_pipeline(fixture_path, sp_out)
    mp_result = run_pipeline_multiprocess(fixture_path, mp_out, num_workers=num_workers)

    assert mp_result.stats.total_packets == sp_result.stats.total_packets
    assert mp_result.stats.forwarded_packets == sp_result.stats.forwarded_packets
    assert mp_result.stats.dropped_packets == sp_result.stats.dropped_packets
    assert mp_result.stats.other_packets == sp_result.stats.other_packets
    assert mp_result.detected_domains == sp_result.detected_domains

    with PcapReader(sp_out) as r:
        sp_packets = [p.data for p in r]
    with PcapReader(mp_out) as r:
        mp_packets = [p.data for p in r]
    assert sp_packets == mp_packets


def test_real_sample_capture_multiprocess_matches_single_process(tmp_path: Path) -> None:
    _assert_pipelines_agree(TEST_DPI_PCAP, tmp_path)


def test_edge_case_fixtures_multiprocess_matches_single_process(tmp_path: Path) -> None:
    for fixture_name in EDGE_CASE_FIXTURES:
        fixture_path = DIFF_FIXTURES / fixture_name
        assert fixture_path.exists(), f"missing fixture: {fixture_path}"
        sub_tmp = tmp_path / fixture_name
        sub_tmp.mkdir()
        _assert_pipelines_agree(fixture_path, sub_tmp, num_workers=2)
