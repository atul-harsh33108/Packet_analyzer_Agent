"""Integration tests for dpi_engine.pipeline (Task 8).

Runs the full single-process pipeline against the real OSC sample capture
with various blocking rules and verifies the end-to-end forward/drop
behavior, output pcap contents, and classification results.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dpi_engine.pcap_io import PcapReader
from dpi_engine.pipeline import run_pipeline
from dpi_engine.rule_manager import RuleManager
from dpi_engine.types import AppType

FIXTURES = Path(__file__).parent / "fixtures"
TEST_DPI_PCAP = FIXTURES / "test_dpi.pcap"


def test_pipeline_with_no_rules_forwards_everything(tmp_path: Path) -> None:
    output = tmp_path / "output.pcap"
    result = run_pipeline(TEST_DPI_PCAP, output)

    assert result.stats.total_packets == 77
    assert result.stats.dropped_packets == 0
    assert result.stats.forwarded_packets == 77

    with PcapReader(output) as reader:
        out_packets = list(reader)
    assert len(out_packets) == 77


def test_pipeline_blocking_an_app_drops_only_its_packets(tmp_path: Path) -> None:
    output = tmp_path / "output.pcap"
    rules = RuleManager()
    rules.block_app(AppType.YOUTUBE)

    result = run_pipeline(TEST_DPI_PCAP, output, rules)

    assert result.stats.dropped_packets > 0
    assert result.stats.forwarded_packets == result.stats.total_packets - result.stats.dropped_packets
    assert result.stats.forwarded_packets < result.stats.total_packets

    with PcapReader(output) as reader:
        out_packets = list(reader)
    assert len(out_packets) == result.stats.forwarded_packets

    # At least one flow should be recorded as blocked for YouTube.
    assert any(app == AppType.YOUTUBE for _, app, _ in result.blocked_flows)


def test_pipeline_blocking_a_domain(tmp_path: Path) -> None:
    output = tmp_path / "output.pcap"
    rules = RuleManager()
    # RuleManager matches exact domains or wildcard patterns (see
    # rule_manager.py) -- the real detected SNI is "www.facebook.com", so a
    # wildcard rule (or the exact string) is needed to match it.
    rules.block_domain("*.facebook.com")

    result = run_pipeline(TEST_DPI_PCAP, output, rules)

    assert result.stats.dropped_packets > 0
    assert any("facebook" in sni for _, _, sni in result.blocked_flows)


def test_pipeline_blocking_an_ip(tmp_path: Path) -> None:
    output = tmp_path / "output.pcap"
    rules = RuleManager()
    # 192.168.1.50 is used by the OSC sample generator for a source that
    # should be blocked regardless of app classification.
    rules.block_ip("192.168.1.50")

    result = run_pipeline(TEST_DPI_PCAP, output, rules)

    assert result.stats.dropped_packets > 0


def test_pipeline_classification_matches_readme_sample_domains(tmp_path: Path) -> None:
    """Cross-check against OSC/README.md's documented sample output list of
    detected domains/SNIs."""
    output = tmp_path / "output.pcap"
    result = run_pipeline(TEST_DPI_PCAP, output)

    domains = set(result.detected_domains)
    assert "www.youtube.com" in domains
    assert "www.facebook.com" in domains
    assert "www.google.com" in domains
    assert "github.com" in domains
    assert result.detected_domains["www.youtube.com"] == AppType.YOUTUBE
    assert result.detected_domains["www.netflix.com"] == AppType.NETFLIX  # bug-fix regression
    assert result.detected_domains["www.microsoft.com"] == AppType.MICROSOFT  # bug-fix regression


def test_pipeline_app_counts_sum_to_total_packets_with_ip_udp(tmp_path: Path) -> None:
    output = tmp_path / "output.pcap"
    result = run_pipeline(TEST_DPI_PCAP, output)

    counted = sum(result.app_counts.values())
    # Every packet that has_ip and (has_tcp or has_udp) gets an app_counts
    # entry; a handful of packets (if any) without IP/TCP/UDP would not.
    assert counted <= result.stats.total_packets
    assert counted > 0


def test_pipeline_refuses_to_overwrite_input(tmp_path: Path) -> None:
    src = tmp_path / "input.pcap"
    src.write_bytes(TEST_DPI_PCAP.read_bytes())

    with pytest.raises(Exception):
        run_pipeline(src, src)


def test_pipeline_forward_and_reverse_direction_blocked_independently(tmp_path: Path) -> None:
    """Regression/behavior-pin test for the documented quirk carried
    forward from main_working.cpp: blocking an app blocks the direction
    that was classified (client->server, carrying the SNI), but the
    reverse direction (server->client) is a different five-tuple and is
    NOT automatically blocked. This matches the original's behavior
    exactly (it never calls FiveTuple.reverse() in its main loop)."""
    output = tmp_path / "output.pcap"
    rules = RuleManager()
    rules.block_app(AppType.YOUTUBE)

    result = run_pipeline(TEST_DPI_PCAP, output, rules)

    blocked_tuples = {t for t, _, _ in result.blocked_flows}
    # None of the blocked tuples' reverses should also appear blocked,
    # because the reverse direction was never classified as YouTube (it
    # never carries the ClientHello).
    for t in blocked_tuples:
        assert t.reverse() not in blocked_tuples
