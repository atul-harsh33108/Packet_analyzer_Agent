"""Tests for report rendering, including the OSC global report that was
dead code in the original and is now actually wired into normal output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import TEST_DPI_PCAP
from dpi_engine.connection_tracker import (
    GlobalStats,
    TrackerStats,
    combine_tracker_reports,
)
from dpi_engine.load_balancer import FastPathStats, LoadBalancerStats
from dpi_engine.pipeline import run_pipeline, run_pipeline_staged
from dpi_engine.report import (
    capabilities,
    render_application_breakdown,
    render_blocked_flows,
    render_detected_domains,
    render_extraction_report,
    render_flow_states,
    render_full_report,
    render_processing_report,
    render_rule_stats,
    render_stage_report,
    render_top_domains,
    result_to_dict,
    result_to_json,
)
from dpi_engine.rule_manager import RuleStats
from dpi_engine.types import AppType, ConnectionState, DPIStats, FiveTuple


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    out = tmp_path_factory.mktemp("report") / "out.pcap"
    return run_pipeline(TEST_DPI_PCAP, out)


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def test_processing_report_uses_inspected_packets_as_the_denominator(result) -> None:
    text = render_processing_report(result)
    assert "Total packets read:  77" in text
    assert "of inspected" in text
    # Every percentage is over the same, stated denominator.
    assert text.count("% of inspected") == 2


def test_processing_report_omits_empty_optional_sections(result) -> None:
    """There is no QUIC in this fixture, so the QUIC line must be absent rather
    than printed as a misleading zero."""
    text = render_processing_report(result)
    assert "QUIC datagrams" not in text


def test_processing_report_reports_quic_when_present(result) -> None:
    from dataclasses import replace

    with_quic = replace(result, quic_packets=5, quic_undecryptable=2)
    text = render_processing_report(with_quic)
    assert "5 seen, 2 not decryptable" in text


def test_extraction_report_covers_every_extractor(result) -> None:
    text = render_extraction_report(result)
    for label in (
        "TLS SNI:",
        "HTTP Host:",
        "DNS query names:",
        "QUIC ClientHello:",
    ):
        assert label in text
    assert "App hits (specific):" in text


def test_application_breakdown_percentages_sum_to_100(result) -> None:
    """Self-normalising denominator: the percentages must actually add up, which
    is what the original's two inconsistent denominators could never do."""
    text = render_application_breakdown(result)
    percentages = [
        float(line.split("%")[0].split()[-1])
        for line in text.splitlines()[1:]
        if "%" in line
    ]
    assert percentages
    assert sum(percentages) == pytest.approx(100.0, abs=0.5)


def test_application_breakdown_handles_an_empty_histogram() -> None:
    class Empty:
        app_counts: dict = {}
        stats = DPIStats()

    assert "no TCP/UDP packets" in render_application_breakdown(Empty())


def test_drop_rate_is_zero_when_nothing_was_inspected() -> None:
    from dpi_engine.pipeline import PipelineResult

    empty = PipelineResult(stats=DPIStats())
    assert empty.drop_rate_percent == 0.0


def test_drop_rate_uses_inspected_packets_only() -> None:
    from dpi_engine.pipeline import PipelineResult

    # 20 ARP/non-IP frames must not dilute the denominator.
    result = PipelineResult(
        stats=DPIStats(
            total_packets=30,
            tcp_packets=8,
            udp_packets=2,
            other_packets=20,
            dropped_packets=5,
        )
    )
    assert result.drop_rate_percent == pytest.approx(50.0)


def test_bar_never_overflows_its_column() -> None:
    """A share above 100% (possible when the denominator is deliberately
    narrower than the pool) must not break the column, which OSC's fixed-width
    box drawing could not guarantee."""
    from dpi_engine.report import _bar

    assert len(_bar(150.0)) == 20  # clamped to full
    assert len(_bar(-5.0)) == 0  # clamped to empty
    assert _bar(0.0) == ""
    assert _bar(100.0) == "#" * 20
    assert _bar(50.0) == "#" * 10


def test_flow_states_reports_a_histogram(result) -> None:
    text = render_flow_states(result.global_stats)
    assert "CLASSIFIED" in text
    assert "NEW" in text
    assert "TOTAL" in text


def test_top_domains_lists_resolved_names(result) -> None:
    text = render_top_domains(result.global_stats)
    assert "www.google.com" in text
    assert "Top" in text


def test_top_domains_respects_the_limit(result) -> None:
    text = render_top_domains(result.global_stats, limit=3)
    assert len([line for line in text.splitlines() if line.startswith("  ")]) == 3


def test_top_domains_is_empty_when_no_names_were_resolved() -> None:
    assert render_top_domains(GlobalStats()) == ""


def test_stage_report_is_empty_for_a_single_stage() -> None:
    assert render_stage_report(None, None) == ""


def test_stage_report_covers_both_tiers(tmp_path: Path) -> None:
    staged = run_pipeline_staged(
        TEST_DPI_PCAP, tmp_path / "o.pcap", num_load_balancers=2, fps_per_lb=2
    )
    text = render_stage_report(staged.load_balancer_stats, staged.fast_path_stats)
    assert "Load balancers:" in text
    assert "Fast paths (aggregate):" in text
    assert "to fast-path 0:" in text


def test_rule_stats_lists_every_category() -> None:
    text = render_rule_stats(RuleStats(1, 2, 3, 4))
    for label in ("blocked IPs:", "blocked apps:", "blocked domains:", "blocked ports:"):
        assert label in text
    assert "1" in text and "4" in text


def test_blocked_flows_and_names_are_omitted_when_empty() -> None:
    assert render_blocked_flows([]) == ""
    assert render_detected_domains(type("R", (), {"detected_domains": {}})()) == ""


def test_full_report_omits_sections_with_no_data() -> None:
    text = render_full_report(
        type(
            "R",
            (),
            {
                "stats": DPIStats(),
                "app_counts": {},
                "detected_domains": {},
                "blocked_flows": [],
                "per_worker_packet_counts": [],
                "fast_path_stats": None,
                "load_balancer_stats": None,
                "quic_packets": 0,
                "quic_undecryptable": 0,
                "global_stats": None,
                "drop_rate_percent": 0.0,
            },
        )()
    )
    assert "=== Application Breakdown ===" in text
    assert "=== Flow State ===" not in text
    assert "=== Blocked Flows" not in text


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def test_result_to_dict_is_fully_serialisable(result) -> None:
    payload = result_to_dict(result)
    json.dumps(payload)  # must not raise
    assert payload["stats"]["total_packets"] == 77
    assert payload["quic"]["sni_extraction_supported"] in (True, False)


def test_result_to_dict_uses_display_names_not_enum_reprs(result) -> None:
    payload = result_to_dict(result)
    assert "Google" in payload["app_counts"]
    assert "Unknown" in payload["app_counts"]
    for name in payload["app_counts"]:
        assert "." not in name
    for entry in payload["detected_domains"].values():
        assert "." not in entry


def test_result_to_dict_includes_the_previously_dead_global_report(result) -> None:
    """OSC built a GlobalConnectionTable with a full report renderer and never
    called it. These keys are how that dead capability became live."""
    payload = result_to_dict(result)
    flows = payload["flows"]
    assert flows["active"] == 43
    assert flows["top_domains"]
    assert "CLASSIFIED" in flows["states"]
    assert flows["unidentified"] > 0


def test_result_to_json_round_trips(result) -> None:
    text = result_to_json(result, RuleStats(1, 0, 0, 0))
    payload = json.loads(text)
    assert payload["rules"]["blocked_ips"] == 1


def test_capabilities_explains_quic_availability() -> None:
    caps = capabilities()
    assert set(caps) == {"quic_sni_extraction", "quic_sni_unavailable_reason"}
    assert caps["quic_sni_extraction"] in (True, False)
    if caps["quic_sni_extraction"]:
        assert caps["quic_sni_unavailable_reason"] is None
    else:
        assert caps["quic_sni_unavailable_reason"]


# ---------------------------------------------------------------------------
# combine_tracker_reports
# ---------------------------------------------------------------------------


def _conn(tuple_, app=AppType.HTTPS, sni="", state=ConnectionState.CLASSIFIED):
    from dpi_engine.types import Connection

    return Connection(tuple=tuple_, app_type=app, sni=sni, state=state)


def test_combine_merges_app_and_domain_histograms() -> None:
    t1, t2, t3 = FiveTuple(1, 2, 3, 4, 6), FiveTuple(5, 6, 7, 8, 6), FiveTuple(9, 10, 11, 12, 6)
    reports = [
        (TrackerStats(active_connections=2), [_conn(t1, AppType.GOOGLE, "a.example")]),
        (
            TrackerStats(active_connections=1),
            [_conn(t2, AppType.NETFLIX, "b.example"), _conn(t3)],
        ),
    ]
    combined = combine_tracker_reports(reports)
    assert combined.total_active_connections == 3
    assert combined.app_distribution == {AppType.GOOGLE: 1, AppType.NETFLIX: 1, AppType.HTTPS: 1}
    assert dict(combined.top_domains) == {"a.example": 1, "b.example": 1}
    assert combined.total_connections == 3


def test_combine_counts_state_histogram_and_unknown() -> None:
    t1, t2 = FiveTuple(1, 2, 3, 4, 6), FiveTuple(5, 6, 7, 8, 6)
    reports = [
        (
            TrackerStats(),
            [
                _conn(t1, AppType.UNKNOWN, state=ConnectionState.NEW),
                _conn(t2, state=ConnectionState.CLOSED),
            ],
        )
    ]
    combined = combine_tracker_reports(reports)
    assert combined.unknown_connections == 1
    assert combined.state_counts == {ConnectionState.NEW: 1, ConnectionState.CLOSED: 1}


def test_top_domains_ties_are_broken_deterministically() -> None:
    """Equal counts must not order by dict iteration order, which varies with
    worker completion order -- otherwise two identical runs print different
    reports."""
    tuples = [FiveTuple(i, 2, 3, 4, 6) for i in range(6)]
    names = ["f.example", "a.example", "e.example", "b.example", "d.example", "c.example"]
    reports = [
        (TrackerStats(), [_conn(t, sni=n) for t, n in zip(tuples, names, strict=True)]),
    ]
    first = combine_tracker_reports(reports).top_domains
    second = combine_tracker_reports(list(reversed(reports))).top_domains
    assert first == second == sorted((n, 1) for n in names)


def test_top_domains_limit_is_honoured_and_validated() -> None:
    tuples = [FiveTuple(i, 2, 3, 4, 6) for i in range(5)]
    reports = [
        (TrackerStats(), [_conn(t, sni=f"n{i}.example") for i, t in enumerate(tuples)]),
    ]
    assert len(combine_tracker_reports(reports, top_domains_limit=2).top_domains) == 2
    assert combine_tracker_reports(reports, top_domains_limit=0).top_domains == []
    with pytest.raises(ValueError):
        combine_tracker_reports(reports, top_domains_limit=-1)


def test_fast_path_stats_to_dict_is_json_serialisable() -> None:
    json.dumps(FastPathStats(fp_id=1, packets_processed=2).to_dict())
    json.dumps(LoadBalancerStats(lb_id=0, per_fp_packets={0: 1}).to_dict())
