"""CLI-level tests for the `run` subcommand."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dpi_engine.cli import main
from dpi_engine.pcap_io import PcapReader

FIXTURES = Path(__file__).parent / "fixtures"
TEST_DPI_PCAP = FIXTURES / "test_dpi.pcap"


def test_run_produces_filtered_output_and_report(tmp_path: Path, capsys) -> None:
    output = tmp_path / "output.pcap"

    exit_code = main(
        ["run", str(TEST_DPI_PCAP), str(output), "--block-app", "YouTube"]
    )

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Total packets read:  77" in out
    assert "Dropped:" in out
    assert "=== Blocked Flows" in out
    assert "YouTube" in out
    assert output.exists()

    with PcapReader(output) as reader:
        packets = list(reader)
    assert len(packets) < 77


def test_run_with_no_rules_forwards_everything(tmp_path: Path, capsys) -> None:
    output = tmp_path / "output.pcap"

    exit_code = main(["run", str(TEST_DPI_PCAP), str(output)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Dropped:             0" in out


def test_run_unknown_app_reports_clean_error(capsys) -> None:
    exit_code = main(
        ["run", str(TEST_DPI_PCAP), "out.pcap", "--block-app", "NotARealApp"]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error:" in captured.err


def test_run_unsupported_domain_pattern_is_rejected(capsys) -> None:
    """A '*' in a position the matcher cannot honour must fail loudly at rule
    construction time, not become a rule that silently never matches (which is
    what OSC's original did)."""
    exit_code = main(
        ["run", str(TEST_DPI_PCAP), "out.pcap", "--block-domain", "foo*.com"]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Unsupported domain pattern" in captured.err


def test_run_save_rules_writes_the_effective_rule_set(tmp_path: Path) -> None:
    output = tmp_path / "output.pcap"
    rules_path = tmp_path / "rules.json"

    exit_code = main(
        [
            "run",
            str(TEST_DPI_PCAP),
            str(output),
            "--block-app",
            "YouTube",
            "--save-rules",
            str(rules_path),
        ]
    )
    assert exit_code == 0
    assert rules_path.exists()

    saved = json.loads(rules_path.read_text(encoding="utf-8"))
    assert saved["blocked_apps"] == ["YouTube"]


def test_version_flag(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "dpi-engine" in out


def test_run_with_workers_flag_uses_multiprocess_and_reports_per_stage(
    tmp_path: Path, capsys
) -> None:
    output = tmp_path / "output.pcap"

    exit_code = main(["run", str(TEST_DPI_PCAP), str(output), "--workers", "4"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "4 fast-path worker process(es)" in out
    assert "Per-stage packets:" in out
    assert "Total packets read:  77" in out

    with PcapReader(output) as reader:
        packets = list(reader)
    assert len(packets) == 77


def test_run_with_load_balancers_uses_the_staged_pipeline(tmp_path: Path, capsys) -> None:
    output = tmp_path / "output.pcap"

    exit_code = main(
        [
            "run",
            str(TEST_DPI_PCAP),
            str(output),
            "--load-balancers",
            "2",
            "--fps-per-lb",
            "2",
        ]
    )
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "2 load balancer(s) -> 4 fast-path process(es)" in out
    # Both tiers report, which is the point of reproducing the two-tier shape.
    assert "=== Pipeline Stages ===" in out
    assert "Load balancers:" in out
    assert "Fast paths (aggregate):" in out
    assert "to fast-path" in out

    with PcapReader(output) as reader:
        assert len(list(reader)) == 77


def test_run_rejects_workers_and_load_balancers_together(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "run",
            str(TEST_DPI_PCAP),
            str(tmp_path / "o.pcap"),
            "--workers",
            "4",
            "--load-balancers",
            "2",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "mutually exclusive" in captured.err


def test_run_rejects_zero_workers(capsys) -> None:
    exit_code = main(["run", str(TEST_DPI_PCAP), "out.pcap", "--workers", "0"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "--workers must be >= 1" in captured.err


def test_run_json_output_is_machine_readable(tmp_path: Path, capsys) -> None:
    output = tmp_path / "output.pcap"

    exit_code = main(
        ["run", str(TEST_DPI_PCAP), str(output), "--json", "--block-app", "YouTube"]
    )
    out = capsys.readouterr().out
    assert exit_code == 0

    payload = json.loads(out)
    assert payload["stats"]["total_packets"] == 77
    assert payload["stats"]["dropped_packets"] > 0
    assert "YouTube" in payload["app_counts"]
    assert payload["quic"]["sni_extraction_supported"] in (True, False)
    # One blocked flow per dropped five-tuple, and YouTube has exactly two
    # five-tuples in this fixture (the TLS flow and its DNS query).
    assert len(payload["blocked_flows"]) == 2
    assert all(entry["app"] == "YouTube" for entry in payload["blocked_flows"])
    # Top names and flow states are the previously-dead global report, and must
    # now actually appear in normal output.
    assert payload["flows"]["top_domains"]
    assert payload["flows"]["states"]


def test_run_flow_timeout_zero_is_accepted(tmp_path: Path, capsys) -> None:
    output = tmp_path / "output.pcap"
    exit_code = main(
        ["run", str(TEST_DPI_PCAP), str(output), "--flow-timeout", "0"]
    )
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Total packets read:  77" in out


def test_run_refuses_to_overwrite_input(capsys) -> None:
    exit_code = main(["run", str(TEST_DPI_PCAP), str(TEST_DPI_PCAP)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error:" in captured.err
