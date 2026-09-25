"""CLI-level test for the `run` subcommand (Task 8)."""

from __future__ import annotations

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
    assert "Total packets:    77" in out
    assert "Dropped:" in out
    assert "=== Blocked Flows ===" in out
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
    assert "Dropped:          0" in out


def test_run_unknown_app_reports_clean_error(capsys) -> None:
    exit_code = main(
        ["run", str(TEST_DPI_PCAP), "out.pcap", "--block-app", "NotARealApp"]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error:" in captured.err


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

    import json

    saved = json.loads(rules_path.read_text(encoding="utf-8"))
    assert saved["blocked_apps"] == ["YouTube"]


def test_version_flag(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "dpi-engine" in out


def test_run_with_workers_flag_uses_multiprocess_and_reports_per_worker(
    tmp_path: Path, capsys
) -> None:
    output = tmp_path / "output.pcap"

    exit_code = main(["run", str(TEST_DPI_PCAP), str(output), "--workers", "4"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "4 workers" in out
    assert "Per-worker:" in out
    assert "Total packets:    77" in out

    with PcapReader(output) as reader:
        packets = list(reader)
    assert len(packets) == 77


def test_run_refuses_to_overwrite_input(capsys) -> None:
    exit_code = main(["run", str(TEST_DPI_PCAP), str(TEST_DPI_PCAP)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error:" in captured.err
