"""CLI-level test for the `rules` subcommand (Task 6)."""

from __future__ import annotations

import json
from pathlib import Path

from dpi_engine.cli import main


def test_rules_block_and_save_then_load_round_trip(tmp_path: Path, capsys) -> None:
    rules_path = tmp_path / "rules.json"

    exit_code = main(
        [
            "rules",
            "--block-app",
            "YouTube",
            "--block-domain",
            "facebook",
            "--save-rules",
            str(rules_path),
        ]
    )
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Blocked app: YouTube" in out
    assert "Blocked domain: facebook" in out
    assert rules_path.exists()

    saved = json.loads(rules_path.read_text(encoding="utf-8"))
    assert saved["blocked_apps"] == ["YouTube"]
    assert saved["blocked_domains"] == ["facebook"]

    exit_code = main(["rules", "--load-rules", str(rules_path)])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Loaded rules from" in out
    assert "1 app(s)" in out
    assert "1 domain(s)" in out


def test_rules_invalid_ip_reports_clean_error(capsys) -> None:
    exit_code = main(["rules", "--block-ip", "999.999.999.999"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error:" in captured.err


def test_rules_unknown_app_reports_clean_error(capsys) -> None:
    exit_code = main(["rules", "--block-app", "NotARealApp"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error:" in captured.err
