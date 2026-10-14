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
    # Two vocabularies, deliberately different (`D-16`): the *display* string
    # above stays "YouTube" because that is what a human is shown, but the
    # *persisted* key is the enum name, which is an identifier rather than
    # presentation copy. Keying a saved file on the display string meant
    # rewording the product silently invalidated every rules file ever saved.
    assert saved["blocked_apps"] == ["YOUTUBE"]
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

def test_loading_a_legacy_rules_file_prints_the_deprecation_notice(
    tmp_path: Path, capsys
) -> None:
    """The warning has to be *visible*, not merely raised.

    Python hides `DeprecationWarning` outside `__main__`, so the alias added by
    `DEC-04` would otherwise load an old rules file with no visible sign that
    it speaks an outdated vocabulary. If the operator never sees the notice,
    every saved file stays on display-name keys forever and the migration half
    of the decision is inert.
    """
    rules_path = tmp_path / "legacy.json"
    rules_path.write_text(
        json.dumps({"version": 1, "blocked_apps": ["YouTube"]}), encoding="utf-8"
    )

    exit_code = main(["rules", "--load-rules", str(rules_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "warning:" in captured.err
    assert "YOUTUBE" in captured.err  # names the canonical key to switch to
    assert "1 app(s)" in captured.out  # and it still loaded


def test_loading_a_canonical_rules_file_prints_no_deprecation_notice(
    tmp_path: Path, capsys
) -> None:
    """Otherwise the notice above would be noise a user learns to ignore, and
    the one that matters would be lost in it."""
    rules_path = tmp_path / "canonical.json"
    rules_path.write_text(
        json.dumps({"version": 1, "blocked_apps": ["YOUTUBE"]}), encoding="utf-8"
    )

    exit_code = main(["rules", "--load-rules", str(rules_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "warning:" not in captured.err
    assert "1 app(s)" in captured.out
