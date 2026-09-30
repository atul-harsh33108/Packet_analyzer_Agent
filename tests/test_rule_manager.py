"""Tests for dpi_engine.rule_manager.

Covers: block/unblock round-trips per category, the should_block priority
order, the case-consistency fix for domain matching, the ipaddress-based IP
validation fix, JSON save/load round-trips, and clean failure on malformed
rules files / invalid values (rather than crashing).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dpi_engine.rule_manager import (
    BlockReasonType,
    RuleManager,
    RuleManagerError,
)
from dpi_engine.types import AppType

# --- IP blocking ----------------------------------------------------------------


def test_block_unblock_ip_round_trip() -> None:
    rm = RuleManager()
    assert not rm.is_ip_blocked("192.168.1.50")

    rm.block_ip("192.168.1.50")
    assert rm.is_ip_blocked("192.168.1.50")
    assert "192.168.1.50" in rm.get_blocked_ips()

    rm.unblock_ip("192.168.1.50")
    assert not rm.is_ip_blocked("192.168.1.50")


def test_invalid_ip_string_is_rejected_with_clear_error() -> None:
    """Regression test for the fix: the original's hand-rolled parseIP
    silently mis-parsed malformed IPs instead of rejecting them."""
    rm = RuleManager()
    with pytest.raises(RuleManagerError):
        rm.block_ip("999.1.1.1")  # octet out of range
    with pytest.raises(RuleManagerError):
        rm.block_ip("10.0.1")  # too few octets
    with pytest.raises(RuleManagerError):
        rm.block_ip("not-an-ip-at-all")
    with pytest.raises(RuleManagerError):
        rm.block_ip("")


def test_valid_ip_edge_cases() -> None:
    rm = RuleManager()
    rm.block_ip("0.0.0.0")
    rm.block_ip("255.255.255.255")
    assert rm.is_ip_blocked("0.0.0.0")
    assert rm.is_ip_blocked("255.255.255.255")


# --- App blocking -----------------------------------------------------------------


def test_block_unblock_app_round_trip() -> None:
    rm = RuleManager()
    assert not rm.is_app_blocked(AppType.YOUTUBE)

    rm.block_app(AppType.YOUTUBE)
    assert rm.is_app_blocked(AppType.YOUTUBE)
    assert AppType.YOUTUBE in rm.get_blocked_apps()

    rm.unblock_app(AppType.YOUTUBE)
    assert not rm.is_app_blocked(AppType.YOUTUBE)


# --- Domain blocking ----------------------------------------------------------------


def test_block_unblock_domain_round_trip() -> None:
    rm = RuleManager()
    rm.block_domain("facebook.com")
    assert rm.is_domain_blocked("facebook.com")

    rm.unblock_domain("facebook.com")
    assert not rm.is_domain_blocked("facebook.com")


def test_domain_case_consistency_fix() -> None:
    """Regression test for the case-sensitivity bug: the original's exact
    domain match was case-sensitive while its wildcard match was
    case-insensitive, letting a case-swap bypass exact-domain blocking.
    This port must match regardless of case, consistently."""
    rm = RuleManager()
    rm.block_domain("Example.com")
    assert rm.is_domain_blocked("example.com")
    assert rm.is_domain_blocked("EXAMPLE.COM")
    assert rm.is_domain_blocked("Example.com")

    rm2 = RuleManager()
    rm2.block_domain("example.com")
    assert rm2.is_domain_blocked("Example.com")  # reverse direction too


def test_wildcard_domain_matches_subdomains_and_bare_apex() -> None:
    rm = RuleManager()
    rm.block_domain("*.facebook.com")

    assert rm.is_domain_blocked("www.facebook.com")
    assert rm.is_domain_blocked("static.facebook.com")
    assert rm.is_domain_blocked("facebook.com")  # bare apex also matches
    assert not rm.is_domain_blocked("notfacebook.com")
    assert not rm.is_domain_blocked("facebook.com.evil.net")


def test_wildcard_domain_case_insensitive() -> None:
    rm = RuleManager()
    rm.block_domain("*.Facebook.com")
    assert rm.is_domain_blocked("www.facebook.com")
    assert rm.is_domain_blocked("WWW.FACEBOOK.COM")


def test_unrelated_domain_not_blocked() -> None:
    rm = RuleManager()
    rm.block_domain("facebook.com")
    assert not rm.is_domain_blocked("google.com")
    assert not rm.is_domain_blocked("")


# --- Port blocking ------------------------------------------------------------------


def test_block_unblock_port_round_trip() -> None:
    rm = RuleManager()
    rm.block_port(8080)
    assert rm.is_port_blocked(8080)
    rm.unblock_port(8080)
    assert not rm.is_port_blocked(8080)


def test_port_accepts_string_input() -> None:
    rm = RuleManager()
    rm.block_port("443")
    assert rm.is_port_blocked(443)


def test_invalid_port_values_rejected() -> None:
    rm = RuleManager()
    with pytest.raises(RuleManagerError):
        rm.block_port(-1)
    with pytest.raises(RuleManagerError):
        rm.block_port(70000)
    with pytest.raises(RuleManagerError):
        rm.block_port("not-a-number")


def test_port_boundary_values_accepted() -> None:
    rm = RuleManager()
    rm.block_port(0)
    rm.block_port(65535)
    assert rm.is_port_blocked(0)
    assert rm.is_port_blocked(65535)


# --- should_block priority order -----------------------------------------------------


def test_should_block_returns_none_when_nothing_matches() -> None:
    rm = RuleManager()
    assert rm.should_block("1.2.3.4", 443, AppType.HTTPS, "example.com") is None


def test_should_block_ip_takes_priority() -> None:
    rm = RuleManager()
    rm.block_ip("1.2.3.4")
    rm.block_port(443)  # also blocked, but IP should win (checked first)

    reason = rm.should_block("1.2.3.4", 443, AppType.HTTPS, "example.com")
    assert reason is not None
    assert reason.type == BlockReasonType.IP


def test_should_block_port_before_app_and_domain() -> None:
    rm = RuleManager()
    rm.block_port(443)
    rm.block_app(AppType.YOUTUBE)

    reason = rm.should_block("1.2.3.4", 443, AppType.YOUTUBE, "youtube.com")
    assert reason is not None
    assert reason.type == BlockReasonType.PORT


def test_should_block_app_before_domain() -> None:
    rm = RuleManager()
    rm.block_app(AppType.YOUTUBE)
    rm.block_domain("youtube.com")

    reason = rm.should_block("1.2.3.4", 443, AppType.YOUTUBE, "youtube.com")
    assert reason is not None
    assert reason.type == BlockReasonType.APP


def test_should_block_domain_as_last_resort() -> None:
    rm = RuleManager()
    rm.block_domain("youtube.com")

    reason = rm.should_block("1.2.3.4", 443, AppType.YOUTUBE, "youtube.com")
    assert reason is not None
    assert reason.type == BlockReasonType.DOMAIN


def test_should_block_empty_domain_never_matches_domain_rules() -> None:
    rm = RuleManager()
    rm.block_domain("youtube.com")
    assert rm.should_block("1.2.3.4", 443, AppType.UNKNOWN, "") is None


# --- Persistence ----------------------------------------------------------------------


def test_save_and_load_rules_round_trip(tmp_path: Path) -> None:
    rm = RuleManager()
    rm.block_ip("192.168.1.50")
    rm.block_app(AppType.YOUTUBE)
    rm.block_app(AppType.TIKTOK)
    rm.block_domain("facebook.com")
    rm.block_domain("*.evil.example")
    rm.block_port(8080)

    path = tmp_path / "rules.json"
    rm.save_rules(path)

    loaded = RuleManager.load_rules(path)

    assert loaded.is_ip_blocked("192.168.1.50")
    assert loaded.is_app_blocked(AppType.YOUTUBE)
    assert loaded.is_app_blocked(AppType.TIKTOK)
    assert loaded.is_domain_blocked("facebook.com")
    assert loaded.is_domain_blocked("sub.evil.example")
    assert loaded.is_port_blocked(8080)
    assert loaded.get_stats() == rm.get_stats()


def test_cli_style_round_trip_block_app_and_domain(tmp_path: Path) -> None:
    """Mirrors the Task 6 CLI demo scenario:
    --block-app YouTube --block-domain facebook --save-rules rules.json
    then --load-rules rules.json."""
    rm = RuleManager()
    rm.block_app(AppType.YOUTUBE)
    rm.block_domain("facebook")

    path = tmp_path / "rules.json"
    rm.save_rules(path)
    loaded = RuleManager.load_rules(path)

    assert loaded.is_app_blocked(AppType.YOUTUBE)
    assert loaded.is_domain_blocked("facebook")


def test_load_rules_missing_file_raises_clean_error(tmp_path: Path) -> None:
    with pytest.raises(RuleManagerError):
        RuleManager.load_rules(tmp_path / "does_not_exist.json")


def test_load_rules_malformed_json_raises_clean_error(tmp_path: Path) -> None:
    """Regression test for the fix: the original's loadRules called
    std::stoi with no exception handling, crashing the whole process on a
    malformed rules file. This port must raise a clean, catchable error."""
    path = tmp_path / "malformed.json"
    path.write_text("{ this is not valid json !!!", encoding="utf-8")

    with pytest.raises(RuleManagerError):
        RuleManager.load_rules(path)


def test_load_rules_non_object_json_raises_clean_error(tmp_path: Path) -> None:
    path = tmp_path / "not_an_object.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")

    with pytest.raises(RuleManagerError):
        RuleManager.load_rules(path)


def test_load_rules_invalid_port_in_file_raises_clean_error(tmp_path: Path) -> None:
    """Direct regression test for the std::stoi-on-malformed-port-line bug:
    a non-numeric or out-of-range port value in the rules file must raise
    RuleManagerError, not crash the process."""
    path = tmp_path / "bad_port.json"
    path.write_text('{"blocked_ports": ["not-a-number"]}', encoding="utf-8")

    with pytest.raises(RuleManagerError):
        RuleManager.load_rules(path)

    path2 = tmp_path / "bad_port2.json"
    path2.write_text('{"blocked_ports": [999999]}', encoding="utf-8")

    with pytest.raises(RuleManagerError):
        RuleManager.load_rules(path2)


def test_load_rules_invalid_ip_in_file_raises_clean_error(tmp_path: Path) -> None:
    path = tmp_path / "bad_ip.json"
    path.write_text('{"blocked_ips": ["999.999.999.999"]}', encoding="utf-8")

    with pytest.raises(RuleManagerError):
        RuleManager.load_rules(path)


def test_load_rules_unknown_app_name_raises_clean_error(tmp_path: Path) -> None:
    path = tmp_path / "bad_app.json"
    path.write_text('{"blocked_apps": ["NotARealApp"]}', encoding="utf-8")

    with pytest.raises(RuleManagerError):
        RuleManager.load_rules(path)


# --- clear_all / stats ----------------------------------------------------------------


def test_clear_all_resets_every_category() -> None:
    rm = RuleManager()
    rm.block_ip("1.2.3.4")
    rm.block_app(AppType.YOUTUBE)
    rm.block_domain("example.com")
    rm.block_port(443)

    rm.clear_all()

    stats = rm.get_stats()
    assert stats.blocked_ips == 0
    assert stats.blocked_apps == 0
    assert stats.blocked_domains == 0
    assert stats.blocked_ports == 0


def test_get_stats_counts_domains_and_patterns_together() -> None:
    rm = RuleManager()
    rm.block_domain("example.com")
    rm.block_domain("*.evil.example")

    stats = rm.get_stats()
    assert stats.blocked_domains == 2
