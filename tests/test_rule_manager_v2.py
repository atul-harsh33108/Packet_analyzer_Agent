"""Tests for the rule manager's copy-on-write concurrency model, the domain
pattern grammar, bulk deltas, and cross-process snapshot transport.

Covers what changed relative to the first version of this port: rules are now
stored as ints and frozen sets behind a lock with immutable snapshots, so the
packet hot path is lock-free and rules can change mid-run.
"""

from __future__ import annotations

import json
import pickle
import threading

import pytest

from dpi_engine.rule_manager import (
    STATIC_RULES,
    BlockReason,
    BlockReasonType,
    DomainPattern,
    RuleManager,
    RuleManagerError,
    RuleSnapshot,
    resolve_app_name,
)
from dpi_engine.types import AppType

# ---------------------------------------------------------------------------
# Domain pattern grammar
# ---------------------------------------------------------------------------


def test_exact_pattern_matches_only_itself() -> None:
    pattern = DomainPattern.parse("Facebook.com")
    assert pattern.matches("facebook.com")
    assert not pattern.matches("www.facebook.com")
    assert not pattern.matches("notfacebook.com")


def test_wildcard_pattern_matches_the_apex_and_subdomains() -> None:
    pattern = DomainPattern.parse("*.example.com")
    assert pattern.matches("example.com")
    assert pattern.matches("www.example.com")
    assert pattern.matches("a.b.example.com")
    assert not pattern.matches("notexample.com")
    assert not pattern.matches("example.com.evil.net")


def test_wildcard_pattern_is_case_insensitive_at_parse_time() -> None:
    assert DomainPattern.parse("*.Example.COM").raw == "*.example.com"
    assert DomainPattern.parse("EXAMPLE.com").matches("example.COM")


def test_wildcard_pattern_requires_a_nonempty_suffix() -> None:
    with pytest.raises(RuleManagerError):
        DomainPattern.parse("*.")


@pytest.mark.parametrize("pattern", ["foo*.com", "*foo", "a*b*c", "*", "sub.*.com"])
def test_unsupported_pattern_shapes_are_rejected_at_construction(pattern: str) -> None:
    """OSC accepted anything containing '*' but only implemented the `*.suffix`
    form, so 'foo*.com' became a rule that silently never matched, forever."""
    with pytest.raises(RuleManagerError, match="Unsupported domain pattern"):
        DomainPattern.parse(pattern)


def test_empty_domain_is_rejected() -> None:
    with pytest.raises(RuleManagerError):
        DomainPattern.parse("   ")


def test_unblock_rejects_the_same_shapes_as_block() -> None:
    rules = RuleManager()
    with pytest.raises(RuleManagerError):
        rules.unblock_domain("foo*.com")


# ---------------------------------------------------------------------------
# IP handling
# ---------------------------------------------------------------------------


def test_ips_are_normalised_so_repeat_adds_are_idempotent() -> None:
    rules = RuleManager()
    rules.block_ip("192.168.1.1")
    rules.block_ip("192.168.1.1")
    assert rules.get_blocked_ips() == ["192.168.1.1"]
    assert rules.get_stats().blocked_ips == 1


def test_ip_accepts_an_int_on_the_hot_path() -> None:
    """The packet parser already has a host-order uint32; formatting it to a
    string and re-parsing it per packet was pure waste."""
    rules = RuleManager()
    rules.block_ip("10.1.2.3")
    snapshot = rules.snapshot()
    assert snapshot.is_ip_blocked(0x0A010203)
    assert not snapshot.is_ip_blocked(0x0A010204)


@pytest.mark.parametrize("bad", ["999.1.1.1", "10.0.1", "", "not-an-ip", "-1.0.0.0"])
def test_malformed_ips_raise_a_typed_error(bad: str) -> None:
    rules = RuleManager()
    with pytest.raises(RuleManagerError):
        rules.block_ip(bad)


def test_out_of_range_int_ip_is_rejected() -> None:
    with pytest.raises(RuleManagerError):
        RuleManager().block_ip(1 << 40)


def test_block_reason_for_an_ip_is_the_canonical_dotted_quad() -> None:
    rules = RuleManager()
    rules.block_ip("10.0.0.1")
    reason = rules.should_block(0x0A000001, 443, AppType.HTTPS, "")
    assert reason == BlockReason(BlockReasonType.IP, "10.0.0.1")


# ---------------------------------------------------------------------------
# Port handling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("port", [0, 80, 443, 65535])
def test_valid_ports_are_accepted(port: int) -> None:
    rules = RuleManager()
    rules.block_port(port)
    assert rules.is_port_blocked(port)


@pytest.mark.parametrize("port", [-1, 65536, 99999, "not-a-port", None])
def test_invalid_ports_raise_a_typed_error(port) -> None:
    with pytest.raises(RuleManagerError):
        RuleManager().block_port(port)


# ---------------------------------------------------------------------------
# should_block priority
# ---------------------------------------------------------------------------


def test_priority_order_is_ip_then_port_then_app_then_domain() -> None:
    rules = RuleManager()
    rules.block_ip("10.0.0.1")
    rules.block_port(443)
    rules.block_app(AppType.YOUTUBE)
    rules.block_domain("evil.example")

    reason = rules.should_block(0x0A000001, 443, AppType.YOUTUBE, "evil.example")
    assert reason.type is BlockReasonType.IP

    reason = rules.should_block(0x0B000001, 443, AppType.YOUTUBE, "evil.example")
    assert reason.type is BlockReasonType.PORT

    reason = rules.should_block(0x0B000001, 80, AppType.YOUTUBE, "evil.example")
    assert reason.type is BlockReasonType.APP

    reason = rules.should_block(0x0B000001, 80, AppType.HTTPS, "evil.example")
    assert reason.type is BlockReasonType.DOMAIN

    assert rules.should_block(0x0B000001, 80, AppType.HTTPS, "") is None
    assert rules.should_block(0x0B000001, 80, AppType.HTTPS, "fine.example") is None


def test_empty_domain_never_blocks() -> None:
    rules = RuleManager()
    rules.block_domain("*.example.com")
    assert rules.should_block(0x0A000001, 80, AppType.HTTPS, "") is None


def test_static_rules_is_the_shared_empty_rule_set() -> None:
    """The no-rules case is the common one, and must not allocate a throwaway
    manager per run."""
    assert STATIC_RULES.get_stats().blocked_ips == 0
    assert STATIC_RULES.should_block(0x0A000001, 443, AppType.HTTPS, "x.example") is None


# ---------------------------------------------------------------------------
# Copy-on-write snapshots
# ---------------------------------------------------------------------------


def test_version_increments_only_on_real_changes() -> None:
    rules = RuleManager()
    start = rules.version

    rules.block_ip("10.0.0.1")
    after_add = rules.version
    assert after_add > start

    rules.block_ip("10.0.0.1")  # already present
    assert rules.version == after_add

    rules.unblock_ip("10.0.0.1")
    assert rules.version > after_add

    rules.unblock_ip("10.0.0.1")  # already absent
    assert rules.version == after_add + 1


def test_a_snapshot_never_changes_under_its_holder() -> None:
    """This is the whole point of copy-on-write: a reader holding a snapshot
    must be immune to concurrent writers, with no lock."""
    rules = RuleManager()
    rules.block_app(AppType.YOUTUBE)
    held = rules.snapshot()

    for app in AppType:
        rules.block_app(app)
    rules.clear_all()

    assert held.is_app_blocked(AppType.YOUTUBE)
    assert held.get_stats().blocked_apps == 1
    assert not rules.snapshot().is_app_blocked(AppType.YOUTUBE)


def test_snapshots_are_frozen() -> None:
    rules = RuleManager()
    rules.block_ip("10.0.0.1")
    snapshot = rules.snapshot()
    with pytest.raises(AttributeError):
        snapshot.version = 99  # type: ignore[misc]
    with pytest.raises(AttributeError):
        snapshot.state.ips = frozenset()  # type: ignore[misc]


def test_snapshots_pickle_for_cross_process_transport() -> None:
    """Workers receive rules by pickle, so this must work and must be lossless."""
    rules = RuleManager()
    rules.block_ip("10.0.0.1")
    rules.block_app(AppType.NETFLIX)
    rules.block_domain("*.example.com")
    rules.block_domain("exact.example")
    rules.block_port(8080)

    original = rules.snapshot()
    restored = pickle.loads(pickle.dumps(original))

    assert restored.version == original.version
    assert restored.state == original.state
    assert restored.should_block(0x0A000001, 8080, AppType.NETFLIX, "a.example.com") == (
        BlockReason(BlockReasonType.IP, "10.0.0.1")
    )


def test_concurrent_readers_and_a_writer_never_observe_a_torn_state() -> None:
    """A reader must always see a coherent rule set, never a half-applied
    update. Run under `-X dev` this is also an assertion that the read path
    takes no lock and cannot deadlock against the writer."""
    rules = RuleManager()
    rules.block_ip("10.0.0.1")
    rules.block_port(443)
    baseline = rules.snapshot()

    stop = threading.Event()
    errors: list[BaseException] = []

    def reader() -> None:
        try:
            while not stop.is_set():
                snapshot = rules.snapshot()
                # Coherence: both of the baseline rules, or neither.
                has_ip = snapshot.is_ip_blocked(0x0A000001)
                has_port = snapshot.is_port_blocked(443)
                assert has_ip is has_port, "torn read"
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    try:
        for i in range(200):
            rules.block_port(1000 + i)
            rules.unblock_port(1000 + i)
    finally:
        stop.set()
        for t in threads:
            t.join()

    assert not errors, errors
    assert rules.snapshot().version > baseline.version


# ---------------------------------------------------------------------------
# Bulk deltas
# ---------------------------------------------------------------------------


def test_apply_delta_adds_and_removes_mixed_categories() -> None:
    rules = RuleManager()
    rules.apply_delta(
        {
            "ips": {"10.0.0.1": True, "10.0.0.2": True},
            "apps": {AppType.YOUTUBE: True},
            "domains": {"*.example.com": True},
            "ports": {443: True},
        }
    )
    stats = rules.get_stats()
    assert (stats.blocked_ips, stats.blocked_apps, stats.blocked_domains, stats.blocked_ports) == (
        2,
        1,
        1,
        1,
    )

    rules.apply_delta({"ips": {"10.0.0.1": False}, "ports": {443: False}})
    stats = rules.get_stats()
    assert stats.blocked_ips == 1
    assert stats.blocked_ports == 0


def test_apply_delta_is_all_or_nothing() -> None:
    """A delta containing one bad value must not partially apply."""
    rules = RuleManager()
    with pytest.raises(RuleManagerError):
        rules.apply_delta({"ips": {"10.0.0.1": True, "not-an-ip": True}})
    assert rules.get_stats().blocked_ips == 0


def test_apply_delta_rejects_an_unknown_category() -> None:
    with pytest.raises(RuleManagerError, match="Unknown rule category"):
        RuleManager().apply_delta({"colours": {"red": True}})


def test_apply_delta_rejects_a_non_app_in_the_apps_category() -> None:
    with pytest.raises(RuleManagerError):
        RuleManager().apply_delta({"apps": {"YouTube": True}})


def test_apply_delta_with_no_changes_does_not_bump_the_version() -> None:
    rules = RuleManager()
    rules.block_ip("10.0.0.1")
    version = rules.version
    rules.apply_delta({"ips": {"10.0.0.1": True}})
    assert rules.version == version


def test_empty_delta_is_a_no_op() -> None:
    rules = RuleManager()
    rules.apply_delta({})
    assert rules.get_stats() == rules.get_stats()


# ---------------------------------------------------------------------------
# App name resolution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["YouTube", "youtube", "YOUTUBE", "  youtube  "])
def test_app_names_resolve_case_insensitively(name: str) -> None:
    assert resolve_app_name(name) is AppType.YOUTUBE


def test_unknown_app_name_lists_the_valid_ones() -> None:
    with pytest.raises(RuleManagerError) as exc:
        resolve_app_name("NotARealApp")
    assert "Valid names" in str(exc.value)
    assert "YouTube" in str(exc.value)


def test_block_app_rejects_a_bare_string() -> None:
    """Callers must resolve the name first, so a typo can never be stored as a
    no-op rule."""
    with pytest.raises(RuleManagerError):
        RuleManager().block_app("YouTube")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_round_trip_through_disk(tmp_path) -> None:
    rules = RuleManager()
    rules.block_ip("10.0.0.1")
    rules.block_ip("192.168.1.1")
    rules.block_app(AppType.TIKTOK)
    rules.block_domain("exact.example")
    rules.block_domain("*.wild.example")
    rules.block_port(8080)

    path = tmp_path / "rules.json"
    rules.save_rules(path)

    restored = RuleManager.load_rules(path)
    assert restored.get_blocked_ips() == ["10.0.0.1", "192.168.1.1"]
    assert restored.get_blocked_apps() == [AppType.TIKTOK]
    assert restored.get_blocked_domains() == ["exact.example", "*.wild.example"]
    assert restored.get_blocked_ports() == [8080]


def test_saved_file_is_stable_and_readable_json(tmp_path) -> None:
    rules = RuleManager()
    for ip in ("10.0.0.3", "10.0.0.1", "10.0.0.2"):
        rules.block_ip(ip)
    path = tmp_path / "rules.json"
    rules.save_rules(path)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["blocked_ips"] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_loading_a_missing_file_raises_a_typed_error(tmp_path) -> None:
    with pytest.raises(RuleManagerError, match="Cannot read rules file"):
        RuleManager.load_rules(tmp_path / "nope.json")


def test_loading_malformed_json_raises_a_typed_error(tmp_path) -> None:
    path = tmp_path / "rules.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(RuleManagerError, match="not valid JSON"):
        RuleManager.load_rules(path)


def test_loading_a_non_object_raises_a_typed_error(tmp_path) -> None:
    path = tmp_path / "rules.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(RuleManagerError, match="must contain a JSON object"):
        RuleManager.load_rules(path)


def test_a_bad_value_inside_a_rules_file_names_the_file(tmp_path) -> None:
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"blocked_ips": ["999.1.1.1"]}), encoding="utf-8")
    with pytest.raises(RuleManagerError) as exc:
        RuleManager.load_rules(path)
    assert "rules.json" in str(exc.value)


def test_unknown_app_name_in_a_rules_file_is_rejected(tmp_path) -> None:
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"blocked_apps": ["NotARealApp"]}), encoding="utf-8")
    with pytest.raises(RuleManagerError, match="Unknown app name"):
        RuleManager.load_rules(path)


def test_wildcards_in_the_blocked_domains_key_are_treated_as_patterns(tmp_path) -> None:
    """A hand-written file may reasonably put '*.example.com' in
    blocked_domains rather than domain_patterns; both spellings must work."""
    path = tmp_path / "rules.json"
    path.write_text(
        json.dumps({"blocked_domains": ["*.example.com"], "domain_patterns": ["*.other.example"]}),
        encoding="utf-8",
    )
    rules = RuleManager.load_rules(path)
    assert rules.is_domain_blocked("www.example.com")
    assert rules.is_domain_blocked("www.other.example")


def test_missing_keys_default_to_empty(tmp_path) -> None:
    path = tmp_path / "rules.json"
    path.write_text("{}", encoding="utf-8")
    rules = RuleManager.load_rules(path)
    assert rules.get_stats().blocked_ips == 0


def test_saving_to_an_unwritable_path_raises_a_typed_error(tmp_path) -> None:
    with pytest.raises(RuleManagerError, match="Cannot write rules file"):
        RuleManager().save_rules(tmp_path / "no" / "such" / "dir" / "rules.json")


def test_snapshot_to_dict_is_stable_and_complete() -> None:
    rules = RuleManager()
    rules.block_ip("10.0.0.1")
    rules.block_app(AppType.ZOOM)
    rules.block_domain("a.example")
    rules.block_domain("*.b.example")
    rules.block_port(53)

    payload = RuleSnapshot(version=rules.version, state=rules.snapshot().state).to_dict()
    assert payload["blocked_ips"] == ["10.0.0.1"]
    # "Stable" is the point of `D-16`: the key has to be `AppType.name`, an
    # identifier, not "Zoom" -- a display string that changes whenever the
    # product is reworded, which would silently invalidate this document.
    assert payload["blocked_apps"] == ["ZOOM"]
    assert payload["blocked_domains"] == ["a.example"]
    assert payload["domain_patterns"] == ["*.b.example"]
    assert payload["blocked_ports"] == [53]
    json.dumps(payload)  # must be serialisable
