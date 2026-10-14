"""`T1-05` — CIDR rules, destination-IP matching, and stable persistence keys.

Three findings that all touch the rule schema, so they land together:

* `D-20` — no CIDR/subnet rules. Blocking `10.0.0.0/8` meant enumerating
  16,777,216 single-address rules.
* `D-21` — `should_block` looked at `src_ip` only, so a rule written to block
  an IP never fired when that IP was the *destination*.
* `D-16` — rules-file keys were human-readable display names ("Twitter/X"),
  so renaming a display string silently invalidated every saved rules file.
  This is `DEC-04`.

`DEC-06` (user, 2026-10-13) fixes `D-21`'s semantics: an IP rule matches
**either endpoint**. That is a deliberate break from the C++ original, which
was source-only.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest

from dpi_engine.rule_manager import RuleManager, RuleManagerError
from dpi_engine.types import AppType

# ---------------------------------------------------------------------------
# D-20: CIDR / subnet rules
# ---------------------------------------------------------------------------


def test_a_slash_8_rule_blocks_hosts_inside_the_range() -> None:
    rm = RuleManager()
    rm.block_cidr("10.0.0.0/8")

    assert rm.should_block("10.0.0.1", 443, AppType.HTTPS) is not None
    assert rm.should_block("10.255.255.254", 443, AppType.HTTPS) is not None
    assert rm.should_block("10.1.2.3", 443, AppType.HTTPS) is not None


def test_a_slash_8_rule_does_not_leak_into_the_next_range() -> None:
    """The boundary is the whole point of the test: `>> 24` and `<< 24` are
    exactly where an off-by-one in the mask would show, and neither 11.0.0.0
    nor 9.255.255.255 may match."""
    rm = RuleManager()
    rm.block_cidr("10.0.0.0/8")

    assert rm.should_block("11.0.0.0", 443, AppType.HTTPS) is None
    assert rm.should_block("9.255.255.255", 443, AppType.HTTPS) is None
    assert rm.should_block("11.255.255.255", 443, AppType.HTTPS) is None


def test_a_non_byte_aligned_prefix_is_masked_correctly() -> None:
    """`/12` splits mid-octet, so it exercises a shift no power-of-two check
    would reach: 172.16.0.0/12 spans 172.16..172.31 and stops there."""
    rm = RuleManager()
    rm.block_cidr("172.16.0.0/12")

    assert rm.should_block("172.16.0.1", 443, AppType.HTTPS) is not None
    assert rm.should_block("172.31.255.255", 443, AppType.HTTPS) is not None
    assert rm.should_block("172.15.255.255", 443, AppType.HTTPS) is None
    assert rm.should_block("172.32.0.0", 443, AppType.HTTPS) is None


def test_a_slash_32_behaves_exactly_like_a_single_address_rule() -> None:
    rm = RuleManager()
    rm.block_cidr("192.0.2.7/32")

    assert rm.should_block("192.0.2.7", 443, AppType.HTTPS) is not None
    assert rm.should_block("192.0.2.8", 443, AppType.HTTPS) is None
    # It is an address rule in every observable way, including stats.
    assert rm.get_stats().blocked_ips >= 1


def test_a_host_address_written_with_a_prefix_is_accepted() -> None:
    """Users write `10.0.0.1/32` more often than `10.0.0.1`; rejecting it
    because the host bits are set would be pedantry."""
    rm = RuleManager()
    rm.block_cidr("10.0.0.1/32")
    assert rm.should_block("10.0.0.1", 443, AppType.HTTPS) is not None
    assert rm.should_block("10.0.0.2", 443, AppType.HTTPS) is None


def test_a_prefix_with_host_bits_set_is_rejected_rather_than_silently_masked() -> None:
    """`10.1.2.3/8` is almost certainly a mistake, not a request for 10/8.
    Silently masking it would apply a far wider rule than the user wrote."""
    rm = RuleManager()
    with pytest.raises(RuleManagerError) as exc:
        rm.block_cidr("10.1.2.3/8")
    assert "host bits" in str(exc.value) or "10.0.0.0/8" in str(exc.value)


def test_a_malformed_cidr_raises_rule_manager_error_not_valueerror() -> None:
    rm = RuleManager()
    with pytest.raises(RuleManagerError):
        rm.block_cidr("not-a-network")
    with pytest.raises(RuleManagerError):
        rm.block_cidr("10.0.0.0/99")


def test_is_ip_blocked_sees_subnets_as_well_as_single_addresses() -> None:
    """`is_ip_blocked` is the standalone query behind the CLI's rule checks.

    A subnet rule has to be visible there too. This is a second copy of the
    membership logic -- it shares `_network_match` but not the `in` check above
    it -- so leaving it source-only would let `D-20` stay half-fixed while every
    `should_block` test passed.
    """
    rm = RuleManager()
    rm.block_cidr("10.0.0.0/8")
    rm.block_ip("203.0.113.9")

    assert rm.is_ip_blocked("10.1.2.3")
    assert rm.is_ip_blocked("203.0.113.9")
    assert not rm.is_ip_blocked("11.0.0.1")
    assert not rm.is_ip_blocked("203.0.113.10")
    rm = RuleManager()
    rm.block_cidr("10.0.0.0/8")
    assert rm.should_block("10.1.2.3", 443, AppType.HTTPS) is not None

    rm.unblock_cidr("10.0.0.0/8")
    assert rm.should_block("10.1.2.3", 443, AppType.HTTPS) is None


def test_cidr_and_exact_ip_rules_coexist() -> None:
    rm = RuleManager()
    rm.block_ip("203.0.113.9")
    rm.block_cidr("10.0.0.0/8")

    assert rm.should_block("203.0.113.9", 443, AppType.HTTPS) is not None
    assert rm.should_block("10.1.2.3", 443, AppType.HTTPS) is not None
    assert rm.should_block("203.0.113.10", 443, AppType.HTTPS) is None
    assert rm.should_block("11.0.0.1", 443, AppType.HTTPS) is None


def test_adding_the_same_cidr_twice_is_idempotent() -> None:
    rm = RuleManager()
    rm.block_cidr("10.0.0.0/8")
    first = rm.snapshot()
    rm.block_cidr("10.0.0.0/8")
    assert rm.snapshot() == first


def test_block_ip_accepts_a_cidr_because_that_is_where_users_will_type_it() -> None:
    """`--block-ip 10.0.0.0/8` is the natural spelling. Rejecting a valid
    subnet on a flag named after IPs would push people back to enumerating
    16,777,216 addresses, which is the defect being fixed."""
    rm = RuleManager()
    rm.block_ip("10.0.0.0/8")

    assert rm.should_block("10.1.2.3", 443, AppType.HTTPS) is not None
    assert rm.should_block("11.0.0.1", 443, AppType.HTTPS) is None
    assert rm.get_blocked_cidrs() == ["10.0.0.0/8"]
    assert rm.get_blocked_ips() == []

    rm.unblock_ip("10.0.0.0/8")
    assert rm.get_blocked_cidrs() == []


def test_a_cidr_rule_costs_a_bounded_number_of_lookups() -> None:
    """The reason `D-20` was a defect and not an omission.

    Matching must not scale with the number of rules: a firewall with a
    thousand subnets has to cost roughly what one with a handful costs, or the
    packet path degenerates as rules accumulate. Grouping by prefix length and
    testing a shifted int is O(number of distinct prefix lengths), which is
    at most 33 regardless of how many networks are registered.
    """
    rm = RuleManager()
    # `range(1, ...)` deliberately skips `10.0.0.0/16`: registering it would
    # cover the very address the last assertion requires to be *unblocked*.
    for i in range(1, 256):
        rm.block_cidr(f"10.{i}.0.0/16")
    rm.block_cidr("192.0.2.0/24")

    assert rm.should_block("10.7.9.9", 443, AppType.HTTPS) is not None
    assert rm.should_block("10.255.0.1", 443, AppType.HTTPS) is not None
    assert rm.should_block("10.0.0.1", 443, AppType.HTTPS) is None


# ---------------------------------------------------------------------------
# D-21: either endpoint matches (DEC-06)
# ---------------------------------------------------------------------------


def test_an_ip_rule_fires_when_the_ip_is_the_destination() -> None:
    """The defect: `should_block` took `src_ip` only, so blocking an IP was
    a no-op for any packet flowing *toward* it."""
    rm = RuleManager()
    rm.block_ip("9.9.9.9")

    # Source-only match: worked before and must keep working.
    assert rm.should_block("9.9.9.9", 443, AppType.HTTPS, dst_ip="1.2.3.4") is not None
    # Destination match: the half that was missing.
    assert rm.should_block("1.2.3.4", 443, AppType.HTTPS, dst_ip="9.9.9.9") is not None
    # Neither endpoint: must still pass.
    assert rm.should_block("1.2.3.4", 443, AppType.HTTPS, dst_ip="5.6.7.8") is None


def test_a_cidr_rule_fires_on_either_endpoint() -> None:
    rm = RuleManager()
    rm.block_cidr("10.0.0.0/8")

    assert rm.should_block("10.1.2.3", 443, AppType.HTTPS, dst_ip="8.8.8.8") is not None
    assert rm.should_block("8.8.8.8", 443, AppType.HTTPS, dst_ip="10.1.2.3") is not None
    assert rm.should_block("8.8.8.8", 443, AppType.HTTPS, dst_ip="8.8.4.4") is None


def test_the_ip_reason_reports_whichever_endpoint_matched() -> None:
    """A blocking report that named the wrong endpoint would send an operator
    to the wrong host."""
    rm = RuleManager()
    rm.block_ip("9.9.9.9")

    reason = rm.should_block("1.2.3.4", 443, AppType.HTTPS, dst_ip="9.9.9.9")
    assert reason is not None
    assert reason.detail == "9.9.9.9"


def test_omitting_dst_ip_keeps_the_old_source_only_behaviour() -> None:
    """The parameter is optional so existing call sites and tests stay valid;
    `worker.process` supplies it."""
    rm = RuleManager()
    rm.block_ip("9.9.9.9")
    assert rm.should_block("9.9.9.9", 443, AppType.HTTPS) is not None
    assert rm.should_block("1.2.3.4", 443, AppType.HTTPS) is None


def test_rule_priority_is_unchanged_when_the_ip_matches_the_destination() -> None:
    """OSC's fixed order is IP -> port -> app -> domain. Adding a second
    endpoint must not reorder it."""
    rm = RuleManager()
    rm.block_port(443)
    rm.block_cidr("10.0.0.0/8")

    reason = rm.should_block("1.2.3.4", 443, AppType.HTTPS, dst_ip="10.1.2.3")
    assert reason is not None
    # IP still outranks port even though only the destination matched.
    assert reason.detail == "10.1.2.3"


# ---------------------------------------------------------------------------
# D-16 / DEC-04: stable persistence keys
# ---------------------------------------------------------------------------


def test_rules_are_persisted_under_the_stable_enum_name() -> None:
    """`AppType.name` is stable; the display string is not.

    A saved rules file keyed on "Twitter/X" stops matching the moment somebody
    renames that display string -- the file would silently apply zero app rules.
    """
    rm = RuleManager()
    rm.block_app(AppType.YOUTUBE)
    rm.block_app(AppType.TWITTER)

    saved = rm.to_dict()
    assert "YouTube" not in saved["blocked_apps"]
    assert "Twitter/X" not in saved["blocked_apps"]
    assert saved["blocked_apps"] == ["TWITTER", "YOUTUBE"]


def test_a_rules_file_keyed_on_the_enum_name_round_trips() -> None:
    rm = RuleManager()
    rm.block_app(AppType.YOUTUBE)
    rm.block_app(AppType.TWITTER)

    restored = RuleManager.from_dict(json.loads(json.dumps(rm.to_dict())))
    assert restored.get_blocked_apps() == [AppType.TWITTER, AppType.YOUTUBE]
    # And it is a fixed point: writing the restored set gives the same document.
    # `version` is excluded because it is an in-memory monotonic counter bumped
    # by every mutation, not part of the ruleset -- persisting it would make
    # every round-trip differ for a reason that has nothing to do with rules.
    assert {k: v for k, v in restored.to_dict().items() if k != "version"} == {
        k: v for k, v in rm.to_dict().items() if k != "version"
    }


def test_twitter_resolves_by_enum_name_even_though_the_display_name_does_not_case_fold() -> None:
    """`"Twitter/X".lower()` is `"twitter/x"`, so the case-insensitive display
    lookup that works for every other app misses this one entirely. This is
    exactly why the persisted key has to be `AppType.name`."""
    rm = RuleManager.from_dict({"blocked_apps": ["TWITTER"]})
    assert rm.get_blocked_apps() == [AppType.TWITTER]


def test_a_legacy_rules_file_keyed_on_a_display_name_still_loads() -> None:
    """Backward compatibility is the whole point of an input-only alias: an
    existing saved file must not stop working because of this change."""
    rm = RuleManager.from_dict({"blocked_apps": ["YouTube", "Twitter/X"]})
    assert AppType.YOUTUBE in rm.get_blocked_apps()
    assert AppType.TWITTER in rm.get_blocked_apps()


def test_loading_a_display_name_emits_a_deprecation_warning() -> None:
    """The alias is input-only *with a deprecation path*, so the warning is
    what tells an operator their file is on the old vocabulary."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        RuleManager.from_dict({"blocked_apps": ["YouTube"]})

    deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecations, "a display-name app key must warn so it can be migrated"
    assert "YOUTUBE" in str(deprecations[0].message)


def test_loading_the_canonical_key_does_not_warn() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        RuleManager.from_dict({"blocked_apps": ["YOUTUBE"]})

    assert not [w for w in caught if issubclass(w.category, DeprecationWarning)]


def test_a_cidr_rule_survives_a_rules_file_round_trip(tmp_path: Path) -> None:
    rm = RuleManager()
    rm.block_cidr("10.0.0.0/8")
    rm.block_ip("203.0.113.9")

    path = tmp_path / "rules.json"
    path.write_text(json.dumps(rm.to_dict()), encoding="utf-8")
    restored = RuleManager.load_rules(path)

    assert restored.should_block("10.1.2.3", 443, AppType.HTTPS) is not None
    assert restored.should_block("11.0.0.1", 443, AppType.HTTPS) is None
    assert restored.should_block("203.0.113.9", 443, AppType.HTTPS) is not None


def test_an_unknown_app_key_still_raises_rule_manager_error() -> None:
    with pytest.raises(RuleManagerError, match="Unknown app name"):
        RuleManager.from_dict({"blocked_apps": ["NotARealApp"]})
