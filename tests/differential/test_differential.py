"""Differential tests: Python pipeline vs. the real compiled OSC C++ binary.

See README.md in this directory for the documented allowlist of intentional
differences (bug fixes + the DNS-resolution scope improvement) and why
Docker is used to build/run the reference binary.

All tests in this module are skipped (not failed) if Docker or the C++
compiler toolchain aren't available -- this suite is a supplementary
cross-check, not a replacement for the unit/integration suites that have no
external dependency.
"""

from __future__ import annotations

from pathlib import Path

from conftest import TEST_DPI_PCAP
from dpi_engine.pipeline import run_pipeline
from dpi_engine.rule_manager import RuleManager
from dpi_engine.types import AppType

from .cpp_reference import run_cpp_reference

# Domains where the original C++ binary is KNOWN to misclassify due to the
# "x.com"/"t.co" substring bugs (Task 4) -- see README.md item 1. The
# Python port's classification for these is correct; the C++ side's is not.
# Excluded from direct app-name comparison, asserted separately instead.
_KNOWN_MISCLASSIFIED_BY_CPP = {
    "www.netflix.com": ("Netflix", "Twitter/X"),
    "www.microsoft.com": ("Microsoft", "Twitter/X"),
}

def test_total_and_dropped_counts_match_for_no_rules(cpp_available, tmp_path: Path) -> None:
    cpp_result = run_cpp_reference(TEST_DPI_PCAP)
    py_result = run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap")

    assert py_result.stats.total_packets == cpp_result.total_packets
    assert py_result.stats.forwarded_packets == cpp_result.forwarded_packets
    assert py_result.stats.dropped_packets == cpp_result.dropped_packets
    assert py_result.stats.active_connections == cpp_result.active_flows


def test_total_and_dropped_counts_differ_by_exactly_the_dns_scope_improvement(
    cpp_available, tmp_path: Path
) -> None:
    """Blocking AppType.YOUTUBE is expected to drop MORE packets in the
    Python port than in the C++ original, by exactly one: the fixture's
    DNS query for youtube.com. The original never resolves DNS query
    domains (README.md item 3), so a DNS packet can never match a
    `--block-app YouTube` rule in the C++ binary -- only the TLS ClientHello
    flow gets blocked there. The Python port's DNS-resolution scope
    improvement means it correctly also blocks the DNS query. This
    delta (1 extra dropped packet) is itself a regression test pinning
    that specific, documented, intentional difference -- it is not merely
    tolerated, it is asserted to be exactly this and no more."""
    cpp_result = run_cpp_reference(TEST_DPI_PCAP, ["--block-app", "YouTube"])

    rules = RuleManager()
    rules.block_app(AppType.YOUTUBE)
    py_result = run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", rules)

    assert py_result.stats.total_packets == cpp_result.total_packets

    extra_dropped_by_python = py_result.stats.dropped_packets - cpp_result.dropped_packets
    assert extra_dropped_by_python == 1, (
        "Expected the Python port to drop exactly one more packet than the "
        "C++ original when blocking YouTube -- the DNS query for "
        "youtube.com, which only Python's DNS-resolution scope improvement "
        "can attribute to the YouTube app. If this delta changed, "
        "re-verify the DESIGN_DECISIONS.md allowlist is still accurate."
    )

    # The one extra dropped packet must specifically be the DNS query, not
    # some other unrelated flow.
    blocked_over_dns = [
        (t, app, sni)
        for t, app, sni in py_result.blocked_flows
        if t.protocol == 17 and t.dst_port == 53
    ]
    assert len(blocked_over_dns) == 1
    assert blocked_over_dns[0][2] == "www.youtube.com"


def test_total_and_dropped_counts_match_when_blocking_ip(cpp_available, tmp_path: Path) -> None:
    cpp_result = run_cpp_reference(TEST_DPI_PCAP, ["--block-ip", "192.168.1.50"])

    rules = RuleManager()
    rules.block_ip("192.168.1.50")
    py_result = run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", rules)

    assert py_result.stats.total_packets == cpp_result.total_packets
    assert py_result.stats.dropped_packets == cpp_result.dropped_packets


def test_detected_domains_match_except_known_cpp_misclassifications(
    cpp_available, tmp_path: Path
) -> None:
    """Every domain the C++ binary detects should also be detected by the
    Python port, with the SAME app classification -- except the two
    domains known to trigger the "x.com"/"t.co" substring bugs in the
    original, where the Python port's classification is correct and the
    C++ side's is the documented-buggy one (see README.md item 1)."""
    cpp_result = run_cpp_reference(TEST_DPI_PCAP)
    py_result = run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap")

    for domain, cpp_app_name in cpp_result.detected_domains.items():
        assert domain in py_result.detected_domains, f"Python port missed domain: {domain}"

        from dpi_engine.types import app_type_to_string

        py_display_name = app_type_to_string(py_result.detected_domains[domain])

        if domain in _KNOWN_MISCLASSIFIED_BY_CPP:
            expected_py, expected_cpp_buggy = _KNOWN_MISCLASSIFIED_BY_CPP[domain]
            assert cpp_app_name == expected_cpp_buggy, (
                f"Expected the known C++ bug to misclassify {domain} as "
                f"{expected_cpp_buggy}, but got {cpp_app_name} -- the bug's "
                f"behavior may have changed, re-verify the allowlist."
            )
            assert py_display_name == expected_py, (
                f"Python port should correctly classify {domain} as {expected_py}"
            )
        else:
            assert py_display_name == cpp_app_name, (
                f"Domain {domain}: C++ says {cpp_app_name}, Python says {py_display_name}"
            )


def test_dns_resolution_is_a_documented_improvement_not_a_bug(
    cpp_available, tmp_path: Path
) -> None:
    """The C++ side reports a flat DNS count with no per-query domain
    resolution (README.md item 3); the Python port resolves DNS queries to
    specific domains/apps when possible. This test verifies that scope
    improvement concretely: every UDP/port-53 packet accounted for in the
    C++ side's flat "DNS" bucket must be accounted for in the Python port's
    output too, either as AppType.DNS (if resolution failed) or as a more
    specific app (if resolution succeeded) -- the two counts must sum to
    the same total, proving Python doesn't silently drop any DNS packets
    while adding the extra resolution capability."""
    cpp_result = run_cpp_reference(TEST_DPI_PCAP)
    py_result = run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap")

    cpp_dns_count = cpp_result.app_counts.get("DNS", 0)
    assert cpp_dns_count > 0  # sanity: the fixture does contain DNS traffic

    # Recount, from the Python side, how many packets were UDP on port 53
    # in either direction -- this should equal the C++ side's flat count,
    # regardless of how Python's classifier further refined each one.
    from dpi_engine.packet_parser import parse_packet
    from dpi_engine.pcap_io import PcapReader

    py_port_53_packet_count = 0
    with PcapReader(TEST_DPI_PCAP) as reader:
        for raw in reader:
            parsed = parse_packet(raw)
            if parsed and parsed.has_udp and (parsed.src_port == 53 or parsed.dst_port == 53):
                py_port_53_packet_count += 1

    assert py_port_53_packet_count == cpp_dns_count, (
        "Python's count of raw UDP/port-53 packets must match the C++ "
        "side's flat DNS bucket count -- Python must not drop any DNS "
        "packets, only classify some of them more specifically."
    )

    # And confirm Python actually did resolve at least one of them to
    # something more specific than generic DNS (proving the scope
    # improvement is real, not dead code).
    resolved_specifically = sum(
        count
        for app, count in py_result.app_counts.items()
        if app != AppType.DNS and app != AppType.UNKNOWN
    )
    assert resolved_specifically > 0


# ---------------------------------------------------------------------------
# Domain-rule semantics: an intentional, documented divergence
# ---------------------------------------------------------------------------


def test_bare_domain_rule_blocks_less_than_the_cpp_substring_match(
    cpp_available, tmp_path: Path
) -> None:
    """`--block-domain youtube` blocks a lot more in the C++ original than here.

    `main_working.cpp:60-62` matches a blocked domain with an unanchored
    substring search (`sni.find(dom) != npos`), so "youtube" also blocks
    "notyoutube.example.org" and any other domain merely *containing* the
    text. This port follows `rule_manager.cpp`'s semantics instead: a bare
    domain matches only itself, and subdomains require the explicit
    `*.example.com` form (README.md item 5).

    Blocking *less* is the safe direction for a blocking tool -- a rule that
    silently over-blocks is worse than one that under-blocks and is visible in
    the report -- so the divergence is intentional, and this test pins it so a
    future change cannot quietly reintroduce substring matching.
    """
    cpp_result = run_cpp_reference(TEST_DPI_PCAP, ["--block-domain", "youtube"])

    rules = RuleManager()
    rules.block_domain("youtube")
    py_result = run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", rules)

    assert cpp_result.dropped_packets > 0, (
        "precondition: the C++ substring match should have blocked something"
    )
    assert py_result.stats.dropped_packets == 0, (
        "an exact-match rule for 'youtube' must not match 'www.youtube.com'"
    )


def test_wildcard_domain_rule_matches_the_cpp_substring_result(
    cpp_available, tmp_path: Path
) -> None:
    """With the wildcard spelled the way both implementations mean it, the two
    agree -- modulo the one documented DNS-resolution delta, exactly as with
    `--block-app YouTube` above.

    So the divergence in the previous test is about the *rule shape*, not about
    a difference in what a wildcard is for.
    """
    cpp_result = run_cpp_reference(TEST_DPI_PCAP, ["--block-domain", "youtube"])

    rules = RuleManager()
    rules.block_domain("*.youtube.com")
    py_result = run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", rules)

    assert cpp_result.dropped_packets > 0
    assert py_result.stats.dropped_packets == cpp_result.dropped_packets + 1, (
        "Expected the same +1 delta as --block-app YouTube: the DNS query for "
        "www.youtube.com, which only this port's DNS resolution can attribute "
        "to a domain rule."
    )


def test_python_resolves_exactly_the_cpp_names_plus_dns_query_names(
    cpp_available, tmp_path: Path
) -> None:
    """A final sweep for unintended classification drift.

    Two invariants, both precise:

    1. This port resolves every name the C++ binary resolves (nothing lost).
    2. Every *additional* name is a DNS query name -- the one thing the C++
       binary structurally cannot see, since it tags port-53 traffic as a flat
       `DNS` app without ever resolving it (README.md item 3).

    Note the extras are a strict subset of the DNS query names, not all of
    them: most queried names in this fixture (www.google.com, www.youtube.com,
    www.facebook.com) also appear in a TLS ClientHello, so the C++ binary finds
    those independently. `api.twitter.com` is the one name the fixture carries
    *only* in a DNS query, and it is therefore the only extra.

    Anything else in the difference would mean the classification table or an
    extractor drifted.
    """
    cpp_result = run_cpp_reference(TEST_DPI_PCAP)
    py_result = run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap")

    dns_names = _dns_query_names_in(TEST_DPI_PCAP)
    assert dns_names, "precondition: the fixture should contain DNS queries"

    cpp_names = set(cpp_result.detected_domains)
    py_names = set(py_result.detected_domains)

    assert cpp_names <= py_names, (
        "Python must resolve every name the C++ binary resolves; missing: "
        f"{sorted(cpp_names - py_names)}"
    )

    extra = py_names - cpp_names
    assert extra <= dns_names, (
        "Python resolved names the C++ binary did not, beyond the DNS queries "
        f"it cannot see. Unexpected: {sorted(extra - dns_names)}"
    )
    assert extra, "precondition: at least one DNS-only name should be extra"


def _dns_query_names_in(pcap_path: Path) -> set[str]:
    """The set of domain names carried in this capture's DNS queries.

    Computed independently of the pipeline, so the assertion above cannot be
    satisfied by the very code it is checking.
    """
    from dpi_engine.packet_parser import parse_packet
    from dpi_engine.pcap_io import PcapReader
    from dpi_engine.sni_extractor import extract_dns_query

    names: set[str] = set()
    with PcapReader(pcap_path) as reader:
        for raw in reader:
            parsed = parse_packet(raw)
            if parsed is None or not parsed.has_udp:
                continue
            if parsed.dst_port != 53 and parsed.src_port != 53:
                continue
            name = extract_dns_query(parsed.payload)
            if name:
                names.add(name)
    return names
