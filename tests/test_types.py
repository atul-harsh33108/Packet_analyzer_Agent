"""Tests for dpi_engine.types.

Covers: FiveTuple hashability/reversal/string formatting, AppType display
names, and sni_to_app_type's classification table (including the priority
order preserved from the original and the intentional "cf-" false-positive
fix).
"""

from __future__ import annotations

from dpi_engine.types import (
    AppType,
    Connection,
    ConnectionState,
    DPIStats,
    FiveTuple,
    PacketAction,
    app_type_to_string,
    sni_to_app_type,
)


# --- FiveTuple ----------------------------------------------------------------------


def test_five_tuple_is_hashable_and_usable_as_dict_key() -> None:
    t1 = FiveTuple(src_ip=1, dst_ip=2, src_port=100, dst_port=443, protocol=6)
    t2 = FiveTuple(src_ip=1, dst_ip=2, src_port=100, dst_port=443, protocol=6)
    table: dict[FiveTuple, str] = {}
    table[t1] = "flow-a"
    assert table[t2] == "flow-a"  # equal tuples hash/compare equal


def test_five_tuple_reverse_swaps_src_and_dst() -> None:
    t = FiveTuple(src_ip=1, dst_ip=2, src_port=100, dst_port=443, protocol=6)
    r = t.reverse()
    assert r == FiveTuple(src_ip=2, dst_ip=1, src_port=443, dst_port=100, protocol=6)
    assert r.reverse() == t


def test_five_tuple_str_formats_ip_dotted_quad_and_protocol_name() -> None:
    # 192.168.1.100 as a big-endian-interpreted uint32.
    ip = (192 << 24) | (168 << 16) | (1 << 8) | 100
    t = FiveTuple(src_ip=ip, dst_ip=0, src_port=1234, dst_port=443, protocol=6)
    s = str(t)
    assert "192.168.1.100:1234" in s
    assert "(TCP)" in s


def test_five_tuple_str_udp_and_unknown_protocol() -> None:
    t_udp = FiveTuple(src_ip=0, dst_ip=0, src_port=1, dst_port=2, protocol=17)
    assert "(UDP)" in str(t_udp)
    t_other = FiveTuple(src_ip=0, dst_ip=0, src_port=1, dst_port=2, protocol=1)
    assert "(?)" in str(t_other)


# --- AppType --------------------------------------------------------------------


def test_app_type_to_string_known_and_default() -> None:
    assert app_type_to_string(AppType.YOUTUBE) == "YouTube"
    assert app_type_to_string(AppType.CLOUDFLARE) == "Cloudflare"
    assert app_type_to_string(AppType.UNKNOWN) == "Unknown"


# --- sni_to_app_type --------------------------------------------------------------


def test_empty_sni_is_unknown() -> None:
    assert sni_to_app_type("") == AppType.UNKNOWN


def test_unrecognized_sni_falls_back_to_https() -> None:
    assert sni_to_app_type("some-random-service.example.net") == AppType.HTTPS


def test_known_sni_patterns_map_to_expected_app_type() -> None:
    cases = {
        "www.google.com": AppType.GOOGLE,
        "fonts.gstatic.com": AppType.GOOGLE,
        "www.youtube.com": AppType.YOUTUBE,
        "i.ytimg.com": AppType.YOUTUBE,
        "www.facebook.com": AppType.FACEBOOK,
        "static.fbcdn.net": AppType.FACEBOOK,
        "www.instagram.com": AppType.INSTAGRAM,
        "web.whatsapp.com": AppType.WHATSAPP,
        "twitter.com": AppType.TWITTER,
        "x.com": AppType.TWITTER,
        "www.netflix.com": AppType.NETFLIX,
        "www.amazon.com": AppType.AMAZON,
        "s3.amazonaws.com": AppType.AMAZON,
        "www.microsoft.com": AppType.MICROSOFT,
        "outlook.office.com": AppType.MICROSOFT,
        "www.apple.com": AppType.APPLE,
        "www.icloud.com": AppType.APPLE,
        "web.telegram.org": AppType.TELEGRAM,
        "t.me": AppType.TELEGRAM,
        "www.tiktok.com": AppType.TIKTOK,
        "open.spotify.com": AppType.SPOTIFY,
        "zoom.us": AppType.ZOOM,
        "discord.com": AppType.DISCORD,
        "discordapp.com": AppType.DISCORD,
        "github.com": AppType.GITHUB,
        "raw.githubusercontent.com": AppType.GITHUB,
        "www.cloudflare.com": AppType.CLOUDFLARE,
    }
    for sni, expected in cases.items():
        assert sni_to_app_type(sni) == expected, f"{sni} -> expected {expected}"


def test_matching_is_case_insensitive() -> None:
    assert sni_to_app_type("WWW.YOUTUBE.COM") == AppType.YOUTUBE
    assert sni_to_app_type("Www.Facebook.Com") == AppType.FACEBOOK


def test_google_pattern_does_not_shadow_youtube_priority_order() -> None:
    """The original checks Google's patterns before YouTube's. Since none of
    Google's patterns are substrings of youtube.com/ytimg.com, YouTube must
    still classify correctly -- this pins the priority-order behavior."""
    assert sni_to_app_type("www.youtube.com") == AppType.YOUTUBE
    assert sni_to_app_type("i9.ytimg.com") == AppType.YOUTUBE


def test_cf_dash_false_positive_is_fixed() -> None:
    """Regression test for the intentional fix: the original's bare 'cf-'
    Cloudflare pattern would false-positive on any domain merely containing
    that substring. This port must NOT misclassify such a domain as
    Cloudflare -- it should fall through to the generic HTTPS fallback."""
    assert sni_to_app_type("cf-anything.example.com") != AppType.CLOUDFLARE
    assert sni_to_app_type("cf-anything.example.com") == AppType.HTTPS
    # But the legitimate pattern still works.
    assert sni_to_app_type("www.cloudflare.com") == AppType.CLOUDFLARE


def test_x_dot_com_false_positive_is_fixed() -> None:
    """Regression test for a bug found during porting (same class as 'cf-'):
    the original's bare 'x.com' Twitter/X pattern false-positives on any
    domain merely ending in those four characters, e.g. netflix.com. This
    port must classify netflix.com as Netflix, not Twitter, while still
    correctly detecting the real x.com."""
    assert sni_to_app_type("www.netflix.com") == AppType.NETFLIX
    assert sni_to_app_type("x.com") == AppType.TWITTER
    assert sni_to_app_type("api.x.com") == AppType.TWITTER
    assert sni_to_app_type("xerox.com") != AppType.TWITTER
    assert sni_to_app_type("fedex.com") != AppType.TWITTER


def test_t_dot_co_false_positive_is_fixed() -> None:
    """Regression test for a second bug found during porting: the original's
    bare 't.co' Twitter/X pattern is a substring of almost any ".com" domain
    whose preceding character is 't' (e.g. "microsoft.com" contains
    "t.co" as of "microsof-t.com"). This port must classify microsoft.com as
    Microsoft, not Twitter, while still correctly detecting the real t.co."""
    assert sni_to_app_type("www.microsoft.com") == AppType.MICROSOFT
    assert sni_to_app_type("t.co") == AppType.TWITTER
    assert sni_to_app_type("share.t.co") == AppType.TWITTER
    assert sni_to_app_type("wechat.com") != AppType.TWITTER


# --- Connection / DPIStats --------------------------------------------------------


def test_connection_defaults() -> None:
    t = FiveTuple(src_ip=1, dst_ip=2, src_port=1, dst_port=2, protocol=6)
    conn = Connection(tuple=t)
    assert conn.state == ConnectionState.NEW
    assert conn.app_type == AppType.UNKNOWN
    assert conn.action == PacketAction.FORWARD
    assert conn.sni == ""
    assert conn.packets_in == 0


def test_dpi_stats_combine_sums_counters() -> None:
    a = DPIStats(total_packets=10, total_bytes=100, forwarded_packets=8, dropped_packets=2)
    b = DPIStats(total_packets=5, total_bytes=50, forwarded_packets=5, dropped_packets=0)

    combined = a.combine(b)

    assert combined.total_packets == 15
    assert combined.total_bytes == 150
    assert combined.forwarded_packets == 13
    assert combined.dropped_packets == 2
    # Original instances are untouched (combine returns a new instance).
    assert a.total_packets == 10
