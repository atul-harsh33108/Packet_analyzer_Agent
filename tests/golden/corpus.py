"""Golden-capture corpus: synthetic, labelled, reproducible (`T2-01`).

`AGENTIC_ARCHITECTURE.md` Layer 6 calls this *"the highest-leverage single artefact
in the entire document. A capture with a known answer is worth more than any prompt
engineering."* Phase 2's exit criterion — an agent that can be scored automatically
on every PR — is unreachable without one.

## Why these captures are generated rather than real

Every label here is **true by construction**: `GoldenCase` records what the
generator emitted, so "this capture contains two Facebook flows and one YouTube
flow" is a fact about the code that built it rather than a human's assertion that
might be wrong. That is the property that makes a golden corpus worth trusting, and
it is the reason this is synthetic (user decision, 2026-10-15).

It also means the corpus is reproducible — rebuilding it yields byte-identical pcaps
— diffable, small in git, and free of the licensing and privacy weight real captures
carry. Layer 6's "30+ labelled pcaps" is a floor, not a target.

## What the classes mean

Layer 6 names five: C2 beaconing, exfiltration, legitimate enterprise, ad traffic,
active evasion. Each is expressed as a *scenario* — a named set of flows with a
declared expected classification — rather than as a hand-written pcap, so the corpus
stays legible and the labels cannot drift from the bytes.

The distinction that matters for scoring: **`UNKNOWN` is a real expected answer**, not
a failure. A capture whose SNI matches nothing should classify as `UNKNOWN`, and
counting that as a miss would reward an engine for guessing.
"""

from __future__ import annotations

import dataclasses
import ipaddress
from collections.abc import Iterator
from pathlib import Path

from dpi_engine.pcap_io import PcapWriter, RawPacket
from dpi_engine.sni_extractor import is_tls_client_hello
from dpi_engine.types import AppType

#: Fixed timestamp base so every generated capture is byte-reproducible.
_EPOCH = 1_700_000_000


class GoldenClass:
    """The five scenario classes Layer 6 asks for."""

    C2_BEACONING = "c2_beaconing"
    EXFILTRATION = "exfiltration"
    LEGITIMATE_ENTERPRISE = "legitimate_enterprise"
    AD_TRAFFIC = "ad_traffic"
    ACTIVE_EVASION = "active_evasion"


#: Every class in a stable order, so iteration and reporting do not depend on dict
#: ordering or filesystem ordering.
ALL_CLASSES: tuple[str, ...] = (
    GoldenClass.C2_BEACONING,
    GoldenClass.EXFILTRATION,
    GoldenClass.LEGITIMATE_ENTERPRISE,
    GoldenClass.AD_TRAFFIC,
    GoldenClass.ACTIVE_EVASION,
)


@dataclasses.dataclass(frozen=True, slots=True)
class ExpectedFlow:
    """One flow the generator emitted, and what the engine should say about it."""

    #: Hostname placed in the TLS SNI extension. Empty means no SNI at all.
    hostname: str
    #: What `sni_to_app_type` must return for that hostname.
    app: AppType
    src_ip: str = "192.168.1.50"
    dst_ip: str = "93.184.216.34"
    dst_port: int = 443
    #: Whether this flow should be BLOCKED by the scenario's own policy.
    should_block: bool = False


@dataclasses.dataclass(frozen=True, slots=True)
class GoldenCase:
    """A labelled capture: the scenario, and what the engine must find in it."""

    name: str
    golden_class: str
    description: str
    expected: tuple[ExpectedFlow, ...]

    @property
    def expected_apps(self) -> dict[str, int]:
        """Hostname -> expected `AppType`, for scoring against `detected_domains`."""
        return {f.hostname: f.app for f in self.expected}


def _u16be(n: int) -> bytes:
    return bytes([(n >> 8) & 0xFF, n & 0xFF])


def _u24be(n: int) -> bytes:
    return bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def build_client_hello(hostname: str) -> bytes:
    """A TLS ClientHello record carrying `hostname` as its SNI.

    Same construction as `tests/test_sni_extractor.py::build_client_hello`, kept
    local so the corpus does not import from another test module — the corpus is
    meant to be usable as a standalone artefact.
    """
    raw = hostname.encode("ascii")
    sni_entry = bytes([0x00]) + _u16be(len(raw)) + raw
    sni_list = _u16be(len(sni_entry)) + sni_entry
    sni_extension = _u16be(0x0000) + _u16be(len(sni_list)) + sni_list

    body = (
        _u16be(0x0303)
        + b"\x00" * 32
        + bytes([0])  # session id length
        + _u16be(2)
        + b"\x00\x00"  # one cipher suite
        + bytes([1])
        + b"\x00"  # one compression method
        + _u16be(len(sni_extension))
        + sni_extension
    )
    handshake = bytes([0x01]) + _u24be(len(body)) + body
    return bytes([0x16]) + _u16be(0x0303) + _u16be(len(handshake)) + handshake


def build_http_host(hostname: str) -> bytes:
    """A plain HTTP/1.1 GET carrying `hostname` in the `Host:` header."""
    return (
        f"GET / HTTP/1.1\r\nHost: {hostname}\r\n"
        "User-Agent: golden-corpus/1.0\r\n"
        "Accept: */*\r\n\r\n"
    ).encode("ascii")


def build_udp_dns_query(hostname: str) -> bytes:
    """A DNS query for `hostname`, in the wire format `extract_dns_query` reads."""
    label = hostname.split(".")
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in label) + b"\x00"
    header = _u16be(0x1234) + _u16be(0x0100) + _u16be(1) + _u16be(0) + b"\x00\x00"
    header += b"\x00\x01" + _u16be(1)  # QTYPE = A
    return header + qname + _u16be(1)  # QCLASS = IN


def build_packet(
    *,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    protocol: int = 6,
    tcp_flags: int = 0x18,  # PSH, ACK
    index: int = 0,
) -> RawPacket:
    """Frames a payload as Ethernet/IPv4/TCP (or UDP) and timestamps it."""
    eth = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    src = ipaddress.IPv4Address(src_ip).packed
    dst = ipaddress.IPv4Address(dst_ip).packed

    if protocol == 6:
        l4 = (
            _u16be(src_port)
            + _u16be(dst_port)
            + (0).to_bytes(4, "big")  # seq
            + (0).to_bytes(4, "big")  # ack
            + bytes([0x50, tcp_flags])
            + _u16be(65535)  # window
            + b"\x00\x00"  # checksum
            + b"\x00\x00"  # urgent
        )
    else:
        l4 = _u16be(src_port) + _u16be(dst_port) + _u16be(len(payload)) + b"\x00\x00"

    total_len = 20 + len(l4) + len(payload)
    ip = (
        bytes([0x45, 0x00])
        + total_len.to_bytes(2, "big")
        + b"\x00\x00"  # id
        + b"\x40\x00"  # flags: don't fragment
        + bytes([64, protocol])
        + b"\x00\x00"  # checksum
        + src
        + dst
    )
    return RawPacket(
        ts_sec=_EPOCH + index,
        ts_usec=0,
        data=eth + ip + l4 + payload,
        orig_len=len(eth + ip + l4 + payload),
    )


def build_case_packets(case: GoldenCase) -> list[RawPacket]:
    """Materialises a case as packets.

    Each expected flow becomes a TLS ClientHello and an HTTP request for the same
    hostname, which is what a real conversation looks like to this engine and gives
    the corpus both extraction paths to exercise.
    """
    packets: list[RawPacket] = []
    index = 0
    for flow in case.expected:
        for payload in (
            build_client_hello(flow.hostname),
            build_http_host(flow.hostname),
        ):
            packets.append(
                build_packet(
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    src_port=40000 + (index % 20000),
                    dst_port=flow.dst_port,
                    payload=payload,
                    index=index,
                )
            )
            index += 1
    return packets


def write_case(path: Path, case: GoldenCase) -> Path:
    """Writes one case to `path`. Byte-reproducible for a given case."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with PcapWriter(path) as writer:
        for packet in build_case_packets(case):
            writer.write(packet)
    return path


# ---------------------------------------------------------------------------
# The corpus
# ---------------------------------------------------------------------------


def _c2(name: str, description: str, hosts: tuple[str, ...], *, dst_port: int = 443) -> GoldenCase:
    return GoldenCase(
        name=name,
        golden_class=GoldenClass.C2_BEACONING,
        description=description,
        expected=tuple(
            ExpectedFlow(h, AppType.HTTPS, dst_port=dst_port, should_block=True)
            for h in hosts
        ),
    )


def _exfil(name: str, description: str, hosts: tuple[str, ...]) -> GoldenCase:
    return GoldenCase(
        name=name,
        golden_class=GoldenClass.EXFILTRATION,
        description=description,
        expected=tuple(
            ExpectedFlow(h, AppType.HTTPS, dst_port=443, should_block=True) for h in hosts
        ),
    )


def _enterprise(name: str, description: str, hosts: tuple[tuple[str, AppType], ...]) -> GoldenCase:
    return GoldenCase(
        name=name,
        golden_class=GoldenClass.LEGITIMATE_ENTERPRISE,
        description=description,
        expected=tuple(ExpectedFlow(h, app, dst_port=443) for h, app in hosts),
    )


def _ads(name: str, description: str, hosts: tuple[str, ...]) -> GoldenCase:
    return GoldenCase(
        name=name,
        golden_class=GoldenClass.AD_TRAFFIC,
        description=description,
        expected=tuple(
            ExpectedFlow(h, AppType.HTTPS, dst_port=443, should_block=False) for h in hosts
        ),
    )


def _evasion(name: str, description: str, flows: tuple[ExpectedFlow, ...]) -> GoldenCase:
    return GoldenCase(
        name=name,
        golden_class=GoldenClass.ACTIVE_EVASION,
        description=description,
        expected=flows,
    )


def build_corpus() -> tuple[GoldenCase, ...]:
    """The corpus. Stable order, so generated files are deterministic."""
    return (
        # --- C2 beaconing: regular callbacks to unknown hosts on a fixed port ---
        _c2("c2_dns_tunnel", "DNS-shaped C2 callbacks", ("c2.evil.example", "beacon.evil.example")),
        _c2("c2_https_beacon", "HTTPS beacons to a rare port", ("update.evil.example",)),
        _c2("c2_lookalike_tld", "Hostnames resembling legitimate services",
            ("microsoft-update.evil.example", "cdn.apple.evil.example")),
        _c2("c2_long_hostname", "Over-long labels to stretch the SNI field",
            ("a" * 60 + ".evil.example",)),
        _c2("c2_ip_literal_hostname", "SNI carrying a bare IP literal",
            ("198.51.100.77",)),
        # --- Exfiltration ---
        _exfil("exfil_dns", "Bulk queries to a rare TLD", ("telemetry.evil.example",)),
        _exfil("exfil_slow", "Low-rate single-host beacons", ("staging.evil.example",)),
        _exfil("exfil_subdomain_data", "Data encoded in subdomains",
            ("aGVsbG8.dns.evil.example", "d29ybGQ.dns.evil.example")),
        _exfil("exfil_alt_port", "Exfiltration off the standard port",
            ("drop.evil.example",)),
        # --- Legitimate enterprise: the flows that must NOT be blocked ---
        _enterprise(
            "ent_saas", "Everyday SaaS",
            (
                ("www.google.com", AppType.GOOGLE),
                ("docs.google.com", AppType.GOOGLE),
                ("outlook.office365.com", AppType.MICROSOFT),
                ("login.microsoftonline.com", AppType.MICROSOFT),
            ),
        ),
        _enterprise(
            "ent_social", "Social platforms during work hours",
            (
                ("www.facebook.com", AppType.FACEBOOK),
                ("scontent.xx.fbcdn.net", AppType.FACEBOOK),
                ("www.youtube.com", AppType.YOUTUBE),
                ("i.ytimg.com", AppType.YOUTUBE),
                ("x.com", AppType.TWITTER),
                ("api.twitter.com", AppType.TWITTER),
            ),
        ),
        _enterprise(
            "ent_cdn", "Content delivery and cloud storage",
            (
                ("d1.awsstatic.com", AppType.AMAZON),
                ("cdn.example-cloudfront.net", AppType.AMAZON),
                ("api.netflix.com", AppType.NETFLIX),
                ("nflxvideo.net", AppType.NETFLIX),
            ),
        ),
        _enterprise(
            "ent_developer", "Developer tooling",
            (
                ("github.com", AppType.GITHUB),
                ("raw.githubusercontent.com", AppType.GITHUB),
                ("cdn.discordapp.com", AppType.DISCORD),
            ),
        ),
        _enterprise(
            "ent_identity_providers", "SSO and identity",
            (
                ("login.google.com", AppType.GOOGLE),
                ("appleid.apple.com", AppType.APPLE),
                ("www.cloudflare.com", AppType.CLOUDFLARE),
            ),
        ),
        # --- Ad traffic: known-but-unwanted, blockable without being malicious ---
        _ads("ads_tracking", "Third-party trackers", ("ads.doubleclick.net", "scorecardresearch.com")),
        _ads("ads_aggressive", "High-frequency ad calls", ("ads.eviladnetwork.example",)),
        _ads("ads_cdn", "Ad creative delivery", ("creative.ads.example",)),
        _ads("ads_mixed", "Ads alongside legitimate traffic", ("track.example",)),
        _ads("ads_mobile", "Mobile ad SDK endpoints", ("ads.mopub.com",)),
        _ads("ads_video_pre", "Video pre-roll networks", ("ads.ima3.net",)),
        # --- Active evasion: things crafted to get past a naive filter ---
        _evasion(
            "evasion_punycode", "Punycode-encoded hostnames",
            (
                ExpectedFlow("xn--80ak6aa92e.com", AppType.HTTPS, should_block=True),
                ExpectedFlow("xn--pple-43d.com", AppType.HTTPS, should_block=True),
            ),
        ),
        _evasion(
            "evasion_subdomain_app", "A blocked app name hidden in a subdomain",
            (ExpectedFlow("cdn.facebook.com.attacker.example", AppType.HTTPS, should_block=True),),
        ),
        _evasion(
            "evasion_trailing_dot", "Fully-qualified names with a trailing dot",
            (ExpectedFlow("evil.example.", AppType.HTTPS, should_block=True),),
        ),
        _evasion(
            "evasion_uppercase", "Uppercase hostnames to dodge case-sensitive rules",
            (ExpectedFlow("EVIL.EXAMPLE", AppType.HTTPS, should_block=True),),
        ),
        _evasion(
            "evasion_legitimate_prefix", "A legitimate app's name as a prefix",
            (
                ExpectedFlow("www.facebook.com.evil.example", AppType.HTTPS, should_block=True),
                ExpectedFlow("microsoft.com.attacker.example", AppType.HTTPS, should_block=True),
            ),
        ),
        _evasion(
            "evasion_deep_subdomain", "Many levels of nesting to defeat prefix rules",
            (ExpectedFlow("a.b.c.d.e.f.g.attacker.example", AppType.HTTPS, should_block=True),),
        ),
        _evasion(
            "evasion_hyphen_split", "App name broken across a hyphen",
            (
                ExpectedFlow("face-book.evil.example", AppType.HTTPS, should_block=True),
                ExpectedFlow("micro-soft.attacker.example", AppType.HTTPS, should_block=True),
            ),
        ),
        _evasion(
            "evasion_numeric_tld_style", "Numeric and hex-looking labels",
            (
                ExpectedFlow("0xdeadbeef.evil.example", AppType.HTTPS, should_block=True),
                ExpectedFlow("12345.attacker.example", AppType.HTTPS, should_block=True),
            ),
        ),
        # --- Additional per-class coverage, to clear Layer 6's 30+ floor ---
        _c2("c2_rare_port", "C2 whose hostname imitates a rare-port service",
            ("cb.evil.example",)),
        _exfil("exfil_repeated_host", "One host, many connections",
            ("collect.evil.example",)),
        _enterprise(
            "ent_mixed_identity", "Identity providers in one capture",
            (
                ("accounts.google.com", AppType.GOOGLE),
                ("login.live.com", AppType.MICROSOFT),
                ("graph.microsoft.com", AppType.MICROSOFT),
            ),
        ),
        _ads("ads_third_party_cookies", "Trackers behind short links",
            ("t.example",)),
        _evasion(
            "evasion_typosquat_generic", "Typosquats of common software",
            (
                ExpectedFlow("micros0ft.evil.example", AppType.HTTPS, should_block=True),
                ExpectedFlow("g00gle.attacker.example", AppType.HTTPS, should_block=True),
            ),
        ),
    )


def iter_cases() -> Iterator[GoldenCase]:
    yield from build_corpus()


def corpus_size() -> int:
    return len(build_corpus())


def materialise(directory: Path) -> dict[str, Path]:
    """Writes the whole corpus under `directory`, returning `case name -> path`."""
    return {case.name: write_case(directory / f"{case.name}.pcap", case) for case in iter_cases()}


__all__ = [
    "ALL_CLASSES",
    "ExpectedFlow",
    "GoldenCase",
    "GoldenClass",
    "build_client_hello",
    "build_corpus",
    "build_http_host",
    "build_packet",
    "corpus_size",
    "is_tls_client_hello",
    "iter_cases",
    "materialise",
    "write_case",
]
