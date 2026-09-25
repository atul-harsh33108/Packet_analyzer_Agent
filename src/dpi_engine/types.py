"""Core DPI data types: five-tuples, application classification, connection
state, and packet actions.

Ports OSC/include/types.h + OSC/src/types.cpp to Python.

Design notes / intentional differences from the original (see
DESIGN_DECISIONS.md):
- FiveTuple is a plain hashable NamedTuple, not a struct + separate hand-rolled
  hash-combine function. Python tuples are hashable and comparable for free;
  the original's FiveTupleHash (types.h) is unnecessary here.
- sni_to_app_type is an explicit ordered list of (AppType, patterns) rather
  than a chain of `if sni.find(...)`. The *matching order* from the original
  is preserved exactly (Google checked before YouTube, etc.) since that order
  is semantically meaningful (e.g. it determines which app wins if a domain
  happens to contain multiple patterns) -- only the case-folding + linear
  scan mechanics changed, not the classification decisions themselves.
- The original's Cloudflare pattern list included the bare substring "cf-",
  which matches as a false positive on any unrelated domain containing that
  substring (e.g. "cf-anything.example.com", or coincidentally any domain
  with "cf-" anywhere in it). This port drops that specific pattern and
  keeps only "cloudflare" -- a deliberate accuracy fix, not a scope cut.
- Found during porting (not in the original prior analysis, but the same bug
  class as "cf-" above): the Twitter/X pattern list includes the bare
  substrings "x.com" and "t.co", both of which are themselves short,
  generic-looking strings that occur inside unrelated domains purely by
  coincidence -- "x.com" inside "netflix.com" ("netfli" + "x.com"), and
  "t.co" inside "microsoft.com" ("microsof" + "t.com" -- note "t.co" is a
  prefix of ".com" itself, so it matches almost any ".com" domain whose
  preceding character is "t"! e.g. "microsoft.com", "wechat.com"). This port
  keeps both patterns but anchors them to domain boundaries (exact match or
  proper subdomain, e.g. domain == "x.com" / ends with ".x.com"; domain ==
  "t.co" / ends with ".t.co") instead of unanchored substrings, preserving
  detection of the real domains while eliminating the false positives.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import NamedTuple


class FiveTuple(NamedTuple):
    """Uniquely identifies a connection/flow. Plain, hashable, comparable.

    protocol: 6 = TCP, 17 = UDP (matches OSC's FiveTuple.protocol).
    """

    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int

    def reverse(self) -> "FiveTuple":
        """Returns the tuple for the opposite direction of the same flow."""
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
        )

    def __str__(self) -> str:
        proto_str = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return (
            f"{_ip_to_str(self.src_ip)}:{self.src_port} -> "
            f"{_ip_to_str(self.dst_ip)}:{self.dst_port} ({proto_str})"
        )


def _ip_to_str(ip: int) -> str:
    return ".".join(str((ip >> shift) & 0xFF) for shift in (24, 16, 8, 0))


class AppType(Enum):
    """Application classification, matching OSC's AppType enum (types.h)."""

    UNKNOWN = auto()
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    TLS = auto()
    QUIC = auto()
    GOOGLE = auto()
    FACEBOOK = auto()
    YOUTUBE = auto()
    TWITTER = auto()
    INSTAGRAM = auto()
    NETFLIX = auto()
    AMAZON = auto()
    MICROSOFT = auto()
    APPLE = auto()
    WHATSAPP = auto()
    TELEGRAM = auto()
    TIKTOK = auto()
    SPOTIFY = auto()
    ZOOM = auto()
    DISCORD = auto()
    GITHUB = auto()
    CLOUDFLARE = auto()


_APP_TYPE_DISPLAY_NAMES: dict[AppType, str] = {
    AppType.UNKNOWN: "Unknown",
    AppType.HTTP: "HTTP",
    AppType.HTTPS: "HTTPS",
    AppType.DNS: "DNS",
    AppType.TLS: "TLS",
    AppType.QUIC: "QUIC",
    AppType.GOOGLE: "Google",
    AppType.FACEBOOK: "Facebook",
    AppType.YOUTUBE: "YouTube",
    AppType.TWITTER: "Twitter/X",
    AppType.INSTAGRAM: "Instagram",
    AppType.NETFLIX: "Netflix",
    AppType.AMAZON: "Amazon",
    AppType.MICROSOFT: "Microsoft",
    AppType.APPLE: "Apple",
    AppType.WHATSAPP: "WhatsApp",
    AppType.TELEGRAM: "Telegram",
    AppType.TIKTOK: "TikTok",
    AppType.SPOTIFY: "Spotify",
    AppType.ZOOM: "Zoom",
    AppType.DISCORD: "Discord",
    AppType.GITHUB: "GitHub",
    AppType.CLOUDFLARE: "Cloudflare",
}


def app_type_to_string(app_type: AppType) -> str:
    return _APP_TYPE_DISPLAY_NAMES.get(app_type, "Unknown")


# Ordered (AppType, patterns) table. Order matters and is preserved from the
# original's if/else-if chain (sniToAppType, types.cpp) -- the first matching
# entry wins. Patterns are matched as case-insensitive substrings, exactly as
# the original did (after its own lowercasing step).
_SNI_PATTERNS: tuple[tuple[AppType, tuple[str, ...]], ...] = (
    (AppType.GOOGLE, ("google", "gstatic", "googleapis", "ggpht", "gvt1")),
    (AppType.YOUTUBE, ("youtube", "ytimg", "youtu.be", "yt3.ggpht")),
    (AppType.FACEBOOK, ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")),
    (AppType.INSTAGRAM, ("instagram", "cdninstagram")),
    (AppType.WHATSAPP, ("whatsapp", "wa.me")),
    # "x.com" and "t.co" are intentionally NOT in this substring list -- see
    # module docstring. Both are handled as domain-boundary-anchored special
    # cases below instead, to avoid false-positiving on domains like
    # "netflix.com" and "microsoft.com".
    (AppType.TWITTER, ("twitter", "twimg")),
    (AppType.NETFLIX, ("netflix", "nflxvideo", "nflximg")),
    (AppType.AMAZON, ("amazon", "amazonaws", "cloudfront", "aws")),
    (
        AppType.MICROSOFT,
        ("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"),
    ),
    (AppType.APPLE, ("apple", "icloud", "mzstatic", "itunes")),
    (AppType.TELEGRAM, ("telegram", "t.me")),
    (AppType.TIKTOK, ("tiktok", "tiktokcdn", "musical.ly", "bytedance")),
    (AppType.SPOTIFY, ("spotify", "scdn.co")),
    (AppType.ZOOM, ("zoom",)),
    (AppType.DISCORD, ("discord", "discordapp")),
    (AppType.GITHUB, ("github", "githubusercontent")),
    # NOTE: the original also matched the bare substring "cf-" here, which
    # false-positives on any domain merely containing that substring. Fixed
    # in this port by dropping it -- see module docstring.
    (AppType.CLOUDFLARE, ("cloudflare",)),
)


def _matches_domain_or_subdomain(lower_sni: str, domain: str) -> bool:
    """True if lower_sni is exactly `domain` or a subdomain of it
    (e.g. domain="x.com" matches "x.com" and "api.x.com", but not
    "netflix.com")."""
    return lower_sni == domain or lower_sni.endswith("." + domain)


def sni_to_app_type(sni: str) -> AppType:
    """Maps an SNI/domain string to an AppType, mirroring OSC's sniToAppType.

    Matching is case-insensitive substring search, evaluated in the fixed
    priority order above. If the SNI is non-empty but matches no known
    pattern, returns HTTPS (mirroring the original's "detected but
    unrecognized" fallback) rather than UNKNOWN.
    """
    if not sni:
        return AppType.UNKNOWN

    lower_sni = sni.lower()

    # Twitter/X: "x.com" and "t.co" are checked as domain-boundary-anchored
    # matches, not bare substrings, to avoid false-positiving on domains
    # like "netflix.com" and "microsoft.com" (see module docstring).
    if _matches_domain_or_subdomain(lower_sni, "x.com") or _matches_domain_or_subdomain(
        lower_sni, "t.co"
    ):
        return AppType.TWITTER

    for app_type, patterns in _SNI_PATTERNS:
        if any(pattern in lower_sni for pattern in patterns):
            return app_type

    return AppType.HTTPS


class ConnectionState(Enum):
    """Matches OSC's ConnectionState (types.h)."""

    NEW = auto()
    ESTABLISHED = auto()
    CLASSIFIED = auto()
    BLOCKED = auto()
    CLOSED = auto()


class PacketAction(Enum):
    """Matches OSC's PacketAction (types.h)."""

    FORWARD = auto()
    DROP = auto()
    INSPECT = auto()
    LOG_ONLY = auto()


@dataclass(slots=True)
class Connection:
    """A tracked flow. Mirrors OSC's Connection (types.h), with the
    classification-lock-in bug fixed at the ConnectionTracker level (Task 7),
    not here -- this dataclass just models state, it doesn't enforce the
    state machine's transition rules itself.
    """

    tuple: FiveTuple
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""

    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0

    first_seen: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)

    action: PacketAction = PacketAction.FORWARD

    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False


@dataclass(slots=True)
class DPIStats:
    """Aggregate run statistics. Mirrors OSC's DPIStats (types.h).

    The original used std::atomic<uint64_t> counters because multiple
    threads incremented them directly. In this port, each multiprocessing
    worker (Task 10) accumulates its own DPIStats locally (no shared,
    concurrently-mutated state) and results are combined in the main
    process after workers finish -- see `combine()` -- which sidesteps the
    need for atomics/locks entirely rather than reimplementing them.
    """

    total_packets: int = 0
    total_bytes: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    other_packets: int = 0
    active_connections: int = 0

    def combine(self, other: "DPIStats") -> "DPIStats":
        """Returns a new DPIStats with counters summed (active_connections
        excepted, since that's a point-in-time gauge, not a running total --
        callers combining post-hoc snapshots should treat it as informational
        only)."""
        return DPIStats(
            total_packets=self.total_packets + other.total_packets,
            total_bytes=self.total_bytes + other.total_bytes,
            forwarded_packets=self.forwarded_packets + other.forwarded_packets,
            dropped_packets=self.dropped_packets + other.dropped_packets,
            tcp_packets=self.tcp_packets + other.tcp_packets,
            udp_packets=self.udp_packets + other.udp_packets,
            other_packets=self.other_packets + other.other_packets,
            active_connections=self.active_connections + other.active_connections,
        )
