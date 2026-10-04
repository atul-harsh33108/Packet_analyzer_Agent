"""Core DPI data types: five-tuples, application classification, connection
state, and packet actions.

Ports OSC/include/types.h + OSC/src/types.cpp to Python.

Design notes / intentional differences from the original (see
DESIGN_DECISIONS.md):
- FiveTuple is a plain hashable NamedTuple, not a struct + separate hand-rolled
  hash-combine function. Python tuples are hashable and comparable for free;
  the original's FiveTupleHash (types.h) is unnecessary here. (Hash *selection*
  -- picking which worker owns a flow -- lives in load_balancer.py, which does
  need an explicit, stable hash, so it defines its own.)
- sni_to_app_type is an explicit ordered table of rules (see `_SNI_RULES`)
  rather than a chain of `if sni.find(...)`. Every rule is evaluated in exactly
  the order the original's `if/else-if` chain evaluated them, and the first
  match wins, so the *priority order* is preserved exactly -- which matters,
  because it decides which app wins when a domain matches more than one
  pattern. Each rule carries up to two kinds of pattern:
    - `substrings`: unanchored, case-insensitive contains-match (the original's
      `lower_sni.find(pat) != npos`).
    - `domains`: anchored to a domain boundary -- matches `d` itself or any
      proper subdomain of `d` (`d == "x.com"`, or endswith ".x.com"). Used
      only where the original's bare substring was demonstrably a bug (see
      below). Anchoring is a strict refinement of substring matching, so
      anchoring a pattern can only ever *lose* matches that were false
      positives to begin with.
- Accuracy fixes to the original's pattern list (both are the same bug class:
  short, generic substrings that occur inside unrelated domains by
  coincidence):
    - "Cloudflare" matched the bare substring "cf-", which hits any domain
      merely containing that text. Dropped; only "cloudflare" is kept.
    - "Twitter/X" matched the bare substrings "x.com" and "t.co". "x.com" is
      inside "netflix.com" ("netfli" + "x.com") and "t.co" is inside
      "microsoft.com" ("microsof" + "t.com") -- in fact "t.co" is a prefix of
      ".com" itself, so it matches nearly any ".com" domain whose preceding
      character is "t". Both are kept but anchored as domain boundaries.
      NOTE: the anchored check sits in its rule at the same priority position
      the original checked Twitter (after WhatsApp, before Netflix) -- an
      earlier revision of this port hoisted it above the whole table, which
      silently re-prioritised it (e.g. "google.x.com" became Twitter instead
      of Google). Do not hoist it again without updating the table order.
- No pattern here is a regex, and none of them are escaped/compiled: they are
  a fixed, closed, hand-audited set of literal substrings, so a plain
  `in` scan is both correct and faster than a compiled regex. Because the list
  is scanned in order and most rules never match, `_SNI_RULES` is a tuple
  (immutable, no accidental runtime mutation) of frozen dataclasses.
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

    def reverse(self) -> FiveTuple:
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


# Ordered classification table. `_SniRule` order IS the evaluation order and
# must stay aligned with the original's `if/else-if` chain in
# sniToAppType (OSC/src/types.cpp:60-194). First match wins.
@dataclass(frozen=True, slots=True)
class _SniRule:
    """One row of the SNI -> AppType table.

    `substrings` and `domains` are both optional; a rule matches if *either*
    form matches (so a rule with only one form set is a plain literal-pattern
    rule, which is the overwhelmingly common case).
    """

    app: AppType
    substrings: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()

    def matches(self, lower_sni: str) -> bool:
        if any(pattern in lower_sni for pattern in self.substrings):
            return True
        return any(_is_domain_or_subdomain(lower_sni, d) for d in self.domains)


_SNI_RULES: tuple[_SniRule, ...] = (
    # Google (including YouTube, which is owned by Google -- so this rule
    # must stay ahead of the YouTube rule).
    _SniRule(
        AppType.GOOGLE,
        substrings=("google", "gstatic", "googleapis", "ggpht", "gvt1"),
    ),
    _SniRule(
        AppType.YOUTUBE,
        substrings=("youtube", "ytimg", "youtu.be", "yt3.ggpht"),
    ),
    # Facebook / Meta.
    _SniRule(
        AppType.FACEBOOK,
        substrings=("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"),
    ),
    _SniRule(AppType.INSTAGRAM, substrings=("instagram", "cdninstagram")),
    _SniRule(AppType.WHATSAPP, substrings=("whatsapp", "wa.me")),
    # Twitter/X. "x.com" and "t.co" are anchored rather than bare substrings
    # because unanchored they false-positive on unrelated domains
    # ("netflix.com", "microsoft.com", ...). See the module docstring.
    _SniRule(
        AppType.TWITTER,
        substrings=("twitter", "twimg"),
        domains=("x.com", "t.co"),
    ),
    _SniRule(AppType.NETFLIX, substrings=("netflix", "nflxvideo", "nflximg")),
    _SniRule(
        AppType.AMAZON,
        substrings=("amazon", "amazonaws", "cloudfront", "aws"),
    ),
    _SniRule(
        AppType.MICROSOFT,
        substrings=("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"),
    ),
    _SniRule(AppType.APPLE, substrings=("apple", "icloud", "mzstatic", "itunes")),
    _SniRule(AppType.TELEGRAM, substrings=("telegram", "t.me")),
    _SniRule(AppType.TIKTOK, substrings=("tiktok", "tiktokcdn", "musical.ly", "bytedance")),
    _SniRule(AppType.SPOTIFY, substrings=("spotify", "scdn.co")),
    _SniRule(AppType.ZOOM, substrings=("zoom",)),
    _SniRule(AppType.DISCORD, substrings=("discord", "discordapp")),
    _SniRule(AppType.GITHUB, substrings=("github", "githubusercontent")),
    # "cf-" from the original was dropped: it matches any domain containing
    # that text. See the module docstring.
    _SniRule(AppType.CLOUDFLARE, substrings=("cloudflare",)),
)


def _is_domain_or_subdomain(lower_sni: str, domain: str) -> bool:
    """True if lower_sni is exactly `domain` or a proper subdomain of it.

    e.g. domain="x.com" matches "x.com" and "api.x.com" but not
    "netflix.com" and not "notx.com".
    """
    return lower_sni == domain or lower_sni.endswith("." + domain)


def sni_to_app_type(sni: str) -> AppType:
    """Maps an SNI/domain/Host string to an AppType, mirroring OSC's
    sniToAppType.

    Matching is case-insensitive, evaluated against `_SNI_RULES` in order,
    first match wins. If the SNI is non-empty but matches no known pattern,
    returns HTTPS (mirroring the original's "SNI present but unrecognized ->
    still TLS/HTTPS" fallback) rather than UNKNOWN. An empty SNI returns
    UNKNOWN, because "no SNI observed" and "unrecognized SNI observed" are
    genuinely different facts and collapsing them would misreport coverage.
    """
    if not sni:
        return AppType.UNKNOWN

    lower_sni = sni.lower()
    for rule in _SNI_RULES:
        if rule.matches(lower_sni):
            return rule.app

    return AppType.HTTPS


class ConnectionState(Enum):
    """Flow lifecycle state. Mirrors OSC's ConnectionState (types.h).

    The original's five values are preserved. Note that OSC's own code paths
    never guarded the transitions between them consistently: a flow locked by
    any classification -- including a bare port-443 guess -- could never be
    upgraded by a later, more accurate SNI result (DESIGN_DECISIONS.md "Bugs
    fixed during the port" item 7), and a CLOSED flow could still be
    re-classified and re-blocked by a later packet. Neither enum governs
    transitions, so the *reachable* set of states is enforced by
    ConnectionTracker, not here; see `is_terminal` below for the invariant that
    replaced OSC's unguarded behaviour.
    """

    NEW = auto()
    ESTABLISHED = auto()
    CLASSIFIED = auto()
    BLOCKED = auto()
    CLOSED = auto()

    @property
    def is_terminal(self) -> bool:
        """True for states a later packet must never move a flow out of.

        BLOCKED and CLOSED are sticky: a blocked flow stays blocked and a
        closed flow stays closed regardless of what later packets say. This
        is the invariant the original violated.
        """
        return self in (ConnectionState.BLOCKED, ConnectionState.CLOSED)


class PacketAction(Enum):
    """What to do with a packet. Mirrors OSC's PacketAction (types.h).

    INSPECT and LOG_ONLY are declared for parity with the original but are
    not produced by any code path in this port (nor were they in the
    original's -- `DPIEngine::handleOutput` only ever forwarded or dropped).
    They are kept so the wire/report vocabulary matches, and so a future
    "log but don't drop" mode has an obvious home; do not assume the pipeline
    can currently emit them.
    """

    FORWARD = auto()
    DROP = auto()
    INSPECT = auto()
    LOG_ONLY = auto()


@dataclass(slots=True)
class Connection:
    """A tracked flow. Mirrors OSC's Connection (types.h).

    This dataclass is pure state: it does not enforce the state machine's
    transition rules. Those live in ConnectionTracker (update_tcp_state /
    classify_connection / block_connection), so there is exactly one place
    that can move a flow between states.
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

    # TCP handshake/teardown tracking, driven by
    # ConnectionTracker.update_tcp_state (ports OSC's
    # FastPathProcessor::updateTCPState, which the first version of this port
    # declared the fields for but never called).
    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False

    @property
    def packets(self) -> int:
        """Total packets seen in both directions of this flow."""
        return self.packets_in + self.packets_out

    @property
    def bytes(self) -> int:
        """Total bytes seen in both directions of this flow."""
        return self.bytes_in + self.bytes_out


@dataclass(slots=True)
class DPIStats:
    """Aggregate run statistics. Mirrors OSC's DPIStats (types.h).

    The original used std::atomic<uint64_t> counters because multiple
    threads incremented them directly. In this port, every execution context
    (the single-process pipeline, each multiprocessing worker, each staged
    FP process) accumulates its own DPIStats locally, with no shared
    concurrently-mutated state, and results are summed afterwards via
    `combine()` -- which removes the need for atomics/locks rather than
    reimplementing them.
    """

    total_packets: int = 0
    total_bytes: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    other_packets: int = 0
    active_connections: int = 0

    def combine(self, other: DPIStats) -> DPIStats:
        """Returns a new DPIStats with counters summed.

        Note that `active_connections` is a point-in-time gauge (how many
        flows the owning tracker held when it was snapshotted), not a running
        total, so summing it across workers means "sum of each worker's final
        gauge". That is the intended, and only meaningful, interpretation
        when combining per-worker snapshots.
        """
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
