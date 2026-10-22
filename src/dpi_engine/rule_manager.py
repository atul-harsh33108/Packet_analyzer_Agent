"""IP / application / domain / port blocking rules, with JSON persistence
and lock-free concurrent reads.

Ports OSC/include/rule_manager.h + OSC/src/rule_manager.cpp to Python.

=============================================================================
Concurrency model (the reason this module is copy-on-write)
=============================================================================
OSC protected each rule category (IPs, apps, domains, ports) with its own
`std::shared_mutex`, because the original's `DPIEngine` let an admin thread
mutate rules *while* FP threads were reading them (dpi_engine.cpp:335-402
exposes blockIP/unblockIP/blockApp/unblockDomain/loadRules/saveRules as
callable during a run).

This port keeps that capability -- rules CAN be changed while a run is in
progress -- but does it without putting a lock on the packet hot path, which
is the one place where lock contention would actually hurt:

- `RuleManager` is the *mutable, thread-safe* front door. It holds a single
  `threading.Lock`, and every mutation rebuilds an immutable `RuleState`
  (frozensets + tuples) and atomically rebinds `self._state`. Mutations
  serialize against each other; that is fine, they are rare.
- `RuleSnapshot` is the immutable, hashable, picklable *result* of
  `RuleManager.snapshot()`. Reading it needs no lock at all: a single
  attribute load of an immutable object is atomic under CPython, and it is
  immutable, so a reader can hold it for as long as it likes and no writer
  can invalidate it underneath it.
- The packet path (`RuleSnapshot.should_block`) therefore takes no lock,
  acquires no lock, and cannot block a writer.

Cross-process propagation: because `RuleSnapshot` is picklable and
immutable, a parent process can ship a new snapshot to worker processes
over a queue and a worker can simply rebind its local reference (see
`worker.FlowProcessor.refresh_rules` and `pipeline.RuleBroadcaster`). The
alternative OSC could not have done safely -- handing live pointers to
mutating per-thread state -- is what this design replaces.

=============================================================================
Fixes applied during the port
=============================================================================
- IP parsing/validation: the original's hand-rolled `parseIP` silently
  mis-parsed malformed strings (no octet range check, no length check) --
  e.g. "999.1.1.1" or "10.0.1" would parse into *some* uint32 with no error.
  This port validates via the stdlib `ipaddress` module and raises a
  clear, catchable `RuleManagerError`.
- Rules are stored/compared as 32-bit ints, not strings. The first version
  of this port formatted the source IP to a dotted-quad string and re-parsed
  it with `ipaddress` on *every packet*; rules are now int-keyed, so the hot
  path is one set lookup with zero string work.
- Domain case-sensitivity: the original's exact-match domain set was never
  case-normalized, while its wildcard pattern matching *was* lowercased
  before comparison -- so blocking "Example.com" would NOT match a lookup
  for "example.com" via the exact-match path, while the equivalent wildcard
  rule would. This let a case-swap bypass exact-domain blocking. This port
  lowercases every domain and pattern consistently at insertion and lookup
  time, everywhere.
- Domain pattern language is now a small, explicit, *validated* grammar
  (see `DomainPattern`): an unsupported placement of `*` is rejected at
  insertion time instead of being silently stored as a rule that can never
  match. The original accepted anything containing `*` but only ever
  implemented the `*.suffix` form, so e.g. "foo*.com" was accepted and then
  matched nothing, forever, with no diagnostic.
- Rules file format: the original's hand-rolled INI-like parser called
  `std::stoi` directly on port lines with no exception handling -- a
  malformed rules file would throw uncaught and kill the process. This port
  uses JSON with all value coercion wrapped in explicit validation that
  raises `RuleManagerError` instead of propagating a raw parser exception.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import threading
import warnings
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import Enum, StrEnum, auto
from pathlib import Path
from typing import Any

from dpi_engine.types import AppType, app_type_to_string

MIN_PORT = 0
MAX_PORT = 65535

# Accepts either a dotted-quad string or an already-converted host-order
# uint32 for the source IP, so the per-packet path never formats an IP string.
IPLike = str | int

# A batch of rule changes: category -> (value -> should it be present).
# True adds, False removes. See `RuleManager.apply_delta`.
RuleDelta = Mapping[str, Mapping[Any, bool]]

_APP_NAME_TO_TYPE: dict[str, AppType] = {app_type_to_string(a): a for a in AppType}
_TYPE_TO_APP_NAME: dict[AppType, str] = {a: app_type_to_string(a) for a in AppType}


class RuleManagerError(Exception):
    """Raised for invalid rule values (bad IP, out-of-range port, malformed
    domain pattern) or unreadable/malformed rules files.

    Always raised in place of letting a lower-level parsing exception
    (ValueError from int()/ipaddress, JSONDecodeError) propagate unexplained.
    """


class BlockReasonType(Enum):
    """Which rule category caused a block. Mirrors OSC's
    RuleManager::BlockReason::Type."""

    IP = auto()
    APP = auto()
    DOMAIN = auto()
    PORT = auto()


@dataclass(frozen=True, slots=True)
class BlockReason:
    """Why a flow was blocked. Mirrors OSC's RuleManager::BlockReason."""

    type: BlockReasonType
    detail: str


class RuleKind(StrEnum):
    """Which category a rule belongs to.

    A `str` enum so a kind is usable as a JSON object key without a conversion at
    every boundary, and so the persisted form stays readable. These strings are
    persisted, so they are part of the file format: renaming one is a migration,
    not a refactor. They match `RuleManager`'s existing vocabulary
    (`blocked_ips`, `blocked_apps`, ...) rather than inventing a second dialect.
    """

    IP = "ip"
    APP = "app"
    DOMAIN = "domain"
    PORT = "port"
    CIDR = "cidr"


@dataclass(frozen=True, slots=True)
class Provenance:
    """Where a rule came from (`T1-04`).

    Exists so an agent's proposal can be reviewed rather than merely obeyed. Three
    questions, and the record is deliberately structured around them:

    - **source** -- the system that produced it (`agent:triage`, `operator:alice`).
      Required, because a record with no source is not provenance; it is a
      decoration that makes a rule look auditable while answering nothing.
    - **author** -- who or what is accountable for it.
    - **evidence** -- what it was based on. Optional in the type but strongly
      expected in practice: an agent that cannot say what it saw is guessing.

    `created_at` defaults to now rather than being required, because forcing a
    timestamp on every call site would make the common path noisier than the
    feature earns.

    **Deliberately not part of `_RuleState`.** The matching state is frozensets read
    by `should_block` on every inspected packet, shared across threads and pickled
    to workers; a provenance record per rule there would put an allocation and a
    lookup on the hot path to serve a question only the control path asks. So this
    lives beside the rules, keyed by the stable keys `D-16` introduced.
    """

    source: str
    author: str
    evidence: str = ""
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.source or not self.source.strip():
            raise ValueError(
                "Provenance requires a source. A rule with no recorded origin is "
                "not auditable, which is the only reason this field exists."
            )
        if not self.author or not self.author.strip():
            raise ValueError("Provenance requires an author.")
        if not self.created_at:
            object.__setattr__(
                self, "created_at", datetime.now(UTC).isoformat(timespec="seconds")
            )

    @property
    def is_agent_sourced(self) -> bool:
        """Whether this rule came from an automated proposer.

        The distinction a gate needs: an agent-proposed rule is exactly the one a
        human should look at before it reaches live traffic, so it has to be
        answerable as a property of the record rather than by string-matching the
        source at each call site.
        """
        return self.source.lower().startswith("agent")

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "author": self.author,
            "evidence": self.evidence,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: object) -> Provenance | None:
        """Rebuilds from persisted JSON, or `None` if the record is unusable.

        Returning `None` rather than raising is the point: provenance is the audit
        trail, the rules are the load-bearing thing, and an unreadable audit entry
        is a reason to distrust *that rule's origin* -- not to stop blocking the
        traffic an operator asked to block. The caller keeps the rule and records
        that its origin is unknown.
        """
        if not isinstance(data, dict):
            return None
        try:
            return cls(
                source=str(data["source"]),
                author=str(data["author"]),
                evidence=str(data.get("evidence", "")),
                created_at=str(data.get("created_at", "")),
            )
        except (KeyError, TypeError, ValueError):
            return None


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One rule and where it came from, as the review path wants to see it."""

    kind: RuleKind
    key: str
    provenance: Provenance


@dataclass(frozen=True, slots=True)
class RuleStats:
    """Rule-set sizes. Mirrors OSC's RuleManager::RuleStats."""

    blocked_ips: int = 0
    blocked_apps: int = 0
    blocked_domains: int = 0
    blocked_ports: int = 0


# ---------------------------------------------------------------------------
# Domain pattern grammar
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DomainPattern:
    """A validated wildcard domain rule.

    The grammar is deliberately tiny -- exactly two forms are supported, both
    anchored at a domain boundary so that a rule can never accidentally
    match an unrelated domain by coincidence:

    ============  ==========================================================
    Form          Matches
    ============  ==========================================================
    exact         the domain itself, e.g. "facebook.com" matches only
                  "facebook.com"
    ``*.suffix``  the domain itself *and* any subdomain of it, e.g.
                  "*.facebook.com" matches "facebook.com", "www.facebook.com"
                  and "a.b.facebook.com" -- but not "notfacebook.com"
    ============  ==========================================================

    A bare ``*`` in any other position is rejected at construction time.
    (OSC's reference binary, main_working.cpp:60-62, instead did an
    unanchored substring search for every blocked domain, which means
    `--block-domain facebook` also blocked "notfacebook.example.org". That
    is strictly more dangerous than useful, so it is *not* reproduced; use an
    explicit `*.facebook.com` for the "and subdomains" intent.)

    Instances are pre-lowercased and their matching is allocation-free, so
    `matches()` is safe to call on every packet.
    """

    raw: str
    #: None for an exact-match rule; otherwise the ".suffix" (including the
    #: leading dot) that a candidate domain must end with.
    suffix: str | None

    @classmethod
    def parse(cls, domain: str) -> DomainPattern:
        lower = domain.strip().lower()
        if not lower:
            raise RuleManagerError("Domain rule must not be empty")

        if "*" not in lower:
            return cls(raw=lower, suffix=None)

        if lower.startswith("*.") and lower.count("*") == 1 and len(lower) > 2:
            return cls(raw=lower, suffix=lower[1:])

        raise RuleManagerError(
            f"Unsupported domain pattern {domain!r}. Supported forms are an "
            "exact domain ('facebook.com') or a leading wildcard "
            "('*.facebook.com'). A bare '*' in any other position is rejected "
            "because it cannot be matched safely at a domain boundary."
        )

    def matches(self, domain: str) -> bool:
        """True if `domain` matches this rule. Case-insensitive.

        Lowercases its input so a caller cannot get a silently wrong answer by
        forgetting to. That costs essentially nothing: CPython's `str.lower()`
        returns the *same object* for an already-lowercase ASCII string, so the
        hot path (which has already lowercased for the exact-match set lookup)
        pays no extra allocation.
        """
        lower = domain.lower()
        if self.suffix is None:
            return lower == self.raw
        # "*.example.com" also matches the apex "example.com" -- this mirrors
        # OSC's domainMatchesPattern, which explicitly allowed it.
        return lower.endswith(self.suffix) or lower == self.suffix[1:]

    def __str__(self) -> str:
        return self.raw


# ---------------------------------------------------------------------------
# Immutable state
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _RuleState:
    """Immutable rule-set internals. All containers are immutable so a
    snapshot can be shared across threads and pickled to other processes
    without any risk of a writer mutating it underneath a reader."""

    ips: frozenset[int] = frozenset()
    apps: frozenset[AppType] = frozenset()
    exact_domains: frozenset[str] = frozenset()
    patterns: tuple[DomainPattern, ...] = ()
    ports: frozenset[int] = frozenset()
    #: `(prefix_length, {network_bits})` pairs, sorted by prefix length and
    #: **grouped by prefix length** (`D-20`). Matching is one right-shift and a
    #: set lookup per *distinct prefix length present* -- at most 33 -- rather
    #: than one `ipaddress` membership test per registered network. A rule set
    #: with a thousand subnets therefore costs about what one with a handful
    #: costs, which is the difference between a rule feature and a throughput
    #: bug. A tuple of tuples rather than a dict so the state stays hashable
    #: and picklable like every other field here.
    networks: tuple[tuple[int, frozenset[int]], ...] = ()

    def stats(self) -> RuleStats:
        # Mirrors OSC's getStats(): blocked_domains counts exact rules plus
        # wildcard patterns. A CIDR rule is an IP rule from the operator's
        # point of view, so subnet rules count toward blocked_ips too.
        return RuleStats(
            blocked_ips=len(self.ips) + sum(len(prefixes) for _, prefixes in self.networks),
            blocked_apps=len(self.apps),
            blocked_domains=len(self.exact_domains) + len(self.patterns),
            blocked_ports=len(self.ports),
        )


@dataclass(frozen=True, slots=True)
class RuleSnapshot:
    """An immutable, picklable view of a rule set.

    This is what the packet path uses. It is frozen and every container it
    reaches is immutable, so:
      * `should_block` needs no lock and cannot observe a torn read;
      * it can be pickled to a worker process at any time;
      * two snapshots never share mutable state.

    Obtain one via `RuleManager.snapshot()`, or keep a single
    `STATIC_RULES` when there are no rules at all (the common case, and it
    keeps the empty-rules case allocation-free).
    """

    version: int
    state: _RuleState

    def should_block(
        self,
        src_ip: IPLike,
        dst_port: int,
        app: AppType,
        domain: str = "",
        *,
        dst_ip: IPLike | None = None,
    ) -> BlockReason | None:
        """Returns the first matching rule, or None.

        Checked in OSC's exact priority order: IP, then port, then app, then
        domain (rule_manager.cpp:209-236). "First" is meaningful -- a flow can
        match several categories, and the reported reason should be the most
        specific one, in this fixed order.

        `src_ip` may be an int (host-order uint32, as the packet parser
        produces) or a string. The int form is preferred on hot paths; the
        string form validates and raises `RuleManagerError` if malformed.

        `dst_ip` is optional and checked **after** the source address but still
        within the IP category, so adding the destination can never demote an
        IP match to a lower-priority reason (`DEC-06`). The C++ original only
        ever considered the source, which meant a rule written to block an IP
        was inert whenever that IP was the destination -- `D-21`.
        """
        state = self.state

        ip_int = _coerce_ip_int(src_ip)
        if ip_int in state.ips:
            return BlockReason(BlockReasonType.IP, _int_to_ip_str(ip_int))
        if _network_match(state.networks, ip_int):
            return BlockReason(BlockReasonType.IP, _int_to_ip_str(ip_int))
        if dst_ip is not None:
            dst_int = _coerce_ip_int(dst_ip)
            if dst_int in state.ips or _network_match(state.networks, dst_int):
                return BlockReason(BlockReasonType.IP, _int_to_ip_str(dst_int))

        if dst_port in state.ports:
            return BlockReason(BlockReasonType.PORT, str(dst_port))

        if app in state.apps:
            return BlockReason(BlockReasonType.APP, _TYPE_TO_APP_NAME[app])

        if domain:
            lower = domain.lower()
            if lower in state.exact_domains or any(
                p.matches(lower) for p in state.patterns
            ):
                return BlockReason(BlockReasonType.DOMAIN, lower)

        return None

    def is_ip_blocked(self, src_ip: IPLike) -> bool:
        ip_int = _coerce_ip_int(src_ip)
        return ip_int in self.state.ips or _network_match(self.state.networks, ip_int)

    def is_app_blocked(self, app: AppType) -> bool:
        return app in self.state.apps

    def is_port_blocked(self, port: int) -> bool:
        return port in self.state.ports

    def is_domain_blocked(self, domain: str) -> bool:
        if not domain:
            return False
        state = self.state
        lower = domain.lower()
        return lower in state.exact_domains or any(p.matches(lower) for p in state.patterns)

    def get_stats(self) -> RuleStats:
        return self.state.stats()

    def to_dict(self) -> dict[str, object]:
        """JSON-serializable form, stable ordering for reproducible files."""
        state = self.state
        return {
            "version": self.version,
            "blocked_ips": [_int_to_ip_str(ip) for ip in sorted(state.ips)],
            # `AppType.name`, not the display string (`D-16`/`DEC-04`): the
            # display name is presentation and changes whenever the product is
            # reworded, so keying a saved file on it means renaming "Twitter/X"
            # silently zeroes every app rule a user has ever saved. The enum
            # name is an identifier by construction. Display names remain
            # accepted on input as a deprecated alias.
            "blocked_apps": sorted(app.name for app in state.apps),
            "blocked_cidrs": self.blocked_cidrs,
            "blocked_domains": sorted(state.exact_domains),
            "domain_patterns": [p.raw for p in state.patterns],
            "blocked_ports": sorted(state.ports),
        }

    @property
    def blocked_ips(self) -> list[str]:
        return [_int_to_ip_str(ip) for ip in sorted(self.state.ips)]

    @property
    def blocked_cidrs(self) -> list[str]:
        """Canonical `address/length` strings in sorted order.

        Sorted and reconstructed from the significant bits rather than echoing
        back whatever the user typed, so a rules file written twice is
        byte-identical no matter which order the rules were added in.
        """
        return [
            f"{_int_to_ip_str(prefix_bits << (32 - prefix_length))}/{prefix_length}"
            for prefix_length, prefixes in sorted(self.state.networks)
            for prefix_bits in sorted(prefixes)
        ]

    @property
    def blocked_apps(self) -> list[AppType]:
        return sorted(self.state.apps, key=lambda a: a.name)

    @property
    def blocked_domains(self) -> list[str]:
        return sorted(self.state.exact_domains) + [p.raw for p in self.state.patterns]

    @property
    def blocked_ports(self) -> list[int]:
        return sorted(self.state.ports)


#: The empty rule set, shared by every run that has no rules. Avoids
#: allocating a throwaway RuleManager for the (very common) no-rules case.
STATIC_RULES = RuleSnapshot(version=0, state=_RuleState())


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _parse_cidr(text: str) -> tuple[int, int]:
    """Parses `a.b.c.d/len` into `(prefix_length, network_bits)`.

    `network_bits` is the network address shifted down past its host bits, so
    it holds only the significant part. Matching is then
    `ip >> (32 - prefix_length) == network_bits`: two integer operations, with
    no `ipaddress` object constructed on the packet path.

    Raises `RuleManagerError` rather than leaking a `ValueError`, matching
    `_coerce_ip_int` -- a malformed rule is user input, and the CLI reports
    `RuleManagerError` by name.

    Host bits are rejected rather than silently masked (`10.1.2.3/8` means the
    user wanted a /8 for one address, and quietly widening it to 10/8 would
    apply a rule far broader than the one written).
    """
    if not isinstance(text, str) or "/" not in text:
        raise RuleManagerError(f"Invalid CIDR '{text}': expected address/prefix-length")
    address, _, prefix = text.rpartition("/")
    try:
        prefix_length = int(prefix)
    except ValueError as exc:
        raise RuleManagerError(
            f"Invalid CIDR '{text}': prefix length '{prefix}' is not a number"
        ) from exc
    if not 0 <= prefix_length <= 32:
        raise RuleManagerError(
            f"Invalid CIDR '{text}': prefix length must be 0-32, got {prefix_length}"
        )
    try:
        network = ipaddress.IPv4Network(f"{address}/{prefix_length}", strict=True)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
        raise RuleManagerError(f"Invalid CIDR '{text}': {exc}") from exc
    return prefix_length, int(network.network_address) >> (32 - prefix_length)


def _network_match(
    networks: tuple[tuple[int, frozenset[int]], ...], ip: int
) -> bool:
    """True if `ip` falls inside any registered subnet.

    Walks the grouped-by-prefix-length table: one shift and one `in` per
    distinct prefix length, independent of how many networks share it.
    `prefix_length == 0` is `ip >> 32`, which is 0 for any 32-bit address --
    matching everything, which is what `/0` means.

    The parens around `32 - prefix_length` are deliberate. `-` binds tighter
    than `>>` in Python, so `ip >> 32 - prefix_length` parses as the same
    expression -- but nothing about that spelling says so, and getting it wrong
    silently shifts the wrong amount rather than failing loudly.
    """
    return any(
        (ip >> (32 - prefix_length)) in network_bits
        for prefix_length, network_bits in networks
    )


def _coerce_ip_int(ip: IPLike) -> int:
    """Normalizes an IP to a host-order uint32, raising RuleManagerError
    (never a bare ValueError) on anything that isn't a dotted-quad IPv4
    address."""
    if isinstance(ip, int):
        if not 0 <= ip <= 0xFFFFFFFF:
            raise RuleManagerError(f"Invalid IPv4 address {ip!r}: out of 32-bit range")
        return ip
    if isinstance(ip, str):
        try:
            return int(ipaddress.IPv4Address(ip))
        except (ipaddress.AddressValueError, ValueError) as exc:
            raise RuleManagerError(f"Invalid IPv4 address '{ip}': {exc}") from exc
    raise RuleManagerError(f"Invalid IPv4 address {ip!r}: expected str or int")


def _normalize_port(port: int | str) -> int:
    try:
        port_int = int(port)
    except (TypeError, ValueError) as exc:
        raise RuleManagerError(f"Invalid port value '{port}': not an integer") from exc

    if not (MIN_PORT <= port_int <= MAX_PORT):
        raise RuleManagerError(
            f"Invalid port value {port_int}: must be between {MIN_PORT} and {MAX_PORT}"
        )
    return port_int


def _int_to_ip_str(ip_int: int) -> str:
    return str(ipaddress.IPv4Address(ip_int))


def resolve_app_name(name: str) -> AppType:
    """Maps a display name ("YouTube", "Twitter/X", ...) to an AppType.

    Case-insensitive, because rule files and CLI flags are written by humans.
    Shared by the CLI and by rules-file loading so both accept the same
    vocabulary.

    On failure the message lists the *canonical* display names, not the
    lowercased lookup keys -- a user needs to see the same spelling the rest
    of the tool prints, and case-insensitive matching means the lowercase form
    would work but is not what they should be copying.

    This is the **display-name** vocabulary. `resolve_app_key` is what rules
    files go through, and it prefers the stable enum name.
    """
    app = _APP_NAME_TO_TYPE.get(name) or _APP_NAME_TO_TYPE_LOOKUP.get(name.strip().lower())
    if app is None:
        valid = ", ".join(sorted(_APP_NAME_TO_TYPE))
        raise RuleManagerError(f"Unknown app name '{name}'. Valid names: {valid}")
    return app


def resolve_app_key(name: str) -> AppType:
    """Resolves an app name **from a rules file**, preferring `AppType.name`.

    Two vocabularies exist and they only look alike:

    * `AppType.name` -- an identifier (`YOUTUBE`, `TWITTER`). Stable: renaming
      it is a code change with a compiler behind it.
    * the display name (`YouTube`, `Twitter/X`) -- presentation copy, which
      changes whenever the product is reworded.

    Rules files used to be keyed on the display name, so every saved file
    already speaks that dialect and it must keep loading (`D-16`). But it is
    now an **input-only alias with a deprecation path**: loading one warns and
      names the canonical key to switch to, so the vocabulary can actually
      migrate instead of merely being documented as deprecated.

    The check is the exact, case-sensitive enum name -- deliberately *not*
    case-insensitive. `YouTube` uppercases to `YOUTUBE`, which is a valid enum
    name, so a case-insensitive canonical check could never tell a display name
    from an identifier and the warning would never fire.
    """
    stripped = name.strip()
    app = AppType.__members__.get(stripped)
    if app is not None:
        return app
    app = resolve_app_name(stripped)
    warnings.warn(
        f"App rule '{stripped}' in a rules file is a display name; it is an "
        f"input-only alias and the persisted key is '{app.name}'. "
        f"Update the file to use '{app.name}'.",
        DeprecationWarning,
        stacklevel=2,
    )
    return app


_APP_NAME_TO_TYPE_LOOKUP: dict[str, AppType] = {
    name.lower(): app for app, name in _TYPE_TO_APP_NAME.items()
}


# ---------------------------------------------------------------------------
# Mutable manager
# ---------------------------------------------------------------------------


class RuleManager:
    """Thread-safe mutable rule set; the admin-facing front door.

    Usage pattern (both supported, neither special-cased internally):

    1. Build rules up front, then treat as read-only (what the CLI does):
       ```
       rules = RuleManager()
       rules.block_app(AppType.YOUTUBE)
       snapshot = rules.snapshot()   # hand to workers, never mutate again
       ```
    2. Mutate while a run is in progress (what OSC's DPIEngine API allowed):
       ```
       rules.block_app(AppType.NETFLIX)   # bump version
       broadcaster.publish()               # ship the new snapshot to workers
       ```

    Every mutating method takes `self._lock`, applies the change to a *copy*
    of the current `_RuleState`, and rebinds it. Readers hold a
    `RuleSnapshot` they already captured, so they never block and never see a
    partial update.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state = _RuleState()
        self._version = 0
        #: `(kind, key) -> Provenance`, for `T1-04`. Guarded by the same lock as
        #: `_state`, and deliberately **not** part of it: this is control-plane
        #: data, read by whoever reviews or persists a rule set and never by the
        #: packet path, so folding it into `_RuleState` would cost the hot path a
        #: per-rule record for no benefit.
        self._provenance: dict[tuple[RuleKind, str], Provenance] = {}

    # ---------- version / snapshots ----------

    @property
    def version(self) -> int:
        """Monotonically increasing; changes on every successful mutation.

        Cheap enough (one int read) to poll per packet, which is how
        `FlowProcessor` decides whether it needs a fresh snapshot.
        """
        return self._version

    def snapshot(self) -> RuleSnapshot:
        """Returns an immutable view of the current rules. Lock-free."""
        return RuleSnapshot(version=self._version, state=self._state)

    def _mutate(self, **changes: Any) -> None:
        """Applies `changes` to a copy of the current state and rebinds it,
        bumping the version. Callers must hold `self._lock`."""
        self._state = replace(self._state, **changes)
        self._version += 1

    # ---------- provenance (`T1-04`) ----------

    @staticmethod
    def _normalise_key(kind: RuleKind, key: object) -> str:
        """Canonical lookup key for a rule, as a string.

        Normalisation matters more than it looks. `block_cidr("10.0.0.0/8")` and
        `block_cidr("10.0.0.0/08")` are the same rule, and `port` arrives as `int`
        from one caller and `str` from another; if those produced different keys,
        provenance would attach to a spelling rather than to the rule, and a
        reviewer following the audit trail would find nothing.
        """
        if kind is RuleKind.PORT:
            return str(int(key))  # type: ignore[call-overload]
        if kind is RuleKind.CIDR:
            # `strict=True`, matching `_parse_cidr`, which rejects host bits
            # (`10.0.0.1/8` is an error, not a rule). Normalising with
            # `strict=False` here would fold a spelling the parser rejects into an
            # existing rule's key, so two spellings would resolve to one record
            # while only one of them is a rule at all.
            return str(ipaddress.ip_network(str(key), strict=True))
        return str(key)

    def _record(
        self, kind: RuleKind, key: object, provenance: Provenance | None
    ) -> None:
        """Attaches or clears provenance for one rule. Callers hold `self._lock`."""
        normalised = self._normalise_key(kind, key)
        if provenance is None:
            # Clearing on removal, so a deleted rule cannot leave an orphan record
            # behind claiming an origin for a rule that no longer exists.
            self._provenance.pop((kind, normalised), None)
        else:
            self._provenance[(kind, normalised)] = provenance

    def provenance_for(self, kind: str, key: object) -> Provenance | None:
        """Returns the provenance recorded for one rule, or `None`.

        A bad *query* (an unknown kind) raises, because a typo there is a caller
        bug that would otherwise read as "this rule has no provenance" -- the exact
        answer a gate must never be able to give by accident.
        """
        rule_kind = RuleKind(kind)
        with self._lock:
            return self._provenance.get((rule_kind, self._normalise_key(rule_kind, key)))

    def is_auto_appliable(self, kind: str, key: object) -> bool:
        """Whether this rule may be put into the live path without human review.

        The precondition for Phase 6's auto-apply tiers, stated as a method so the
        policy has exactly one home. A rule with no recorded origin is **not**
        auto-appliable: an automated system putting an untraceable rule into a
        path that drops traffic is precisely the failure this feature exists to
        prevent.
        """
        return self.provenance_for(kind, key) is not None

    def audit(self) -> list[AuditEntry]:
        """Every rule that has provenance, for review.

        Sorted by `(kind, key)` so a diff between two audits is stable and readable
        rather than dependent on dict ordering.
        """
        with self._lock:
            items = sorted(self._provenance.items())
        return [AuditEntry(kind=k, key=key, provenance=p) for (k, key), p in items]

    # ---------- IP blocking ----------

    def block_ip(self, ip: IPLike, *, provenance: Provenance | None = None) -> None:
        if isinstance(ip, str) and "/" in ip:
            # `--block-ip 10.0.0.0/8` is how most people will reach subnet
            # rules, so accept it here rather than rejecting a perfectly valid
            # CIDR on a flag named after IPs. Forwarded with its provenance, or
            # the subnet would land with no recorded origin.
            self.block_cidr(ip, provenance=provenance)
            return
        ip_int = _coerce_ip_int(ip)
        with self._lock:
            # Recorded before the idempotence check: re-declaring an existing rule
            # with new provenance is how an operator updates *who* vouched for it,
            # and it must not be swallowed by the early return.
            self._record(RuleKind.IP, _int_to_ip_str(ip_int), provenance)
            if ip_int in self._state.ips:
                return
            self._mutate(ips=self._state.ips | {ip_int})

    def unblock_ip(self, ip: IPLike) -> None:
        if isinstance(ip, str) and "/" in ip:
            self.unblock_cidr(ip)
            return
        ip_int = _coerce_ip_int(ip)
        with self._lock:
            self._record(RuleKind.IP, _int_to_ip_str(ip_int), None)
            if ip_int not in self._state.ips:
                return
            self._mutate(ips=self._state.ips - {ip_int})

    def is_ip_blocked(self, ip: IPLike) -> bool:
        return self.snapshot().is_ip_blocked(ip)

    def get_blocked_ips(self) -> list[str]:
        return self.snapshot().blocked_ips

    # ---------- CIDR / subnet blocking (D-20) ----------

    def block_cidr(self, cidr: str, *, provenance: Provenance | None = None) -> None:
        """Blocks every address in `a.b.c.d/len`, as one rule.

        Grouped by prefix length rather than held as `ipaddress` objects, so
        matching on the packet path is a shift plus a set lookup per distinct
        prefix length present -- independent of how many networks are
        registered. See `_network_match`.

        Idempotent: re-registering a subnet that is already present leaves the
        state untouched, so it does not bump the snapshot version and does not
        spuriously wake a live-rules consumer. Provenance is still updated in that
        case, because declaring a rule that already exists with a new author is a
        legitimate act.
        """
        prefix_length, network_bits = _parse_cidr(cidr)
        with self._lock:
            self._record(RuleKind.CIDR, cidr, provenance)
            grouped = dict(self._state.networks)
            existing = grouped.get(prefix_length, frozenset())
            if network_bits in existing:
                return
            grouped[prefix_length] = existing | {network_bits}
            self._mutate(networks=tuple(sorted(grouped.items())))

    def unblock_cidr(self, cidr: str) -> None:
        prefix_length, network_bits = _parse_cidr(cidr)
        with self._lock:
            self._record(RuleKind.CIDR, cidr, None)
            grouped = dict(self._state.networks)
            existing = grouped.get(prefix_length)
            if not existing or network_bits not in existing:
                return
            remaining = existing - {network_bits}
            if remaining:
                grouped[prefix_length] = remaining
            else:
                # Drop the prefix-length bucket entirely when it empties, so a
                # lookup never walks a key that would only ever miss.
                del grouped[prefix_length]
            self._mutate(networks=tuple(sorted(grouped.items())))

    def is_cidr_blocked(self, cidr: str) -> bool:
        prefix_length, network_bits = _parse_cidr(cidr)
        grouped = dict(self.snapshot().state.networks)
        return network_bits in grouped.get(prefix_length, frozenset())

    def get_blocked_cidrs(self) -> list[str]:
        return self.snapshot().blocked_cidrs

    # ---------- App blocking ----------

    def block_app(self, app: AppType, *, provenance: Provenance | None = None) -> None:
        if not isinstance(app, AppType):
            raise RuleManagerError(f"Invalid app rule {app!r}: expected an AppType")
        with self._lock:
            # Keyed by `AppType.name`, the stable identifier `D-16` introduced --
            # never the display name, which is presentation copy and would detach
            # the provenance record the moment the product was reworded.
            self._record(RuleKind.APP, app.name, provenance)
            if app in self._state.apps:
                return
            self._mutate(apps=self._state.apps | {app})

    def unblock_app(self, app: AppType) -> None:
        with self._lock:
            self._record(RuleKind.APP, app.name, None)
            if app not in self._state.apps:
                return
            self._mutate(apps=self._state.apps - {app})

    def is_app_blocked(self, app: AppType) -> bool:
        return self.snapshot().is_app_blocked(app)

    def get_blocked_apps(self) -> list[AppType]:
        return self.snapshot().blocked_apps

    # ---------- Domain blocking ----------

    def block_domain(self, domain: str, *, provenance: Provenance | None = None) -> None:
        """Blocks an exact domain ("facebook.com") or a wildcard
        ("*.facebook.com"). Raises RuleManagerError for an unsupported
        pattern shape rather than storing a rule that can never match."""
        pattern = DomainPattern.parse(domain)
        with self._lock:
            self._record(RuleKind.DOMAIN, pattern.raw, provenance)
            if pattern.suffix is None:
                if pattern.raw in self._state.exact_domains:
                    return
                self._mutate(exact_domains=self._state.exact_domains | {pattern.raw})
            else:
                if any(p.raw == pattern.raw for p in self._state.patterns):
                    return
                self._mutate(patterns=(*self._state.patterns, pattern))

    def unblock_domain(self, domain: str) -> None:
        pattern = DomainPattern.parse(domain)
        with self._lock:
            self._record(RuleKind.DOMAIN, pattern.raw, None)
            if pattern.suffix is None:
                if pattern.raw not in self._state.exact_domains:
                    return
                self._mutate(exact_domains=self._state.exact_domains - {pattern.raw})
            else:
                remaining = tuple(p for p in self._state.patterns if p.raw != pattern.raw)
                if len(remaining) == len(self._state.patterns):
                    return
                self._mutate(patterns=remaining)

    def is_domain_blocked(self, domain: str) -> bool:
        return self.snapshot().is_domain_blocked(domain)

    def get_blocked_domains(self) -> list[str]:
        return self.snapshot().blocked_domains

    # ---------- Port blocking ----------

    def block_port(self, port: int | str, *, provenance: Provenance | None = None) -> None:
        port_int = _normalize_port(port)
        with self._lock:
            self._record(RuleKind.PORT, port_int, provenance)
            if port_int in self._state.ports:
                return
            self._mutate(ports=self._state.ports | {port_int})

    def unblock_port(self, port: int | str) -> None:
        port_int = _normalize_port(port)
        with self._lock:
            self._record(RuleKind.PORT, port_int, None)
            if port_int not in self._state.ports:
                return
            self._mutate(ports=self._state.ports - {port_int})

    def is_port_blocked(self, port: int) -> bool:
        return self.snapshot().is_port_blocked(port)

    def get_blocked_ports(self) -> list[int]:
        return self.snapshot().blocked_ports

    # ---------- Combined check (convenience over snapshot()) ----------

    def should_block(
        self,
        src_ip: IPLike,
        dst_port: int,
        app: AppType,
        domain: str = "",
        *,
        dst_ip: IPLike | None = None,
    ) -> BlockReason | None:
        # A second copy of this signature, and the one `worker.process` actually
        # calls. Adding a parameter to only the snapshot-level method would have
        # left `D-21` open in every real run while the unit tests, which go
        # through `RuleManager` directly, reported it fixed -- so both are
        # declared and this forwards.
        return self.snapshot().should_block(src_ip, dst_port, app, domain, dst_ip=dst_ip)

    # ---------- Bulk operations ----------

    def clear_all(self) -> None:
        with self._lock:
            if self._state == _RuleState():
                return
            self._state = _RuleState()
            self._version += 1

    def apply_delta(self, delta: RuleDelta) -> None:
        """Applies a batch of add/remove operations atomically.

        This is the primitive an admin/API layer wants for "update the rules"
        operations: either every requested change lands, or (because each
        item is validated before any state is swapped) none of them do.

        Recognised keys, each a mapping of value -> bool (True = add,
        False = remove): "ips", "apps", "domains", "ports".

        Each category is normalised into its own typed local *before* the lock
        is taken, rather than into one heterogeneous container. That keeps the
        validation pass obviously separate from the state swap, and keeps every
        value statically typed.
        """
        ip_changes: set[tuple[int, bool]] = set()
        app_changes: set[tuple[AppType, bool]] = set()
        domain_changes: set[tuple[DomainPattern, bool]] = set()
        port_changes: set[tuple[int, bool]] = set()

        for key, values in delta.items():
            match key:
                case "ips":
                    ip_changes = {(_coerce_ip_int(v), add) for v, add in values.items()}
                case "apps":
                    for value, add in values.items():
                        if not isinstance(value, AppType):
                            raise RuleManagerError(
                                f"Invalid app rule {value!r}: expected an AppType"
                            )
                        app_changes.add((value, add))
                case "domains":
                    domain_changes = {
                        (DomainPattern.parse(v), add) for v, add in values.items()
                    }
                case "ports":
                    port_changes = {(_normalize_port(v), add) for v, add in values.items()}
                case _:
                    raise RuleManagerError(
                        f"Unknown rule category {key!r}. Expected one of: "
                        "ips, apps, domains, ports"
                    )

        with self._lock:
            state = self._state
            ips = set(state.ips)
            apps = set(state.apps)
            exact = set(state.exact_domains)
            patterns = list(state.patterns)
            ports = set(state.ports)

            for ip, add in ip_changes:
                if add:
                    ips.add(ip)
                else:
                    ips.discard(ip)
            for app, add in app_changes:
                if add:
                    apps.add(app)
                else:
                    apps.discard(app)
            for pattern, add in domain_changes:
                if pattern.suffix is None:
                    if add:
                        exact.add(pattern.raw)
                    else:
                        exact.discard(pattern.raw)
                elif add:
                    if not any(p.raw == pattern.raw for p in patterns):
                        patterns.append(pattern)
                else:
                    patterns[:] = [p for p in patterns if p.raw != pattern.raw]
            for port, add in port_changes:
                if add:
                    ports.add(port)
                else:
                    ports.discard(port)

            new_state = _RuleState(
                ips=frozenset(ips),
                apps=frozenset(apps),
                exact_domains=frozenset(exact),
                patterns=tuple(patterns),
                ports=frozenset(ports),
            )
            if new_state != state:
                self._state = new_state
                self._version += 1

    # ---------- Persistence ----------

    def to_dict(self) -> dict[str, object]:
        """Serialises the rule set, including provenance when there is any.

        The `provenance` key is **omitted entirely** when no rule has any, rather
        than emitted as an empty object. Every rules file written before `T1-04`
        has no such key, so omitting it keeps `save_rules` output byte-identical for
        the overwhelmingly common case of rules with no recorded origin -- which
        also keeps this change invisible to anything diffing rules files.
        """
        document = self.snapshot().to_dict()
        with self._lock:
            records = dict(self._provenance)
        if records:
            grouped: dict[str, dict[str, object]] = {}
            for (kind, key), prov in records.items():
                grouped.setdefault(kind.value, {})[key] = prov.to_dict()
            document["provenance"] = grouped
        return document

    def save_rules(self, path: str | Path) -> None:
        """Writes rules as JSON. Raises RuleManagerError if the file cannot be
        written."""
        try:
            Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        except OSError as exc:
            raise RuleManagerError(f"Cannot write rules file '{path}': {exc}") from exc

    @classmethod
    def load_rules(cls, path: str | Path) -> RuleManager:
        """Reads rules from JSON into a new manager.

        Raises RuleManagerError (never a bare JSONDecodeError/ValueError) on a
        missing, unreadable, or malformed rules file -- the direct fix for the
        original's unguarded `stoi` crash-on-malformed-input bug.
        """
        try:
            raw = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise RuleManagerError(f"Cannot read rules file '{path}': {exc}") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuleManagerError(f"Rules file '{path}' is not valid JSON: {exc}") from exc

        return cls.from_dict(data, source=path)

    @classmethod
    def from_dict(cls, data: object, *, source: str | Path = "<dict>") -> RuleManager:
        """Builds a manager from an already-decoded rules document.

        `source` is only used to make error messages point at the file the
        bad value came from.
        """
        if not isinstance(data, dict):
            raise RuleManagerError(f"Rules file '{source}' must contain a JSON object")

        manager = cls()
        try:
            manager.apply_delta(
                {
                    "ips": {ip: True for ip in data.get("blocked_ips", [])},
                    "apps": {
                        resolve_app_key(name): True for name in data.get("blocked_apps", [])
                    },
                    "domains": {d: True for d in data.get("blocked_domains", [])},
                    "ports": {port: True for port in data.get("blocked_ports", [])},
                }
            )
            # domain_patterns is written separately by to_dict() but may
            # legitimately be absent from hand-written files.
            manager.apply_delta(
                {"domains": {p: True for p in data.get("domain_patterns", [])}}
            )
            # Subnets are their own key because a /8 is not an address, and
            # they go through `block_cidr` so there is exactly one CIDR parser
            # (`D-20`). Absent from every file written before this existed,
            # which is why it is a `get` rather than a required field.
            for cidr in data.get("blocked_cidrs", []):
                manager.block_cidr(str(cidr))
        except RuleManagerError as exc:
            raise RuleManagerError(f"Rules file '{source}': {exc}") from exc

        manager._load_provenance(data.get("provenance"))
        return manager

    def _load_provenance(self, raw: object) -> None:
        """Restores provenance records, tolerating anything unreadable.

        A rule with an unusable provenance record keeps the rule and loses the
        origin. That asymmetry is deliberate and is the important judgement here:
        the rules are the load-bearing thing, and provenance is the audit trail.
        Failing the whole file because one audit entry is malformed would mean a
        corrupt annotation could stop the operator blocking the traffic they asked
        to block -- and the gate would then report "no provenance" for a rule that
        is in force, which is the one answer `is_auto_appliable` must never give by
        accident.
        """
        if not isinstance(raw, dict):
            return
        with self._lock:
            for kind_name, entries in raw.items():
                try:
                    kind = RuleKind(kind_name)
                except ValueError:
                    # A kind this build does not know. Skipped rather than fatal:
                    # a newer file read by an older binary should still enforce the
                    # rules it does understand.
                    continue
                if not isinstance(entries, dict):
                    continue
                for key, record in entries.items():
                    prov = Provenance.from_dict(record)
                    if prov is not None:
                        self._provenance[(kind, self._normalise_key(kind, key))] = prov

    # ---------- Statistics ----------

    def get_stats(self) -> RuleStats:
        return self.snapshot().get_stats()


def ruleset_fingerprint(ruleset: object) -> str:
    """A stable fingerprint of the rules document a run was produced with.

    The store wants a caller-supplied fingerprint and will not invent one, because
    a hash of "whatever was loaded" looks authoritative while being unable to see
    a rule added to a live `RuleManager` mid-run. This hashes the *document the
    caller sent*, which is exactly what was in force. No rules is the empty
    string, not a hash of `null`.

    One home for it, because two callers produce stored runs -- the MCP layer's
    `run_dpi` and the engine's own `dpi-engine run --store-root` -- and two
    hashes of the same document would be two facts.
    """
    if ruleset is None:
        return ""
    canonical = json.dumps(ruleset, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
