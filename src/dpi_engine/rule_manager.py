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

import ipaddress
import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum, auto
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

    def stats(self) -> RuleStats:
        # Mirrors OSC's getStats(): blocked_domains counts exact rules plus
        # wildcard patterns.
        return RuleStats(
            blocked_ips=len(self.ips),
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
    ) -> BlockReason | None:
        """Returns the first matching rule, or None.

        Checked in OSC's exact priority order: IP, then port, then app, then
        domain (rule_manager.cpp:209-236). "First" is meaningful -- a flow can
        match several categories, and the reported reason should be the most
        specific one, in this fixed order.

        `src_ip` may be an int (host-order uint32, as the packet parser
        produces) or a string. The int form is preferred on hot paths; the
        string form validates and raises `RuleManagerError` if malformed.
        """
        state = self.state

        ip_int = _coerce_ip_int(src_ip)
        if ip_int in state.ips:
            return BlockReason(BlockReasonType.IP, _int_to_ip_str(ip_int))

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
        return _coerce_ip_int(src_ip) in self.state.ips

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
            "blocked_apps": sorted(_TYPE_TO_APP_NAME[a] for a in state.apps),
            "blocked_domains": sorted(state.exact_domains),
            "domain_patterns": [p.raw for p in state.patterns],
            "blocked_ports": sorted(state.ports),
        }

    @property
    def blocked_ips(self) -> list[str]:
        return [_int_to_ip_str(ip) for ip in sorted(self.state.ips)]

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
    """
    app = _APP_NAME_TO_TYPE.get(name) or _APP_NAME_TO_TYPE_LOOKUP.get(name.strip().lower())
    if app is None:
        valid = ", ".join(sorted(_APP_NAME_TO_TYPE))
        raise RuleManagerError(f"Unknown app name '{name}'. Valid names: {valid}")
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

    # ---------- IP blocking ----------

    def block_ip(self, ip: IPLike) -> None:
        ip_int = _coerce_ip_int(ip)
        with self._lock:
            if ip_int in self._state.ips:
                return
            self._mutate(ips=self._state.ips | {ip_int})

    def unblock_ip(self, ip: IPLike) -> None:
        ip_int = _coerce_ip_int(ip)
        with self._lock:
            if ip_int not in self._state.ips:
                return
            self._mutate(ips=self._state.ips - {ip_int})

    def is_ip_blocked(self, ip: IPLike) -> bool:
        return self.snapshot().is_ip_blocked(ip)

    def get_blocked_ips(self) -> list[str]:
        return self.snapshot().blocked_ips

    # ---------- App blocking ----------

    def block_app(self, app: AppType) -> None:
        if not isinstance(app, AppType):
            raise RuleManagerError(f"Invalid app rule {app!r}: expected an AppType")
        with self._lock:
            if app in self._state.apps:
                return
            self._mutate(apps=self._state.apps | {app})

    def unblock_app(self, app: AppType) -> None:
        with self._lock:
            if app not in self._state.apps:
                return
            self._mutate(apps=self._state.apps - {app})

    def is_app_blocked(self, app: AppType) -> bool:
        return self.snapshot().is_app_blocked(app)

    def get_blocked_apps(self) -> list[AppType]:
        return self.snapshot().blocked_apps

    # ---------- Domain blocking ----------

    def block_domain(self, domain: str) -> None:
        """Blocks an exact domain ("facebook.com") or a wildcard
        ("*.facebook.com"). Raises RuleManagerError for an unsupported
        pattern shape rather than storing a rule that can never match."""
        pattern = DomainPattern.parse(domain)
        with self._lock:
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

    def block_port(self, port: int | str) -> None:
        port_int = _normalize_port(port)
        with self._lock:
            if port_int in self._state.ports:
                return
            self._mutate(ports=self._state.ports | {port_int})

    def unblock_port(self, port: int | str) -> None:
        port_int = _normalize_port(port)
        with self._lock:
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
    ) -> BlockReason | None:
        return self.snapshot().should_block(src_ip, dst_port, app, domain)

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
        return self.snapshot().to_dict()

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
                    "apps": {resolve_app_name(name): True for name in data.get("blocked_apps", [])},
                    "domains": {d: True for d in data.get("blocked_domains", [])},
                    "ports": {port: True for port in data.get("blocked_ports", [])},
                }
            )
            # domain_patterns is written separately by to_dict() but may
            # legitimately be absent from hand-written files.
            manager.apply_delta(
                {"domains": {p: True for p in data.get("domain_patterns", [])}}
            )
        except RuleManagerError as exc:
            raise RuleManagerError(f"Rules file '{source}': {exc}") from exc
        return manager

    # ---------- Statistics ----------

    def get_stats(self) -> RuleStats:
        return self.snapshot().get_stats()
