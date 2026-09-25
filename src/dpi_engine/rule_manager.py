"""IP / application / domain / port blocking rules, with JSON persistence.

Ports OSC/include/rule_manager.h + OSC/src/rule_manager.cpp to Python.

Fixes applied during the port (see DESIGN_DECISIONS.md "Bugs fixed"):
- IP parsing/validation: the original's hand-rolled parseIP silently
  mis-parsed malformed strings (no octet range check, no length check) --
  e.g. "999.1.1.1" or "10.0.1" would parse into *some* uint32 with no error.
  This port uses the stdlib `ipaddress` module, which raises a clear,
  catchable ValueError on any malformed address instead of silently
  corrupting the rule.
- Domain case-sensitivity: the original's exact-match domain set was never
  case-normalized, while its wildcard pattern matching *was* lowercased
  before comparison -- so blocking "Example.com" would NOT match a lookup
  for "example.com" via the exact-match path, while the equivalent wildcard
  rule would. This let a case-swap bypass exact-domain blocking. This port
  lowercases every domain and pattern consistently at insertion and lookup
  time, everywhere.
- Rules file format: the original's hand-rolled INI-like parser called
  `std::stoi` directly on port lines with no exception handling -- a
  malformed/corrupted rules file (e.g. a non-numeric line under
  [BLOCKED_PORTS]) would throw uncaught and crash the entire process. This
  port uses JSON (via the stdlib `json` module) for both save and load, and
  wraps all value coercion (port range, IP format, app name) in explicit
  validation that raises a clear, catchable RuleManagerError instead of
  propagating a raw parser exception.

Threading model note: the original protected each rule category with its
own std::shared_mutex because rules could be mutated by one thread (e.g. a
CLI/admin interface) while FP threads read them concurrently. This port's
architecture (see DESIGN_DECISIONS.md "Architecture") loads rules once in
the main process and passes an immutable snapshot to each worker process at
startup -- rule mutation during a run is out of scope for v1. Because of
this, RuleManager itself does not need any locking: within a single process
it's just a plain mutable object used before workers start, and each worker
process gets its own independent copy (via multiprocessing's pickling),
which is safe as long as no worker calls a mutating method (they don't --
see Task 10's worker.py, which only calls should_block()).
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional

from dpi_engine.types import AppType, app_type_to_string


class RuleManagerError(Exception):
    """Raised for invalid rule values (bad IP, out-of-range port) or
    unreadable/malformed rules files. Always raised in place of letting a
    lower-level parsing exception (ValueError from int()/ipaddress, JSON
    decode errors) propagate unexplained.
    """


class BlockReasonType(Enum):
    IP = auto()
    APP = auto()
    DOMAIN = auto()
    PORT = auto()


@dataclass(frozen=True, slots=True)
class BlockReason:
    """Mirrors OSC's RuleManager::BlockReason."""

    type: BlockReasonType
    detail: str


@dataclass(frozen=True, slots=True)
class RuleStats:
    """Mirrors OSC's RuleManager::RuleStats."""

    blocked_ips: int
    blocked_apps: int
    blocked_domains: int
    blocked_ports: int


_APP_NAME_TO_TYPE: dict[str, AppType] = {app_type_to_string(a): a for a in AppType}

MIN_PORT = 0
MAX_PORT = 65535


def _normalize_ip(ip: str) -> str:
    """Validates and normalizes an IPv4 address string.

    Raises RuleManagerError (never a bare ValueError) on anything that
    isn't a valid dotted-quad IPv4 address -- this is the direct fix for
    the original's unvalidated parseIP.
    """
    try:
        return str(ipaddress.IPv4Address(ip))
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise RuleManagerError(f"Invalid IPv4 address '{ip}': {exc}") from exc


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


def _domain_matches_pattern(lower_domain: str, lower_pattern: str) -> bool:
    """Mirrors OSC's domainMatchesPattern: `*.example.com` matches any
    subdomain of example.com AND the bare apex domain example.com itself.
    Both arguments must already be lowercased by the caller.
    """
    if not (len(lower_pattern) >= 2 and lower_pattern[0] == "*" and lower_pattern[1] == "."):
        return False

    suffix = lower_pattern[1:]  # ".example.com"
    if lower_domain.endswith(suffix):
        return True

    bare = lower_pattern[2:]  # "example.com"
    return lower_domain == bare


class RuleManager:
    """Manages IP/app/domain/port blocking rules.

    Not thread-safe by design -- see module docstring "Threading model
    note". Intended usage: build/load rules in the main process before
    starting workers, then treat the instance as read-only.
    """

    def __init__(self) -> None:
        self._blocked_ips: set[str] = set()
        self._blocked_apps: set[AppType] = set()
        self._blocked_domains: set[str] = set()  # lowercased exact matches
        self._domain_patterns: list[str] = []  # lowercased wildcard patterns
        self._blocked_ports: set[int] = set()

    # ---------- IP blocking ----------

    def block_ip(self, ip: str) -> None:
        self._blocked_ips.add(_normalize_ip(ip))

    def unblock_ip(self, ip: str) -> None:
        self._blocked_ips.discard(_normalize_ip(ip))

    def is_ip_blocked(self, ip: str) -> bool:
        return _normalize_ip(ip) in self._blocked_ips

    def get_blocked_ips(self) -> list[str]:
        return sorted(self._blocked_ips)

    # ---------- App blocking ----------

    def block_app(self, app: AppType) -> None:
        self._blocked_apps.add(app)

    def unblock_app(self, app: AppType) -> None:
        self._blocked_apps.discard(app)

    def is_app_blocked(self, app: AppType) -> bool:
        return app in self._blocked_apps

    def get_blocked_apps(self) -> list[AppType]:
        return sorted(self._blocked_apps, key=lambda a: a.name)

    # ---------- Domain blocking ----------

    def block_domain(self, domain: str) -> None:
        lower = domain.lower()
        if "*" in lower:
            if lower not in self._domain_patterns:
                self._domain_patterns.append(lower)
        else:
            self._blocked_domains.add(lower)

    def unblock_domain(self, domain: str) -> None:
        lower = domain.lower()
        if "*" in lower:
            if lower in self._domain_patterns:
                self._domain_patterns.remove(lower)
        else:
            self._blocked_domains.discard(lower)

    def is_domain_blocked(self, domain: str) -> bool:
        if not domain:
            return False
        lower_domain = domain.lower()

        if lower_domain in self._blocked_domains:
            return True

        return any(_domain_matches_pattern(lower_domain, p) for p in self._domain_patterns)

    def get_blocked_domains(self) -> list[str]:
        return sorted(self._blocked_domains) + list(self._domain_patterns)

    # ---------- Port blocking ----------

    def block_port(self, port: int | str) -> None:
        self._blocked_ports.add(_normalize_port(port))

    def unblock_port(self, port: int | str) -> None:
        self._blocked_ports.discard(_normalize_port(port))

    def is_port_blocked(self, port: int) -> bool:
        return port in self._blocked_ports

    def get_blocked_ports(self) -> list[int]:
        return sorted(self._blocked_ports)

    # ---------- Combined check ----------

    def should_block(
        self,
        src_ip: str,
        dst_port: int,
        app: AppType,
        domain: str,
    ) -> Optional[BlockReason]:
        """Mirrors OSC's shouldBlock. Checked in the same priority order:
        IP, then port, then app, then domain."""
        if self.is_ip_blocked(src_ip):
            return BlockReason(BlockReasonType.IP, _normalize_ip(src_ip))

        if self.is_port_blocked(dst_port):
            return BlockReason(BlockReasonType.PORT, str(dst_port))

        if self.is_app_blocked(app):
            return BlockReason(BlockReasonType.APP, app_type_to_string(app))

        if domain and self.is_domain_blocked(domain):
            return BlockReason(BlockReasonType.DOMAIN, domain)

        return None

    # ---------- Persistence ----------

    def to_dict(self) -> dict:
        return {
            "blocked_ips": self.get_blocked_ips(),
            "blocked_apps": [app_type_to_string(a) for a in self.get_blocked_apps()],
            "blocked_domains": sorted(self._blocked_domains),
            "domain_patterns": list(self._domain_patterns),
            "blocked_ports": self.get_blocked_ports(),
        }

    def save_rules(self, path: str | Path) -> None:
        """Writes rules as JSON. Raises RuleManagerError if the file cannot
        be written (mirrors the original returning false on open failure,
        but with an actual error message instead of a bare bool)."""
        try:
            Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        except OSError as exc:
            raise RuleManagerError(f"Cannot write rules file '{path}': {exc}") from exc

    @classmethod
    def load_rules(cls, path: str | Path) -> "RuleManager":
        """Reads rules from JSON. Raises RuleManagerError (never a bare
        JSONDecodeError/ValueError) on a missing, unreadable, or malformed
        rules file -- this is the direct fix for the original's unguarded
        std::stoi crash-on-malformed-input bug."""
        try:
            raw = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise RuleManagerError(f"Cannot read rules file '{path}': {exc}") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuleManagerError(f"Rules file '{path}' is not valid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise RuleManagerError(f"Rules file '{path}' must contain a JSON object")

        manager = cls()

        for ip in data.get("blocked_ips", []):
            manager.block_ip(ip)

        for app_name in data.get("blocked_apps", []):
            app = _APP_NAME_TO_TYPE.get(app_name)
            if app is None:
                raise RuleManagerError(
                    f"Rules file '{path}' contains unknown app name '{app_name}'"
                )
            manager.block_app(app)

        for domain in data.get("blocked_domains", []):
            manager.block_domain(domain)

        for pattern in data.get("domain_patterns", []):
            manager.block_domain(pattern)

        for port in data.get("blocked_ports", []):
            manager.block_port(port)

        return manager

    def clear_all(self) -> None:
        self._blocked_ips.clear()
        self._blocked_apps.clear()
        self._blocked_domains.clear()
        self._domain_patterns.clear()
        self._blocked_ports.clear()

    def get_stats(self) -> RuleStats:
        return RuleStats(
            blocked_ips=len(self._blocked_ips),
            blocked_apps=len(self._blocked_apps),
            blocked_domains=len(self._blocked_domains) + len(self._domain_patterns),
            blocked_ports=len(self._blocked_ports),
        )
