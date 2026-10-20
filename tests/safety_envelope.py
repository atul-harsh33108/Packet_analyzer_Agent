"""Safety-envelope model and an AST-based forbidden-call scanner (`T2-03`).

**Why this exists.** `tests/test_safety_constraints.py` scanned shipped source with
*regular expressions over raw text*. That is not an AST scan, despite what
`DESIGN_DECISIONS.md` claimed. Measured against nine ordinary, working ways to reach
the network or a shell, it caught **one**:

    >>> MISSED  from urllib import request; request.urlopen(...)
    >>> MISSED  from subprocess import run; run([...])
    >>> MISSED  import subprocess as sp; sp.run([...])
    >>> MISSED  import socket as s; s.socket()
    >>> MISSED  from socket import socket; socket()
    >>> MISSED  __import__('os').system('id')
    >>> MISSED  getattr(__builtins__, 'eval')('1+1')
    >>> MISSED  from os import system; system('id')
    CAUGHT    from urllib.request import urlopen(...)

Which import spelling someone happens to use decided whether a network call was
reported. `A-03`'s complaint is exactly this: the "no network" guarantee "quietly
stops being true... and nothing will report it."

**The approach.** Resolve each module's imports into an alias map, then resolve every
call through it, so `import subprocess as sp; sp.run()` and `from subprocess import
run; run()` both resolve to `subprocess.run`. Static resolution cannot catch
deliberate obfuscation (`getattr(os, "system")` built at runtime from variables) and
this module does not pretend otherwise -- it catches *inadvertent* violations, which
is the realistic failure mode for a codebase where nobody is trying to smuggle a
socket past the test.

**Envelopes.** `A-03` requires the agent layer to be allowed network access as a
deliberate, documented widening, while the deterministic core stays offline. That
only means something if the widening is *bounded* and *named*, which is what
`Envelope` is for: each package under `src/` is assigned exactly one, and anything
its envelope still forbids is still enforced.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Envelope:
    """What a package is permitted to do.

    A `False` field is enforced by `scan_source`. A `True` field is a deliberate,
    documented widening -- never a default, and never inferred.
    """

    name: str
    #: May make outbound network calls (HTTP fetches, DNS, threat-intel lookups).
    network: bool = False
    #: May open raw sockets / sniff a live interface. Never permitted for any layer:
    #: `AUDIT.md` A-03 holds that "real time" can never mean sniffing an interface.
    live_capture: bool = False
    #: May eval/exec dynamically.
    dynamic_exec: bool = False
    #: May shell out via subprocess.
    subprocess: bool = False

    def forbids(self) -> dict[str, bool]:
        return {
            "network": not self.network,
            "live_capture": not self.live_capture,
            "dynamic_exec": not self.dynamic_exec,
            "subprocess": not self.subprocess,
        }


#: The deterministic core. Offline, passive, file-based. This is the existing
#: `DESIGN_DECISIONS.md` envelope, unchanged -- the widening must not touch it.
OFFLINE_CORE = Envelope("OFFLINE_CORE")

#: The agent layer (Phases 3-5). Network access is *permitted here only*, because
#: threat-intel lookups, ASN resolution and app identification need it. Everything
#: else is still refused: no raw sockets, no sniffing, no dynamic execution, no
#: shelling out. An agent that could open a raw socket could forge traffic, and one
#: that could `eval` could execute whatever a lookup returned.
NETWORKED_AGENT = Envelope("NETWORKED_AGENT", network=True)

#: Every shipped package under `src/` and the envelope it is held to.
#:
#: This mapping is the load-bearing part of `A-03`. The old scanner hardcoded one
#: path, so adding `src/agents/` left the existing test passing while half the
#: shipped tree went uninspected. A test asserts every package on disk has an entry
#: here, which turns that silent gap into a failing test at the moment the second
#: package is created.
#:
#: It has now fired once for real: creating `src/dpi_mcp/` for Phase 3 failed
#: `test_every_shipped_package_declares_an_envelope` until the declaration below was
#: added, which is the intended behaviour rather than an obstacle.
PACKAGE_ENVELOPES: dict[str, Envelope] = {
    "dpi_engine": OFFLINE_CORE,
    # Phase 3's MCP tool surface (Layer 2). OFFLINE_CORE, not NETWORKED_AGENT,
    # because it serves **stdio** only: the client is a local host process and the
    # server's entire I/O surface is inherited pipes. Adding Streamable HTTP
    # (`DEC-08` defers it) would require widening this to NETWORKED_AGENT plus an
    # auth surface in front of a policy engine.
    "dpi_mcp": OFFLINE_CORE,
}

#: Capability -> the dotted call prefixes that violate it.
#:
#: Matched against *resolved* dotted names, so aliases and from-imports collapse
#: onto the canonical form.
_CAPABILITY_RULES: dict[str, tuple[str, ...]] = {
    "network": (
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "urllib.request.Request",
        "urllib.request.OpenerDirector.open",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "requests.patch",
        "requests.request",
        "httpx.get",
        "httpx.post",
        "httpx.request",
        "aiohttp.ClientSession",
        "ftplib.FTP",
        "smtplib.SMTP",
        "telnetlib.Telnet",
        "xmlrpc.client.ServerProxy",
        "asyncio.open_connection",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        # The `mcp` SDK's own HTTP stack (`DEC-09`, `T3-05`). The SDK is an
        # optional extra, and installing it does not make a network call
        # legal - it makes a network call *possible*, which is a different
        # thing and exactly the difference a gate exists to police. The
        # server is stdio-only, and these are the calls that would stop it
        # being so: an ASGI server to serve on, an app to serve, and the
        # SDK's two HTTP transports. `httpx2` is the HTTP client this SDK
        # version depends on; `httpx` above is the name it used to have.
        "uvicorn.run",
        "uvicorn.Server",
        "starlette.applications.Starlette",
        "sse_starlette.sse.EventSourceResponse",
        "sse_starlette.sse.App",
        "mcp.server.sse.SseServerTransport",
        "mcp.server.streamable_http_manager.StreamableHTTPSessionManager",
        "httpx2.get",
        "httpx2.post",
        "httpx2.put",
        "httpx2.delete",
        "httpx2.patch",
        "httpx2.request",
    ),
    "live_capture": (
        "socket.socket",
        "socket.create_connection",
        "socket.create_server",
        "scapy.sendp",
        "scapy.send",
        "scapy.sniff",
        "scapy.sendrecv",
        "scapy.sr",
        "scapy.sr1",
    ),
    "dynamic_exec": (
        "eval",
        "exec",
        "compile",
        "__import__",
        "builtins.eval",
        "builtins.exec",
        # These two are here because the text net used to catch them only as a side
        # effect of its `\b` bug: `builtins.compile(` read as a bare `compile(`. With
        # the bug fixed (`T3-08`) nothing else names them; `builtins.eval`/`exec` were
        # already listed, so this closes the same hole for the other two names.
        "builtins.compile",
        "builtins.__import__",
    ),
    "subprocess": (
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "os.system",
        "os.popen",
        "os.execv",
        "os.execve",
        "os.spawnl",
        "pty.spawn",
    ),
}

#: `X.foo` also violates `X.foo.bar`, but `urllib` alone does not -- importing urllib
#: to format a string is legitimate. Prefix matching is on full dotted segments.
_BARE_NAMES = {
    "dynamic_exec": {"eval", "exec", "compile", "__import__"},
    "subprocess": {"os.system", "os.popen"},
}


@dataclass(frozen=True)
class Violation:
    """One forbidden call, with where it was found."""

    path: str
    line: int
    capability: str
    resolved: str
    envelope: str


class _AliasResolver(ast.NodeVisitor):
    """Builds a map of locally-bound name -> canonical dotted path."""

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                # `import a.b.c` binds `a`.
                self.aliases[alias.name.split(".")[0]] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None or node.level:
            # Relative import: stays within the package, resolves fine.
            if node.level and node.module:
                for alias in node.names:
                    local = alias.asname or alias.name
                    self.aliases.setdefault(local, alias.name)
            return
        for alias in node.names:
            local = alias.asname or alias.name
            if alias.name == "*":
                # A star import can shadow anything, and this records the module --
                # but `resolve()` does not expand `"*"`, and the text net below needs
                # a literal `os.system(`, so `from os import *` + `system("id")` is
                # detected by **neither** pass. Recording it is not a defence; the gap
                # is `T3-08`'s first follow-up.
                self.aliases.setdefault("*", node.module)
                continue
            self.aliases[local] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    @staticmethod
    def _collapse_star_re_exports(resolved: str) -> str:
        """`scapy.all.sniff` -> `scapy.sniff`.

        `scapy.all` re-exports the whole package, so `from scapy.all import sniff`
        is the normal way anyone writes it and resolves to `scapy.all.sniff`. The
        capability rules name the canonical path, so the `all` hop has to come out
        or a live-capture call reads as an unrelated name.
        """
        head, _, tail = resolved.partition(".all.")
        if head and tail:
            return f"{head}.{tail}"
        return resolved

    def resolve(self, dotted: str) -> str:
        """Expands a dotted expression through the alias map where possible."""
        parts = dotted.split(".")
        head = parts[0]
        if head in self.aliases:
            target = self.aliases[head]
            # `import urllib.request` binds `urllib` -> `urllib.request`, so joining
            # the remaining segments would double up. Only extend when the alias is
            # not already a prefix of the expression.
            if dotted == target or dotted.startswith(target + "."):
                return dotted
            return f"{target}.{'.'.join(parts[1:])}" if len(parts) > 1 else target
        return dotted


def _dotted(node: ast.expr) -> str | None:
    """Renders `a.b.c()`'s callee as `a.b.c`, or None if it is not a static path."""
    parts: list[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return None
    parts.append(cur.id)
    return ".".join(reversed(parts))


def scan_source(
    source: str,
    envelope: Envelope,
    path: str = "<synthetic>",
) -> list[Violation]:
    """Returns every call in `source` that `envelope` forbids.

    Raises SyntaxError on unparseable input rather than returning an empty list: a
    scanner that silently finds nothing in a file it cannot parse is the exact
    vacuous-pass failure this whole task exists to prevent.
    """
    tree = ast.parse(source)

    resolver = _AliasResolver()
    resolver.visit(tree)

    forbidden = envelope.forbids()
    bare = {cap: _BARE_NAMES.get(cap, set()) for cap in forbidden if not forbidden[cap]}
    bare = {cap: names for cap, names in bare.items() if forbidden[cap]}

    found: list[Violation] = []
    seen: set[tuple[int, str, str]] = set()

    def record(capability: str, resolved: str, lineno: int) -> None:
        key = (lineno, capability, resolved)
        if key in seen:
            return
        seen.add(key)
        found.append(Violation(path, lineno, capability, resolved, envelope.name))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted(node.func)
        if dotted is None:
            continue
        resolved = _AliasResolver._collapse_star_re_exports(resolver.resolve(dotted))

        for capability, prefixes in _CAPABILITY_RULES.items():
            if not forbidden[capability]:
                continue
            if resolved in bare.get(capability, set()):
                record(capability, resolved, node.lineno)
                break
            for prefix in prefixes:
                # `subprocess.run` matches a call to it, and also `subprocess.run(...)`
                # reached via an attribute of the result.
                if resolved == prefix or resolved.startswith(prefix + "."):
                    record(capability, resolved, node.lineno)
                    break

    # Secondary net: regex over the raw text, so a call that is *written as text*
    # still trips -- the AST has no Call node for `COMMAND = "os.system('id')"`, and
    # `source` keeps string literals. It resolves nothing, so it can only name the
    # rule prefix, never the dotted callee.
    #
    # The left edge is `(?<![\w.])` rather than `\b`: a word boundary sits between
    # `.` and `c`, so `re.compile(` read as a bare `compile(` and every attribute call
    # in the tree violated its envelope (`D-28`). "Not preceded by a word character or
    # a dot" keeps `"os.system(` and `[os.system(` and drops `x.compile(`.
    #
    # Known gaps, in neither pass: a call reached through a value rather than a name.
    # `getattr(os, "system")(...)` has no `(` after the name and the AST sees an outer
    # Call on an inner one; `from os import *` + `system(...)` has no dotted path at
    # all. Both are recorded as follow-ups rather than papered over here.
    for capability, prefixes in _CAPABILITY_RULES.items():
        if not forbidden[capability]:
            continue
        for prefix in prefixes:
            pattern = re.compile(rf"(?<![\w.]){re.escape(prefix)}\s*\(")
            for m in pattern.finditer(source):
                record(
                    capability,
                    prefix,
                    source[: m.start()].count("\n") + 1,
                )

    return sorted(found, key=lambda v: (v.path, v.line, v.capability, v.resolved))


def shipped_packages(src_root: Path) -> set[str]:
    """Every importable package directory directly under `src/`.

    Deliberately only direct children with an `__init__.py`: a package nested two
    levels down inherits its top-level package's envelope, and scanning for nested
    ones here would demand an entry that the registry does not model.
    """
    return {
        d.name
        for d in src_root.iterdir()
        if d.is_dir() and (d / "__init__.py").exists()
    }
