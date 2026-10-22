"""The agent tree's own safety suite, plus the boundary that makes it mean
something (`T2-03`, closes `A-03`).

`A-03` states the problem precisely:

> The existing safety test scopes `src/dpi_engine/` only, the agent tree needs its
> own, separate safety suite. Without that, the "no network" guarantee quietly stops
> being true the moment agent code lands in the same repository, and nothing will
> report it.

and the shape of the fix:

> The agent layer *will* need network - threat-intel lookups, ASN resolution, web
> search for app identification. This is a deliberate, documented widening of the
> envelope for the agent layer only; the deterministic core stays offline.

**The failure mode this is built to prevent is silent scope reduction.** The old
scanner hardcoded one directory. Creating `src/agents/` would leave every existing
test green while half the shipped tree became uninspected - and since Phase 3 is
where the first agent lands, the gap would open at exactly the moment the guarantee
matters most. So the load-bearing test here is not "no network calls"; it is
`test_every_shipped_package_declares_an_envelope`, which fails the moment any
package exists without a declared envelope.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from safety_envelope import (
    NETWORKED_AGENT,
    OFFLINE_CORE,
    PACKAGE_ENVELOPES,
    Envelope,
    scan_source,
    shipped_packages,
)

SRC_ROOT = Path(__file__).resolve().parents[1] / "src"


def _package_dir(name: str) -> Path:
    return SRC_ROOT / name


def _py_files(pkg: str) -> list[Path]:
    return sorted(_package_dir(pkg).rglob("*.py"))


# ---------------------------------------------------------------------------
# The boundary itself: every shipped package is assigned an envelope
# ---------------------------------------------------------------------------


class TestEnvelopeCoverage:
    """The `A-03` fix proper."""

    def test_every_shipped_package_declares_an_envelope(self) -> None:
        """**The load-bearing test.**

        Any package on disk without a `PACKAGE_ENVELOPES` entry is an uninspected
        part of the shipped tree. When Phase 3 creates `src/agents/`, this fails and
        says so, rather than the existing suite continuing to pass over
        `src/dpi_engine/` while quietly ignoring everything else.

        The failure message is written for the person about to create the package,
        because that is exactly when it will be read.
        """
        on_disk = shipped_packages(SRC_ROOT)
        undeclared = sorted(on_disk - set(PACKAGE_ENVELOPES))
        stale = sorted(set(PACKAGE_ENVELOPES) - on_disk)

        assert not undeclared, (
            f"{len(undeclared)} shipped package(s) have no declared safety "
            f"envelope: {undeclared}. Every package under `src/` must appear in "
            "`safety_envelope.PACKAGE_ENVELOPES` with either OFFLINE_CORE (the "
            "deterministic core, offline) or NETWORKED_AGENT (the agent layer, "
            "permitted to make network calls deliberately). An undeclared package "
            "is not scanned by anything, which is precisely the silent gap A-03 "
            "describes."
        )
        assert not stale, (
            f"PACKAGE_ENVELOPES names {stale}, which do not exist under {SRC_ROOT}. "
            "A removed package left behind an envelope that no longer guards "
            "anything."
        )

    def test_the_core_is_held_to_the_offline_envelope(self) -> None:
        """`dpi_engine` must never be widened.

        The agent layer's network access is a widening *for that layer only*. If the
        deterministic engine were ever granted the same, the product would no longer
        have a passive/offline core at all - and `DESIGN_DECISIONS.md`'s envelope
        would be true only on paper.
        """
        assert PACKAGE_ENVELOPES["dpi_engine"] is OFFLINE_CORE
        for field in ("network", "live_capture", "dynamic_exec", "subprocess"):
            assert getattr(OFFLINE_CORE, field) is False, (
                f"OFFLINE_CORE.{field} is permissive; the deterministic core must "
                "stay passive and offline"
            )

    def test_the_agent_envelope_widens_network_only(self) -> None:
        """The widening must be exactly one capability wide.

        A permissive agent envelope is how "the agent layer may use the network"
        turns into "nothing is enforced any more". Specifically: no raw sockets (an
        agent that could open one could forge traffic), no dynamic execution (an
        agent that could `eval` could run whatever a threat-intel lookup returned),
        and no shelling out.
        """
        assert NETWORKED_AGENT.network is True
        assert NETWORKED_AGENT.live_capture is False, (
            "live capture is forbidden for every layer: AUDIT.md A-03 holds that "
            "'real time' can never mean sniffing an interface"
        )
        assert NETWORKED_AGENT.dynamic_exec is False
        assert NETWORKED_AGENT.subprocess is False

    def test_no_envelope_allows_live_capture(self) -> None:
        """Structural check, so adding a future envelope cannot quietly permit it.

        Individual assertions on `NETWORKED_AGENT` would not catch a *new* envelope
        that set `live_capture=True`; this does.
        """
        for name, env in PACKAGE_ENVELOPES.items():
            assert env.live_capture is False, (
                f"envelope for {name!r} permits live capture; no layer may"
            )

    def test_every_envelope_declares_itself(self) -> None:
        """A nameless envelope is unreportable in a failure message."""
        for name, env in PACKAGE_ENVELOPES.items():
            assert env.name, f"envelope for {name!r} has an empty name"
            assert isinstance(env, Envelope)


# ---------------------------------------------------------------------------
# The scanner must actually detect things
# ---------------------------------------------------------------------------
#
# Every assertion below is satisfied by a healthy run of the current tree, which is
# exactly why they cannot be left implicit: a scanner that finds nothing looks
# exactly like a scanner that cannot find anything. These force violations.


_CASES: list[tuple[str, str, str]] = [
    # (label, source, capability expected to be reported)
    ("urllib from-import", "from urllib import request\nrequest.urlopen('http://x')", "network"),
    ("urllib direct import", "from urllib.request import urlopen\nurlopen('http://x')", "network"),
    ("module import then call", "import urllib.request\nurllib.request.urlopen('http://x')", "network"),
    ("http.client", "import http.client\nhttp.client.HTTPSConnection('h')", "network"),
    ("requests", "import requests\nrequests.get('http://x')", "network"),
    ("subprocess from-import", "from subprocess import run\nrun(['id'])", "subprocess"),
    ("subprocess aliased", "import subprocess as sp\nsp.run(['id'])", "subprocess"),
    ("os.system aliased", "import os as o\no.system('id')", "subprocess"),
    ("os.system from-import", "from os import system\nsystem('id')", "subprocess"),
    ("socket aliased", "import socket as s\ns.socket()", "live_capture"),
    ("socket from-import", "from socket import socket\nsocket()", "live_capture"),
    ("scapy sendp", "from scapy.all import sendp\nsendp(pkt)", "live_capture"),
    ("eval", "eval('1+1')", "dynamic_exec"),
    ("exec", "exec('x=1')", "dynamic_exec"),
    ("compile", "compile('x', '<s>', 'exec')", "dynamic_exec"),
    ("dynamic import", "__import__('os').system('id')", "dynamic_exec"),
    # `D-29`: a call reached through a value rather than through a name.
    ("getattr value", "import os\ngetattr(os, 'system')('id')", "subprocess"),
    (
        "getattr value bound to a name",
        "import os\nf = getattr(os, 'system')\nf('id')",
        "subprocess",
    ),
    ("star import", "from os import *\nsystem('id')", "subprocess"),
    ("star import of subprocess", "from subprocess import *\nrun(['id'])", "subprocess"),
    (
        "getattr of a network call",
        "import urllib.request\ngetattr(urllib.request, 'urlopen')('http://x')",
        "network",
    ),
]


class TestScannerDetectsRealViolations:
    """The regression proof that the old regex scanner could not give.

    `test_safety_constraints.py` matched regular expressions against raw text. Run
    against the first eight of these, it reported **one**. Whichever import
    spelling someone happened to type decided whether a network call was caught.
    """

    @pytest.mark.parametrize(
        ("label", "source", "capability"), _CASES, ids=[c[0] for c in _CASES]
    )
    def test_violation_is_detected(self, label: str, source: str, capability: str) -> None:
        violations = scan_source(source, OFFLINE_CORE, path="<probe>")
        reported = {v.capability for v in violations}
        assert capability in reported, (
            f"{label}: expected a {capability!r} violation, got {sorted(reported) or 'nothing'}. "
            "The scanner resolved the call to "
            f"{[v.resolved for v in violations] or 'nothing at all'}."
        )

    def test_every_detection_names_a_line_and_a_path(self) -> None:
        """A violation nobody can locate is a violation nobody fixes."""
        violations = scan_source(
            "import requests\n\n\nrequests.get('http://x')", OFFLINE_CORE, path="probe.py"
        )
        assert violations, "expected a violation"
        v = violations[0]
        assert v.path == "probe.py"
        assert v.line == 4, f"reported line {v.line}, expected 4"
        assert v.envelope == "OFFLINE_CORE"
        assert v.resolved

    def test_clean_source_reports_nothing(self) -> None:
        """The other half: a scanner that reports everything is as useless as one
        that reports nothing, and would be turned off within a week."""
        clean = """
import json
from pathlib import Path

def load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))
"""
        assert scan_source(clean, OFFLINE_CORE) == []

    def test_unparseable_source_raises_rather_than_reporting_nothing(self) -> None:
        """A scanner that returns empty for a file it cannot parse is the exact
        vacuous pass `A-03` is about."""
        with pytest.raises(SyntaxError):
            scan_source("def broken(:\n  pass", OFFLINE_CORE)

    def test_a_networked_envelope_permits_the_network_call(self) -> None:
        """The widening must actually widen, or it is a lie in the other direction."""
        assert scan_source("import requests\nrequests.get('http://x')", NETWORKED_AGENT) == []

    @pytest.mark.parametrize(
        ("label", "source"),
        [
            ("socket", "import socket\nsocket.socket()"),
            ("scapy", "from scapy.all import sniff\nsniff()"),
            ("eval", "eval('1+1')"),
            ("exec", "exec('x=1')"),
            ("subprocess", "import subprocess\nsubprocess.run(['id'])"),
            ("os.system", "import os\nos.system('id')"),
        ],
    )
    def test_a_networked_envelope_still_refuses_everything_else(
        self, label: str, source: str
    ) -> None:
        """Permitting network must not have permitted anything by accident."""
        assert scan_source(source, NETWORKED_AGENT), (
            f"{label}: NETWORKED_AGENT should still refuse this; the agent envelope "
            "is meant to widen network access only"
        )


# ---------------------------------------------------------------------------
# `D-29` (`T3-11`): a call reached through a value
# ---------------------------------------------------------------------------
#
# `D-28` fixed the *text* net. `D-29` is the other half: the AST pass resolves a
# call through a **name** -- `import os` then `os.system(...)`, `from os import
# system` then `system(...)` -- and a call reached through a **value** has no
# name to resolve. `getattr(os, "system")(...)` is an outer call on an inner one,
# and `from os import *` + `system(...)` has no dotted path at all. Neither was
# caught by either pass, and both are ordinary ways to write the same call.
#
# The repair resolves the *spelling* as well as the name: a `getattr` call says
# which attribute it reaches for, and a star import makes every member of the
# imported module a candidate for a name the alias map could not place.


class TestACallReachedThroughAValue:
    @pytest.mark.parametrize(
        ("label", "source", "expected"),
        [
            ("getattr called directly", "import os\ngetattr(os, 'system')('id')", "os.system"),
            (
                "getattr bound to a name",
                "import os\nf = getattr(os, 'system')\nf('id')",
                "os.system",
            ),
            (
                "getattr of an aliased module",
                "import os as o\ngetattr(o, 'system')('id')",
                "os.system",
            ),
            ("star import", "from os import *\nsystem('id')", "os.system"),
            ("star import of subprocess", "from subprocess import *\nrun(['id'])", "subprocess.run"),
            (
                "getattr of a network call",
                "import urllib.request\ngetattr(urllib.request, 'urlopen')('http://x')",
                "urllib.request.urlopen",
            ),
        ],
    )
    def test_the_resolved_name_is_the_canonical_one(
        self, label: str, source: str, expected: str
    ) -> None:
        """Not merely "something was reported" -- the *name* is what a reader needs.

        A violation reported as `getattr` tells a reader nothing; a violation
        reported as `os.system` names the capability that was broken.
        """
        violations = scan_source(source, OFFLINE_CORE, path="<probe>")
        assert violations, f"{label}: nothing was reported"
        assert expected in {v.resolved for v in violations}, (
            f"{label}: expected the call to resolve to {expected!r}, got "
            f"{sorted(v.resolved for v in violations)}"
        )

    @pytest.mark.parametrize(
        ("label", "source"),
        [
            ("a getattr for a harmless attribute", "import os\np = getattr(os, 'getcwd')\nprint(p())"),
            ("a star import of a harmless module", "from pathlib import *\nPath('.').exists()"),
            ("a star import of os, calling something else", "from os import *\nprint(getcwd())"),
            (
                "an explicit import wins over the star guess",
                "from os import *\nfrom json import system\nsystem('id')",
            ),
        ],
    )
    def test_it_does_not_report_what_it_should_not(self, label: str, source: str) -> None:
        """A scanner that reports everything is turned off within a week.

        The star-import candidates are guesses, so they have to be *narrow*: a
        name the alias map could place is never guessed at.
        """
        assert scan_source(source, OFFLINE_CORE, path="<probe>") == [], (
            f"{label}: reported something it should not have"
        )

    def test_a_name_built_at_runtime_is_outside_what_the_scanner_claims(self) -> None:
        """The honest limit, asserted rather than implied.

        A module or attribute name assembled from variables at runtime cannot be
        resolved statically, and this scanner does not pretend otherwise: it
        catches the *inadvertent* violation, not the deliberate one. The
        assertion is here so the limit is a stated fact rather than a comment
        that drifts.
        """
        source = "import os\nname = 'sys' + 'tem'\ngetattr(os, name)('id')\n"
        assert scan_source(source, OFFLINE_CORE, path="<probe>") == []


# ---------------------------------------------------------------------------
# `D-28` (`T3-08`): an attribute call is not a bare call
# ---------------------------------------------------------------------------
#
# The net resolves nothing. It looks for a literal rule prefix followed by `(`, and
# `\b` looked like the right left edge -- but `\b` matches between `.` and `c`, so
# `re.compile(` was read as a bare `compile(` and every use of `re.compile` in the
# shipped tree violated `OFFLINE_CORE`. `run_store.py` avoided the module to stay
# green; a scanner that punishes the stdlib teaches people to spell calls
# differently, which is the evasion the scanner exists to catch.
#
# The repair is a negative lookbehind. It is not, however, a one-line repair:
# `builtins.compile(` and `builtins.__import__(` are also preceded by a dot, they are
# genuine `dynamic_exec` calls, and the net was the **only** thing catching them --
# `_CAPABILITY_RULES["dynamic_exec"]` lists `builtins.eval` and `builtins.exec` but
# not those two. So the lookbehind alone would have traded one false positive for
# two false negatives. Both directions are asserted here, and the resolved name is
# the assertion: a rule reports `builtins.compile`, the net can only report `compile`.

_PHANTOMS: list[tuple[str, str]] = [
    ("re.compile", 'import re\npattern = re.compile(r"[0-9]+")\n'),
    ("re.compile then used", 'import re\np = re.compile(r"a+")\nm = p.match("aaa")\n'),
    ("a method named compile", 'builder.compile("template")\n'),
    ("a method named eval", 'handler.eval("1+1")\n'),
    ("a method named exec", 'shell.exec("ls -la")\n'),
    ("a longer identifier ending in the name", "recompile(pattern)\n"),
]

#: Genuine calls whose left edge looks exactly like an attribute's.
_ATTRIBUTE_REACHABLE: list[tuple[str, str, str]] = [
    (
        "builtins.compile",
        'import builtins\nbuiltins.compile("x", "<s>", "exec")\n',
        "builtins.compile",
    ),
    (
        "builtins.compile via alias",
        'import builtins as b\nb.compile("x", "<s>", "exec")\n',
        "builtins.compile",
    ),
    ("builtins.__import__", 'import builtins\nbuiltins.__import__("os")\n', "builtins.__import__"),
    (
        "builtins.__import__ via alias",
        'import builtins as b\nb.__import__("os")\n',
        "builtins.__import__",
    ),
    ("builtins.eval", 'import builtins\nbuiltins.eval("1+1")\n', "builtins.eval"),
    ("builtins.exec", 'import builtins\nbuiltins.exec("x=1")\n', "builtins.exec"),
]


class TestAnAttributeCallIsNotABareCall:
    """`D-28`: the net must not invent a forbidden call out of an attribute."""

    @pytest.mark.parametrize(("label", "source"), _PHANTOMS, ids=[c[0] for c in _PHANTOMS])
    def test_an_attribute_call_is_not_reported(self, label: str, source: str) -> None:
        violations = scan_source(source, OFFLINE_CORE, path="<probe>")
        assert violations == [], (
            f"{label}: reported {[(v.capability, v.resolved) for v in violations]}. "
            "An attribute call is not the bare builtin it is named after."
        )

    @pytest.mark.parametrize(
        ("label", "source", "resolved"),
        _ATTRIBUTE_REACHABLE,
        ids=[c[0] for c in _ATTRIBUTE_REACHABLE],
    )
    def test_a_forbidden_call_behind_an_attribute_is_still_reported(
        self, label: str, source: str, resolved: str
    ) -> None:
        """The half the one-character fix would have dropped.

        Asserting the *resolved* name is what separates the rule from the net: the
        rule knows the call is `builtins.compile`, the net only knows the text ends
        in `compile(`. Pinning `compile` here would pass for the wrong reason.
        """
        violations = scan_source(source, OFFLINE_CORE, path="<probe>")
        reported = [(v.capability, v.resolved) for v in violations]
        assert reported == [("dynamic_exec", resolved)], (
            f"{label}: expected exactly dynamic_exec/{resolved}, got {reported or 'nothing'}"
        )

    def test_the_net_still_catches_a_call_assembled_as_text(self) -> None:
        """Non-vacuity for the net itself.

        After the repair the AST pass covers every executable spelling, so a blank
        `(?<!...)` that never matches would keep this file green. The net's remaining
        job is the call that is *built* rather than written: the AST sees a string,
        and the text still says `os.system(`. The left context there is a quote, so
        this also pins the lookbehind to "not a word character and not a dot" --
        whitespace-only would lose it.
        """
        source = """
import os

COMMAND = "os.system('id')"
"""
        violations = scan_source(source, OFFLINE_CORE, path="<probe>")
        reported = [(v.capability, v.resolved) for v in violations]
        assert reported == [("subprocess", "os.system")], (
            f"expected the text net to report os.system, got {reported or 'nothing'}"
        )


def _imported_modules(source: str) -> set[str]:
    """Every module named by an import in `source`, fully qualified."""
    tree = ast.parse(source)
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            modules.add(node.module)
    return modules


# ---------------------------------------------------------------------------
# `DEC-09`: the SDK's dependency tree is not a licence to open a socket
# ---------------------------------------------------------------------------
#
# The SDK is an optional extra that installs an ASGI server, a web framework and
# an HTTP client. Installing it does not make a network call legal - it makes one
# *possible*, and the difference between those two is exactly what a gate
# exists to police. The server is stdio-only, so the calls that would stop it
# being so are network calls.

_HTTP_CALLS: list[tuple[str, str]] = [
    ("uvicorn.run", "import uvicorn\nuvicorn.run(app)"),
    ("uvicorn.Server", "from uvicorn import Server\nServer(config)"),
    (
        "starlette app",
        "import starlette.applications\nstarlette.applications.Starlette(routes=[])",
    ),
    (
        "sse response",
        "from sse_starlette.sse import EventSourceResponse\nEventSourceResponse([])",
    ),
    (
        "mcp sse transport",
        "from mcp.server.sse import SseServerTransport\nSseServerTransport('/messages/')",
    ),
    (
        "mcp streamable http manager",
        "from mcp.server.streamable_http_manager import StreamableHTTPSessionManager\n"
        "StreamableHTTPSessionManager()",
    ),
    ("httpx2 get", "import httpx2\nhttpx2.get('http://x')"),
]


class TestTheHttpStackIsANetworkCapability:
    """`DEC-09`: the calls that would make this tree a network service."""

    @pytest.mark.parametrize(
        ("label", "source"), _HTTP_CALLS, ids=[c[0] for c in _HTTP_CALLS]
    )
    def test_it_is_reported_as_a_network_call(self, label: str, source: str) -> None:
        violations = scan_source(source, OFFLINE_CORE, path="<probe>")
        assert "network" in {v.capability for v in violations}, (
            f"{label}: expected a network violation, got "
            f"{[(v.capability, v.resolved) for v in violations] or 'nothing'}. "
            "The SDK installs this stack; nothing here may call it."
        )


class TestTheServerCannotBecomeANetworkServer:
    """`DEC-09`: stdio only, enforced at the import level too.

    The scanner checks *calls*. This checks *imports*, for the one file allowed
    to import the SDK at all: the SDK's HTTP transports are **modules**, so
    importing one is how a stdio server becomes a network server without a
    single call that a call-based rule would notice.
    """

    def test_the_server_imports_only_the_stdio_modules(self) -> None:
        source = (SRC_ROOT / "dpi_mcp" / "server.py").read_text(encoding="utf-8")
        imported = _imported_modules(source)
        sdk_modules = {name for name in imported if name == "mcp" or name.startswith("mcp.")}
        assert sdk_modules, "the server must import the SDK it serves"
        for name in sdk_modules:
            assert name in {"mcp.server", "mcp.server.stdio", "mcp.types"}, (
                f"{name} is not a stdio module. The SDK's HTTP transports are how a "
                "stdio server becomes a network server, and importing one is enough."
            )

    def test_the_server_does_not_import_the_asgi_stack(self) -> None:
        source = (SRC_ROOT / "dpi_mcp" / "server.py").read_text(encoding="utf-8")
        imported = _imported_modules(source)
        for forbidden in ("uvicorn", "starlette", "sse_starlette", "httpx", "httpx2"):
            assert forbidden not in imported, (
                f"{forbidden} must not be imported by the server: it is the stack that "
                "serves HTTP, and importing it is the first step to doing that."
            )

    def test_the_import_scan_can_fail(self) -> None:
        """A scan that cannot fail is not a scan.

        The same discipline `T3-03` applied to its structural check.
        """
        source = "import uvicorn\nfrom mcp.server.sse import SseServerTransport\n"
        imported = _imported_modules(source)
        assert "uvicorn" in imported
        assert "mcp.server.sse" in imported


class TestTheAgentLayerCannotReachTheNetwork:
    """`DEC-11`: the runtime is `OFFLINE_CORE`, and provably so.

    The envelope scanner checks *calls*; this checks *imports*. An import of an
    HTTP client in a package held to `OFFLINE_CORE` is exactly the failure the
    core's own test names: *"a core that transitively loads an HTTP client is
    offline in name only"*. Here the risk is the mirror image -- an agent that
    can reach the network can be *told* to by whatever it read in a capture, so
    the code that reads captures must not be able to phone home at all.

    The `mcp` SDK is allowed, because it is a *protocol* library and the agent
    layer has to speak it to reach the tools. Its HTTP transports are not: the
    same rule the MCP server is held to (`TestTheServerCannotBecomeANetworkServer`).
    """

    #: Modules that can reach the network, by their full import name.
    _NETWORK_MODULES = (
        "httpx",
        "httpx2",
        "urllib.request",
        "requests",
        "socket",
        "aiohttp",
        "http.client",
        "uvicorn",
        "starlette",
        "sse_starlette",
    )

    #: The SDK's HTTP transports, in either direction.
    _MCP_HTTP_TRANSPORTS = (
        "mcp.client.streamable_http",
        "mcp.client.sse",
        "mcp.server.sse",
        "mcp.server.streamable_http",
        "mcp.server.streamable_http_manager",
    )

    def _agent_modules(self) -> list[Path]:
        return sorted((SRC_ROOT / "dpi_agents").rglob("*.py"))

    def test_the_agent_layer_imports_no_network_stack(self) -> None:
        modules = self._agent_modules()
        assert modules, "the agent package is missing; the rule would pass vacuously"
        for path in modules:
            imported = _imported_modules(path.read_text(encoding="utf-8"))
            for forbidden in self._NETWORK_MODULES:
                assert forbidden not in imported, (
                    f"{path.name} imports {forbidden!r}. The agent runtime is "
                    "`OFFLINE_CORE`: the code that reads a capture must not be able "
                    "to reach the network, because a capture can tell it to."
                )

    def test_the_agent_layer_imports_no_http_transport(self) -> None:
        for path in self._agent_modules():
            imported = _imported_modules(path.read_text(encoding="utf-8"))
            for forbidden in self._MCP_HTTP_TRANSPORTS:
                assert forbidden not in imported, (
                    f"{path.name} imports {forbidden!r}. The agent layer speaks the "
                    "MCP tool surface; it does not serve HTTP."
                )

    def test_the_scan_can_fail(self) -> None:
        """A scan that cannot fail is not a scan."""
        source = "import httpx\nfrom mcp.client.sse import sse_client\n"
        imported = _imported_modules(source)
        assert "httpx" in imported
        assert "mcp.client.sse" in imported


# ---------------------------------------------------------------------------
# The boundary must hold in the real tree, and in the direction that matters
# ---------------------------------------------------------------------------


class TestShippedTreeConforms:
    def test_no_package_violates_its_own_envelope(self) -> None:
        """The actual assertion about today's code."""
        violations = []
        for pkg, envelope in PACKAGE_ENVELOPES.items():
            for path in _py_files(pkg):
                rel = path.relative_to(SRC_ROOT)
                for v in scan_source(path.read_text(encoding="utf-8"), envelope, str(rel)):
                    violations.append(
                        f"{v.path}:{v.line}: {v.capability} ({v.resolved}) "
                        f"violates {envelope.name}"
                    )
        assert not violations, (
            "shipped source violates its declared safety envelope:\n  "
            + "\n  ".join(violations)
        )

    def test_the_core_does_not_import_the_agent_tree(self) -> None:
        """**The widening must not leak backwards.**

        Network is permitted in the agent layer. If `dpi_engine` could import it,
        the core's offline guarantee would hold only as long as nobody made that
        call - and a core that transitively loads an HTTP client is offline in name
        only. This is the difference between "the agent layer may use the network"
        and "the product uses the network".
        """
        networked = {
            name
            for name, env in PACKAGE_ENVELOPES.items()
            if env.network or env.live_capture or env.dynamic_exec or env.subprocess
        }
        assert "dpi_engine" not in networked, (
            "dpi_engine must stay OFFLINE_CORE for this test to mean anything"
        )

        offenders = []
        for path in _py_files("dpi_engine"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                roots: list[str] = []
                if isinstance(node, ast.Import):
                    roots = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                    roots = [node.module.split(".")[0]]
                for root in roots:
                    if root in networked:
                        offenders.append(
                            f"{path.relative_to(SRC_ROOT)}:{node.lineno} imports "
                            f"{root!r}, whose envelope permits network access"
                        )
        assert not offenders, (
            "the deterministic core imports a package whose envelope permits "
            "network access:\n  " + "\n  ".join(offenders)
        )

    def test_the_scan_actually_reads_the_real_tree(self) -> None:
        """Non-vacuity for the suite as a whole.

        If `_py_files` silently returned nothing, every test in this class would
        pass having inspected zero lines of shipped code - which is precisely the
        green-but-empty shape `A-03` warns about.
        """
        total = sum(len(_py_files(pkg)) for pkg in PACKAGE_ENVELOPES)
        assert total >= 15, (
            f"only {total} shipped .py files were visible to the scanner; if that "
            "is wrong the scan is not inspecting the tree it claims to"
        )
        for pkg in PACKAGE_ENVELOPES:
            assert _py_files(pkg), f"no .py files found for declared package {pkg!r}"
