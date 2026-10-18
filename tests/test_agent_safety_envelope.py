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
    ("dynamic import", "__import__('os').system('id')", "dynamic_exec"),
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
