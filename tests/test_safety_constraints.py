"""Task 11: static-analysis-style tests enforcing the safety constraints
from DESIGN_DECISIONS.md ("Safety constraints" section) directly against
the shipped source tree (src/dpi_engine/), not just asserting it once
during development. These tests fail loudly if a future change
accidentally introduces a live-capture, packet-injection, or
network-calling code path.

Scope: only src/dpi_engine/ is scanned. Test code (tests/) is explicitly
allowed to use `socket` for crafting synthetic packet fixtures (see
tests/test_worker_stress.py, tests/differential/fixtures/generate_edge_cases.py)
and `subprocess`/`docker` for the differential test harness's C++
reference binary (tests/differential/cpp_reference.py) -- neither of those
runs as part of the shipped tool, so they're out of scope for this
enforcement.
"""

from __future__ import annotations

import re
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src" / "dpi_engine"

# Patterns that would indicate a live-capture, packet-injection, or
# network-calling code path if found in shipped source. Each entry is
# (pattern, human description) for clear failure messages.
FORBIDDEN_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bsocket\.socket\s*\("), "raw socket creation (socket.socket)"),
    (re.compile(r"\bsocket\.create_connection\s*\("), "outbound network connection"),
    (re.compile(r"\.connect\s*\(\s*\("), "socket connect() call"),
    (re.compile(r"\bscapy\.sendp\s*\(|\bsendp\s*\("), "scapy packet injection (sendp)"),
    (re.compile(r"\bscapy\.sniff\s*\(|\bsniff\s*\("), "scapy live capture (sniff)"),
    (re.compile(r"\bsr1?\s*\("), "scapy send/receive (sr/sr1)"),
    (re.compile(r"^\s*(import scapy|from scapy)", re.MULTILINE), "scapy import in shipped code"),
    (re.compile(r"\burllib\.request\b"), "urllib network request"),
    (re.compile(r"\brequests\.(get|post|put|delete|patch)\s*\("), "requests HTTP call"),
    (re.compile(r"\bhttp\.client\b"), "http.client network call"),
    (re.compile(r"\bsubprocess\."), "subprocess invocation"),
    (re.compile(r"\bos\.system\s*\("), "shell command execution (os.system)"),
    (re.compile(r"\bos\.popen\s*\("), "shell command execution (os.popen)"),
    (re.compile(r"\beval\s*\("), "dynamic code execution (eval)"),
    (re.compile(r"\bexec\s*\("), "dynamic code execution (exec)"),
]


def _iter_source_files() -> list[Path]:
    return sorted(SRC_DIR.rglob("*.py"))


def test_src_dir_exists_and_has_python_files() -> None:
    """Sanity check for the scan itself -- if this fails, the other tests
    in this module are vacuously (and misleadingly) passing."""
    files = _iter_source_files()
    assert len(files) >= 8, f"expected multiple source files in {SRC_DIR}, found {files}"


def test_no_forbidden_network_or_live_capture_calls_in_shipped_source() -> None:
    violations: list[str] = []
    for path in _iter_source_files():
        text = path.read_text(encoding="utf-8")
        for pattern, description in FORBIDDEN_PATTERNS:
            match = pattern.search(text)
            if match:
                line_no = text[: match.start()].count("\n") + 1
                violations.append(f"{path.relative_to(SRC_DIR.parent)}:{line_no}: {description}")

    assert not violations, (
        "Found forbidden network/live-capture/dynamic-execution call(s) in "
        "shipped source (src/dpi_engine/), violating the passive/offline/"
        "file-based-only safety constraint from DESIGN_DECISIONS.md:\n"
        + "\n".join(violations)
    )


def test_socket_module_only_used_for_ip_string_formatting() -> None:
    """The only legitimate use of the stdlib `socket` module in this
    codebase is inet_ntoa/inet_aton for IPv4 dotted-quad string formatting
    (packet_parser.py) -- not for any actual networking. This test pins
    that down explicitly rather than relying solely on the forbidden-
    pattern scan above."""
    socket_users = []
    for path in _iter_source_files():
        text = path.read_text(encoding="utf-8")
        if re.search(r"\bimport socket\b", text):
            socket_users.append(path)

    for path in socket_users:
        text = path.read_text(encoding="utf-8")
        # Every use of `socket.<something>` in this file must be one of
        # the pure string-formatting helpers.
        for match in re.finditer(r"\bsocket\.(\w+)", text):
            attr = match.group(1)
            assert attr in ("inet_ntoa", "inet_aton"), (
                f"{path}: unexpected socket.{attr}() call -- only inet_ntoa/"
                f"inet_aton (IP string formatting) are allowed in shipped code"
            )


def test_no_scapy_dependency_in_shipped_source() -> None:
    """scapy is a dev/test-only dependency (see DESIGN_DECISIONS.md
    'Library choices') -- it must never be imported by shipped code, only
    by the differential test suite's cross-check helpers."""
    for path in _iter_source_files():
        text = path.read_text(encoding="utf-8")
        assert "scapy" not in text.lower(), f"{path}: unexpected reference to scapy"
