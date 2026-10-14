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

import pytest

from conftest import TEST_DPI_PCAP

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


# ---------------------------------------------------------------------------
# D-12: a failure after dispatch must not leak children or queues
# ---------------------------------------------------------------------------


def _spy_on_processes_and_queues(monkeypatch: pytest.MonkeyPatch) -> tuple[list, list]:
    """Record every mp.Process and mp.Queue the pipeline creates."""
    import multiprocessing as mp

    processes: list = []
    queues: list = []

    real_process = mp.Process
    real_queue = mp.Queue

    def process_spy(*args: object, **kwargs: object):
        p = real_process(*args, **kwargs)
        processes.append(p)
        return p

    def queue_spy(*args: object, **kwargs: object):
        q = real_queue(*args, **kwargs)
        queues.append(q)
        return q

    monkeypatch.setattr(mp, "Process", process_spy)
    monkeypatch.setattr(mp, "Queue", queue_spy)
    return processes, queues


@pytest.mark.parametrize("variant", ["multiprocess", "staged"])
def test_failure_during_result_collection_leaves_no_surviving_children(
    variant: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_collect` raising must still terminate children and close queues.

    `_collect` converts a lost worker into a `RuntimeError` after a bounded wait,
    which is exactly the kind of failure the caller cannot recover from -- and
    previously the `join` / `_close_quietly` sequence sat *after* it with no
    `finally`, so the failure path re-introduced the very leak the
    dispatch-phase shutdown protocol exists to prevent (D-12).

    Asserted on queues being closed and processes being reaped, both of which
    are deterministic. Asserting `not is_alive()` would not be: by this point the
    workers have already been sent shutdown sentinels, so they exit on their own
    regardless, and the bug would hide.
    """
    from dpi_engine import pipeline
    from dpi_engine.rule_manager import RuleManager

    processes, queues = _spy_on_processes_and_queues(monkeypatch)

    def boom(*args: object, **kwargs: object):
        raise RuntimeError("injected result-collection failure")

    # Both, because which one collects depends on `reorder_window`: streaming
    # mode goes through `_collect_streaming` and the legacy second pass through
    # `_collect`. Patching only the old one would inject nothing, the pipeline
    # would succeed, and the test would fail for the wrong reason -- or worse,
    # a future `pytest.raises` that happened to match something else could pass
    # without the teardown ever being exercised.
    monkeypatch.setattr(pipeline, "_collect", boom)
    monkeypatch.setattr(pipeline, "_collect_streaming", boom)

    out = tmp_path / "out.pcap"
    with pytest.raises(RuntimeError, match="injected result-collection failure"):
        if variant == "staged":
            pipeline.run_pipeline_staged(
                str(TEST_DPI_PCAP), out, RuleManager(),
                num_load_balancers=1, fps_per_lb=1,
            )
        else:
            pipeline.run_pipeline_multiprocess(
                str(TEST_DPI_PCAP), out, RuleManager(), num_workers=2,
            )

    assert processes, "no processes were created, so the test proved nothing"
    assert queues, "no queues were created, so the test proved nothing"

    unclosed = [q for q in queues if not getattr(q, "_closed", False)]
    assert not unclosed, (
        f"{len(unclosed)} of {len(queues)} queues were left open after the "
        f"failure; teardown must run on every exit path, not just the happy one"
    )

    unreaped = [p for p in processes if p.exitcode is None]
    assert not unreaped, (
        f"{len(unreaped)} of {len(processes)} child processes were never "
        f"reaped after the failure"
    )


# ---------------------------------------------------------------------------
# S-03: docstrings must not cite symbols that do not exist
# ---------------------------------------------------------------------------


def test_docstrings_reference_only_symbols_that_exist() -> None:
    """No shipped docstring may point at a symbol that is not there.

    Three docstrings cited `pipeline.QuicFlowTable`,
    `pipeline.RuleBroadcaster.SnapshotHolder` and a `with_fast_path_stats=True`
    parameter, none of which has ever existed. All three survived for as long as
    the audit had been running, because prose has no compiler: a renamed or
    deleted symbol leaves the documentation confidently wrong rather than
    failing a build.

    This walks every module docstring, class docstring and function docstring,
    extracts backtick-quoted dotted references, and resolves each one. Only
    references whose first segment names a module in this package are checked --
    `docs/DESIGN_DECISIONS.md` and stdlib names are out of scope -- and
    filename-ish references (`quic.py`) are skipped, since they are paths, not
    attributes.

    Honest scope: this catches references *qualified by module*. It does not
    catch a bare phantom parameter name (`with_fast_path_stats=True`, which has
    no dot to resolve), nor a prose claim like load_balancer's "the LB stage
    parses Ethernet/IP/TCP/UDP". A variant that tried to catch those flagged 5
    legitimate cross-references for every 1 true positive, so it was not worth
    the false alarms.
    """
    import ast
    import importlib
    import re

    module_stems = {p.stem for p in SRC_DIR.glob("*.py")}
    dotted = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\b")
    span = re.compile(r"`([^`\n]+)`")

    checked = 0
    violations: list[str] = []

    for path in sorted(SRC_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))

        for node in ast.walk(tree):
            if not isinstance(
                node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                continue
            doc = ast.get_docstring(node)
            if not doc:
                continue

            for text in span.findall(doc):
                if text.endswith((".py", ".md", ".json", ".yml", ".yaml", ".pcap")):
                    continue
                for ref in dotted.findall(text):
                    head, _, rest = ref.partition(".")
                    if head == "dpi_engine":
                        target, chain = "dpi_engine", rest.split(".")
                    elif head in module_stems:
                        target, chain = f"dpi_engine.{head}", rest.split(".")
                    else:
                        continue

                    checked += 1
                    obj = importlib.import_module(target)
                    for attr in chain:
                        if not hasattr(obj, attr):
                            where = getattr(node, "name", "<module>")
                            violations.append(
                                f"{path.name}:{node.lineno} "
                                f"({where}) cites `{ref}`, but {target} has no "
                                f"attribute {attr!r}"
                            )
                            break
                        obj = getattr(obj, attr)

    assert not violations, "docstrings cite symbols that do not exist:\n  " + "\n  ".join(
        violations
    )
    assert checked > 0, (
        "the check resolved 0 references, so it is not actually inspecting "
        "anything and would pass vacuously"
    )


# --- R-10: the test-only latency knob must be inert in a normal run -----------


def test_the_test_delay_knob_is_inert_outside_tests() -> None:
    """No production run may be slowed by a stray environment variable.

    `worker._TEST_DELAY_SECONDS` is a latency knob that lives inside the
    per-packet path, reachable only by setting
    `DPI_ENGINE_TEST_WORKER_DELAY_MS` before the process starts. It has to stay
    for `test_worker_stress.py` -- Windows' `spawn` re-imports `worker.py` in
    each child, and environment variables are inherited where a monkeypatch
    would not be -- but it must resolve to 0.0 in every ordinary run.

    The value is resolved once at import rather than read per packet (`R-10`),
    so this assertion is meaningful: it proves the knob was never armed, not
    merely that nobody set it between packets.
    """
    import os

    from dpi_engine import worker

    assert worker._TEST_DELAY_MS_ENV_VAR not in os.environ, (
        f"{worker._TEST_DELAY_MS_ENV_VAR} is set in this environment; every "
        "packet in every worker would be delayed by it"
    )
    assert worker._TEST_DELAY_SECONDS == 0.0, (
        f"the test delay resolved to {worker._TEST_DELAY_SECONDS}s; it must be "
        "0.0 unless the variable was set before import"
    )


def test_the_test_delay_knob_is_resolved_at_import_not_per_packet() -> None:
    """Setting the variable after import must have no effect.

    This is the property that makes the knob safe: it cannot be armed after the
    process is running, so there is no window in which a running engine's
    per-packet latency changes underneath it.
    """
    import os

    from dpi_engine import worker

    assert worker._TEST_DELAY_SECONDS == 0.0
    os.environ[worker._TEST_DELAY_MS_ENV_VAR] = "500"
    try:
        # Already imported, so the module-level constant is unchanged.
        assert worker._TEST_DELAY_SECONDS == 0.0, (
            "the delay must be resolved at import time, not per packet"
        )
        # ...and the resolver would produce 0.5s only for a fresh import.
        assert worker._resolve_test_delay_seconds() == 0.5
    finally:
        del os.environ[worker._TEST_DELAY_MS_ENV_VAR]


def test_an_unparseable_delay_value_is_ignored() -> None:
    """A typo in the variable must not crash the worker at import time.

    `_resolve_test_delay_seconds()` runs at import in every worker process, so a
    `ValueError` escaping it would turn a harmless stray variable into a failed
    run. Malformed, negative and absurd values all resolve to something safe.
    """
    import os

    from dpi_engine import worker

    original = os.environ.get(worker._TEST_DELAY_MS_ENV_VAR)
    try:
        for raw in ("not-a-number", "", "-5", "1e999"):
            os.environ[worker._TEST_DELAY_MS_ENV_VAR] = raw
            resolved = worker._resolve_test_delay_seconds()
            assert resolved == 0.0 or 0.0 < resolved < 3600.0, (
                f"{raw!r} resolved to {resolved}"
            )
        os.environ[worker._TEST_DELAY_MS_ENV_VAR] = "not-a-number"
        assert worker._resolve_test_delay_seconds() == 0.0
    finally:
        if original is None:
            os.environ.pop(worker._TEST_DELAY_MS_ENV_VAR, None)
        else:
            os.environ[worker._TEST_DELAY_MS_ENV_VAR] = original
