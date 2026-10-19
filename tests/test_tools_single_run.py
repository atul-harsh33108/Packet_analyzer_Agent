"""The three synchronous single-run tools (`T3-03`).

Two of these tests look like they are about nothing. They are the most important ones
here:

* `test_no_tool_module_imports_the_mcp_sdk` is **structural**. The SDK is not installed
  in this environment, so "the tools work without it" is true no matter what the tools
  do. An import check would be green on a codebase that imported `mcp` on line one of
  every module, because the import would raise and be... nowhere, since nothing calls it.
  Reading the source for the dependency is the only version of that claim that can fail.
* `test_the_tools_run_with_the_sdk_forced_absent` is **behavioural**, and its probe
  checks that its own block worked. A block that silently does nothing makes the probe
  pass on exactly the code it exists to reject.

The rest check that each tool is what it says: typed, callable as plain Python, and
faithful to the engine's own semantics rather than a second interpretation of them.
"""

from __future__ import annotations

import ast
import inspect
import json
import subprocess
import sys
from pathlib import Path
from typing import get_type_hints

import pytest

from conftest import TEST_DPI_PCAP
from dpi_engine.rule_manager import RuleManagerError
from dpi_engine.rules.simulator import SimulationReport
from dpi_mcp.tools import (
    RunMode,
    ToolInputError,
    build_rule_manager,
    inspect_capture,
    run_dpi,
    simulate_ruleset,
)

REPO = Path(__file__).resolve().parents[1]
PROBE = Path(__file__).resolve().parent / "_mcp_absent_probe.py"

#: The one module allowed to import the SDK (`T3-05`). Named here rather than left to
#: review, so that the day `server.py` lands this test is already the thing that decides
#: where the import may live.
SDK_WIRING_MODULE = Path("src/dpi_mcp/server.py")

TOOLS = (inspect_capture, run_dpi, simulate_ruleset)


def _imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


def test_no_tool_module_imports_the_mcp_sdk() -> None:
    package = REPO / "src" / "dpi_mcp"
    offenders = [
        str(path.relative_to(REPO))
        for path in sorted(package.rglob("*.py"))
        if "mcp" in _imported_roots(path)
        and path.relative_to(REPO).as_posix() != SDK_WIRING_MODULE.as_posix()
    ]
    assert not offenders, (
        f"the MCP SDK may only be imported by {SDK_WIRING_MODULE}; found it in {offenders}"
    )


def test_the_structural_scan_can_fail() -> None:
    """The scan above is only worth anything if it detects a real import."""
    probe = REPO / "src" / "_t3_03_scan_probe.py"
    probe.write_text("import mcp\nfrom mcp.server import Server\n", encoding="utf-8")
    try:
        assert "mcp" in _imported_roots(probe)
        clean = REPO / "src" / "dpi_mcp" / "tools" / "errors.py"
        assert "mcp" not in _imported_roots(clean), "the scan flags a module with no SDK import"
    finally:
        probe.unlink()


def test_the_tools_run_with_the_sdk_forced_absent() -> None:
    proc = subprocess.run(
        [sys.executable, str(PROBE)],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"probe failed:\n{proc.stdout}\n{proc.stderr}"
    assert "RESULT packets=77 bytes=5738" in proc.stdout, proc.stdout
    assert "wrote=True" in proc.stdout, proc.stdout


@pytest.mark.parametrize("tool", TOOLS, ids=lambda t: t.__name__)
def test_each_tool_is_fully_annotated(tool: object) -> None:
    hints = get_type_hints(tool)
    signature = inspect.signature(tool)
    assert "return" in hints, f"{tool.__name__} has no return annotation"
    unannotated = [name for name in signature.parameters if name not in hints]
    assert not unannotated, f"{tool.__name__} leaves {unannotated} unannotated"


def test_the_tools_are_exported() -> None:
    import dpi_mcp.tools as tools

    assert {"inspect_capture", "run_dpi", "simulate_ruleset"} <= set(tools.__all__)


# ---------------------------------------------------------------------------
# inspect_capture
# ---------------------------------------------------------------------------


def test_inspect_capture_returns_the_engines_own_profile() -> None:
    profile = inspect_capture(TEST_DPI_PCAP)
    assert profile.packet_count == 77
    assert profile.captured_bytes == 5738
    assert json.loads(profile.to_json())["sha256"] == profile.sha256


def test_inspect_capture_forwards_the_bounds() -> None:
    """Bounds are part of the tool contract, not decoration."""
    from dpi_engine.pcap_io import PcapLimitExceededError

    with pytest.raises(PcapLimitExceededError):
        inspect_capture(TEST_DPI_PCAP, max_total_packets=5)

    assert inspect_capture(TEST_DPI_PCAP, max_total_packets=1000).packet_count == 77


# ---------------------------------------------------------------------------
# build_rule_manager
# ---------------------------------------------------------------------------


def test_none_means_no_rules() -> None:
    rules = build_rule_manager(None)
    assert rules.get_stats().blocked_apps == 0
    assert rules.get_stats().blocked_ips == 0


def test_a_dict_is_delegated_to_the_engines_own_loader() -> None:
    rules = build_rule_manager({"blocked_ips": ["203.0.113.5"], "blocked_apps": ["FACEBOOK"]})
    stats = rules.get_stats()
    assert stats.blocked_apps == 1
    assert stats.blocked_ips == 1


def test_a_bad_ruleset_raises_the_engines_error_not_a_new_one() -> None:
    """One validator, so the tool and `dpi-engine run --load-rules` cannot disagree."""
    with pytest.raises(RuleManagerError):
        build_rule_manager({"blocked_ips": ["not-an-ip"]})
    with pytest.raises(RuleManagerError):
        build_rule_manager(["blocked_ips"])  # shape is checked by `from_dict` too


def test_tool_input_error_is_a_value_error() -> None:
    assert issubclass(ToolInputError, ValueError)


# ---------------------------------------------------------------------------
# run_dpi
# ---------------------------------------------------------------------------


def test_run_dpi_writes_the_filtered_capture(tmp_path: Path) -> None:
    out = tmp_path / "forwarded.pcap"
    result = run_dpi(TEST_DPI_PCAP, out, {"blocked_apps": ["FACEBOOK"]})
    assert out.exists()
    assert result.stats.total_packets == 77
    assert len(result.blocked_flows) == 2


def test_run_dpi_with_no_ruleset_blocks_nothing(tmp_path: Path) -> None:
    result = run_dpi(TEST_DPI_PCAP, tmp_path / "out.pcap")
    assert result.blocked_flows == []


def test_run_dpi_flow_rows_are_opt_in(tmp_path: Path) -> None:
    """`T3-06`'s flag, surfaced: `None` means "not asked for", `()` would mean "none"."""
    off = run_dpi(TEST_DPI_PCAP, tmp_path / "off.pcap")
    on = run_dpi(TEST_DPI_PCAP, tmp_path / "on.pcap", with_flow_table=True)

    assert off.flow_table is None
    assert on.flow_table is not None
    assert len(on.flow_table) == 27


def test_a_bad_mode_is_a_tool_input_error(tmp_path: Path) -> None:
    with pytest.raises(ToolInputError, match="mode must be one of"):
        run_dpi(TEST_DPI_PCAP, tmp_path / "out.pcap", mode="turbo")
    assert not (tmp_path / "out.pcap").exists(), "a rejected call must not have run"


def test_the_three_modes_are_the_same_answer_on_one_capture(tmp_path: Path) -> None:
    """The modes differ in *how* they run, not in what they report.

    This is the tool-level version of the guarantee `T3-06` established for the pipeline
    variants: if the tool's argument mapping silently dropped an option on one path, the
    three would diverge here.
    """
    ruleset = {"blocked_apps": ["FACEBOOK"]}
    results = {
        mode: run_dpi(TEST_DPI_PCAP, tmp_path / f"{mode.value}.pcap", ruleset, mode=mode)
        for mode in RunMode
    }
    for mode, result in results.items():
        assert result.stats.total_packets == 77, mode
        assert len(result.blocked_flows) == 2, mode
        assert result.app_counts == results[RunMode.SINGLE].app_counts, mode

    # Equality of the *report* is not enough to prove the mode was honoured: a tool that
    # silently ran the single-process pipeline for every mode would satisfy every
    # assertion above. The observable difference is the execution contexts: one for the
    # single-process path, one per worker for the multiprocess path, and one per load
    # balancer for the staged one -- all of them adding up to the same 77 packets. This
    # is what pins `workers` and `load_balancers` to the arguments they are mapped to.
    contexts = {mode: results[mode].per_worker_packet_counts for mode in RunMode}
    assert contexts[RunMode.SINGLE] == [77]
    assert len(contexts[RunMode.MULTIPROCESS]) == 4, "the default worker count was not passed"
    assert len(contexts[RunMode.STAGED]) == 2, "the default load-balancer count was not passed"
    for mode, counts in contexts.items():
        assert sum(counts) == 77, f"{mode} lost packets across its contexts: {counts}"


def test_a_mode_string_is_accepted_like_the_enum(tmp_path: Path) -> None:
    """A tool argument arrives as a string over the wire."""
    by_string = run_dpi(TEST_DPI_PCAP, tmp_path / "a.pcap", mode="single")
    assert by_string.stats.total_packets == 77


def test_a_bad_ruleset_reaches_the_engine_error(tmp_path: Path) -> None:
    with pytest.raises(RuleManagerError):
        run_dpi(TEST_DPI_PCAP, tmp_path / "out.pcap", {"blocked_apps": ["NOT_AN_APP"]})


def test_fold_bidirectional_reaches_the_engine(tmp_path: Path) -> None:
    """A dropped option is invisible unless something measures it.

    Folding is the option most likely to be silently lost: `run_dpi` forwards it as one
    keyword among nine, and if it were dropped the run would still succeed and still
    report 77 packets. It is observable here -- 27 flow rows folded, 43 unfolded -- which
    is why it is asserted rather than assumed. (`enable_quic` is **not** observable on this
    fixture: it carries no QUIC, so that argument's mapping is unproven by tests. Recorded
    as a gap rather than papered over.)
    """
    folded = run_dpi(TEST_DPI_PCAP, tmp_path / "folded.pcap", with_flow_table=True)
    unfolded = run_dpi(
        TEST_DPI_PCAP, tmp_path / "unfolded.pcap", fold_bidirectional=False, with_flow_table=True
    )
    assert len(folded.flow_table or ()) == 27
    assert len(unfolded.flow_table or ()) == 43
    assert folded.app_counts != unfolded.app_counts


def test_mode_specific_counts_reach_the_engine(tmp_path: Path) -> None:
    """Each count is passed through, proven by the engine rejecting a bad one.

    If the tool dropped any of these arguments the engine's default would be used and no
    error would be raised, so this is the one observation that distinguishes "forwarded"
    from "quietly defaulted" without depending on internal process counts.
    """
    with pytest.raises(ValueError, match="num_workers"):
        run_dpi(TEST_DPI_PCAP, tmp_path / "w.pcap", mode=RunMode.MULTIPROCESS, workers=0)
    with pytest.raises(ValueError, match="num_load_balancers"):
        run_dpi(TEST_DPI_PCAP, tmp_path / "l.pcap", mode=RunMode.STAGED, load_balancers=0)
    with pytest.raises(ValueError, match="fps_per_lb"):
        run_dpi(TEST_DPI_PCAP, tmp_path / "f.pcap", mode=RunMode.STAGED, fps_per_lb=0)


# ---------------------------------------------------------------------------
# simulate_ruleset
# ---------------------------------------------------------------------------


def test_simulate_ruleset_reports_the_change_it_would_make(tmp_path: Path) -> None:
    report = simulate_ruleset(
        TEST_DPI_PCAP, {"blocked_apps": ["FACEBOOK"]}, output_dir=tmp_path / "sim"
    )
    assert isinstance(report, SimulationReport)
    assert len(report.newly_blocked) == 2
    assert report.baseline_blocked == 0
    assert report.candidate_blocked == 2
    assert (tmp_path / "sim" / "baseline_sim.pcap").exists()
    assert (tmp_path / "sim" / "candidate_sim.pcap").exists()


def test_simulate_ruleset_defaults_its_baseline_to_no_rules(tmp_path: Path) -> None:
    default = simulate_ruleset(TEST_DPI_PCAP, {"blocked_apps": ["FACEBOOK"]}, output_dir=tmp_path / "a")
    explicit = simulate_ruleset(
        TEST_DPI_PCAP,
        {"blocked_apps": ["FACEBOOK"]},
        baseline=None,
        output_dir=tmp_path / "b",
    )
    assert default.newly_blocked == explicit.newly_blocked


def test_simulating_a_ruleset_against_itself_changes_nothing(tmp_path: Path) -> None:
    """The diff is relative to the baseline, so an identical policy is a clean no-op."""
    ruleset = {"blocked_apps": ["FACEBOOK"]}
    report = simulate_ruleset(
        TEST_DPI_PCAP, ruleset, baseline=ruleset, output_dir=tmp_path / "sim"
    )
    assert report.newly_blocked == ()
    assert report.newly_allowed == ()
    assert report.candidate_dropped == report.baseline_dropped


def test_simulate_ruleset_rejects_a_malformed_candidate(tmp_path: Path) -> None:
    with pytest.raises(RuleManagerError):
        simulate_ruleset(TEST_DPI_PCAP, {"blocked_ports": [-1]}, output_dir=tmp_path / "sim")
