"""The three synchronous single-run tools (`T3-03`).

`AGENTIC_ARCHITECTURE.md`'s Layer 2 names four single-run tools. Three are here; the
fourth, `stream_dpi_events`, became `T3-07`, because it is not an adapter -- the engine
has no async, no threading and no streaming consumer contract to adapt. Tracker §7
records that split.

The design document also names two result types the engine has never had:

* `CaptureProfile` now exists, in `dpi_engine.capture_profile`. `inspect_capture` needed
  a real object, and `dpi-engine inspect` was already computing exactly these facts
  inline, so the CLI adopts the shared function rather than keeping a private copy.
* `DPIReport` does **not** exist, and is not invented here. `run_dpi` returns the
  engine's own `PipelineResult`; the agent-facing projection is
  `dpi_engine.report.result_to_dict`, which already exists and is already tested.
  Inventing a parallel report type would create a second place for the same numbers to
  be computed -- the shape that produced `D-25`'s reserved zeros and `D-16`'s two rule
  maps.

**Two design signatures are incomplete, and the gap is the engine's, not the tool's.**

* `run_dpi(path, ruleset, mode)` cannot be implemented as written: every `run_pipeline*`
  entry point *writes a filtered pcap*, so an output path is part of the contract rather
  than an optional extra. The tool takes `output` explicitly instead of inventing a
  temporary file, because a tool that silently writes somewhere the caller did not
  choose is a tool whose side effects cannot be found. `simulate_ruleset` has the same
  shape for `output_dir`.
* The capture argument is called `capture` in all three tools even though the design
  writes `path` for two of them and `capture` for the third. One name for one thing
  matters more at a protocol boundary than matching an inconsistent document.

**Validation is not duplicated here.** The engine already rejects `num_workers < 1`,
`num_load_balancers < 1` and `fps_per_lb < 1` with a `ValueError`, and
`ToolInputError` *is* a `ValueError`, so callers catch either. Re-checking those counts
in the tool would put one rule in two homes, which is the failure mode this project
keeps meeting; the only genuinely tool-level rule is `mode`, which the engine has no
concept of.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

from dpi_engine.capture_profile import CaptureProfile, profile_capture
from dpi_engine.pcap_io import DEFAULT_MAX_PACKET_SIZE, DEFAULT_MAX_TOTAL_PACKETS
from dpi_engine.pipeline import (
    PipelineResult,
    run_pipeline,
    run_pipeline_multiprocess,
    run_pipeline_staged,
)
from dpi_engine.rules.simulator import SimulationReport
from dpi_engine.rules.simulator import simulate_ruleset as _engine_simulate_ruleset
from dpi_mcp.tools.errors import ToolInputError
from dpi_mcp.tools.ruleset import build_rule_manager

__all__ = ["RunMode", "inspect_capture", "run_dpi", "simulate_ruleset"]


class RunMode(StrEnum):
    """Which of the engine's three run entry points a call selects.

    A tool argument arrives as a string, so it is parsed rather than trusted: `"single"`,
    `"multiprocess"` or `"staged"`. Anything not given is left at the engine's own
    default (4 workers; 2 load balancers x 2 fast paths).
    """

    SINGLE = "single"
    MULTIPROCESS = "multiprocess"
    STAGED = "staged"


def _coerce_mode(mode: RunMode | str) -> RunMode:
    if isinstance(mode, RunMode):
        return mode
    try:
        return RunMode(mode)
    except ValueError as exc:
        allowed = ", ".join(m.value for m in RunMode)
        raise ToolInputError(f"mode must be one of: {allowed}; got {mode!r}") from exc


def inspect_capture(
    capture: str | Path,
    *,
    max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
    max_total_packets: int = DEFAULT_MAX_TOTAL_PACKETS,
) -> CaptureProfile:
    """Describes a capture without inspecting any of it.

    This is the ingest agent's entry point: it answers "is this a capture I can work on,
    and what is it?" -- identity, linktype, snaplen, packet and byte counts, and the
    packet-length range -- using the same parser and the same bounds as every other
    reader in the project. `PcapError` propagates unwrapped so the caller learns *why*
    (truncated, pcapng, over the bound) rather than only that it failed.
    """
    return profile_capture(
        capture,
        max_packet_size=max_packet_size,
        max_total_packets=max_total_packets,
    )


def run_dpi(
    capture: str | Path,
    output: str | Path,
    ruleset: object = None,
    *,
    mode: RunMode | str = RunMode.SINGLE,
    workers: int = 4,
    load_balancers: int = 2,
    fps_per_lb: int = 2,
    enable_quic: bool = True,
    fold_bidirectional: bool = True,
    with_flow_table: bool = False,
    max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
    max_total_packets: int = DEFAULT_MAX_TOTAL_PACKETS,
) -> PipelineResult:
    """Runs the engine over `capture`, writing forwarded packets to `output`.

    `ruleset` is a rules document (or `None` for no rules), never a `RuleManager`; see
    `build_rule_manager`. `mode` picks the single-process, multiprocess or staged
    pipeline; the two multiprocess variants differ only in the shape of their process
    tree, so they share every option here.

    `with_flow_table` is off by default, matching the engine: the per-flow rows are only
    worth their memory to a caller that will ask questions about the run afterwards --
    building a run store, for instance.

    `with_global_stats` is deliberately not exposed. It exists on `run_pipeline` only,
    so surfacing it would give the three modes different contracts for no benefit, and
    its default is what the report needs.
    """
    chosen = _coerce_mode(mode)
    rules = build_rule_manager(ruleset, source="<run_dpi ruleset>")
    shared: dict[str, Any] = {
        "max_packet_size": max_packet_size,
        "max_total_packets": max_total_packets,
        "enable_quic": enable_quic,
        "fold_bidirectional": fold_bidirectional,
        "with_flow_table": with_flow_table,
    }
    if chosen is RunMode.SINGLE:
        return run_pipeline(capture, output, rules, **shared)
    if chosen is RunMode.MULTIPROCESS:
        return run_pipeline_multiprocess(capture, output, rules, num_workers=workers, **shared)
    return run_pipeline_staged(
        capture,
        output,
        rules,
        num_load_balancers=load_balancers,
        fps_per_lb=fps_per_lb,
        **shared,
    )


def simulate_ruleset(
    capture: str | Path,
    candidate: object,
    *,
    output_dir: str | Path,
    baseline: object = None,
    enable_quic: bool = True,
    fold_bidirectional: bool = True,
) -> SimulationReport:
    """Reports what `candidate` would change about `capture`, relative to `baseline`.

    `baseline` defaults to **no rules**, which is the honest reading of "what would this
    ruleset change": the comparison is against the policy currently in force, and a tool
    that guessed at one from disk would compare against a file the caller never named.
    Pass a rules document explicitly to diff two candidate policies.

    Both arguments are rules documents, not `RuleManager`s. Reporting is always relative
    to the baseline, because "blocks 40% of flows" means nothing without what the
    incumbent already blocks. The engine writes `baseline_sim.pcap` and
    `candidate_sim.pcap` into `output_dir`; that directory is required rather than
    defaulted, for the reason given in the module docstring.
    """
    return _engine_simulate_ruleset(
        build_rule_manager(baseline, source="<baseline ruleset>"),
        build_rule_manager(candidate, source="<candidate ruleset>"),
        capture,
        output_dir=output_dir,
        enable_quic=enable_quic,
        fold_bidirectional=fold_bidirectional,
    )
