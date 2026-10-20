"""Counterfactual ruleset simulation (`T1-06`, closes `A-05`).

Answers, before a policy change is applied, what the change would do to a given
capture — by running the **real pipeline twice** and diffing the results.

The design constraint that shapes everything here: **do not reimplement
decision logic**. A simulator that re-derived "would this flow be blocked?" would
be a second source of truth, free to drift from the one production uses, and every
number it reported would be a guess wearing the costume of a measurement. So both
runs go through `run_pipeline`, and the diff is taken over artefacts the engine
already produces:

- per-packet ``forwarded`` decisions, read off ``PacketParsed`` events, keyed by
  ``sequence_index`` (the reader's own ordering, so the two runs align packet for
  packet);
- blocked flows, taken from ``PipelineResult.blocked_flows``.

The cost is two pipeline runs and the difference is **exact** rather than sampled
or estimated. For a two-pass design over a file capture, that is the cheap way to
get a trustworthy answer; a sampling scheme would be faster and would make the
result a statistic, which is the wrong shape for a safety check.

Simulation is a read-only operation. It writes two output pcaps into the caller's
`output_dir` because `run_pipeline` writes forwarded packets as a side effect of
running at all, and those pcaps are themselves useful (the candidate output is
literally what the traffic would look like under the new ruleset). It never
modifies the input capture, and never touches a global rule registry — both runs
use private `RuleManager` instances handed in by the caller.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

from dpi_engine.events import EventBus, FlowBlocked, PacketParsed
from dpi_engine.pipeline import PipelineResult, run_pipeline
from dpi_engine.rule_manager import RuleManager
from dpi_engine.types import AppType, FiveTuple


@dataclasses.dataclass(frozen=True, slots=True)
class FlowDelta:
    """One flow whose disposition differs between the two runs."""

    #: Canonical flow key, as the tracker computes it (direction-folded when
    #: `DEC-05` folding is on), so the same conversation compares equal in both
    #: runs regardless of which direction carried the ClientHello.
    flow_key: FiveTuple
    app_type: AppType
    sni: str
    # No per-flow byte or packet count here. The pipeline reports bytes against the
    # folded flow key, so attributing bytes to the *delta* would need a second
    # accounting pass that could disagree with the engine's own totals -- and a
    # counter that is always 0, or only sometimes right, is worse than no counter.
    # Aggregate packet counts are on `SimulationReport` and come straight from
    # `DPIStats`.

    def to_dict(self) -> dict[str, Any]:
        """The delta as JSON-ready data.

        Owned here rather than at the boundary that needs it (`T3-05`). The MCP
        layer must not keep its own copy of these fields: two projections of one
        report drift apart silently, and the drifting one is the one an agent
        reads. The five-tuple becomes a **named** object rather than a bare
        array, because five numbers in a row do not say which is the port.
        """
        return {
            "flow_key": dict(self.flow_key._asdict()),
            "app_type": self.app_type.name,
            "sni": self.sni,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class SimulationReport:
    """What a candidate ruleset would change about a capture."""

    #: Flows the candidate blocks that the baseline allowed.
    newly_blocked: tuple[FlowDelta, ...]
    #: Flows the baseline blocked that the candidate allows.
    newly_allowed: tuple[FlowDelta, ...]
    #: Flows blocked in **both** runs. Present because a report that only shows
    #: change invites reading "no delta" as "no blocking", which is how a
    #: pre-existing block gets lost.
    unchanged_blocked: tuple[FlowDelta, ...]

    baseline_blocked: int
    candidate_blocked: int
    baseline_dropped: int
    candidate_dropped: int
    baseline_forwarded: int
    candidate_forwarded: int
    baseline_total_packets: int
    candidate_total_packets: int
    #: Change in percentage of inspected packets dropped, in points. Signed:
    #: positive means the candidate drops more.
    drop_rate_change_percent: float
    #: True when the candidate would forward nothing at all.
    total_loss: bool

    baseline_output: Path
    candidate_output: Path

    #: Populated from the per-packet decision diff. Private because it is derived
    #: from the two runs and must not be settable by a caller who could put the two
    #: halves of the report out of step.
    _packets_changed: int = 0

    @property
    def flows_changed(self) -> int:
        return len(self.newly_blocked) + len(self.newly_allowed)

    @property
    def packets_changed(self) -> int:
        """Packets whose forward/drop decision differs between the two runs.

        Counted from the per-packet decision bitmaps, so it is unsigned and counts
        *moves in either direction*.

        This is deliberately **not** ``candidate_dropped - baseline_dropped``. That
        difference is a net figure: swapping one blocked app for another moves
        exactly as many packets as it frees while dropping exactly as many as
        before, so the net is 0 even though every one of those packets changed
        disposition. Measured on the sample capture, blocking Facebook and then
        YouTube instead drops 2 packets either way, but 4 packets change decision.
        Reporting the net as "packets changed" would make the single most
        disruptive kind of edit — a policy substitution — look like no change at
        all.
        """
        return self._packets_changed

    @property
    def net_packets_dropped(self) -> int:
        """Signed change in dropped packets. Zero for a pure substitution."""
        return self.candidate_dropped - self.baseline_dropped

    @property
    def unchanged_blocked_deltas(self) -> tuple[FlowDelta, ...]:
        return self.unchanged_blocked

    def to_dict(self) -> dict[str, Any]:
        """The report as JSON-ready data.

        The engine owns this projection for the same reason `CaptureProfile` owns
        its own: the MCP surface (`T3-05`) must not grow a second copy of these
        fields. The two output paths become strings because `Path` is not JSON,
        and the derived counters are included because they are the answers a
        reader actually wants -- `packets_changed` in particular, which is not
        the difference of the two dropped counts.
        """
        return {
            "newly_blocked": [delta.to_dict() for delta in self.newly_blocked],
            "newly_allowed": [delta.to_dict() for delta in self.newly_allowed],
            "unchanged_blocked": [delta.to_dict() for delta in self.unchanged_blocked],
            "baseline_blocked": self.baseline_blocked,
            "candidate_blocked": self.candidate_blocked,
            "baseline_dropped": self.baseline_dropped,
            "candidate_dropped": self.candidate_dropped,
            "baseline_forwarded": self.baseline_forwarded,
            "candidate_forwarded": self.candidate_forwarded,
            "baseline_total_packets": self.baseline_total_packets,
            "candidate_total_packets": self.candidate_total_packets,
            "drop_rate_change_percent": self.drop_rate_change_percent,
            "total_loss": self.total_loss,
            "baseline_output": str(self.baseline_output),
            "candidate_output": str(self.candidate_output),
            "flows_changed": self.flows_changed,
            "packets_changed": self.packets_changed,
            "net_packets_dropped": self.net_packets_dropped,
        }

    def summary(self) -> str:
        """A one-line human-readable summary, for CLI and log output."""
        return (
            f"{self.flows_changed} flows change "
            f"(+{len(self.newly_blocked)} blocked / -{len(self.newly_allowed)} allowed), "
            f"drop rate {self.drop_rate_change_percent:+.2f} points, "
            f"{self.candidate_dropped}/{self.candidate_total_packets} packets dropped"
        )


@dataclasses.dataclass(slots=True)
class _Run:
    """Everything one pipeline run produced that the diff needs."""

    result: PipelineResult
    #: `sequence_index` -> whether that packet was forwarded. This is the decision
    #: bitmap, read from the same events that drive the fold.
    decisions: dict[int, bool]
    blocked: dict[FiveTuple, FlowDelta]
    output: Path


def _record_run(
    input_path: str | Path,
    rules: RuleManager,
    output: Path,
) -> _Run:
    """Runs the real pipeline once, recording its decisions and blocked flows."""
    bus = EventBus()
    decisions: dict[int, bool] = {}
    blocked: dict[FiveTuple, FlowDelta] = {}

    def on_event(event: object) -> None:
        if isinstance(event, PacketParsed):
            decisions[event.sequence_index] = event.forwarded
        elif isinstance(event, FlowBlocked):
            blocked[event.five_tuple] = FlowDelta(
                flow_key=event.five_tuple, app_type=event.app_type, sni=event.sni
            )

    bus.subscribe(on_event)

    result = run_pipeline(input_path, output, rules, bus=bus)

    # `blocked_flows` is the engine's own tally; the event stream is used to fill
    # in the per-flow detail. Preferring the result's list as the source of truth
    # for *which* flows are blocked keeps the report aligned with the number the
    # pipeline reports to the CLI, rather than to a second count derived here.
    blocked = {
        five_tuple: FlowDelta(flow_key=five_tuple, app_type=app, sni=sni)
        for five_tuple, app, sni in result.blocked_flows
    }

    return _Run(result=result, decisions=decisions, blocked=blocked, output=output)


def _flow_keys_changed(baseline: dict[int, bool], candidate: dict[int, bool]) -> int:
    """Packets whose decision differs. Used as an internal consistency check."""
    shared = baseline.keys() & candidate.keys()
    return sum(1 for i in shared if baseline[i] != candidate[i])


def simulate_ruleset(
    baseline_rules: RuleManager,
    candidate_rules: RuleManager,
    input_path: str | Path,
    *,
    output_dir: str | Path,
    enable_quic: bool = True,
    fold_bidirectional: bool = True,
) -> SimulationReport:
    """Simulates `candidate_rules` against `input_path` and diffs it against
    `baseline_rules`.

    Both runs use the production single-process pipeline, so the simulation and
    the eventual production run follow the same decision path. The two output
    pcaps are written into `output_dir` as `baseline_sim.pcap` and
    `candidate_sim.pcap`; `output_dir` is created if absent.

    `baseline_rules` is the incumbent policy and `candidate_rules` the proposed
    one. Reporting is always relative to the baseline, because "blocks 40% of
    flows" is only meaningful next to what the current ruleset already does.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    baseline = _record_run(input_path, baseline_rules, out_dir / "baseline_sim.pcap")
    candidate = _record_run(input_path, candidate_rules, out_dir / "candidate_sim.pcap")

    baseline_keys = set(baseline.blocked)
    candidate_keys = set(candidate.blocked)

    newly_blocked = tuple(
        candidate.blocked[k] for k in sorted(candidate_keys - baseline_keys, key=_sort_key)
    )
    newly_allowed = tuple(
        baseline.blocked[k] for k in sorted(baseline_keys - candidate_keys, key=_sort_key)
    )
    unchanged_blocked = tuple(
        baseline.blocked[k] for k in sorted(baseline_keys & candidate_keys, key=_sort_key)
    )

    b_stats, c_stats = baseline.result.stats, candidate.result.stats

    # `drop_rate_percent` is a `PipelineResult` property, not a `DPIStats` one: it
    # divides by the *inspected* packet count, which only the result knows about.
    baseline_rate = baseline.result.drop_rate_percent
    candidate_rate = candidate.result.drop_rate_percent

    report = SimulationReport(
        newly_blocked=newly_blocked,
        newly_allowed=newly_allowed,
        unchanged_blocked=unchanged_blocked,
        baseline_blocked=len(baseline_keys),
        candidate_blocked=len(candidate_keys),
        baseline_dropped=b_stats.dropped_packets,
        candidate_dropped=c_stats.dropped_packets,
        baseline_forwarded=b_stats.forwarded_packets,
        candidate_forwarded=c_stats.forwarded_packets,
        baseline_total_packets=b_stats.total_packets,
        candidate_total_packets=c_stats.total_packets,
        drop_rate_change_percent=candidate_rate - baseline_rate,
        total_loss=c_stats.forwarded_packets == 0 and c_stats.dropped_packets > 0,
        baseline_output=baseline.output,
        candidate_output=candidate.output,
        _packets_changed=_flow_keys_changed(baseline.decisions, candidate.decisions),
    )

    # The two runs must have seen the same packets, or nothing derived by comparing
    # them means anything. Raised rather than reported: a simulation that quietly
    # returns figures from two different inputs is the failure mode this component
    # exists to prevent, and the caller has no way to detect it.
    #
    # What is *not* checked here is the earlier, wrong assumption that the
    # per-packet diff must equal the change in the dropped counter. It does not:
    # substituting one blocked app for another drops the same number of packets
    # while changing the disposition of every one of them, so a net-zero drop
    # delta can accompany a large real diff. That was found by a test, not by
    # inspection.
    if baseline.decisions.keys() != candidate.decisions.keys():
        missing = baseline.decisions.keys() - candidate.decisions.keys()
        extra = candidate.decisions.keys() - baseline.decisions.keys()
        raise RuntimeError(
            "simulation is inconsistent: the two runs did not see the same "
            f"packets (baseline has {len(missing)} the candidate lacks, candidate "
            f"has {len(extra)} the baseline lacks). No delta between them can be "
            "trusted."
        )

    return report


def _sort_key(five_tuple: FiveTuple) -> tuple[int, int, int, int, int]:
    """Total order over flow keys, so a report is stable across runs.

    `FiveTuple` compares fine as a tuple, but naming the fields keeps the intent
    explicit and survives someone adding an unorderable field to it later.
    """
    return (
        five_tuple.src_ip,
        five_tuple.dst_ip,
        five_tuple.src_port,
        five_tuple.dst_port,
        five_tuple.protocol,
    )
