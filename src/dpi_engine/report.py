"""Report rendering: human-readable text and machine-readable JSON.

Replaces OSC's three separate ad-hoc report builders --
`DPIEngine::generateReport` (dpi_engine.cpp:408-462),
`DPIEngine::generateClassificationReport` / `FPManager::generateClassificationReport`
(fast_path.cpp:338-402) and `GlobalConnectionTable::generateReport`
(connection_tracker.cpp:218-270) -- with one module, and adds a JSON form the
original never had.

=============================================================================
What OSC got wrong about reporting, and what is different here
=============================================================================
1. **The global/top-domain report was dead code.** OSC built a
   `GlobalConnectionTable` in `DPIEngine::initialize` and had a full
   `generateReport()` for it, but `DPIEngine::processFile` printed
   `generateReport()` and `generateClassificationReport()` and *never called*
   `global_conn_table_->generateReport()`. The table was constructed,
   registered, and then ignored. This module's `render_top_domains` is wired
   into the normal `dpi-engine run` output, so the same data is finally shown.

2. **Percentages used inconsistent denominators.** `main_working.cpp:298`
   divided per-app counts by *total packets read* (including ARP, IPv6 and
   other frames that were never candidates for a rule), while
   `fast_path.cpp:387` divided by *classified + unknown connections*. Two
   reports from the same run disagreed. Here there is exactly one documented
   denominator per quantity, chosen to match the thing being measured, and it
   is stated in the output.

3. **Box-drawing characters were hand-aligned with `std::setw`.** Those reports
   break the moment a value exceeds its column. This module uses plain
   `f`-string field widths with no fixed total width, so nothing can overflow a
   box, and the JSON form has no alignment at all.

4. **No machine-readable output.** Every OSC report was human-only, so nothing
   downstream could consume it. `result_to_dict` provides a stable,
   fully-serialisable form for the same data.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from dpi_engine.connection_tracker import GlobalStats
from dpi_engine.load_balancer import FastPathStats, LoadBalancerStats
from dpi_engine.pipeline import PipelineResult
from dpi_engine.quic import quic_sni_supported, unsupported_reason
from dpi_engine.rule_manager import RuleStats
from dpi_engine.types import AppType, FiveTuple, app_type_to_string

#: Width of the ASCII bar in the application breakdown. 20 characters = 100%.
_BAR_WIDTH = 20


def _bar(percent: float, width: int = _BAR_WIDTH) -> str:
    """A proportional ASCII bar, clamped to `width` so a >100% share (possible
    when the denominator is deliberately different from the numerator's pool)
    can never overflow the column."""
    filled = round(percent / 100.0 * width)
    filled = max(0, min(width, filled))
    return "#" * filled


def _pct(part: int, whole: int) -> float:
    return 0.0 if whole <= 0 else 100.0 * part / whole


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def render_processing_report(result: PipelineResult) -> str:
    """Packet-level counters and the forward/drop outcome.

    Percentages are all over *inspected* packets (TCP + UDP), the only packets
    a rule could ever apply to, so the drop rate is not diluted by unrelated
    link-layer traffic.
    """
    stats = result.stats
    inspected = stats.tcp_packets + stats.udp_packets
    lines = [
        "=== Processing Report ===",
        f"Total packets read:  {stats.total_packets}",
        f"Total bytes read:    {stats.total_bytes}",
        f"  TCP packets:       {stats.tcp_packets}",
        f"  UDP packets:       {stats.udp_packets}",
        f"  other/non-IP:      {stats.other_packets}",
        f"Inspected packets:   {inspected}",
        f"Forwarded:           {stats.forwarded_packets} ({_pct(stats.forwarded_packets, inspected):.1f}% of inspected)",
        f"Dropped:             {stats.dropped_packets} ({result.drop_rate_percent:.1f}% of inspected)",
        f"Active flows (end):  {stats.active_connections}",
    ]
    if result.per_worker_packet_counts:
        counts = ", ".join(
            f"stage{i}={c}" for i, c in enumerate(result.per_worker_packet_counts)
        )
        lines.append(f"Per-stage packets:   {counts}")
    if result.quic_packets or result.quic_undecryptable:
        lines.append(
            f"QUIC datagrams:      {result.quic_packets} seen, "
            f"{result.quic_undecryptable} not decryptable"
        )
    return "\n".join(lines)


def render_extraction_report(result: PipelineResult) -> str:
    """What the DPI layer actually managed to read, and coverage.

    This is the section that answers "how much of this capture did the engine
    genuinely understand?", which a raw app histogram does not: a capture full
    of QUIC 1-RTT looks identical to a capture full of unknown junk unless you
    can see that QUIC was recognised and reported as unreadable.
    """
    fp = result.fast_path_stats
    if fp is None:
        return ""
    attempts = fp.sni_extractions + fp.http_host_extractions + fp.dns_extractions + fp.quic_extractions
    lines = [
        "=== Inspection Coverage ===",
        f"Names extracted:     {attempts}",
        f"  TLS SNI:           {fp.sni_extractions}",
        f"  HTTP Host:         {fp.http_host_extractions}",
        f"  DNS query names:   {fp.dns_extractions}",
        f"  QUIC ClientHello:  {fp.quic_extractions}",
        f"App hits (specific): {fp.classification_hits}",
        f"Flows reaped:        {fp.flows_reaped}",
    ]
    if result.quic_packets:
        note = (
            "all decryptable"
            if result.quic_undecryptable == 0
            else f"{result.quic_undecryptable} could not be decrypted"
        )
        lines.append(f"QUIC coverage:       {note}")
    if result.quic_packets and not quic_sni_supported():
        reason = unsupported_reason() or "unavailable"
        lines.append(f"  note: {reason}")
    return "\n".join(lines)


def render_application_breakdown(result: PipelineResult) -> str:
    """Per-packet application histogram, sorted by volume.

    Denominator is the sum of the histogram itself, so the percentages always
    sum to 100% over the packets that were classified -- the one place where a
    self-normalising denominator is the honest choice, because the numerator
    *is* that pool.
    """
    if not result.app_counts:
        return "=== Application Breakdown ===\n(no TCP/UDP packets)"

    total = sum(result.app_counts.values())
    lines = ["=== Application Breakdown ==="]
    for app, count in sorted(
        result.app_counts.items(), key=lambda kv: (-kv[1], app_type_to_string(kv[0]))
    ):
        pct = _pct(count, total)
        lines.append(
            f"{app_type_to_string(app):<14} {count:>7}  {pct:5.1f}%  {_bar(pct)}"
        )
    return "\n".join(lines)


def render_detected_domains(result: PipelineResult, limit: int = 0) -> str:
    """Every name the engine resolved, with the app it mapped to."""
    if not result.detected_domains:
        return ""
    items = sorted(result.detected_domains.items())
    if limit > 0:
        items = items[:limit]
    lines = [f"=== Resolved Names ({len(result.detected_domains)}) ==="]
    lines += [
        f"  {domain} -> {app_type_to_string(app)}" for domain, app in items
    ]
    return "\n".join(lines)


def render_top_domains(global_stats: GlobalStats, limit: int = 20) -> str:
    """The most-seen names across live flows.

    This is the analogue of `GlobalConnectionTable::generateReport`'s "TOP
    DOMAINS" section, which OSC built but never printed (see the module
    docstring).
    """
    if not global_stats.top_domains:
        return ""
    shown = global_stats.top_domains[:limit] if limit > 0 else global_stats.top_domains
    lines = [f"=== Top {len(shown)} Names by Active Flows ==="]
    for domain, count in shown:
        lines.append(f"  {domain:<50} {count:>5}")
    return "\n".join(lines)


def render_flow_states(global_stats: GlobalStats) -> str:
    """Live flows by lifecycle state, and the aggregate tracker counters.

    A histogram rather than one line per state, for the reason documented on
    `GlobalStats.state_counts`.
    """
    lines = ["=== Flow State ==="]
    total = sum(global_stats.state_counts.values())
    for state, count in sorted(
        global_stats.state_counts.items(), key=lambda kv: (-kv[1], kv[0].name)
    ):
        lines.append(f"  {state.name:<12} {count:>7}  {_pct(count, total):5.1f}%")
    lines.append(f"  {'TOTAL':<12} {total:>7}")
    return "\n".join(lines)


def render_rule_stats(stats: RuleStats) -> str:
    lines = ["=== Active Rules ==="]
    lines += [
        f"  blocked IPs:       {stats.blocked_ips}",
        f"  blocked apps:      {stats.blocked_apps}",
        f"  blocked domains:   {stats.blocked_domains}",
        f"  blocked ports:     {stats.blocked_ports}",
    ]
    return "\n".join(lines)


def render_blocked_flows(blocked_flows: Sequence[tuple[FiveTuple, AppType, str]]) -> str:
    if not blocked_flows:
        return ""
    lines = [f"=== Blocked Flows ({len(blocked_flows)}) ==="]
    for tuple_, app, sni in blocked_flows:
        detail = f": {sni}" if sni else ""
        lines.append(f"  {tuple_} -> {app_type_to_string(app)}{detail}")
    return "\n".join(lines)


def render_stage_report(
    load_balancer_stats: LoadBalancerStats | None,
    fast_path_stats: FastPathStats | None,
) -> str:
    """Per-stage counters, the analogue of OSC's report sections for the load
    balancer and fast path.

    Emitted only when there is something to say, and only in the staged
    pipeline: the single-tier pipeline has one stage and its totals are already
    in the processing report.
    """
    if load_balancer_stats is None and fast_path_stats is None:
        return ""
    lines = ["=== Pipeline Stages ==="]
    if load_balancer_stats is not None:
        lines += [
            "  Load balancers:",
            f"    packets received:   {load_balancer_stats.packets_received}",
            f"    packets dispatched: {load_balancer_stats.packets_dispatched}",
        ]
        for fp_id, count in sorted(load_balancer_stats.per_fp_packets.items()):
            lines.append(f"    to fast-path {fp_id}:  {count}")
    if fast_path_stats is not None:
        lines += [
            "  Fast paths (aggregate):",
            f"    packets processed:  {fast_path_stats.packets_processed}",
            f"    packets forwarded:  {fast_path_stats.packets_forwarded}",
            f"    packets dropped:    {fast_path_stats.packets_dropped}",
            f"    connections:        {fast_path_stats.connections_tracked}",
            f"    flows reaped:       {fast_path_stats.flows_reaped}",
            f"    rule updates:       {fast_path_stats.rule_updates_applied}",
        ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Whole-run reports
# ---------------------------------------------------------------------------


def render_full_report(
    result: PipelineResult,
    rule_stats: RuleStats | None = None,
    *,
    top_domains_limit: int = 20,
) -> str:
    """The complete human-readable report for one run.

    Sections that have no data are omitted rather than printed empty, so the
    output stays readable on a capture that, say, contained no QUIC.
    """
    sections = [
        render_processing_report(result),
        render_stage_report(result.load_balancer_stats, result.fast_path_stats),
        render_extraction_report(result),
        render_application_breakdown(result),
        render_flow_states(result.global_stats) if result.global_stats else "",
        render_top_domains(result.global_stats, top_domains_limit)
        if result.global_stats
        else "",
        render_rule_stats(rule_stats) if rule_stats else "",
        render_blocked_flows(result.blocked_flows),
        render_detected_domains(result),
    ]
    return "\n\n".join(section for section in sections if section)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def result_to_dict(
    result: PipelineResult,
    rule_stats: RuleStats | None = None,
) -> dict[str, Any]:
    """A fully JSON-serialisable view of a run.

    Enum keys are rendered as their display names / names rather than as
    `AppType.GOOGLE`, so consumers see `"Google"` and `"NEW"` -- the same
    vocabulary the text report uses. Nothing here is a dataclass instance, so
    `json.dumps` cannot fail on a non-serialisable field.
    """
    payload: dict[str, Any] = {
        "stats": {
            "total_packets": result.stats.total_packets,
            "total_bytes": result.stats.total_bytes,
            "tcp_packets": result.stats.tcp_packets,
            "udp_packets": result.stats.udp_packets,
            "other_packets": result.stats.other_packets,
            "forwarded_packets": result.stats.forwarded_packets,
            "dropped_packets": result.stats.dropped_packets,
            "active_connections": result.stats.active_connections,
            "drop_rate_percent": round(result.drop_rate_percent, 4),
        },
        "app_counts": {
            app_type_to_string(app): count
            for app, count in sorted(
                result.app_counts.items(), key=lambda kv: -kv[1]
            )
        },
        "detected_domains": {
            domain: app_type_to_string(app)
            for domain, app in sorted(result.detected_domains.items())
        },
        "blocked_flows": [
            {
                "flow": str(tuple_),
                "app": app_type_to_string(app),
                "sni": sni,
            }
            for tuple_, app, sni in result.blocked_flows
        ],
        "quic": {
            "datagrams_seen": result.quic_packets,
            "undecryptable": result.quic_undecryptable,
            "sni_extraction_supported": quic_sni_supported(),
        },
        "per_stage_packet_counts": list(result.per_worker_packet_counts),
    }

    if result.fast_path_stats is not None:
        payload["fast_path_stats"] = result.fast_path_stats.to_dict()
    if result.load_balancer_stats is not None:
        payload["load_balancer_stats"] = result.load_balancer_stats.to_dict()
    if result.global_stats is not None:
        gs = result.global_stats
        payload["flows"] = {
            "active": gs.total_active_connections,
            "total_seen": gs.total_connections_seen,
            "classified": gs.classified_connections,
            "blocked": gs.blocked_connections,
            "unidentified": gs.unknown_connections,
            "states": {state.name: count for state, count in sorted(
                gs.state_counts.items(), key=lambda kv: kv[0].name
            )},
            "top_domains": [
                {"name": domain, "flows": count} for domain, count in gs.top_domains
            ],
        }
    if rule_stats is not None:
        payload["rules"] = {
            "blocked_ips": rule_stats.blocked_ips,
            "blocked_apps": rule_stats.blocked_apps,
            "blocked_domains": rule_stats.blocked_domains,
            "blocked_ports": rule_stats.blocked_ports,
        }
    return payload


def result_to_json(
    result: PipelineResult,
    rule_stats: RuleStats | None = None,
    *,
    indent: int | None = 2,
) -> str:
    return json.dumps(result_to_dict(result, rule_stats), indent=indent, sort_keys=False)


def capabilities() -> Mapping[str, Any]:
    """What this build can and cannot do, for `dpi-engine inspect`.

    Reported rather than assumed: a user who sees "QUIC SNI: unavailable" can
    act on it, whereas a silent fallback just looks like a quiet network.
    """
    return {
        "quic_sni_extraction": quic_sni_supported(),
        "quic_sni_unavailable_reason": unsupported_reason(),
    }
