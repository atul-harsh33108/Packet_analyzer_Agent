"""Command-line entry point for the DPI engine (`dpi-engine` console script).

Subcommands
-----------
``inspect``  pcap header, packet summary, and what this build can do
``dump``     five-tuple / protocol / flags / payload size for every packet
``rules``    build and edit a blocking rule set (IP/app/domain/port), JSON I/O
``run``      the full pipeline: read, classify, apply rules, write filtered
             output pcap, print the report. With ``--store-root DIR`` it also
             writes the run to the store, so an agent can query it later, and
             prints the run id on stderr.

Pipeline selection for ``run`` (``--workers`` / ``--load-balancers``)::

    --workers 1                      single process, no IPC (default)
    --workers N            (N > 1)   reader parses -> N fast-path processes
    --load-balancers K               reader -> K load balancers -> K*F fast paths
    --load-balancers K --fps-per-lb F

Every subcommand that reads a pcap exposes ``--max-packet-size`` /
``--max-total-packets``; ``run`` additionally exposes ``--max-connections`` and
``--flow-timeout``.

``run`` accepts ``--json`` for machine-readable output instead of the text
report.
"""

from __future__ import annotations

import argparse
import sys
import warnings

from dpi_engine.capture_profile import profile_capture
from dpi_engine.connection_tracker import (
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_REAP_INTERVAL_PACKETS,
    DEFAULT_STALE_TIMEOUT_SECONDS,
)
from dpi_engine.packet_parser import parse_packet
from dpi_engine.pcap_io import (
    DEFAULT_MAX_PACKET_SIZE,
    DEFAULT_MAX_TOTAL_PACKETS,
    PcapError,
    PcapReader,
)
from dpi_engine.pipeline import (
    DEFAULT_REORDER_WINDOW,
    PipelineResult,
    run_pipeline,
    run_pipeline_multiprocess,
    run_pipeline_staged,
)
from dpi_engine.report import capabilities, render_full_report, result_to_json
from dpi_engine.rule_manager import (
    RuleManager,
    RuleManagerError,
    resolve_app_name,
    ruleset_fingerprint,
)
from dpi_engine.run_store import RunStore, record_from_result
from dpi_engine.types import app_type_to_string

# ---------------------------------------------------------------------------
# Shared argument groups
# ---------------------------------------------------------------------------


def _add_pcap_bounds_args(parser: argparse.ArgumentParser) -> None:
    """The safety bounds shared by every subcommand that reads a pcap."""
    parser.add_argument(
        "--max-packet-size",
        type=int,
        default=DEFAULT_MAX_PACKET_SIZE,
        metavar="BYTES",
        help="Reject any packet larger than this many bytes (default: %(default)s).",
    )
    parser.add_argument(
        "--max-total-packets",
        type=int,
        default=DEFAULT_MAX_TOTAL_PACKETS,
        metavar="N",
        help="Reject files containing more than this many packets (default: %(default)s).",
    )


def _add_rule_building_args(parser: argparse.ArgumentParser, *, removals: bool = False) -> None:
    """The rule-mutation flags shared by `rules` and `run`."""
    parser.add_argument(
        "--block-ip",
        action="append",
        default=[],
        metavar="IP",
        help="Block an IP, or a whole subnet as CIDR (e.g. 10.0.0.0/8). "
        "Matches either endpoint (DEC-06), not just the source.",
    )
    parser.add_argument(
        "--block-app",
        action="append",
        default=[],
        metavar="APP",
        help="Block an application (e.g. YouTube, TikTok). Case-insensitive.",
    )
    parser.add_argument(
        "--block-domain",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="Block a domain ('facebook.com') or its subdomains "
        "('*.facebook.com'). Matching is anchored at domain boundaries; a "
        "pattern with '*' anywhere else is rejected.",
    )
    parser.add_argument(
        "--block-port",
        action="append",
        default=[],
        metavar="PORT",
        help="Block a destination port.",
    )
    if not removals:
        return
    parser.add_argument(
        "--unblock-ip",
        action="append",
        default=[],
        metavar="IP",
        help="Unblock an IP, or a whole subnet as CIDR (e.g. 10.0.0.0/8).",
    )
    parser.add_argument(
        "--unblock-app",
        action="append",
        default=[],
        metavar="APP",
        help="Unblock an application.",
    )
    parser.add_argument(
        "--unblock-domain",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="Unblock a domain or wildcard pattern.",
    )
    parser.add_argument(
        "--unblock-port",
        action="append",
        default=[],
        metavar="PORT",
        help="Unblock a destination port.",
    )


def _apply_rule_args(rules: RuleManager, args: argparse.Namespace) -> None:
    """Applies every --block-* / --unblock-* flag onto `rules`, in that order.

    Ordering matters: loads first (from the subcommand's own sequencing), then
    blocks, then unblocks. So a command that loads a file and unblocks one
    entry ends up with exactly that entry removed, which is the only ordering
    a user can predict.

    Raises RuleManagerError on any invalid value.
    """
    for ip in args.block_ip:
        rules.block_ip(ip)
    for app_name in args.block_app:
        rules.block_app(resolve_app_name(app_name))
    for domain in args.block_domain:
        rules.block_domain(domain)
    for port in args.block_port:
        rules.block_port(port)

    for ip in getattr(args, "unblock_ip", []) or []:
        rules.unblock_ip(ip)
    for app_name in getattr(args, "unblock_app", []) or []:
        rules.unblock_app(resolve_app_name(app_name))
    for domain in getattr(args, "unblock_domain", []) or []:
        rules.unblock_domain(domain)
    for port in getattr(args, "unblock_port", []) or []:
        rules.unblock_port(port)


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------


def _cmd_inspect(args: argparse.Namespace) -> int:
    # Delegates to the engine's one capture-profile implementation (`T3-03`), which is
    # also what the MCP `inspect_capture` tool calls. This used to be hand-rolled here,
    # and a second copy in `dpi_mcp` would have been a fact with two homes: the day one
    # of them learned about `orig_len` vs file size, the other would silently disagree.
    try:
        profile = profile_capture(
            args.pcap_file,
            max_packet_size=args.max_packet_size,
            max_total_packets=args.max_total_packets,
        )
    except PcapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # `args.pcap_file`, not `profile.path`: the profile normalises the path, and a
    # user who typed a forward slash should see their own string echoed back.
    print(f"File:            {args.pcap_file}")
    print(f"Linktype:        {profile.linktype} (Ethernet)")
    print(f"Snaplen:         {profile.snaplen}")
    print(f"Packet count:    {profile.packet_count}")
    print(f"Total bytes:     {profile.captured_bytes}")
    if profile.packet_count:
        print(f"Min pkt length:  {profile.min_packet_length}")
        print(f"Max pkt length:  {profile.max_packet_length}")
    print()
    print("Capabilities:")
    caps = capabilities()
    if caps["quic_sni_extraction"]:
        print("  QUIC SNI:       available (QUIC Initial packets are decrypted)")
    else:
        print(f"  QUIC SNI:       unavailable -- {caps['quic_sni_unavailable_reason']}")
    return 0


# ---------------------------------------------------------------------------
# dump
# ---------------------------------------------------------------------------


def _cmd_dump(args: argparse.Namespace) -> int:
    try:
        with PcapReader(
            args.pcap_file,
            max_packet_size=args.max_packet_size,
            max_total_packets=args.max_total_packets,
        ) as reader:
            for i, raw in enumerate(reader):
                parsed = parse_packet(raw)
                if parsed is None:
                    print(f"[{i}] <unparseable frame, {raw.orig_len} bytes>")
                    continue

                if parsed.has_ip:
                    flags = f" [{parsed.tcp_flags_str()}]" if parsed.has_tcp else ""
                    print(
                        f"[{i}] {parsed.protocol_str()} "
                        f"{parsed.src_ip_str}:{parsed.src_port} -> "
                        f"{parsed.dst_ip_str}:{parsed.dst_port}"
                        f"{flags} payload={len(parsed.payload)}B"
                    )
                else:
                    print(f"[{i}] {parsed.protocol_str()} (non-IP frame)")
    except PcapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------


def _load_rules_with_notices(path: str) -> RuleManager:
    """Loads a rules file, printing any deprecation warnings it raises.

    Python suppresses `DeprecationWarning` unless it is raised in `__main__`,
    so `DEC-04`'s display-name alias would otherwise load a legacy rules file
    with no visible sign that anything is outdated. A deprecation nobody can
    see migrates nobody, which would make the "deprecation path" in the
    decision a formality rather than a migration. Both CLI call sites load
    through here so the notice cannot be forgotten at one of them.
    """
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        manager = RuleManager.load_rules(path)
    for notice in caught:
        if issubclass(notice.category, DeprecationWarning):
            print(f"warning: {notice.message}", file=sys.stderr)
    return manager


def _cmd_rules(args: argparse.Namespace) -> int:
    try:
        if args.load_rules:
            manager = _load_rules_with_notices(args.load_rules)
            print(f"Loaded rules from: {args.load_rules}")
        else:
            manager = RuleManager()

        before = manager.get_stats()
        _apply_rule_args(manager, args)
        after = manager.get_stats()

        for ip in args.block_ip:
            print(f"Blocked IP: {ip}")
        for app_name in args.block_app:
            print(f"Blocked app: {app_type_to_string(resolve_app_name(app_name))}")
        for domain in args.block_domain:
            print(f"Blocked domain: {domain}")
        for port in args.block_port:
            print(f"Blocked port: {port}")
        for ip in args.unblock_ip:
            print(f"Unblocked IP: {ip}")
        for app_name in args.unblock_app:
            print(f"Unblocked app: {app_type_to_string(resolve_app_name(app_name))}")
        for domain in args.unblock_domain:
            print(f"Unblocked domain: {domain}")
        for port in args.unblock_port:
            print(f"Unblocked port: {port}")

        print(
            f"Rule stats: {after.blocked_ips} IP(s), {after.blocked_apps} app(s), "
            f"{after.blocked_domains} domain(s), {after.blocked_ports} port(s)"
        )
        if after != before and not args.save_rules:
            print("(not saved; pass --save-rules to persist)")

        if args.save_rules:
            manager.save_rules(args.save_rules)
            print(f"Saved rules to: {args.save_rules}")
    except RuleManagerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def _describe_mode(args: argparse.Namespace) -> str:
    if args.load_balancers:
        return (
            f"staged: reader -> {args.load_balancers} load balancer(s) -> "
            f"{args.load_balancers * args.fps_per_lb} fast-path process(es)"
        )
    if args.workers > 1:
        return f"{args.workers} fast-path worker process(es)"
    return "single process"


def _cmd_run(args: argparse.Namespace) -> int:
    rules = RuleManager()
    try:
        if args.load_rules:
            rules = _load_rules_with_notices(args.load_rules)
        _apply_rule_args(rules, args)
        if args.save_rules:
            rules.save_rules(args.save_rules)
            print(f"Saved rules to: {args.save_rules}")
    except RuleManagerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.workers < 1:
        print(f"error: --workers must be >= 1, got {args.workers}", file=sys.stderr)
        return 1
    if args.load_balancers and args.workers != 1:
        print(
            "error: --workers and --load-balancers are mutually exclusive; "
            "the staged pipeline sizes itself from --load-balancers/--fps-per-lb",
            file=sys.stderr,
        )
        return 1
    if args.load_balancers and args.load_balancers < 1:
        print(
            f"error: --load-balancers must be >= 1, got {args.load_balancers}",
            file=sys.stderr,
        )
        return 1
    if args.load_balancers and args.fps_per_lb < 1:
        print(f"error: --fps-per-lb must be >= 1, got {args.fps_per_lb}", file=sys.stderr)
        return 1

    if not args.json:
        print(f"DPI Engine (Python port) -- {_describe_mode(args)}")
        print(f"Input:  {args.input_pcap}")
        print(f"Output: {args.output_pcap}")
        print()

    try:
        result = _execute(args, rules)
    except (PcapError, ValueError) as exc:
        # PcapError covers read/write/format/bounds failures (including the
        # overwrite-protection check). ValueError covers an invalid
        # --workers/--load-balancers/--fps-per-lb value.
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.store_root:
        # The id goes to stderr, not stdout: stdout is the report, and
        # `--json` promises stdout is machine-readable.
        try:
            run_id = _store_run(args, rules, result)
        except (OSError, ValueError) as exc:
            print(f"error: could not store the run: {exc}", file=sys.stderr)
            return 1
        print(f"Stored run: {run_id}", file=sys.stderr)

    if args.json:
        print(result_to_json(result, rules.get_stats()))
    else:
        print(render_full_report(result, rules.get_stats(), top_domains_limit=args.top_domains))
    return 0


def _store_run(args: argparse.Namespace, rules: RuleManager, result: PipelineResult) -> str:
    """Write the run to the store and return its id.

    The stored run is what an agent asks questions about later: `query_flows`,
    `get_flow_detail` and `diff_runs` read it, and they read nothing else.

    The ruleset fingerprint is the hash of the rules *in force* -- the
    effective rule set, not the file it was read from -- so two spellings of the
    same rules are one observation. The MCP layer fingerprints the document it
    was sent, which is the same fingerprint whenever that document is the
    canonical one.
    """
    record = record_from_result(
        result,
        capture_path=args.input_pcap,
        ruleset=ruleset_fingerprint(rules.to_dict()),
    )
    RunStore(args.store_root).save(record)
    return record.run_id


def _execute(args: argparse.Namespace, rules: RuleManager) -> PipelineResult:
    """Dispatches to the pipeline variant the flags select. Split out from
    `_cmd_run` so the flag validation above stays readable."""
    common = {
        "max_connections": args.max_connections,
        "max_packet_size": args.max_packet_size,
        "max_total_packets": args.max_total_packets,
        "stale_timeout_seconds": None if args.flow_timeout <= 0 else args.flow_timeout,
        "reap_interval_packets": args.reap_interval,
        "enable_quic": not args.no_quic,
        # All three variants take it, so unlike `live_rules` it belongs in
        # `common`. Getting this wrong would look like a working run with a
        # subtly different flow table, which is the failure mode D-03 taught.
        "fold_bidirectional": not args.exact_tuple_flows,
        # The per-flow rows are only worth their memory to a caller that will
        # ask questions about the run afterwards -- and the store is exactly
        # that caller. Without `--store-root` nothing asks, so nothing is kept.
        "with_flow_table": bool(args.store_root),
    }

    # `reorder_window` is deliberately NOT in `common`: `run_pipeline` writes
    # each packet as it decides, in input order, with no buffer to size, so it
    # has no such parameter.
    reorder_window = None if args.reorder_window <= 0 else args.reorder_window

    # `live_rules` is deliberately NOT in `common`: `run_pipeline` has no such
    # parameter, because a one-shot single-process run owns its RuleManager and
    # nothing can mutate it mid-run, so the channel would be pure cost. It must
    # therefore be passed explicitly to *both* multiprocess variants -- it used
    # to be passed to only one of them, which is how `--live-rules` came to be
    # silently ignored whenever `--load-balancers` selected the staged pipeline
    # (D-03). A run that ignored the flag looked exactly like one that honoured
    # it, because nothing was mutating the ruleset either way.

    if args.load_balancers:
        return run_pipeline_staged(
            args.input_pcap,
            args.output_pcap,
            rules,
            num_load_balancers=args.load_balancers,
            fps_per_lb=args.fps_per_lb,
            live_rules=args.live_rules,
            reorder_window=reorder_window,
            **common,
        )

    if args.workers > 1:
        return run_pipeline_multiprocess(
            args.input_pcap,
            args.output_pcap,
            rules,
            num_workers=args.workers,
            live_rules=args.live_rules,
            reorder_window=reorder_window,
            **common,
        )

    # Single-process: a RuleBroadcaster is only needed if something could
    # change the rules mid-run, and in a one-shot CLI run nothing can, so it is
    # omitted and the per-packet check disappears entirely.
    return run_pipeline(args.input_pcap, args.output_pcap, rules, **common)


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    from dpi_engine import __version__

    parser = argparse.ArgumentParser(
        prog="dpi-engine",
        description="Deep packet inspection over pcap files: classify by "
        "TLS/HTTP/DNS/QUIC, apply blocking rules, write a filtered capture.",
    )
    parser.add_argument("--version", action="version", version=f"dpi-engine {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Print pcap header info, packet summary, and this build's capabilities.",
    )
    inspect_parser.add_argument("pcap_file", help="Path to the pcap file to inspect.")
    _add_pcap_bounds_args(inspect_parser)
    inspect_parser.set_defaults(func=_cmd_inspect)

    dump_parser = subparsers.add_parser(
        "dump", help="Print five-tuple + protocol for every packet in a pcap."
    )
    dump_parser.add_argument("pcap_file", help="Path to the pcap file to dump.")
    _add_pcap_bounds_args(dump_parser)
    dump_parser.set_defaults(func=_cmd_dump)

    rules_parser = subparsers.add_parser(
        "rules", help="Manage blocking rules: block/unblock IPs, apps, domains, ports."
    )
    rules_parser.add_argument(
        "--load-rules", metavar="PATH", help="Load an existing rules JSON file first."
    )
    rules_parser.add_argument(
        "--save-rules", metavar="PATH", help="Save the resulting rule set to a JSON file."
    )
    _add_rule_building_args(rules_parser, removals=True)
    rules_parser.set_defaults(func=_cmd_rules)

    run_parser = subparsers.add_parser(
        "run", help="Run the DPI pipeline: read, classify, filter, write output pcap."
    )
    run_parser.add_argument("input_pcap", help="Path to the input pcap file.")
    run_parser.add_argument(
        "output_pcap", help="Path to write the filtered output pcap."
    )
    run_parser.add_argument(
        "--load-rules", metavar="PATH", help="Load a rules JSON file before applying --block-*."
    )
    run_parser.add_argument(
        "--save-rules", metavar="PATH", help="Save the resulting rule set to a JSON file."
    )
    _add_rule_building_args(run_parser)

    stage = run_parser.add_argument_group(
        "pipeline stages",
        "Leave all of these alone for the single-process default.",
    )
    stage.add_argument(
        "--workers",
        type=int,
        default=1,
        metavar="N",
        help="Number of fast-path worker processes (default: 1). Values > 1 "
        "use the single-tier multiprocessing pipeline. Mutually exclusive with "
        "--load-balancers.",
    )
    stage.add_argument(
        "--load-balancers",
        type=int,
        default=0,
        metavar="K",
        help="Use the two-tier staged pipeline with K load-balancer processes "
        "and K*--fps-per-lb fast paths. 0 (the default) disables it.",
    )
    stage.add_argument(
        "--fps-per-lb",
        type=int,
        default=2,
        metavar="F",
        help="Fast-path processes per load balancer (default: %(default)s). "
        "Only used with --load-balancers.",
    )
    stage.add_argument(
        "--live-rules",
        action="store_true",
help="Open a per-worker control channel so a RuleManager mutated "
          "while the run is in progress takes effect on the next packet. "
          "Costs one non-blocking queue drain per packet per worker. "
          "Has no effect in single-process mode, where nothing can mutate "
          "the ruleset mid-run: a one-shot run owns its RuleManager and "
          "opens no channel, so the flag is only meaningful when embedding "
          "run_pipeline_multiprocess/run_pipeline_staged directly.",
    )

    tuning = run_parser.add_argument_group("tuning")
    tuning.add_argument(
        "--reorder-window",
        type=int,
        default=DEFAULT_REORDER_WINDOW,
        metavar="W",
        help="How many packets the parent may hold awaiting a worker's verdict "
        "before it gives up preserving input order (default: %(default)s). "
        "Within the window output is byte-identical and in input order; beyond "
        "it, packets whose verdict has not arrived are written out of order "
        "rather than dropped or guessed at. 0 falls back to re-reading the "
        "input in a second pass -- slower to produce anything, but always in "
        "input order. Has no effect in single-process mode, which writes each "
        "packet as it decides and never reorders.",
    )
    tuning.add_argument(
        "--exact-tuple-flows",
        action="store_true",
        help="Key each direction of a conversation as its own flow, instead of "
        "folding the two together (DEC-05). This is the C++ reference "
        "behaviour and is what the differential suite pins. The default folds, "
        "which is a deliberate parity break: it is what makes packets_in and "
        "bytes_in mean anything, and it stops a flow being split across "
        "workers.",
    )

    tuning.add_argument(
        "--max-connections",
        type=int,
        default=DEFAULT_MAX_CONNECTIONS,
        metavar="N",
        help="Maximum tracked flows per process before the least-recently-used "
        "is evicted (default: %(default)s).",
    )
    tuning.add_argument(
        "--flow-timeout",
        type=float,
        default=DEFAULT_STALE_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help="Reclaim flows idle for this long, and reclaim closed flows "
        "immediately (default: %(default)s). 0 disables the idle reaper; "
        "eviction by --max-connections still applies.",
    )
    tuning.add_argument(
        "--reap-interval",
        type=int,
        default=DEFAULT_REAP_INTERVAL_PACKETS,
        metavar="N",
        help="Run a stale-flow sweep at most once per N packets (default: "
        "%(default)s). Each sweep is O(live flows); lowering this reclaims "
        "idle memory sooner at the cost of more sweeps. 0 disables automatic "
        "sweeping entirely.",
    )
    tuning.add_argument(
        "--top-domains",
        type=int,
        default=20,
        metavar="N",
        help="How many top names to list by active flow count (default: %(default)s).",
    )
    tuning.add_argument(
        "--no-quic",
        action="store_true",
        help="Skip QUIC inspection entirely (slightly faster; QUIC traffic is "
        "then counted as unclassified rather than as QUIC).",
    )

    output = run_parser.add_argument_group("output")
    output.add_argument(
        "--json",
        action="store_true",
        help="Emit the report as JSON instead of text.",
    )

    store = run_parser.add_argument_group("store")
    store.add_argument(
        "--store-root",
        metavar="DIR",
        help="Also write the run to the run store under DIR, and print its run id "
        "on stderr. The stored run is what an agent queries later (query_flows, "
        "get_flow_detail, diff_runs); without this flag the store is populated "
        "only by the MCP server. Costs the per-flow rows, which are otherwise "
        "not kept.",
    )

    _add_pcap_bounds_args(run_parser)
    run_parser.set_defaults(func=_cmd_run)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point registered as the `dpi-engine` console script."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    # `set_defaults(func=...)` is untyped argparse; every registered handler
    # returns an int exit code, which is asserted by the test suite.
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
