"""Command-line entry point for the DPI engine (`dpi-engine` console script).

Subcommands:
- `inspect`: print pcap global header + packet summary info (no classification).
- `dump`: print five-tuple/protocol/flags/payload-size for every packet.
- `rules`: build up a blocking rule set (IP/app/domain/port), save/load as JSON.
- `run`: the full pipeline -- read, classify, apply rules, write a filtered
  output pcap, print a processing report. Supports --workers N for the
  hash-partitioned multiprocessing pipeline (Task 10).

Every subcommand that reads a pcap exposes --max-packet-size/--max-total-packets
(Task 11 resource bounds); `run` additionally exposes --max-connections.
"""

from __future__ import annotations

import argparse
import sys

from dpi_engine.connection_tracker import DEFAULT_MAX_CONNECTIONS
from dpi_engine.packet_parser import parse_packet
from dpi_engine.pcap_io import (
    DEFAULT_MAX_PACKET_SIZE,
    DEFAULT_MAX_TOTAL_PACKETS,
    PcapError,
    PcapReader,
)
from dpi_engine.pipeline import run_pipeline, run_pipeline_multiprocess
from dpi_engine.rule_manager import RuleManager, RuleManagerError
from dpi_engine.types import AppType, app_type_to_string

_APP_NAME_TO_TYPE = {app_type_to_string(a).lower(): a for a in AppType}


def _add_pcap_bounds_args(parser: argparse.ArgumentParser) -> None:
    """Adds the shared --max-packet-size/--max-total-packets flags used by
    every subcommand that reads a pcap file."""
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


def _add_rule_building_args(parser: argparse.ArgumentParser) -> None:
    """Adds the shared --block-ip/--block-app/--block-domain/--block-port
    flags used by both `rules` and `run`."""
    parser.add_argument(
        "--block-ip", action="append", default=[], metavar="IP", help="Block a source IP."
    )
    parser.add_argument(
        "--block-app",
        action="append",
        default=[],
        metavar="APP",
        help="Block an application (e.g. YouTube, TikTok).",
    )
    parser.add_argument(
        "--block-domain",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="Block a domain or wildcard pattern (e.g. facebook.com or *.facebook.com).",
    )
    parser.add_argument(
        "--block-port", action="append", default=[], metavar="PORT", help="Block a destination port."
    )


def _apply_rule_building_args(rules: RuleManager, args: argparse.Namespace) -> None:
    """Applies --block-ip/--block-app/--block-domain/--block-port from
    parsed args onto an existing RuleManager. Raises RuleManagerError on
    any invalid value (unknown app name, malformed IP, out-of-range port)."""
    for ip in args.block_ip:
        rules.block_ip(ip)
    for app_name in args.block_app:
        rules.block_app(_resolve_app_name(app_name))
    for domain in args.block_domain:
        rules.block_domain(domain)
    for port in args.block_port:
        rules.block_port(port)


def _cmd_inspect(args: argparse.Namespace) -> int:
    try:
        with PcapReader(
            args.pcap_file,
            max_packet_size=args.max_packet_size,
            max_total_packets=args.max_total_packets,
        ) as reader:
            packet_count = 0
            total_bytes = 0
            min_len = None
            max_len = 0
            for pkt in reader:
                packet_count += 1
                total_bytes += pkt.orig_len
                if min_len is None or pkt.orig_len < min_len:
                    min_len = pkt.orig_len
                if pkt.orig_len > max_len:
                    max_len = pkt.orig_len

            print(f"File:           {args.pcap_file}")
            print(f"Linktype:       {reader.linktype} (Ethernet)")
            print(f"Snaplen:        {reader.snaplen}")
            print(f"Packet count:   {packet_count}")
            print(f"Total bytes:    {total_bytes}")
            if packet_count:
                print(f"Min pkt length: {min_len}")
                print(f"Max pkt length: {max_len}")
    except PcapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


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


def _cmd_run(args: argparse.Namespace) -> int:
    rules = RuleManager()
    try:
        if args.load_rules:
            rules = RuleManager.load_rules(args.load_rules)

        _apply_rule_building_args(rules, args)

        if args.save_rules:
            rules.save_rules(args.save_rules)
            print(f"Saved rules to: {args.save_rules}")
    except RuleManagerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    mode = f"{args.workers} workers" if args.workers and args.workers > 1 else "single-process"
    print(f"DPI Engine v0.1 (Python port, {mode})")
    print(f"Input:  {args.input_pcap}")
    print(f"Output: {args.output_pcap}")
    print()

    try:
        if args.workers and args.workers > 1:
            result = run_pipeline_multiprocess(
                args.input_pcap,
                args.output_pcap,
                rules,
                num_workers=args.workers,
                max_connections=args.max_connections,
                max_packet_size=args.max_packet_size,
                max_total_packets=args.max_total_packets,
            )
        else:
            result = run_pipeline(
                args.input_pcap,
                args.output_pcap,
                rules,
                max_connections=args.max_connections,
                max_packet_size=args.max_packet_size,
                max_total_packets=args.max_total_packets,
            )
    except (PcapError, ValueError) as exc:
        # PcapError covers read/write/format/bounds failures (including the
        # overwrite-protection check, which raises PcapError -- see
        # pcap_io.PcapWriter). ValueError covers an invalid --workers value.
        print(f"error: {exc}", file=sys.stderr)
        return 1

    stats = result.stats
    print("=== Processing Report ===")
    print(f"Total packets:    {stats.total_packets}")
    print(f"Total bytes:      {stats.total_bytes}")
    print(f"TCP packets:      {stats.tcp_packets}")
    print(f"UDP packets:      {stats.udp_packets}")
    print(f"Forwarded:        {stats.forwarded_packets}")
    print(f"Dropped:          {stats.dropped_packets}")
    print(f"Active flows:     {stats.active_connections}")
    if result.per_worker_packet_counts:
        counts_str = ", ".join(
            f"worker{i}={c}" for i, c in enumerate(result.per_worker_packet_counts)
        )
        print(f"Per-worker:       {counts_str}")
    print()

    print("=== Application Breakdown ===")
    total_for_pct = sum(result.app_counts.values()) or 1
    for app, count in sorted(result.app_counts.items(), key=lambda kv: kv[1], reverse=True):
        pct = 100.0 * count / total_for_pct
        bar = "#" * int(pct / 5)
        print(f"{app_type_to_string(app):<15} {count:>6}  {pct:5.1f}%  {bar}")
    print()

    if result.detected_domains:
        print("=== Detected Domains/SNIs ===")
        for domain, app in sorted(result.detected_domains.items()):
            print(f"  - {domain} -> {app_type_to_string(app)}")
        print()

    if result.blocked_flows:
        print("=== Blocked Flows ===")
        for tuple_, app, sni in result.blocked_flows:
            detail = f": {sni}" if sni else ""
            print(f"  - {tuple_} ({app_type_to_string(app)}{detail})")

    return 0


def _resolve_app_name(name: str) -> AppType:
    app = _APP_NAME_TO_TYPE.get(name.lower())
    if app is None:
        valid = ", ".join(sorted(_APP_NAME_TO_TYPE))
        raise RuleManagerError(f"Unknown app name '{name}'. Valid names: {valid}")
    return app


def _cmd_rules(args: argparse.Namespace) -> int:
    try:
        if args.load_rules:
            manager = RuleManager.load_rules(args.load_rules)
            print(f"Loaded rules from: {args.load_rules}")
        else:
            manager = RuleManager()

        for ip in args.block_ip:
            manager.block_ip(ip)
            print(f"Blocked IP: {ip}")
        for app_name in args.block_app:
            app = _resolve_app_name(app_name)
            manager.block_app(app)
            print(f"Blocked app: {app_type_to_string(app)}")
        for domain in args.block_domain:
            manager.block_domain(domain)
            print(f"Blocked domain: {domain}")
        for port in args.block_port:
            manager.block_port(port)
            print(f"Blocked port: {port}")

        stats = manager.get_stats()
        print(
            f"Rule stats: {stats.blocked_ips} IP(s), {stats.blocked_apps} app(s), "
            f"{stats.blocked_domains} domain(s), {stats.blocked_ports} port(s)"
        )

        if args.save_rules:
            manager.save_rules(args.save_rules)
            print(f"Saved rules to: {args.save_rules}")
    except RuleManagerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    from dpi_engine import __version__

    parser = argparse.ArgumentParser(prog="dpi-engine")
    parser.add_argument(
        "--version", action="version", version=f"dpi-engine {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command")

    inspect_parser = subparsers.add_parser(
        "inspect", help="Print pcap global header and packet summary info."
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
        "rules", help="Manage blocking rules: block IPs/apps/domains/ports, save/load."
    )
    rules_parser.add_argument(
        "--load-rules", metavar="PATH", help="Load an existing rules JSON file first."
    )
    rules_parser.add_argument(
        "--save-rules", metavar="PATH", help="Save the resulting rule set to a JSON file."
    )
    _add_rule_building_args(rules_parser)
    rules_parser.set_defaults(func=_cmd_rules)

    run_parser = subparsers.add_parser(
        "run", help="Run the full DPI pipeline: read, classify, filter, write output pcap."
    )
    run_parser.add_argument("input_pcap", help="Path to the input pcap file.")
    run_parser.add_argument("output_pcap", help="Path to write the filtered output pcap.")
    run_parser.add_argument(
        "--load-rules", metavar="PATH", help="Load a rules JSON file before applying --block-* flags."
    )
    run_parser.add_argument(
        "--save-rules",
        metavar="PATH",
        help="Save the resulting rule set (loaded + --block-* flags) to a JSON file.",
    )
    _add_rule_building_args(run_parser)
    run_parser.add_argument(
        "--workers",
        type=int,
        default=1,
        metavar="N",
        help="Number of worker processes for hash-partitioned multiprocessing "
        "(default: 1, meaning single-process). Values > 1 use "
        "run_pipeline_multiprocess.",
    )
    _add_pcap_bounds_args(run_parser)
    run_parser.add_argument(
        "--max-connections",
        type=int,
        default=DEFAULT_MAX_CONNECTIONS,
        metavar="N",
        help="Maximum tracked flows before the oldest is evicted (default: %(default)s). "
        "Bounds per-process memory use regardless of how many distinct "
        "five-tuples appear in the capture.",
    )
    run_parser.set_defaults(func=_cmd_run)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point registered as the `dpi-engine` console script."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
