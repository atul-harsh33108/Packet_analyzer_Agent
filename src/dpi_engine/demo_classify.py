"""Task 7 demo: single-process, end-to-end classification over a pcap.

Wires together pcap_io -> packet_parser -> connection_tracker ->
sni_extractor/types classification, with no rule-checking or output-pcap
writing yet (those land in Task 8's full pipeline). This exists to
demonstrate and manually sanity-check the ConnectionTracker in isolation
before it's wired into the real pipeline.

Usage: uv run python -m dpi_engine.demo_classify <pcap_file>
"""

from __future__ import annotations

import sys

from dpi_engine.connection_tracker import ConnectionTracker
from dpi_engine.packet_parser import ParsedPacket, parse_packet
from dpi_engine.pcap_io import PcapError, PcapReader
from dpi_engine.sni_extractor import extract_dns_query, extract_http_host, extract_sni
from dpi_engine.types import AppType, FiveTuple, app_type_to_string, sni_to_app_type


def classify_packet(parsed: ParsedPacket) -> tuple[AppType, str, bool] | None:
    """Attempts to classify a single packet's payload.

    Returns (app_type, sni_or_host, confirmed) or None if nothing could be
    determined from this packet alone (e.g. an empty-payload SYN/ACK).
    Mirrors the classification order used by the original's FastPath
    (SNI -> HTTP Host -> DNS -> port-based fallback guess).
    """
    if not parsed.payload:
        return None

    if parsed.has_tcp and parsed.dst_port == 443:
        sni = extract_sni(parsed.payload)
        if sni:
            return sni_to_app_type(sni), sni, True

    if parsed.has_tcp and parsed.dst_port == 80:
        host = extract_http_host(parsed.payload)
        if host:
            return sni_to_app_type(host), host, True

    if parsed.has_udp and parsed.dst_port == 53:
        query = extract_dns_query(parsed.payload)
        if query:
            return sni_to_app_type(query), query, True

    # Low-confidence port-based fallback guess (never overwrites a
    # confirmed classification -- see connection_tracker.py).
    if parsed.has_tcp and parsed.dst_port == 443:
        return AppType.HTTPS, "", False
    if parsed.has_tcp and parsed.dst_port == 80:
        return AppType.HTTP, "", False

    return None


def run(pcap_path: str) -> int:
    tracker = ConnectionTracker(fp_id=0)

    try:
        with PcapReader(pcap_path) as reader:
            for raw in reader:
                parsed = parse_packet(raw)
                if parsed is None or not parsed.has_ip:
                    continue

                five_tuple = FiveTuple(
                    src_ip=parsed.src_ip,
                    dst_ip=parsed.dst_ip,
                    src_port=parsed.src_port,
                    dst_port=parsed.dst_port,
                    protocol=parsed.protocol,
                )
                conn = tracker.get_or_create_connection(five_tuple)
                tracker.update_connection(conn, len(raw.data), is_outbound=True)

                result = classify_packet(parsed)
                if result is not None:
                    app_type, sni_or_host, confirmed = result
                    tracker.classify_connection(conn, app_type, sni_or_host, confirmed=confirmed)
    except PcapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"{'Flow':<45} {'App':<12} {'SNI/Host':<25} {'Pkts':>6}")
    print("-" * 90)
    for conn in tracker.get_all_connections():
        flow_str = str(conn.tuple)
        app_str = app_type_to_string(conn.app_type)
        pkt_count = conn.packets_in + conn.packets_out
        print(f"{flow_str:<45} {app_str:<12} {conn.sni:<25} {pkt_count:>6}")

    stats = tracker.get_stats()
    print("-" * 90)
    print(
        f"Total connections seen: {stats.total_connections_seen}  "
        f"Classified: {stats.classified_connections}"
    )
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m dpi_engine.demo_classify <pcap_file>", file=sys.stderr)
        return 2
    return run(sys.argv[1])


if __name__ == "__main__":
    sys.exit(main())
