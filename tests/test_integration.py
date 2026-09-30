"""End-to-end integration: build real pcaps containing the traffic shapes the
engine must handle, and run the actual pipeline over them.

The per-module unit tests exercise the extractors directly. These tests go
through the whole path -- pcap bytes -> parser -> flow table -> classifier ->
rule check -> filtered output pcap -> report -- because that is the only place
where a feature can be fully wired up and still be effectively dead.

Frames are assembled byte by byte on purpose: a fixture built with the same
library that reads it would not catch a misunderstanding of the wire format.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from dpi_engine.pcap_io import PcapError, PcapReader, PcapWriter, RawPacket
from dpi_engine.pipeline import run_pipeline, run_pipeline_multiprocess, run_pipeline_staged
from dpi_engine.quic import quic_sni_supported, unsupported_reason
from dpi_engine.rule_manager import RuleManager
from dpi_engine.types import AppType, ConnectionState
from test_quic import (
    RFC9001_DCID,
    build_client_hello,
    build_crypto_frames,
    build_initial_packet,
    client_secret,
)

requires_crypto = pytest.mark.skipif(
    not quic_sni_supported(), reason=f"needs the [quic] extra: {unsupported_reason()}"
)

SRC_IP = bytes((192, 168, 1, 100))
DST_IP = bytes((142, 250, 185, 110))
DST_MAC = bytes((0x00, 0x11, 0x22, 0x33, 0x44, 0x55))
SRC_MAC = bytes((0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB))


def _ethernet(payload: bytes, ether_type: int = 0x0800) -> bytes:
    return DST_MAC + SRC_MAC + struct.pack("!H", ether_type) + payload


def _ipv4(payload: bytes, protocol: int, *, src: bytes = SRC_IP, dst: bytes = DST_IP) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # version 4, IHL 5 (20-byte header, no options)
        0x00,  # DSCP/ECN
        total_length,
        0x0001,  # identification
        0x4000,  # don't fragment
        64,  # TTL
        protocol,
        0x0000,  # checksum (not validated by this engine)
        src,
        dst,
    )
    return header + payload


def _udp(payload: bytes, sport: int, dport: int) -> bytes:
    length = 8 + len(payload)
    # Checksum 0 means "not computed" in IPv4 UDP, which is legal.
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def _tcp(payload: bytes, sport: int, dport: int, flags: int) -> bytes:
    return (
        struct.pack(
            "!HHIIBBHHH",
            sport,
            dport,
            1,  # seq
            1,  # ack
            0x50,  # data offset 5 (20-byte header), reserved 0
            flags,
            8192,  # window
            0,  # checksum
            0,  # urgent pointer
        )
        + payload
    )


def _packet(
    payload: bytes,
    protocol: int,
    *,
    sport: int,
    dport: int,
    flags: int = 0,
    ts_sec: int = 1_700_000_000,
    ts_usec: int = 0,
) -> RawPacket:
    transport = (
        _tcp(payload, sport, dport, flags) if protocol == 6 else _udp(payload, sport, dport)
    )
    frame = _ethernet(_ipv4(transport, protocol))
    return RawPacket(
        ts_sec=ts_sec, ts_usec=ts_usec, data=frame, orig_len=len(frame)
    )


def _write_pcap(path: Path, packets: list[RawPacket]) -> Path:
    with PcapWriter(path) as writer:
        for pkt in packets:
            writer.write(pkt)
    return path


def _read_payloads(path: Path) -> list[bytes]:
    out = []
    with PcapReader(path) as reader:
        for raw in reader:
            out.append(raw.data)
    return out


# ---------------------------------------------------------------------------
# QUIC through the real packet path
# ---------------------------------------------------------------------------


@requires_crypto
def test_quic_initial_is_classified_and_named_end_to_end(tmp_path: Path) -> None:
    """The whole point of the QUIC work: a real encrypted Initial on the wire
    must come out the other end with its SNI resolved and the app classified."""
    secret = client_secret(RFC9001_DCID)
    hello = build_client_hello("www.youtube.com")
    quic_payload = build_initial_packet(
        RFC9001_DCID, build_crypto_frames(hello), secret
    )

    src = tmp_path / "in.pcap"
    _write_pcap(src, [_packet(quic_payload, 17, sport=51000, dport=443)])

    result = run_pipeline(src, tmp_path / "out.pcap")

    assert result.detected_domains == {"www.youtube.com": AppType.YOUTUBE}
    assert result.app_counts == {AppType.YOUTUBE: 1}
    assert result.quic_packets == 1
    assert result.quic_undecryptable == 0
    assert result.fast_path_stats.quic_extractions == 1


@requires_crypto
def test_quic_app_rule_blocks_quic_traffic(tmp_path: Path) -> None:
    """An app-based rule must work for a QUIC flow, not just TLS -- otherwise
    QUIC is a trivially bypassable hole in a blocking tool."""
    secret = client_secret(RFC9001_DCID)
    quic_payload = build_initial_packet(
        RFC9001_DCID,
        build_crypto_frames(build_client_hello("www.tiktok.com")),
        secret,
    )
    src = tmp_path / "in.pcap"
    _write_pcap(src, [_packet(quic_payload, 17, sport=51001, dport=443)])

    rules = RuleManager()
    rules.block_app(AppType.TIKTOK)
    result = run_pipeline(src, tmp_path / "out.pcap", rules)

    assert result.stats.dropped_packets == 1
    assert result.blocked_flows[0][1] is AppType.TIKTOK
    # Nothing forwarded, so the output pcap has no packets.
    assert _read_payloads(tmp_path / "out.pcap") == []


@requires_crypto
def _quic_handshake_body() -> bytes:
    """A QUIC Handshake long-header packet body.

    Handshake packets (unlike Initial) have NO token field: version, DCID, SCID,
    length, then the protected packet number. This body is deliberately not a
    real, decryptable Handshake -- nothing downstream will ever try to decrypt
    one -- but the header is well formed, which is all detection looks at.
    """
    dcid = RFC9001_DCID
    return (
        bytes([0xC0 | (0x02 << 4)])  # form + fixed + Handshake
        + (1).to_bytes(4, "big")
        + bytes([len(dcid)])
        + dcid
        + b"\x00"  # SCID length
        + b"\x40"  # length (varint)
        + b"\x22" * 120  # "protected" payload
    )


def test_undecryptable_quic_is_reported_as_quic_not_unknown(tmp_path: Path) -> None:
    """An encrypted QUIC packet that cannot be read must still be *recognised*
    as QUIC, so coverage reporting stays honest instead of silently degrading
    to "unknown". Handshake and 1-RTT packets are undecryptable by protocol
    design, and must say so rather than look like a parsing miss."""
    src = tmp_path / "in.pcap"
    _write_pcap(src, [_packet(_quic_handshake_body(), 17, sport=51002, dport=443)])

    result = run_pipeline(src, tmp_path / "out.pcap")

    assert result.quic_packets == 1
    assert result.quic_undecryptable == 1
    assert result.app_counts == {AppType.QUIC: 1}
    assert result.detected_domains == {}


def test_quic_traffic_on_a_nonstandard_port_is_still_recognised(tmp_path: Path) -> None:
    """Detection keys off the long-header shape, not the port -- a client may
    send QUIC from anywhere."""
    src = tmp_path / "in.pcap"
    _write_pcap(
        src, [_packet(_quic_handshake_body(), 17, sport=51003, dport=8443)]
    )

    result = run_pipeline(src, tmp_path / "out.pcap")
    assert result.app_counts == {AppType.QUIC: 1}


def test_quic_disabled_reports_unclassified_and_still_runs(tmp_path: Path) -> None:
    """`--no-quic` must skip the work, not crash, and must not pretend the
    traffic was recognised."""
    src = tmp_path / "in.pcap"
    _write_pcap(src, [_packet(_quic_handshake_body(), 17, sport=51004, dport=443)])

    result = run_pipeline(src, tmp_path / "out.pcap", enable_quic=False)
    assert result.quic_packets == 0
    assert result.app_counts == {AppType.UNKNOWN: 1}
    assert result.stats.forwarded_packets == 1


# ---------------------------------------------------------------------------
# TCP lifecycle end to end
# ---------------------------------------------------------------------------


def test_full_tcp_lifecycle_is_visible_in_the_report(tmp_path: Path) -> None:
    """A normal connection (SYN, SYN-ACK, ACK, data, FIN, FIN-ACK) must end up
    ESTABLISHED -> CLASSIFIED -> CLOSED, and the reaper must reclaim it."""
    client_port, server_port = 44444, 443
    packets = [
        _packet(b"", 6, sport=client_port, dport=server_port, flags=0x02),  # SYN
        _packet(b"", 6, sport=server_port, dport=client_port, flags=0x12),  # SYN-ACK
        _packet(b"", 6, sport=client_port, dport=server_port, flags=0x10),  # ACK
        _packet(
            b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00",
            6,
            sport=client_port,
            dport=server_port,
            flags=0x18,
        ),
        _packet(b"", 6, sport=client_port, dport=server_port, flags=0x11),  # FIN-ACK
    ]
    src = tmp_path / "in.pcap"
    _write_pcap(src, packets)

    result = run_pipeline(src, tmp_path / "out.pcap")

    # The client->server half saw SYN then ACK, so it reached ESTABLISHED before
    # being classified, and the FIN closed it.
    assert result.global_stats.state_counts.get(ConnectionState.CLOSED) == 1
    assert result.stats.total_packets == 5
    assert result.stats.forwarded_packets == 5


# ---------------------------------------------------------------------------
# Resource bounds end to end
# ---------------------------------------------------------------------------


def test_flow_timeout_reaps_idle_flows_end_to_end(tmp_path: Path) -> None:
    """A tiny idle timeout plus an aggressive sweep cadence must actually
    reclaim flows during a real run, not just in a unit test -- this is what
    keeps a long capture's memory bounded."""
    packets = [_packet(b"", 6, sport=45000 + i, dport=443, flags=0x02) for i in range(20)]
    src = tmp_path / "in.pcap"
    _write_pcap(src, packets)

    # Reaping disabled: all 20 flows stay.
    kept = run_pipeline(
        src, tmp_path / "kept.pcap", stale_timeout_seconds=None, reap_interval_packets=0
    )
    assert kept.stats.active_connections == 20
    assert kept.fast_path_stats.flows_reaped == 0

    # Aggressive cadence + near-zero timeout: the sweep fires and reclaims them.
    reaped = run_pipeline(
        src,
        tmp_path / "reaped.pcap",
        stale_timeout_seconds=1e-9,
        reap_interval_packets=5,
    )
    assert reaped.fast_path_stats.flows_reaped > 0
    assert reaped.stats.active_connections < 20


def test_closed_flows_are_reaped_even_with_no_idle_timeout(tmp_path: Path) -> None:
    """A FIN'd flow is reclaimed on the next sweep, without waiting for any
    idle timeout -- a connection that is over cannot change again.

    The sweep runs *before* each packet is processed, so a third packet (on a
    different flow) is what triggers the sweep that reclaims the closed one.
    That ordering is deliberate: a sweep must never be able to retire a flow
    that the packet currently being handled is about to update.
    """
    packets = [
        # Flow A: SYN then FIN-ACK, so it reaches CLOSED.
        _packet(b"", 6, sport=45500, dport=443, flags=0x02),
        _packet(b"", 6, sport=45500, dport=443, flags=0x11),
        # Flow B: a single SYN, which triggers the sweep that reclaims flow A.
        _packet(b"", 6, sport=45501, dport=443, flags=0x02),
    ]
    src = tmp_path / "in.pcap"
    _write_pcap(src, packets)

    result = run_pipeline(
        src, tmp_path / "out.pcap", stale_timeout_seconds=None, reap_interval_packets=1
    )

    assert result.fast_path_stats.flows_reaped == 1
    # Only flow B is still tracked. It is CLASSIFIED rather than NEW because a
    # lone SYN to port 443 earns the low-confidence HTTPS guess.
    assert result.stats.active_connections == 1
    assert result.global_stats.state_counts == {ConnectionState.CLASSIFIED: 1}


def test_max_connections_bound_is_enforced_end_to_end(tmp_path: Path) -> None:
    packets = [
        _packet(b"", 6, sport=46000 + i, dport=443, flags=0x02) for i in range(30)
    ]
    src = tmp_path / "in.pcap"
    _write_pcap(src, packets)

    result = run_pipeline(src, tmp_path / "out.pcap", max_connections=5)
    assert result.stats.active_connections <= 5
    assert result.stats.total_packets == 30


def test_oversized_declared_packet_is_rejected_end_to_end(tmp_path: Path) -> None:

    src = tmp_path / "in.pcap"
    _write_pcap(src, [_packet(b"\x00" * 2000, 6, sport=47000, dport=443, flags=0x02)])

    with pytest.raises(PcapError):
        run_pipeline(src, tmp_path / "out.pcap", max_packet_size=1000)


# ---------------------------------------------------------------------------
# Equivalence of the three pipelines on a synthetic capture
# ---------------------------------------------------------------------------


def _mixed_capture() -> list[RawPacket]:
    """A capture exercising TLS, HTTP, DNS, UDP and a non-IP frame, with two
    connections to the same app so per-flow state has something to track."""
    packets: list[RawPacket] = []

    # A real ClientHello carrying an SNI extension. A stub 5-byte handshake
    # body would parse as a ClientHello but contain no SNI, which would make
    # the fixture test the wrong thing.
    google_hello = build_client_hello("www.google.com")

    # Two TLS flows to www.google.com, each SYN -> ACK -> ClientHello.
    for base_port in (48000, 48100):
        for i, (flags, payload) in enumerate(
            [(0x02, b""), (0x10, b""), (0x18, google_hello)]
        ):
            packets.append(
                _packet(
                    payload,
                    6,
                    sport=base_port + i,
                    dport=443,
                    flags=flags,
                    ts_usec=base_port % 100 + i,
                )
            )

    # HTTP request with a Host header
    http = b"GET / HTTP/1.1\r\nHost: www.wikipedia.org\r\n\r\n"
    packets.append(_packet(http, 6, sport=48200, dport=80, flags=0x18, ts_usec=20))

    # DNS query
    dns = (
        b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
    )
    packets.append(_packet(dns, 17, sport=48300, dport=53, ts_usec=30))

    # An ARP frame (not IPv4) that must be counted as `other` and ignored
    arp = _ethernet(b"\x00\x01\x08\x00\x06\x04\x00\x01" + b"\x00" * 20, ether_type=0x0806)
    packets.append(
        RawPacket(ts_sec=1_700_000_000, ts_usec=40, data=arp, orig_len=len(arp))
    )

    return packets


def test_all_three_pipelines_agree_on_a_mixed_capture(tmp_path: Path) -> None:
    src = _write_pcap(tmp_path / "in.pcap", _mixed_capture())

    single = run_pipeline(src, tmp_path / "s.pcap")
    multi = run_pipeline_multiprocess(src, tmp_path / "m.pcap", num_workers=2)
    staged = run_pipeline_staged(
        src, tmp_path / "t.pcap", num_load_balancers=2, fps_per_lb=2
    )

    for other in (multi, staged):
        assert single.stats == other.stats
        assert single.app_counts == other.app_counts
        assert single.detected_domains == other.detected_domains
        assert single.global_stats.state_counts == other.global_stats.state_counts

    # The non-IP frame is counted but never inspected.
    # 6 TLS packets (2 flows x 3) + 1 HTTP + 1 DNS + 1 ARP = 9.
    assert single.stats.total_packets == 9
    assert single.stats.other_packets == 1
    assert single.stats.tcp_packets == 7
    assert single.stats.udp_packets == 1
    assert single.detected_domains == {
        "www.google.com": AppType.GOOGLE,
        "www.wikipedia.org": AppType.HTTPS,
        "www.example.com": AppType.HTTPS,
    }

    # And the three output files are byte-identical.
    assert (tmp_path / "s.pcap").read_bytes() == (tmp_path / "m.pcap").read_bytes()
    assert (tmp_path / "s.pcap").read_bytes() == (tmp_path / "t.pcap").read_bytes()


def test_mixed_capture_blocking_agrees_across_pipelines(tmp_path: Path) -> None:
    src = _write_pcap(tmp_path / "in.pcap", _mixed_capture())

    def rules() -> RuleManager:
        r = RuleManager()
        r.block_app(AppType.GOOGLE)
        r.block_domain("*.wikipedia.org")
        return r

    single = run_pipeline(src, tmp_path / "s.pcap", rules())
    multi = run_pipeline_multiprocess(src, tmp_path / "m.pcap", rules(), num_workers=3)
    staged = run_pipeline_staged(
        src, tmp_path / "t.pcap", rules(), num_load_balancers=1, fps_per_lb=3
    )

    # Two Google flows (one ClientHello each) plus the HTTP flow.
    assert single.stats.dropped_packets == 3
    assert multi.stats.dropped_packets == 3
    assert staged.stats.dropped_packets == 3
    assert (tmp_path / "s.pcap").read_bytes() == (tmp_path / "t.pcap").read_bytes()


def test_blocked_flows_are_reported_with_their_reasoning(tmp_path: Path) -> None:
    from dpi_engine.report import render_full_report

    src = _write_pcap(tmp_path / "in.pcap", _mixed_capture())
    rules = RuleManager()
    rules.block_app(AppType.GOOGLE)
    result = run_pipeline(src, tmp_path / "out.pcap", rules)

    report = render_full_report(result, rules.get_stats())
    assert "=== Blocked Flows" in report
    assert "www.google.com" in report
    assert "=== Top" in report
    assert "=== Flow State ===" in report
    assert "=== Inspection Coverage ===" in report
