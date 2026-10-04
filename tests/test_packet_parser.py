"""Tests for dpi_engine.packet_parser.

Covers: parsing real TCP-with-payload / SYN / UDP frames pulled from the
OSC sample capture, non-IP (ARP) frame handling, and truncated-mid-header
frames returning safe partial results instead of crashing.
"""

from __future__ import annotations

import socket

import dpkt

from conftest import TEST_DPI_PCAP
from dpi_engine.packet_parser import ParsedPacket, five_tuple_of, parse_packet
from dpi_engine.pcap_io import PcapReader, RawPacket


def _load_all_parsed() -> list[ParsedPacket]:
    with PcapReader(TEST_DPI_PCAP) as reader:
        raws = list(reader)
    parsed = [parse_packet(r) for r in raws]
    assert all(p is not None for p in parsed), "every real sample packet must parse"
    return parsed  # type: ignore[return-value]


# --- Real sample capture ----------------------------------------------------------


def test_all_sample_packets_parse_without_error() -> None:
    parsed = _load_all_parsed()
    assert len(parsed) == 77  # cross-checked against OSC/README.md sample report


def test_first_packet_is_tcp_syn_to_port_443() -> None:
    parsed = _load_all_parsed()
    first = parsed[0]

    assert first.has_ip
    assert first.has_tcp
    assert first.src_ip_str == "192.168.1.100"
    assert first.dst_port == 443
    assert first.tcp_flags & dpkt.tcp.TH_SYN
    assert not (first.tcp_flags & dpkt.tcp.TH_ACK)
    assert first.payload == b""  # SYN packets carry no payload


def test_fourth_packet_carries_tls_client_hello_payload() -> None:
    parsed = _load_all_parsed()
    pkt = parsed[3]

    assert pkt.has_tcp
    assert pkt.tcp_flags & dpkt.tcp.TH_PUSH
    assert pkt.tcp_flags & dpkt.tcp.TH_ACK
    assert len(pkt.payload) > 0
    # TLS handshake record: content type 0x16 (Handshake).
    assert pkt.payload[0] == 0x16


def test_five_tuple_helper_matches_parsed_fields() -> None:
    parsed = _load_all_parsed()
    pkt = parsed[0]
    tup = five_tuple_of(pkt)
    assert tup == (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)


def test_mac_and_ip_string_formatting_are_stable_across_hosts() -> None:
    """Regression test for the original's latent big-endian-host formatting
    bug (types.cpp's formatIP assumed the host's memcpy byte order). The
    formatting here must not depend on host endianness -- it always treats
    the stored integer as produced by big-endian wire-byte interpretation."""
    parsed = _load_all_parsed()
    pkt = parsed[0]
    assert pkt.src_ip_str == "192.168.1.100"
    assert len(pkt.src_mac_str.split(":")) == 6


# --- Non-IP frames -----------------------------------------------------------------


def test_arp_frame_parses_as_non_ip() -> None:
    # Ethernet header with ARP ethertype (0x0806), zero-filled ARP body.
    frame = b"\xff" * 6 + b"\x00" * 6 + b"\x08\x06" + b"\x00" * 28
    raw = RawPacket(ts_sec=0, ts_usec=0, data=frame, orig_len=len(frame))

    parsed = parse_packet(raw)

    assert parsed is not None
    assert parsed.ether_type == dpkt.ethernet.ETH_TYPE_ARP
    assert not parsed.has_ip
    assert not parsed.has_tcp
    assert not parsed.has_udp
    assert parsed.protocol_str() == "ethertype-0x0806"


# --- Truncated / malformed frames --------------------------------------------------


def test_frame_shorter_than_ethernet_header_returns_none() -> None:
    frame = b"\x00" * 5  # Ethernet header is 14 bytes minimum
    raw = RawPacket(ts_sec=0, ts_usec=0, data=frame, orig_len=len(frame))

    assert parse_packet(raw) is None


def test_ip_header_present_but_tcp_header_truncated_does_not_crash() -> None:
    """Mirrors the exact bug class found in the original createPacketJob:
    an IP header claiming TCP follows, but too few bytes remain for even a
    minimal 20-byte TCP header. Must degrade to has_tcp=False, not read
    past the buffer."""
    tcp_too_short = b"\x04\xd2\x01\xbb\x00\x00\x00\x00\x00\x00"  # 10 bytes, not 20
    ip_total_len = 20 + len(tcp_too_short)
    ip_hdr = (
        bytes([0x45, 0x00])
        + ip_total_len.to_bytes(2, "big")
        + b"\x00" * 4
        + bytes([0x40, 6])  # TTL=64, proto=TCP
        + b"\x00\x00"  # checksum
        + socket.inet_aton("10.0.0.1")
        + socket.inet_aton("10.0.0.2")
    )
    eth_hdr = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    frame = eth_hdr + ip_hdr + tcp_too_short
    raw = RawPacket(ts_sec=0, ts_usec=0, data=frame, orig_len=len(frame))

    parsed = parse_packet(raw)

    assert parsed is not None
    assert parsed.has_ip
    assert not parsed.has_tcp  # truncated header must not be trusted as parsed
    assert parsed.payload == b""


def test_ip_header_itself_truncated_does_not_crash() -> None:
    eth_hdr = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    frame = eth_hdr + b"\x45\x00\x00"  # 3 bytes of a 20-byte minimum IP header
    raw = RawPacket(ts_sec=0, ts_usec=0, data=frame, orig_len=len(frame))

    parsed = parse_packet(raw)

    assert parsed is not None
    assert not parsed.has_ip


def test_udp_packet_parses_correctly() -> None:
    udp_payload = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # fake DNS-ish
    udp_len = 8 + len(udp_payload)
    udp_hdr = (
        (12345).to_bytes(2, "big")
        + (53).to_bytes(2, "big")
        + udp_len.to_bytes(2, "big")
        + (0).to_bytes(2, "big")
    )
    ip_total_len = 20 + udp_len
    ip_hdr = (
        bytes([0x45, 0x00])
        + ip_total_len.to_bytes(2, "big")
        + b"\x00" * 4
        + bytes([0x40, 17])  # TTL=64, proto=UDP
        + b"\x00\x00"
        + socket.inet_aton("10.0.0.1")
        + socket.inet_aton("8.8.8.8")
    )
    eth_hdr = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    frame = eth_hdr + ip_hdr + udp_hdr + udp_payload
    raw = RawPacket(ts_sec=0, ts_usec=0, data=frame, orig_len=len(frame))

    parsed = parse_packet(raw)

    assert parsed is not None
    assert parsed.has_udp
    assert not parsed.has_tcp
    assert parsed.src_port == 12345
    assert parsed.dst_port == 53
    assert parsed.dst_ip_str == "8.8.8.8"
    assert parsed.payload == udp_payload
