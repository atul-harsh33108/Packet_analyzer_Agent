"""Tests for dpi_engine.packet_parser.

Covers: parsing real TCP-with-payload / SYN / UDP frames pulled from the
OSC sample capture, non-IP (ARP) frame handling, and truncated-mid-header
frames returning safe partial results instead of crashing.
"""

from __future__ import annotations

import socket

import dpkt
import pytest

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


# ---------------------------------------------------------------------------
# D-14: VLAN / 802.1Q and QinQ
# ---------------------------------------------------------------------------
#
# `dpkt.ethernet.Ethernet` reads the EtherType at offset 12 and stops. On a
# tagged frame that is 0x8100, which is not IPv4, so the frame was returned as
# "non-IP, nothing further to parse" -- and 100% of VLAN-tagged traffic was
# silently discarded. VLAN-tagged captures are the norm in enterprise networks,
# so this is the traffic the tool is most likely to be pointed at.
#
# The critical property is not merely "tags are now parsed" but that **tagging
# does not change the flow**: the key stays L3, so a tagged frame and its
# untagged twin must produce an identical FiveTuple and an identical
# classification. A VLAN-aware-but-tag-sensitive parser would be worse than the
# bug, because it would split one conversation into two half-classified flows.


_ETH_IP = b"\x08\x00"
_TAG_8021Q = b"\x81\x00"
_TAG_8021AD = b"\x88\xa8"
_TAG_QINQ = b"\x91\x00"


def _vlan_tci(vid: int, priority: int = 0, cfi: int = 0) -> bytes:
    tci = ((cfi & 1) << 12) | ((priority & 0x7) << 13) | (vid & 0x0FFF)
    return tci.to_bytes(2, "big")


def _tag(inner: bytes, vid: int, tag_type: bytes = _TAG_8021Q, priority: int = 0) -> bytes:
    """Wraps an Ethernet frame in one VLAN tag."""
    return inner[:12] + tag_type + _vlan_tci(vid, priority) + inner[12:]


def _untagged_tcp_frame(
    *, src_port: int = 51000, dst_port: int = 443, payload: bytes = b""
) -> bytes:
    """A minimal, well-formed Ethernet/IPv4/TCP frame."""
    eth = b"\xaa" * 6 + b"\xbb" * 6 + _ETH_IP
    tcp = (
        src_port.to_bytes(2, "big")
        + dst_port.to_bytes(2, "big")
        + (0).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + bytes([0x50, 0x18])          # data offset 5 words, PSH|ACK
        + (65535).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + payload
    )
    total_len = 20 + len(tcp)
    ip = (
        bytes([0x45, 0x00])
        + total_len.to_bytes(2, "big")
        + b"\x00\x00"
        + b"\x40\x00"
        + bytes([64, 6])                # TTL 64, protocol TCP
        + b"\x00\x00"
        + socket.inet_aton("10.1.2.3")
        + socket.inet_aton("93.184.216.34")
    )
    return eth + ip + tcp


def _raw(frame: bytes) -> RawPacket:
    return RawPacket(ts_sec=0, ts_usec=0, data=frame, orig_len=len(frame))


def test_untagged_frame_reports_no_vlan() -> None:
    parsed = parse_packet(_raw(_untagged_tcp_frame()))
    assert parsed is not None
    assert parsed.has_ip and parsed.has_tcp
    assert parsed.vlan_id is None, "an untagged frame must not claim a VLAN"
    assert parsed.vlan_priority == 0


def test_single_vlan_tag_is_peeled_and_metadata_preserved() -> None:
    parsed = parse_packet(_raw(_tag(_untagged_tcp_frame(), 42, _TAG_8021Q, priority=5)))
    assert parsed is not None
    assert parsed.has_ip, "a VLAN-tagged IPv4 frame must still be recognised as IP"
    assert parsed.has_tcp
    assert parsed.vlan_id == 42
    assert parsed.vlan_priority == 5
    assert parsed.ether_type == dpkt.ethernet.ETH_TYPE_IP, (
        "the reported EtherType should be the *inner* one, after the tag is gone"
    )


@pytest.mark.parametrize(
    "tag_type", [_TAG_8021Q, _TAG_8021AD, _TAG_QINQ], ids=["8021q", "8021ad", "qinq"]
)
def test_all_three_tag_ethertypes_are_peeled(tag_type: bytes) -> None:
    """802.1Q, 802.1ad (provider) and 0x9100 (legacy QinQ) are all in the wild."""
    parsed = parse_packet(_raw(_tag(_untagged_tcp_frame(), 7, tag_type)))
    assert parsed is not None
    assert parsed.has_ip and parsed.has_tcp
    assert parsed.vlan_id == 7


def test_double_tagged_frame_keeps_the_innermost_vlan() -> None:
    """QinQ: the outer tag is the service provider's, the inner one the
    customer's. The inner VID is the more meaningful of the two, so it is the
    one reported."""
    # `_tag` wraps outside, so the tag applied *first* ends up innermost:
    # the wire order is 200 (802.1Q, service provider) then 100 (802.1ad).
    frame = _tag(_tag(_untagged_tcp_frame(), 100, _TAG_8021AD), 200, _TAG_8021Q)
    parsed = parse_packet(_raw(frame))
    assert parsed is not None
    assert parsed.has_ip and parsed.has_tcp
    assert parsed.vlan_id == 100, (
        f"expected the innermost VID 100, not the outer 200; got {parsed.vlan_id}"
    )
    assert parsed.ether_type == dpkt.ethernet.ETH_TYPE_IP


def test_triple_tagged_frame_still_parses() -> None:
    # Applied 1, 2, 3 -> wire order is 3, 2, 1 -> innermost is 1.
    frame = _tag(_tag(_tag(_untagged_tcp_frame(), 1), 2), 3)
    parsed = parse_packet(_raw(frame))
    assert parsed is not None
    assert parsed.has_ip and parsed.has_tcp
    assert parsed.vlan_id == 1, (
        f"expected the innermost VID 1; got {parsed.vlan_id}"
    )


def test_pathological_tag_nesting_is_bounded_and_does_not_hang() -> None:
    """A frame claiming more tags than any real network uses must terminate.

    The peel loop advances 4 bytes per tag, so without a bound a crafted frame
    could in principle keep it spinning; and a frame that *lies* about its
    nesting depth must degrade to "not IP" rather than be half-unwrapped into a
    bogus inner EtherType.
    """
    inner = _untagged_tcp_frame()
    frame = inner
    for _ in range(40):  # far beyond the bound
        frame = _tag(frame, 9)

    parsed = parse_packet(_raw(frame))
    assert parsed is not None, "must still return a ParsedPacket, not raise"
    assert not parsed.has_ip, (
        "a frame nested past the bound should degrade to non-IP, not be "
        "partially unwrapped into a fabricated inner EtherType"
    )


def test_truncated_vlan_tag_degrades_safely() -> None:
    """A tag that claims another tag but has no bytes left must not crash."""
    frame = _untagged_tcp_frame()[:14] + _TAG_8021Q  # header + type, no TCI/next-type
    parsed = parse_packet(_raw(frame))
    assert parsed is not None
    assert not parsed.has_ip


def test_tagging_does_not_change_the_flow_key() -> None:
    """The whole point: the flow key stays L3, so tags must not partition flows."""
    untagged = parse_packet(_raw(_untagged_tcp_frame()))
    tagged = parse_packet(_raw(_tag(_untagged_tcp_frame(), 1234)))

    assert untagged is not None and tagged is not None
    assert five_tuple_of(untagged) == five_tuple_of(tagged), (
        "a VLAN tag must not change the five-tuple; if it does, one conversation "
        "becomes two half-classified flows"
    )
    assert (untagged.src_ip, tagged.src_ip) == (untagged.src_ip, untagged.src_ip)
    assert tagged.dst_port == untagged.dst_port == 443
    assert tagged.protocol == untagged.protocol == 6


def test_tagging_does_not_change_classification_or_payload() -> None:
    """End-to-end: the extracted SNI must survive tagging, since that is what the
    tool actually acts on. A parser that reports the fields but not the payload
    would pass the flow-key test and still misclassify every flow as UNKNOWN."""
    from dpi_engine.sni_extractor import extract_sni

    hello = _minimal_client_hello("vlan.example")
    untagged = parse_packet(_raw(_untagged_tcp_frame(payload=hello)))
    tagged = parse_packet(_raw(_tag(_untagged_tcp_frame(payload=hello), 77)))

    assert untagged is not None and tagged is not None
    assert untagged.payload == tagged.payload, "tagging must not disturb the payload"
    assert extract_sni(untagged.payload) == "vlan.example"
    assert extract_sni(tagged.payload) == "vlan.example"


def _minimal_client_hello(server_name: str) -> bytes:
    """A TLS ClientHello body carrying just enough for `extract_sni`."""
    name = server_name.encode()
    # server_name entry: type(1) + length(2) + name, wrapped in a list length(2)
    sni_entry = b"\x00" + len(name).to_bytes(2, "big") + name
    sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
    # extension: type(2)=server_name + ext length(2) + body
    sni_extension = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list

    body = (
        b"\x03\x03"                       # client_version TLS 1.2
        + b"\x00" * 32                     # random
        + b"\x00"                          # session_id length
        + b"\x00\x02\x00\x2f"            # cipher suites (len 2, TLS_RSA...)
        + b"\x01\x00"                     # compression methods
        + len(sni_extension).to_bytes(2, "big")   # extensions block length
        + sni_extension
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
