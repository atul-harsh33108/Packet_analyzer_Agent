"""Ethernet / IPv4 / TCP / UDP header parsing.

Ports OSC/include/packet_parser.h + OSC/src/packet_parser.cpp to Python,
using dpkt.ethernet.Ethernet for the actual dissection (see
DESIGN_DECISIONS.md for why this layer is delegated to dpkt rather than
hand-rolled).

This directly fixes the bugs identified in the original C++ analysis for
this file:
- packet_parser.cpp read multi-byte fields (EtherType, TCP ports, TCP
  seq/ack, UDP ports) via `reinterpret_cast<const uint16_t*>`/`uint32_t*`
  on a `uint8_t*` buffer — undefined behavior (unaligned access, strict
  aliasing violation) on platforms that care. dpkt parses every field via
  its own struct-unpacking code internally; nothing in this module ever
  reinterprets raw bytes as a wider integer type via pointer casting.
- The original's "skip N bytes then trust the next read" pattern (e.g. TCP
  data-offset byte read without checking the full header fits) is not
  reproduced: dpkt's sub-parsers raise dpkt.dpkt.NeedData / dpkt.dpkt.UnpackError
  internally when a layer's declared length doesn't fit the buffer, and
  degrade a partially-parsed sub-layer to raw `bytes` rather than
  proceeding to read past the end of the buffer (verified empirically: a
  truncated TCP header inside a longer, valid IP packet is exposed as
  `ip.data == bytes`, not as a TCP object with garbage fields).

Safety: pure computation on caller-provided bytes. No file, socket, or
network access happens in this module.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

import dpkt
import dpkt.ethernet
import dpkt.ip
import dpkt.tcp
import dpkt.udp

from dpi_engine.pcap_io import RawPacket

# TCP flag bit names, matching OSC's tcpFlagsToString (packet_parser.cpp).
TCP_FLAG_NAMES: tuple[tuple[int, str], ...] = (
    (dpkt.tcp.TH_FIN, "FIN"),
    (dpkt.tcp.TH_SYN, "SYN"),
    (dpkt.tcp.TH_RST, "RST"),
    (dpkt.tcp.TH_PUSH, "PSH"),
    (dpkt.tcp.TH_ACK, "ACK"),
    (dpkt.tcp.TH_URG, "URG"),
)


@dataclass(slots=True)
class ParsedPacket:
    """Human-readable parsed packet fields, mirroring OSC's ParsedPacket
    (packet_parser.h), minus the raw MAC-address/formatted-string fields
    the original kept as strings — those are exposed as properties here
    instead of being precomputed, to avoid doing string work for packets
    nothing ends up inspecting.
    """

    src_mac: bytes = b""
    dst_mac: bytes = b""
    ether_type: int = 0

    #: 802.1Q VLAN ID, or None for an untagged frame. Metadata only -- the flow
    #: key stays L3, so tagging never splits a conversation in two. Kept because
    #: it is what Phase 5 fingerprinting needs. For QinQ this is the *innermost*
    #: (customer) VID; the provider's outer tag is the less meaningful of the two.
    vlan_id: int | None = None
    #: 802.1Q priority (PCP), 0-7. Metadata only, as above.
    vlan_priority: int = 0

    has_ip: bool = False
    src_ip: int = 0  # host-byte-order uint32, consistent with OSC's FiveTuple
    dst_ip: int = 0
    ip_ttl: int = 0
    protocol: int = 0  # 6 = TCP, 17 = UDP, 0 = none/other

    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dst_port: int = 0
    seq_number: int = 0
    ack_number: int = 0
    tcp_flags: int = 0

    # Payload bytes after all parsed headers (TLS/HTTP/DNS inspection
    # operates on this). Never aliases into a mutable buffer the caller
    # might resize later (see lifetime-hazard note in the original's
    # packet_parser.cpp) -- always an independent `bytes` slice.
    payload: bytes = field(default_factory=bytes)

    @property
    def src_ip_str(self) -> str:
        return _int_to_ip_str(self.src_ip) if self.has_ip else ""

    @property
    def dst_ip_str(self) -> str:
        return _int_to_ip_str(self.dst_ip) if self.has_ip else ""

    @property
    def src_mac_str(self) -> str:
        return _mac_to_str(self.src_mac)

    @property
    def dst_mac_str(self) -> str:
        return _mac_to_str(self.dst_mac)

    def tcp_flags_str(self) -> str:
        if not self.has_tcp:
            return ""
        names = [name for bit, name in TCP_FLAG_NAMES if self.tcp_flags & bit]
        return ",".join(names) if names else "-"

    def protocol_str(self) -> str:
        if self.has_tcp:
            return "TCP"
        if self.has_udp:
            return "UDP"
        if self.has_ip:
            return f"IP-proto-{self.protocol}"
        return f"ethertype-0x{self.ether_type:04x}"


def _mac_to_str(mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac)


def _int_to_ip_str(ip_int: int) -> str:
    return socket.inet_ntoa(ip_int.to_bytes(4, "big"))


def _ip_bytes_to_int(ip_bytes: bytes) -> int:
    """Converts dpkt's 4-byte big-endian IP address to a host uint32.

    Note: this is host-byte-order-independent by construction (always
    interprets the wire bytes as big-endian and produces the same integer
    on any host), which fixes the original's latent big-endian-host bug
    (types.cpp's formatIP assumed the host's own memcpy byte order matched
    little-endian formatting expectations).
    """
    return int.from_bytes(ip_bytes, "big")


#: dst(6) + src(6) + type(2).
_ETHERNET_HEADER_LEN = 14

#: TCI(2) + inner EtherType(2).
_VLAN_TAG_LEN = 4

#: EtherTypes that introduce an 802.1Q/802.1ad tag. `0x8100` is plain 802.1Q,
#: `0x88a8` is 802.1ad (provider bridging, what carriers actually use), and
#: `0x9100` is legacy QinQ still emitted by some stacks.
_VLAN_ETHER_TYPES = frozenset({0x8100, 0x88A8, 0x9100})

#: How many tags to peel before declaring a frame pathological. Each tag is 4
#: bytes and sits between the Ethernet header and the L3 header, so the loop is
#: O(tags) and terminates regardless -- but a frame claiming more nesting than
#: any real network uses is either malformed or hostile, and it should degrade to
#: "not IP" rather than be unwrapped on the attacker's terms. Real deployments
#: top out at double tagging.
_MAX_VLAN_TAGS = 4


def _peel_vlan_tags(data: bytes) -> tuple[bytes, int | None, int]:
    """Removes any 802.1Q tags from an Ethernet frame.

    `dpkt.ethernet.Ethernet` reads the EtherType at offset 12 and stops, so on a
    tagged frame that is `0x8100` -- not IPv4 -- and the frame came back as
    "non-IP, nothing further to parse". Every VLAN-tagged packet was therefore
    silently discarded, which in an enterprise capture is most of the traffic
    (`D-14`). This rebuilds the frame with the tags spliced out so the existing
    dpkt path can be reused unchanged.

    Returns `(frame, vlan_id, vlan_priority)`. The frame is returned **unchanged**
    if it is untagged, truncated mid-tag, or nested deeper than
    `_MAX_VLAN_TAGS` -- in every one of those cases the caller sees a VLAN
    EtherType and correctly reports a non-IP frame, rather than getting a
    fabricated inner EtherType from a half-unwrapped hostile frame.
    """
    if len(data) < _ETHERNET_HEADER_LEN:
        return data, None, 0

    ether_type = int.from_bytes(data[12:14], "big")
    if ether_type not in _VLAN_ETHER_TYPES:
        return data, None, 0

    offset = _ETHERNET_HEADER_LEN
    vlan_id: int | None = None
    vlan_priority = 0

    for _ in range(_MAX_VLAN_TAGS):
        if len(data) < offset + _VLAN_TAG_LEN:
            return data, vlan_id, vlan_priority  # truncated mid-tag
        tci = int.from_bytes(data[offset : offset + 2], "big")
        vlan_priority = (tci >> 13) & 0x7
        vlan_id = tci & 0x0FFF
        ether_type = int.from_bytes(data[offset + 2 : offset + 4], "big")
        offset += _VLAN_TAG_LEN
        if ether_type not in _VLAN_ETHER_TYPES:
            return data[:12] + ether_type.to_bytes(2, "big") + data[offset:], vlan_id, vlan_priority

    # Nested deeper than the bound: leave it alone rather than trust it.
    return data, vlan_id, vlan_priority


def parse_packet(raw: RawPacket) -> ParsedPacket | None:
    """Parses a single raw Ethernet frame.

    Returns None (rather than raising) for frames too short to contain even
    an Ethernet header, or any other structurally invalid frame -- this is
    the expected, safe outcome for malformed/truncated captured packets, not
    an error condition callers need to handle via exception handling.
    """
    try:
        eth = dpkt.ethernet.Ethernet(raw.data)
    except dpkt.dpkt.NeedData:
        return None
    except dpkt.dpkt.UnpackError:
        return None

    # Peel 802.1Q before handing the frame to dpkt, which would otherwise stop at
    # the tag and report every tagged packet as non-IP (`D-14`). Peeled first
    # rather than by reconstructing a dpkt VLAN object so the rest of this
    # function -- and its payload slices -- are untouched by tagging.
    frame, vlan_id, vlan_priority = _peel_vlan_tags(raw.data)
    if frame is not raw.data:
        try:
            eth = dpkt.ethernet.Ethernet(frame)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            return None

    parsed = ParsedPacket(
        src_mac=bytes(eth.src),
        dst_mac=bytes(eth.dst),
        ether_type=eth.type,
        vlan_id=vlan_id,
        vlan_priority=vlan_priority,
    )

    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        # Non-IPv4 frame (ARP, IPv6, VLAN-tagged, etc.) -- not an error,
        # just nothing further to parse. IPv6 support is a documented
        # limitation (see DESIGN_DECISIONS.md / README known limitations),
        # matching the original, which was IPv4-only throughout.
        return parsed

    ip = eth.data
    if not isinstance(ip, dpkt.ip.IP):
        # EtherType claimed IPv4 but the bytes didn't actually parse as one.
        return parsed

    parsed.has_ip = True
    parsed.src_ip = _ip_bytes_to_int(ip.src)
    parsed.dst_ip = _ip_bytes_to_int(ip.dst)
    parsed.ip_ttl = ip.ttl
    parsed.protocol = ip.p

    transport = ip.data

    if ip.p == dpkt.ip.IP_PROTO_TCP and isinstance(transport, dpkt.tcp.TCP):
        parsed.has_tcp = True
        parsed.src_port = transport.sport
        parsed.dst_port = transport.dport
        parsed.seq_number = transport.seq
        parsed.ack_number = transport.ack
        parsed.tcp_flags = transport.flags
        payload = transport.data
        parsed.payload = bytes(payload) if not isinstance(payload, bytes) else payload

    elif ip.p == dpkt.ip.IP_PROTO_UDP and isinstance(transport, dpkt.udp.UDP):
        parsed.has_udp = True
        parsed.src_port = transport.sport
        parsed.dst_port = transport.dport
        payload = transport.data
        parsed.payload = bytes(payload) if not isinstance(payload, bytes) else payload

    # If ip.p claimed TCP/UDP but the sub-layer didn't actually parse as
    # such (truncated header shorter than the minimum), `transport` is raw
    # bytes and has_tcp/has_udp stay False, payload stays empty -- this is
    # the safe degrade-to-"nothing further parsed" behavior, not a crash.

    return parsed


def five_tuple_of(parsed: ParsedPacket) -> tuple[int, int, int, int, int]:
    """Returns the five-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
    as a plain hashable tuple. See Task 4 (types.py) for the FiveTuple
    wrapper used by the flow table; this helper is usable standalone by
    anything that only needs the raw tuple (e.g. the hash-partitioning
    dispatch in the multiprocessing pipeline, Task 10).
    """
    return (parsed.src_ip, parsed.dst_ip, parsed.src_port, parsed.dst_port, parsed.protocol)
