"""Generates the crafted edge-case pcaps used by the differential test
suite (Task 9). Run manually to (re)generate the fixtures:

    uv run python -m tests.differential.fixtures.generate_edge_cases

These exercise the specific bugs fixed during the port (truncated TLS
Client Hello, truncated TCP header) so the differential suite can confirm
the Python port handles them safely while documenting how the original
C++ binary behaves on the same input (crash vs. clean handling is itself
part of what's being verified -- see test_differential_edge_cases.py).
"""

from __future__ import annotations

import socket
from pathlib import Path

from dpi_engine.pcap_io import PcapWriter, RawPacket

OUT_DIR = Path(__file__).parent


def eth_hdr(src_mac: bytes = b"\xaa" * 6, dst_mac: bytes = b"\xbb" * 6) -> bytes:
    return dst_mac + src_mac + b"\x08\x00"


def ip_hdr(src_ip: str, dst_ip: str, proto: int, payload_len: int) -> bytes:
    total_len = 20 + payload_len
    return (
        bytes([0x45, 0x00])
        + total_len.to_bytes(2, "big")
        + b"\x00\x00"
        + b"\x40\x00"
        + bytes([64, proto])
        + b"\x00\x00"
        + socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
    )


def tcp_hdr(src_port: int, dst_port: int, flags: int = 0x18) -> bytes:
    return (
        src_port.to_bytes(2, "big")
        + dst_port.to_bytes(2, "big")
        + (0).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + bytes([0x50, flags])
        + (65535).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
    )


def u16be(n: int) -> bytes:
    return n.to_bytes(2, "big")


def u24be(n: int) -> bytes:
    return n.to_bytes(3, "big")


def build_client_hello(sni_hostname: bytes) -> bytes:
    sni_entry = bytes([0x00]) + u16be(len(sni_hostname)) + sni_hostname
    sni_list = u16be(len(sni_entry)) + sni_entry
    sni_extension = u16be(0x0000) + u16be(len(sni_list)) + sni_list

    client_hello_body = (
        u16be(0x0303)
        + b"\x00" * 32
        + bytes([0])  # session id length
        + u16be(2)
        + b"\x00\x00"  # cipher suites
        + bytes([1])
        + b"\x00"  # compression methods
        + u16be(len(sni_extension))
        + sni_extension
    )
    handshake = bytes([0x01]) + u24be(len(client_hello_body)) + client_hello_body
    record = bytes([0x16]) + u16be(0x0303) + u16be(len(handshake)) + handshake
    return record


def write_pcap(path: Path, packets: list[bytes]) -> None:
    with PcapWriter(path) as writer:
        for i, data in enumerate(packets):
            writer.write(RawPacket(ts_sec=1700000000 + i, ts_usec=0, data=data, orig_len=len(data)))


def generate_truncated_client_hello() -> None:
    """A TLS Client Hello truncated at offset 43 -- exactly the point
    where the original C++ SNIExtractor::extract had NO bounds check
    before reading the session ID length byte (see DESIGN_DECISIONS.md
    bug #2). A syntactically valid SYN/ACK handshake precedes it so the
    flow is tracked normally; the truncated payload is the only unusual
    part.
    """
    full_hello = build_client_hello(b"truncated-test.example")
    truncated_hello = full_hello[:43]

    packets = [
        eth_hdr() + ip_hdr("192.168.1.100", "10.0.0.1", 6, 20) + tcp_hdr(50000, 443, flags=0x02),
        eth_hdr() + ip_hdr("10.0.0.1", "192.168.1.100", 6, 20) + tcp_hdr(443, 50000, flags=0x12),
        eth_hdr() + ip_hdr("192.168.1.100", "10.0.0.1", 6, 20) + tcp_hdr(50000, 443, flags=0x10),
        eth_hdr()
        + ip_hdr("192.168.1.100", "10.0.0.1", 6, 20 + len(truncated_hello))
        + tcp_hdr(50000, 443, flags=0x18)
        + truncated_hello,
    ]
    write_pcap(OUT_DIR / "truncated_client_hello.pcap", packets)


def generate_truncated_tcp_header() -> None:
    """An IP packet claiming TCP follows, but with fewer than 20 bytes
    remaining -- exactly the class of bug found in the original's
    createPacketJob (dpi_engine.cpp) and packet_parser.cpp's unaligned
    reads. main_working.cpp itself also has a related unchecked read
    (`raw.data[payload_offset + 12]` without checking that + 12 fits)."""
    short_tcp = b"\x04\xd2\x01\xbb\x00\x00\x00\x00\x00\x00"  # 10 bytes, not 20
    packet = eth_hdr() + ip_hdr("192.168.1.100", "10.0.0.1", 6, len(short_tcp)) + short_tcp
    write_pcap(OUT_DIR / "truncated_tcp_header.pcap", [packet])


def generate_oversized_declared_lengths() -> None:
    """A Client Hello whose session-ID-length byte claims far more bytes
    than actually exist in the packet -- the "validate the length prefix
    but not the skipped region" bug class (DESIGN_DECISIONS.md bug #2/#3).
    """
    malicious_hello = (
        bytes([0x16])
        + u16be(0x0303)
        + u16be(9)
        + bytes([0x01])
        + u24be(5)
        + u16be(0x0303)
        + b"\x00" * 32
        + bytes([200])  # claims 200 bytes of session ID; none actually follow
    )
    packet = (
        eth_hdr()
        + ip_hdr("192.168.1.100", "10.0.0.1", 6, 20 + len(malicious_hello))
        + tcp_hdr(50000, 443, flags=0x18)
        + malicious_hello
    )
    write_pcap(OUT_DIR / "oversized_declared_lengths.pcap", [packet])


def generate_normal_small_capture() -> None:
    """A small, well-formed capture (one full TLS handshake with a
    complete Client Hello) as a control/sanity fixture -- confirms the
    differential harness itself works correctly on "nothing weird here"
    input before trusting its results on the adversarial fixtures above.
    """
    hello = build_client_hello(b"control.example.com")
    packets = [
        eth_hdr() + ip_hdr("192.168.1.100", "10.0.0.1", 6, 20) + tcp_hdr(50000, 443, flags=0x02),
        eth_hdr() + ip_hdr("10.0.0.1", "192.168.1.100", 6, 20) + tcp_hdr(443, 50000, flags=0x12),
        eth_hdr() + ip_hdr("192.168.1.100", "10.0.0.1", 6, 20) + tcp_hdr(50000, 443, flags=0x10),
        eth_hdr()
        + ip_hdr("192.168.1.100", "10.0.0.1", 6, 20 + len(hello))
        + tcp_hdr(50000, 443, flags=0x18)
        + hello,
    ]
    write_pcap(OUT_DIR / "control_normal_capture.pcap", packets)


def main() -> None:
    generate_normal_small_capture()
    generate_truncated_client_hello()
    generate_truncated_tcp_header()
    generate_oversized_declared_lengths()
    print(f"Generated edge-case fixtures in {OUT_DIR}")


if __name__ == "__main__":
    main()
