"""Tests for dpi_engine.sni_extractor.

Covers: valid TLS Client Hello with SNI (both a hand-crafted fixture and the
real capture in test_dpi.pcap), truncation at every possible offset (must
never crash), HTTP Host header extraction (including mixed case), DNS query
extraction (with and without name compression), and the specific bug-fix
regression the original lacked a check for (missing bounds check after
version+random skip).
"""

from __future__ import annotations

from pathlib import Path

from dpi_engine.packet_parser import parse_packet
from dpi_engine.pcap_io import PcapReader
from dpi_engine.sni_extractor import (
    extract_dns_query,
    extract_http_host,
    extract_sni,
    is_dns_query,
    is_http_request,
    is_tls_client_hello,
)

FIXTURES = Path(__file__).parent / "fixtures"
TEST_DPI_PCAP = FIXTURES / "test_dpi.pcap"


def _u16be(n: int) -> bytes:
    return bytes([(n >> 8) & 0xFF, n & 0xFF])


def _u24be(n: int) -> bytes:
    return bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def build_client_hello(
    sni_hostname: bytes = b"example.com",
    *,
    session_id_length: int = 0,
    cipher_suites_length: int = 2,
    compression_methods_length: int = 1,
    include_sni_extension: bool = True,
) -> bytes:
    """Builds a syntactically valid (enough) TLS Client Hello record
    containing an SNI extension, for use as a positive-path test fixture.
    """
    session_id = b"\x00" * session_id_length
    cipher_suites = b"\x00" * cipher_suites_length
    compression_methods = b"\x00" * compression_methods_length

    if include_sni_extension:
        sni_entry = bytes([0x00]) + _u16be(len(sni_hostname)) + sni_hostname  # type + len + value
        sni_list = _u16be(len(sni_entry)) + sni_entry  # server_name_list length + entries
        sni_extension = _u16be(0x0000) + _u16be(len(sni_list)) + sni_list  # ext type + ext len + body
        extensions = sni_extension
    else:
        extensions = b""

    client_hello_body = (
        _u16be(0x0303)  # client version
        + b"\x00" * 32  # random
        + bytes([session_id_length])
        + session_id
        + _u16be(cipher_suites_length)
        + cipher_suites
        + bytes([compression_methods_length])
        + compression_methods
        + _u16be(len(extensions))
        + extensions
    )

    handshake = bytes([0x01]) + _u24be(len(client_hello_body)) + client_hello_body  # ClientHello type + len
    record_length = len(handshake)
    record = bytes([0x16]) + _u16be(0x0303) + _u16be(record_length) + handshake

    return record


# --- Valid Client Hello -------------------------------------------------------------


def test_build_client_hello_fixture_is_recognized_as_client_hello() -> None:
    record = build_client_hello()
    assert is_tls_client_hello(record)


def test_extract_sni_from_crafted_client_hello() -> None:
    record = build_client_hello(sni_hostname=b"www.example.org")
    assert extract_sni(record) == "www.example.org"


def test_extract_sni_returns_none_when_no_sni_extension_present() -> None:
    record = build_client_hello(include_sni_extension=False)
    assert extract_sni(record) is None


def test_extract_sni_with_nonzero_session_id_and_cipher_suites() -> None:
    record = build_client_hello(
        sni_hostname=b"another.test",
        session_id_length=32,
        cipher_suites_length=8,
        compression_methods_length=1,
    )
    assert extract_sni(record) == "another.test"


def test_non_client_hello_payload_returns_none() -> None:
    assert extract_sni(b"not a tls record at all, just plain bytes") is None
    assert extract_sni(b"") is None
    assert extract_sni(b"\x16\x03\x01") is None  # too short (< 9 bytes)


# --- Real capture -------------------------------------------------------------------


def _load_tls_payloads() -> list[bytes]:
    with PcapReader(TEST_DPI_PCAP) as reader:
        raws = list(reader)
    payloads = []
    for raw in raws:
        parsed = parse_packet(raw)
        if parsed and parsed.has_tcp and parsed.dst_port == 443 and len(parsed.payload) > 5:
            payloads.append(parsed.payload)
    return payloads


def test_real_capture_contains_extractable_sni_values() -> None:
    payloads = _load_tls_payloads()
    assert len(payloads) > 0

    found_snis = [extract_sni(p) for p in payloads]
    found_snis = [s for s in found_snis if s is not None]

    assert len(found_snis) > 0
    # Cross-checked against OSC/README.md's documented sample output
    # ("Detected Domains/SNIs": www.youtube.com, www.facebook.com,
    # www.google.com, github.com, ...).
    assert any("youtube" in s or "facebook" in s or "google" in s for s in found_snis)


# --- Truncation safety: must never crash, at any offset -----------------------------


def test_truncated_client_hello_never_crashes_at_any_offset() -> None:
    """Regression test for the original's missing bounds check after
    skipping client version + random (fixed offset 43): truncating a valid
    Client Hello at every possible byte offset must always return either a
    valid result or None, never raise."""
    full_record = build_client_hello(sni_hostname=b"truncation-test.example")

    for cut in range(0, len(full_record) + 1):
        truncated = full_record[:cut]
        # Must not raise under any circumstance.
        result = extract_sni(truncated)
        assert result is None or isinstance(result, str)


def test_client_hello_truncated_right_after_random_returns_none() -> None:
    """Precisely targets the original bug: offset 43 (5 record header + 4
    handshake header + 2 client version + 32 random) is exactly where the
    original read the session ID length byte with zero bounds check."""
    full_record = build_client_hello()
    truncated = full_record[:43]  # nothing left to read the session ID length from
    assert extract_sni(truncated) is None


def test_client_hello_with_oversized_declared_lengths_does_not_crash() -> None:
    """Session ID / cipher suite / compression method / extension lengths
    that claim far more bytes than actually exist must not cause an
    out-of-bounds read -- this is the fix for the original's 'validate the
    length prefix but not the skipped region' pattern."""
    # session_id_length byte says 200, but there's nothing after it.
    malicious = bytes([0x16]) + _u16be(0x0303) + _u16be(9) + bytes([0x01]) + _u24be(5) + _u16be(
        0x0303
    ) + b"\x00" * 32 + bytes([200])
    assert extract_sni(malicious) is None


# --- HTTP Host header ----------------------------------------------------------------


def test_http_get_with_host_header() -> None:
    request = b"GET / HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: test\r\n\r\n"
    assert is_http_request(request)
    assert extract_http_host(request) == "www.example.com"


def test_http_host_header_case_insensitive() -> None:
    request = b"GET /path HTTP/1.1\r\nhOsT: MixedCase.Example.com\r\n\r\n"
    assert extract_http_host(request) == "MixedCase.Example.com"


def test_http_host_header_strips_port() -> None:
    request = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
    assert extract_http_host(request) == "example.com"


def test_non_http_payload_returns_none() -> None:
    assert extract_http_host(b"\x16\x03\x01\x00\x50random tls bytes") is None
    assert extract_http_host(b"") is None
    assert extract_http_host(b"XX") is None


def test_http_request_without_host_header_returns_none() -> None:
    request = b"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n"
    assert extract_http_host(request) is None


# --- DNS query ------------------------------------------------------------------------


def build_dns_query(domain: str = "example.com") -> bytes:
    header = (
        b"\x12\x34"  # transaction id
        + b"\x01\x00"  # flags: QR=0 (query), standard query
        + _u16be(1)  # QDCOUNT = 1
        + _u16be(0)
        + _u16be(0)
        + _u16be(0)
    )
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode("ascii")
    question += b"\x00"  # root label
    question += _u16be(1) + _u16be(1)  # QTYPE=A, QCLASS=IN
    return header + question


def test_dns_query_extraction() -> None:
    packet = build_dns_query("www.example.com")
    assert is_dns_query(packet)
    assert extract_dns_query(packet) == "www.example.com"


def test_dns_response_is_not_treated_as_query() -> None:
    packet = bytearray(build_dns_query("www.example.com"))
    packet[2] |= 0x80  # set QR bit -> response
    assert not is_dns_query(bytes(packet))
    assert extract_dns_query(bytes(packet)) is None


def test_dns_query_with_compression_pointer_does_not_crash_or_loop() -> None:
    """A label length byte with the top two bits set (>= 0xC0) is a
    compression pointer. The original does not resolve it -- it just stops
    parsing. This must terminate cleanly (no infinite loop, no crash),
    returning whatever was accumulated before the pointer (possibly None)."""
    header = (
        b"\x12\x34" + b"\x01\x00" + _u16be(1) + _u16be(0) + _u16be(0) + _u16be(0)
    )
    # "www" label, then a compression pointer (0xC0 0x0C) instead of a real
    # label -- must not be followed/dereferenced.
    question = bytes([3]) + b"www" + bytes([0xC0, 0x0C]) + _u16be(1) + _u16be(1)
    packet = header + question

    result = extract_dns_query(packet)  # must not raise or hang
    assert result is None or result == "www"


def test_dns_query_too_short_returns_none() -> None:
    assert extract_dns_query(b"\x00" * 5) is None
    assert extract_dns_query(b"") is None
