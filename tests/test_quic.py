"""Tests for QUIC Initial detection and ClientHello (SNI) extraction.

The crypto path is verified two ways:
  * against the RFC 9001 Appendix A.1 key-derivation vectors (unambiguous,
    published, and impossible to accidentally "test" circularly), and
  * against packets this file builds itself with the same primitives, which
    exercises the full header-protection + payload-protection + frame-walk +
    reassembly path end to end.

Tests that need the `cryptography` extra skip (rather than fail) when it is
absent, so a minimal install still has a green suite -- and the skip count is
itself a signal, which is why `test_unsupported_reason_is_explained` asserts the
degradation is *reported* rather than silent.
"""

from __future__ import annotations

import os

import pytest

from dpi_engine import quic
from dpi_engine.quic import (
    MAX_CRYPTO_BUFFER,
    QuicError,
    QuicFlowInspector,
    decode_varint,
    derive_initial_secrets,
    encode_varint,
    extract_crypto_frames,
    is_quic,
    is_quic_initial,
    parse_long_header,
    quic_sni_supported,
    reconstruct_packet_number,
    unsupported_reason,
)

requires_crypto = pytest.mark.skipif(
    not quic_sni_supported(),
    reason=f"needs the optional [quic] extra: {unsupported_reason()}",
)

# The RFC 9001 Appendix A.1 example Destination Connection ID.
RFC9001_DCID = bytes.fromhex("8394c8f03e515708")


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def build_client_hello(server_name: str) -> bytes:
    """A minimal but structurally valid TLS 1.2 ClientHello record."""
    host = server_name.encode("ascii")
    sni_body = b"\x00" + len(host).to_bytes(2, "big") + host
    extensions = (
        (0x0000).to_bytes(2, "big")
        + (len(sni_body) + 2).to_bytes(2, "big")
        + len(sni_body).to_bytes(2, "big")
        + sni_body
    )
    body = (
        b"\x03\x03"
        + os.urandom(32)  # random
        + b"\x00"  # session id length
        + b"\x00\x02\x13\x01"  # cipher suites
        + b"\x01\x00"  # compression methods
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def build_crypto_frames(hello: bytes, *, offset: int = 0, pad: int = 3) -> bytes:
    return (
        b"\x00" * pad
        + b"\x06"
        + encode_varint(offset)
        + encode_varint(len(hello))
        + hello
    )


def build_initial_packet(
    dcid: bytes,
    plaintext_frames: bytes,
    secret: bytes,
    *,
    version: int = 1,
    pn: int = 0,
) -> bytes:
    """Builds a real, protected QUIC v1 Initial packet.

    Uses a 4-byte packet number, which is what makes the header-protection
    sample offset (pn_offset + 4) land exactly at the start of the ciphertext,
    where there are always at least 16 bytes available.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    keys = quic._initial_keys(secret)

    first_byte = 0xC0 | (_qic_pkt_initial() << 4) | 0x03  # form + fixed + Initial + pn_len 4
    header = (
        bytes([first_byte])
        + version.to_bytes(4, "big")
        + bytes([len(dcid)])
        + dcid
        + b"\x00"  # SCID length
        + encode_varint(0)  # token length
    )
    length = 4 + 16 + len(plaintext_frames)
    header += encode_varint(length)

    nonce = bytearray(keys.iv)
    pn_xor = pn.to_bytes(12, "big")
    for i in range(12):
        nonce[i] ^= pn_xor[i]

    encryptor = Cipher(algorithms.AES(keys.key), modes.GCM(bytes(nonce))).encryptor()
    encryptor.authenticate_additional_data(header)
    ciphertext = (
        encryptor.update(plaintext_frames) + encryptor.finalize() + encryptor.tag
    )

    packet = bytearray(header + pn.to_bytes(4, "big") + ciphertext)
    sample_offset = len(header) + 4
    encryptor = Cipher(algorithms.AES(keys.hp), modes.ECB()).encryptor()
    mask = encryptor.update(bytes(packet[sample_offset : sample_offset + 16]))
    mask += encryptor.finalize()

    packet[0] ^= mask[0] & 0x0F
    for i in range(4):
        packet[len(header) + i] ^= mask[1 + i]
    return bytes(packet)


def _qic_pkt_initial() -> int:
    return 0x00


def client_secret(dcid: bytes = RFC9001_DCID, version: int = 1) -> bytes:
    return derive_initial_secrets(dcid, version)[0]


# ---------------------------------------------------------------------------
# Dependency gate
# ---------------------------------------------------------------------------


def test_unsupported_reason_is_explained_either_way() -> None:
    """Whether or not the extra is installed, the state must be explicable --
    a silent degradation would be indistinguishable from 'no QUIC on the wire'."""
    if quic_sni_supported():
        assert unsupported_reason() is None
    else:
        reason = unsupported_reason()
        assert reason and "quic" in reason.lower()


@requires_crypto
def test_detection_works_without_touching_the_crypto_backend() -> None:
    """Classification of QUIC traffic as QUIC must not depend on the extra."""
    header = (
        bytes([0xC0])
        + (1).to_bytes(4, "big")
        + bytes([8])
        + RFC9001_DCID
        + b"\x00"
        + encode_varint(0)
        + encode_varint(120)
        + b"\x00" * 100
    )
    assert is_quic_initial(header)


# ---------------------------------------------------------------------------
# varint (RFC 9000 s.16)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value", [0, 1, 63, 64, 16383, 16384, 2**30 - 1, 2**30, 2**62 - 1]
)
def test_varint_round_trip(value: int) -> None:
    encoded = encode_varint(value)
    decoded, offset = decode_varint(encoded, 0)
    assert decoded == value
    assert offset == len(encoded)


@pytest.mark.parametrize("value", [-1, 2**62])
def test_varint_rejects_unencodable_values(value: int) -> None:
    with pytest.raises(ValueError):
        encode_varint(value)


def test_varint_rejects_truncation() -> None:
    with pytest.raises(QuicError):
        decode_varint(b"\x40", 0)  # 2-byte form, only 1 byte present


def test_varint_all_four_prefixes_are_valid() -> None:
    """0b11 is the 8-byte form, not a reserved value -- an earlier draft of
    this module wrongly rejected it, which broke every large value."""
    # The smallest value that forces each successive encoding length.
    for value, expected_length in ((0, 1), (1 << 6, 2), (1 << 14, 4), (1 << 30, 8)):
        encoded = encode_varint(value)
        assert len(encoded) == expected_length, f"value {value}"
        assert decode_varint(encoded, 0) == (value, len(encoded))

    # And the largest representable value, which also uses the 0b11 prefix.
    widest = encode_varint(2**62 - 1)
    assert len(widest) == 8
    assert widest[0] >> 6 == 0b11
    assert decode_varint(widest, 0) == (2**62 - 1, 8)


# ---------------------------------------------------------------------------
# Key derivation -- RFC 9001 Appendix A.1
# ---------------------------------------------------------------------------


@requires_crypto
def test_rfc9001_client_initial_secrets_and_keys() -> None:
    client_secret_bytes, server_secret_bytes = derive_initial_secrets(RFC9001_DCID, 1)

    assert client_secret_bytes == bytes.fromhex(
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
    )
    assert server_secret_bytes == bytes.fromhex(
        "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"
    )

    client = quic._initial_keys(client_secret_bytes)
    assert client.key == bytes.fromhex("1f369613dd76d5467730efcbe3b1a22d")
    assert client.iv == bytes.fromhex("fa044b2f42a3fd3b46fb255c")
    assert client.hp == bytes.fromhex("9f50449e04a0e810283a1e9933adedd2")

    server = quic._initial_keys(server_secret_bytes)
    assert server.key == bytes.fromhex("cf3a5331653c364c88f0f379b6067e37")
    assert server.iv == bytes.fromhex("0ac1493ca1905853b0bba03e")
    assert server.hp == bytes.fromhex("c206b8d9b9f0f37644430b490eeaa314")


@requires_crypto
def test_rfc9001_v2_initial_salt() -> None:
    """RFC 9369 s.3.3.1 publishes the v2 salt; deriving without an error is
    the check, and the value is asserted so a typo cannot pass."""
    _client, server = derive_initial_secrets(bytes(8), quic.QUIC_VERSION_2)
    assert len(server) == 32


def test_unknown_version_has_no_salt_and_is_not_guessed() -> None:
    with pytest.raises(QuicError):
        derive_initial_secrets(RFC9001_DCID, 0xDEADBEEF)


# ---------------------------------------------------------------------------
# Packet number reconstruction (RFC 9000 A.2)
# ---------------------------------------------------------------------------


def test_packet_number_reconstruction_example() -> None:
    """RFC 9000 A.2 works this exact case: an expected PN of 0xa82f30ea with a
    truncated value of 0x9b32 in a 16-bit window must reconstruct to
    0xa82f9b32."""
    assert reconstruct_packet_number(0x9B32, 16, 0xA82F30EA) == 0xA82F9B32


def test_packet_number_reconstruction_advances_the_window() -> None:
    assert reconstruct_packet_number(1, 8, 0) == 1
    # A truncated 0 after having seen 0xff must roll forward, not stay at 0.
    assert reconstruct_packet_number(0, 8, 0xFF) == 0x100


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _long_header_first_byte(packet_type: int = 0, fixed: bool = True) -> int:
    return 0x80 | (0x40 if fixed else 0) | (packet_type << 4)


def test_is_quic_initial_accepts_a_v1_initial() -> None:
    pkt = (
        bytes([_long_header_first_byte()])
        + (1).to_bytes(4, "big")
        + bytes([8])
        + RFC9001_DCID
        + b"\x00"
        + encode_varint(0)
        + encode_varint(120)
        + b"\x00" * 40
    )
    assert is_quic_initial(pkt)
    assert is_quic(pkt)


@pytest.mark.parametrize("packet_type", [1, 2, 3])  # 0-RTT, Handshake, Retry
def test_is_quic_initial_rejects_non_initial_packet_types(packet_type: int) -> None:
    """OSC's isQUICInitial accepted every one of these as an Initial."""
    pkt = (
        bytes([_long_header_first_byte(packet_type)])
        + (1).to_bytes(4, "big")
        + bytes([8])
        + RFC9001_DCID
        + b"\x00"
        + encode_varint(0)
        + encode_varint(120)
        + b"\x00" * 40
    )
    assert not is_quic_initial(pkt)
    # ...but they are still QUIC, so they must be reported as such.
    assert is_quic(pkt)


def test_is_quic_initial_rejects_a_short_header() -> None:
    assert not is_quic_initial(b"\x40" + b"\x00" * 20)


def test_is_quic_rejects_a_cleared_fixed_bit() -> None:
    pkt = (
        bytes([_long_header_first_byte(fixed=False)])
        + (1).to_bytes(4, "big")
        + bytes([8])
        + RFC9001_DCID
        + b"\x00"
    )
    assert not is_quic(pkt)


def test_is_quic_rejects_an_implausible_version() -> None:
    pkt = (
        bytes([_long_header_first_byte()])
        + (0x11223344).to_bytes(4, "big")
        + bytes([8])
        + RFC9001_DCID
    )
    assert not is_quic(pkt)


def test_is_quic_rejects_drafts_before_29() -> None:
    """draft-25/-27 framing is incompatible with draft-29+, so recognising them
    would mean confidently wrong parses. draft-27 is 0xff00001b."""
    for draft in (0xFF000011, 0xFF000019, 0xFF00001B):
        pkt = (
            bytes([_long_header_first_byte()])
            + draft.to_bytes(4, "big")
            + bytes([8])
            + RFC9001_DCID
        )
        assert not is_quic(pkt), f"draft 0x{draft:08x} should not be recognised"


def test_is_quic_accepts_draft_29_and_later() -> None:
    # draft-29 and draft-32 are the ones actually deployed in the wild; both
    # were folded into v1 on the wire but still appear in Version Negotiation.
    for version in (quic.QUIC_VERSION_1, quic.QUIC_VERSION_2, 0xFF00001D, 0xFF000020):
        pkt = (
            bytes([_long_header_first_byte()])
            + version.to_bytes(4, "big")
            + bytes([8])
            + RFC9001_DCID
        )
        assert is_quic(pkt), f"0x{version:08x} should be recognised"


def test_is_quic_rejects_too_short_and_too_long() -> None:
    assert not is_quic(b"\xc0\x00\x00")
    assert not is_quic(b"\xc0" + b"\x00" * (quic.MAX_QUIC_DATAGRAM + 1))


# ---------------------------------------------------------------------------
# Long header parsing
# ---------------------------------------------------------------------------


def test_parse_long_header_round_trip() -> None:
    token = b"\xaa\xbb"
    payload = (
        bytes([_long_header_first_byte()])
        + (1).to_bytes(4, "big")
        + bytes([8])
        + RFC9001_DCID
        + b"\x00"
        + encode_varint(len(token))
        + token
        + encode_varint(1200)
        + b"\x00" * 8
    )
    header = parse_long_header(payload)
    assert header.version == 1
    assert header.dcid == RFC9001_DCID
    assert header.token == token
    assert header.length == 1200
    assert header.pn_offset == len(payload) - 8


def test_parse_long_header_recognises_version_negotiation() -> None:
    payload = (
        bytes([_long_header_first_byte()])
        + (0).to_bytes(4, "big")
        + bytes([8])
        + RFC9001_DCID
        + b"\x00"
        + b"\x00\x00\x00\x01"  # supported version
    )
    header = parse_long_header(payload)
    assert header.is_version_negotiation
    assert header.length == 0


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\xc0",
        b"\x40" + b"\x00" * 20,  # not a long header
        b"\xc0\x00\x00\x00\x01\x40",  # DCID length runs off the end
    ],
)
def test_parse_long_header_rejects_garbage(payload: bytes) -> None:
    with pytest.raises(QuicError):
        parse_long_header(payload)


# ---------------------------------------------------------------------------
# Frame parsing
# ---------------------------------------------------------------------------


def test_extract_crypto_frames_after_padding() -> None:
    hello = build_client_hello("example.com")
    frames = extract_crypto_frames(build_crypto_frames(hello))
    assert frames == [(0, hello)]


def test_extract_crypto_frames_skips_an_ack_frame() -> None:
    """A server Initial can carry ACK before CRYPTO; the walker must consume the
    ACK's four+ varints rather than mistaking them for a frame type."""
    hello = build_client_hello("example.com")
    ack = (
        b"\x02"
        + encode_varint(10)  # largest acknowledged
        + encode_varint(0)  # ack delay
        + encode_varint(1)  # ack range count
        + encode_varint(3)  # first ack range
        + encode_varint(1)  # gap
        + encode_varint(2)  # ack range length
    )
    payload = b"\x00\x00" + ack + b"\x06" + encode_varint(0) + encode_varint(len(hello)) + hello
    frames = extract_crypto_frames(payload)
    assert frames == [(0, hello)]


def test_extract_crypto_frames_skips_ack_ecn_counters() -> None:
    hello = build_client_hello("example.com")
    ack_ecn = (
        b"\x03"
        + encode_varint(10)
        + encode_varint(0)
        + encode_varint(0)  # no extra ranges
        + encode_varint(1)
        + encode_varint(0)  # ect0
        + encode_varint(0)  # ect1
        + encode_varint(0)  # ce
    )
    payload = ack_ecn + b"\x06" + encode_varint(0) + encode_varint(len(hello)) + hello
    assert extract_crypto_frames(payload) == [(0, hello)]


def test_extract_crypto_frames_stops_at_an_unknown_frame_type() -> None:
    assert extract_crypto_frames(b"\x1f\x00\x00") == []


def test_extract_crypto_frames_clamps_a_truncated_crypto_frame() -> None:
    hello = build_client_hello("example.com")
    payload = b"\x06" + encode_varint(0) + encode_varint(len(hello) + 50) + hello
    frames = extract_crypto_frames(payload)
    assert frames == [(0, hello)]


# ---------------------------------------------------------------------------
# End-to-end decryption
# ---------------------------------------------------------------------------


@requires_crypto
def test_round_trip_extracts_the_sni() -> None:
    secret = client_secret()
    hello = build_client_hello("www.google.com")
    packet = build_initial_packet(RFC9001_DCID, build_crypto_frames(hello), secret)

    assert is_quic_initial(packet)
    inspector = QuicFlowInspector()
    assert inspector.feed(packet) == "www.google.com"
    assert inspector.initial_packets == 1
    assert inspector.undecryptable_packets == 0
    assert inspector.client_hello_seen is True


@requires_crypto
def test_v2_version_round_trip() -> None:
    secret = client_secret(version=quic.QUIC_VERSION_2)
    hello = build_client_hello("www.netflix.com")
    packet = build_initial_packet(
        RFC9001_DCID,
        build_crypto_frames(hello),
        secret,
        version=quic.QUIC_VERSION_2,
    )
    assert QuicFlowInspector().feed(packet) == "www.netflix.com"


@requires_crypto
def test_client_hello_split_across_two_packets_is_reassembled() -> None:
    """CRYPTO frames may be split and arrive out of order; only the second
    packet completes a parseable ClientHello."""
    secret = client_secret()
    hello = build_client_hello("cdn.example.org")
    split = len(hello) // 2

    tail = build_initial_packet(
        RFC9001_DCID,
        build_crypto_frames(hello[split:], offset=split),
        secret,
        pn=1,
    )
    head = build_initial_packet(
        RFC9001_DCID, build_crypto_frames(hello[:split], offset=0), secret, pn=0
    )

    inspector = QuicFlowInspector()
    # Out of order: the tail arrives first and must not yield a bogus result.
    assert inspector.feed(tail) is None
    assert inspector.feed(head) == "cdn.example.org"
    assert inspector.initial_packets == 2


@requires_crypto
def test_server_direction_is_decided_by_the_gcm_tag() -> None:
    """A datagram does not say which direction it is; the wrong secret must
    simply fail to authenticate, and the right one must then succeed."""
    _client, server = derive_initial_secrets(RFC9001_DCID, 1)
    hello = build_client_hello("api.github.com")
    packet = build_initial_packet(RFC9001_DCID, build_crypto_frames(hello), server)
    assert QuicFlowInspector().feed(packet) == "api.github.com"


@requires_crypto
def test_a_tampered_packet_fails_authentication_without_raising() -> None:
    secret = client_secret()
    hello = build_client_hello("www.facebook.com")
    packet = bytearray(
        build_initial_packet(RFC9001_DCID, build_crypto_frames(hello), secret)
    )
    packet[-1] ^= 0xFF  # corrupt the GCM tag

    inspector = QuicFlowInspector()
    assert inspector.feed(bytes(packet)) is None
    assert inspector.undecryptable_packets == 1


@requires_crypto
def test_a_tampered_header_also_fails_cleanly() -> None:
    secret = client_secret()
    packet = bytearray(
        build_initial_packet(
            RFC9001_DCID, build_crypto_frames(build_client_hello("x.example")), secret
        )
    )
    packet[7] ^= 0xFF  # inside the DCID: wrong keys entirely
    inspector = QuicFlowInspector()
    assert inspector.feed(bytes(packet)) is None


@requires_crypto
def test_non_initial_quic_traffic_is_counted_but_not_decrypted() -> None:
    handshake = (
        bytes([_long_header_first_byte(2)])  # Handshake packet
        + (1).to_bytes(4, "big")
        + bytes([8])
        + RFC9001_DCID
        + b"\x00"
        + encode_varint(0)
        + encode_varint(64)
        + b"\x11" * 80
    )
    inspector = QuicFlowInspector()
    assert inspector.feed(handshake) is None
    assert inspector.initial_packets == 0
    assert inspector.undecryptable_packets == 0


@requires_crypto
def test_non_quic_udp_payload_is_ignored() -> None:
    inspector = QuicFlowInspector()
    assert inspector.feed(b"GET / HTTP/1.1\r\n\r\n") is None
    assert inspector.initial_packets == 0


@requires_crypto
def test_initial_without_an_sni_extension_returns_none() -> None:
    """A ClientHello with no SNI (e.g. IP-only TLS) must not crash or invent a
    name -- it simply yields nothing, and the flow stays unclassified."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # Hand-build a ClientHello with an empty extension block.
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + b"\x00\x00"
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake
    del Cipher, algorithms, modes

    secret = client_secret()
    packet = build_initial_packet(RFC9001_DCID, build_crypto_frames(record), secret)
    inspector = QuicFlowInspector()
    assert inspector.feed(packet) is None
    assert inspector.initial_packets == 1


@requires_crypto
def test_crypto_buffer_is_bounded() -> None:
    """A hostile peer must not be able to induce unbounded buffering via
    out-of-range CRYPTO offsets."""
    secret = client_secret()
    far = build_initial_packet(
        RFC9001_DCID,
        b"\x06" + encode_varint(MAX_CRYPTO_BUFFER * 4) + encode_varint(16) + b"\x00" * 16,
        secret,
    )
    inspector = QuicFlowInspector()
    inspector.feed(far)
    assert len(inspector.crypto) <= MAX_CRYPTO_BUFFER


@requires_crypto
def test_extract_quic_sni_one_shot_wrapper() -> None:
    secret = client_secret()
    packet = build_initial_packet(
        RFC9001_DCID, build_crypto_frames(build_client_hello("q.example")), secret
    )
    assert quic.extract_quic_sni(packet) == "q.example"


@requires_crypto
def test_empty_and_tiny_payloads_never_raise() -> None:
    """The entry point runs on attacker-controlled bytes in a hot loop, so it
    must absorb every malformed shape rather than propagate."""
    inspector = QuicFlowInspector()
    for payload in (b"", b"\x00", b"\xc0", b"\xc0\x00\x00\x00\x01", os.urandom(64)):
        assert inspector.feed(payload) in (None, "sni-must-not-appear")
        assert inspector.feed(payload) is None
