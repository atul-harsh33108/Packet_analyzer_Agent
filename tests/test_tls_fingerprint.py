"""The TLS fingerprint (`T5-01`): JA3/JA3S, JA4/JA4S, and the hello's features.

Why this file exists
--------------------
The gate is "computed from a real ClientHello and **matches the published
definition**". A test that checks a hash against the same hash function it is
testing proves only that hashing works, so the vectors below are taken from the
publishing bodies and the bytes are built independently of the expected string:

* JA3/JA3S -- the two worked examples in the `salesforce/ja3` README.
* JA4 -- the worked example in FoxIO's `technical_details/JA4.md`, including the
  raw sorted lists, so a mismatch says *which* part is wrong.
* JA4S -- FoxIO's published Sliver server fingerprint, ``t130200_1301_a56c5b993250``.
  The extension pair whose hash is ``a56c5b993250`` is ``0x002b,0x0033`` in
  arrival order, which is what the hello below carries; the test is therefore an
  end-to-end match of the published output, not a restatement of its formula.

Two choices are pinned here because the sources are silent about them:

1. **A truncated hello yields no fingerprint.** `extract_sni` tolerates capture
   truncation by design; a fingerprint must not, because a hash over half a
   cipher list looks exactly like a fact. Every prefix of a valid hello is
   asserted to return `None`.
2. **The ALPN field follows JA4.md's documented rule** -- the hex representation
   when either end is not alphanumeric. FoxIO's Python reference substitutes
   ``9`` for non-ASCII bytes instead; the two agree for every IANA-registered
   ALPN value, and the non-alphanumeric examples below pin the documented rule.

What this file does not claim: parity with tshark's output for a non-alphanumeric
ALPN. That divergence is recorded in the task record.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from dpi_engine.sni_extractor import extract_sni
from dpi_engine.tls_fingerprint import (
    ClientHelloFeatures,
    fingerprint_client_hello,
    fingerprint_server_hello,
)

# ---------------------------------------------------------------------------
# Builders -- deliberately independent of the module under test
# ---------------------------------------------------------------------------

_SNI = 0x0000
_SUPPORTED_GROUPS = 0x000A
_EC_POINT_FORMATS = 0x000B
_SIGNATURE_ALGORITHMS = 0x000D
_ALPN = 0x0010
_SUPPORTED_VERSIONS = 0x002B


def _u16(value: int) -> bytes:
    return bytes([(value >> 8) & 0xFF, value & 0xFF])


def _u24(value: int) -> bytes:
    return bytes([(value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])


def _u16_vector(values: Sequence[int]) -> bytes:
    raw = b"".join(_u16(v) for v in values)
    return _u16(len(raw)) + raw


def _byte_vector(raw: bytes) -> bytes:
    return bytes([len(raw)]) + raw


def _extension(extension_type: int, body: bytes = b"") -> bytes:
    return _u16(extension_type) + _u16(len(body)) + body


def _sni_body(hostname: str = "example.com") -> bytes:
    # RFC 6066: ServerNameList is a uint16 length followed by ServerName
    # entries, each a one-byte name type and a uint16-length-prefixed name.
    # There is no per-entry length field of its own.
    raw = hostname.encode("ascii")
    entry = b"\x00" + _u16(len(raw)) + raw
    return _u16(len(entry)) + entry


def _alpn_body(protocols: Sequence[bytes]) -> bytes:
    entries = b"".join(bytes([len(p)]) + p for p in protocols)
    return _u16(len(entries)) + entries


def _supported_versions_body(versions: Sequence[int]) -> bytes:
    return _byte_vector(b"".join(_u16(v) for v in versions))


def _server_version(version: int) -> bytes:
    """The ServerHello form of supported_versions: the selected version, bare.

    RFC 8446 section 4.2.1: the extension_data is ``ProtocolVersion
    selected_version``, two bytes -- not the client's 1-byte-length-prefixed
    vector. `T5-03` found `T5-01` reading both with the client's form, which
    refused every conformant TLS 1.3 ServerHello.
    """
    return _u16(version)


Extension = tuple[int, bytes]


def build_client_hello(
    *,
    legacy_version: int = 0x0303,
    ciphers: Sequence[int] = (0x1301,),
    extensions: Sequence[Extension] = (),
    include_extensions: bool = True,
    session_id: bytes = b"",
    compression_methods: bytes = b"\x00",
    cipher_list_length: int | None = None,
    extension_block_length: int | None = None,
    raw_extension_block: bytes | None = None,
) -> bytes:
    """A structurally valid ClientHello, with knobs for the invalid variants."""
    body = _u16(legacy_version) + b"\x11" * 32
    body += bytes([len(session_id)]) + session_id
    cipher_bytes = b"".join(_u16(c) for c in ciphers)
    declared_ciphers = len(cipher_bytes) if cipher_list_length is None else cipher_list_length
    body += _u16(declared_ciphers) + cipher_bytes
    body += bytes([len(compression_methods)]) + compression_methods
    if include_extensions:
        if raw_extension_block is not None:
            block = raw_extension_block
        else:
            block = b"".join(_extension(t, b) for t, b in extensions)
        declared_block = len(block) if extension_block_length is None else extension_block_length
        body += _u16(declared_block) + block
    handshake = b"\x01" + _u24(len(body)) + body
    return b"\x16" + _u16(0x0303) + _u16(len(handshake)) + handshake


def build_server_hello(
    *,
    legacy_version: int = 0x0303,
    cipher: int = 0x1301,
    extensions: Sequence[Extension] = (),
    include_extensions: bool = True,
    session_id: bytes = b"",
) -> bytes:
    body = _u16(legacy_version) + b"\x22" * 32
    body += bytes([len(session_id)]) + session_id
    body += _u16(cipher) + b"\x00"
    if include_extensions:
        block = b"".join(_extension(t, b) for t, b in extensions)
        body += _u16(len(block)) + block
    handshake = b"\x02" + _u24(len(body)) + body
    return b"\x16" + _u16(0x0303) + _u16(len(handshake)) + handshake


def _features(payload: bytes) -> ClientHelloFeatures:
    found = fingerprint_client_hello(payload)
    assert found is not None, "the hello was expected to be parseable"
    return found


# ---------------------------------------------------------------------------
# Published vectors
# ---------------------------------------------------------------------------


#: The two worked examples in the `salesforce/ja3` README, with their published
#: MD5 values. The second has no extensions at all, which is also the test that
#: a hello ending after its compression methods is not treated as truncated.
JA3_VECTORS = (
    (
        "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0",
        "ada70206e40642a3e4461f35503241d5",
        (769, (47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4), (0, 10, 11), (23, 24, 25)),
    ),
    (
        "769,4-5-10-9-100-98-3-6-19-18-99,,,",
        "de350869b8c85de67a350c8d186f11e6",
        (769, (4, 5, 10, 9, 100, 98, 3, 6, 19, 18, 99), (), ()),
    ),
)

#: JA4.md's worked example. Every list is in arrival order, as the spec presents
#: it; the expected hash is over the *sorted* lists the spec also prints.
JA4_VECTOR_CIPHERS = (
    0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
    0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
)
JA4_VECTOR_EXTENSIONS = (
    0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002D,
    0x000D, 0x0005, 0x0023, 0x0012, 0x002B, 0xFF01, 0x000B, 0x000A, 0x0015,
)
JA4_VECTOR_SIGNATURE_ALGORITHMS = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)


def ja4_vector_hello() -> bytes:
    """The ClientHello behind JA4.md's ``t13d1516h2_8daaf6152771_e5627efa2ab1``."""
    bodies: dict[int, bytes] = {
        _SNI: _sni_body(),
        _ALPN: _alpn_body([b"h2"]),
        _SIGNATURE_ALGORITHMS: _u16_vector(JA4_VECTOR_SIGNATURE_ALGORITHMS),
        _SUPPORTED_VERSIONS: _supported_versions_body([0x0304]),
        _SUPPORTED_GROUPS: _u16_vector((0x001D, 0x0017)),
        _EC_POINT_FORMATS: _byte_vector(bytes([0])),
    }
    extensions = [(t, bodies.get(t, b"")) for t in JA4_VECTOR_EXTENSIONS]
    return build_client_hello(ciphers=JA4_VECTOR_CIPHERS, extensions=extensions)


@pytest.mark.parametrize(("expected_string", "expected_hash", "case"), JA3_VECTORS)
def test_ja3_matches_the_published_salesforce_vectors(
    expected_string: str, expected_hash: str, case: tuple[int, Sequence[int], Sequence[int], Sequence[int]]
) -> None:
    version, ciphers, extension_types, curves = case
    bodies = {
        _SNI: _sni_body(),
        _SUPPORTED_GROUPS: _u16_vector(curves),
        _EC_POINT_FORMATS: _byte_vector(bytes([0])),
    }
    hello = build_client_hello(
        legacy_version=version,
        ciphers=ciphers,
        extensions=[(t, bodies.get(t, b"")) for t in extension_types],
        include_extensions=bool(extension_types),
    )

    found = _features(hello)

    assert found.ja3_string == expected_string
    assert found.ja3 == expected_hash


def test_ja4_matches_the_published_foxio_vector() -> None:
    found = _features(ja4_vector_hello())

    # The `a` part is human-readable: TLS over TCP, TLS 1.3, a domain (SNI),
    # 15 ciphers, 16 extensions, first ALPN "h2".
    assert found.ja4_a == "t13d1516h2"
    assert found.ja4_b == "8daaf6152771"
    assert found.ja4_c == "e5627efa2ab1"
    assert found.ja4 == "t13d1516h2_8daaf6152771_e5627efa2ab1"

    assert len(found.cipher_suites) == 15
    assert found.extensions == JA4_VECTOR_EXTENSIONS
    assert found.signature_algorithms == JA4_VECTOR_SIGNATURE_ALGORITHMS


def test_ja4s_matches_the_published_foxio_server_fingerprint() -> None:
    """``t130200_1301_a56c5b993250`` is FoxIO's published Sliver JA4S.

    The ``a`` part is TLS, version 13 (from supported_versions), 2 extensions, no
    ALPN; the ``b`` part is the server's chosen cipher; the ``c`` part is the
    hash of ``002b,0033`` in arrival order -- the pair this hello carries.
    ``supported_versions`` is built in the ServerHello form, which is the form a
    real TLS 1.3 server sends.
    """
    hello = build_server_hello(
        cipher=0x1301,
        extensions=(
            (_SUPPORTED_VERSIONS, _server_version(0x0304)),
            (0x0033, b""),
        ),
    )

    found = fingerprint_server_hello(hello)
    assert found is not None
    assert found.ja4s == "t130200_1301_a56c5b993250"


def test_a_server_hello_version_extension_is_a_bare_uint16() -> None:
    """RFC 8446 section 4.2.1, and a bug `T5-03` found by wiring the server half.

    The ClientHello sends a 1-byte-length-prefixed list of versions; the
    ServerHello sends the one selected version, two bytes and no length. Reading
    both with the ClientHello's form refused every conformant TLS 1.3
    ServerHello -- which is most traffic -- while a TLS 1.2 ServerHello, which
    has no such extension, parsed fine. The knob that decides JA4S's version
    field made it look right whenever it was tested by hand.
    """
    rfc_form = build_server_hello(
        extensions=((_SUPPORTED_VERSIONS, _server_version(0x0304)), (0x0033, b""))
    )
    client_form = build_server_hello(
        extensions=((_SUPPORTED_VERSIONS, _supported_versions_body([0x0304])), (0x0033, b""))
    )

    found = fingerprint_server_hello(rfc_form)
    assert found is not None
    assert found.supported_versions == (0x0304,)
    assert found.ja4s_a == "t130200"
    assert fingerprint_server_hello(client_form) is None


# ---------------------------------------------------------------------------
# The features themselves -- a signature needs the lists, not only the hashes
# ---------------------------------------------------------------------------


def test_the_client_hello_features_are_the_lists_the_hash_is_taken_over() -> None:
    version, ciphers, extension_types, curves = JA3_VECTORS[0][2]
    bodies = {
        _SNI: _sni_body(),
        _SUPPORTED_GROUPS: _u16_vector(curves),
        _EC_POINT_FORMATS: _byte_vector(bytes([0])),
    }
    hello = build_client_hello(
        legacy_version=version,
        ciphers=ciphers,
        extensions=[(t, bodies.get(t, b"")) for t in extension_types],
    )

    found = _features(hello)

    assert found.client_version == 769
    assert found.cipher_suites == tuple(ciphers)
    assert found.extensions == tuple(extension_types)
    assert found.elliptic_curves == (23, 24, 25)
    assert found.ec_point_formats == (0,)
    assert found.supported_versions == ()
    assert found.version_histogram == ((769, 1),)
    assert found.alpn_protocols == ()
    assert found.signature_algorithms == ()
    assert found.grease_values == ()


def test_the_version_histogram_counts_what_the_client_offered() -> None:
    hello = build_client_hello(
        legacy_version=0x0301,
        extensions=((_SUPPORTED_VERSIONS, _supported_versions_body([0x0303, 0x0304, 0x0304])),),
    )

    found = _features(hello)

    assert found.supported_versions == (0x0303, 0x0304, 0x0304)
    assert found.version_histogram == ((0x0303, 1), (0x0304, 2))


def test_a_hello_with_no_ciphers_or_extensions_still_produces_a_fingerprint() -> None:
    """JA4 defines the empty cases (``00`` count, zero hashes); they are not errors."""
    found = _features(build_client_hello(ciphers=(), include_extensions=False))

    assert found.cipher_suites == ()
    assert found.extensions == ()
    assert found.ja4_a == "t12i000000"
    assert found.ja4_b == "000000000000"
    assert found.ja4_c == "000000000000"
    assert found.ja3_string == "771,,,,"


# ---------------------------------------------------------------------------
# GREASE -- removed before the hash, counted separately
# ---------------------------------------------------------------------------


def _grease_free_hello() -> bytes:
    return build_client_hello(
        ciphers=(0x1301,),
        extensions=(
            (_SNI, _sni_body()),
            (_SUPPORTED_GROUPS, _u16_vector((0x001D,))),
            (_SUPPORTED_VERSIONS, _supported_versions_body([0x0304])),
        ),
    )


def _greased_hello() -> bytes:
    return build_client_hello(
        ciphers=(0x0A0A, 0x1301),
        extensions=(
            (0x1A1A, b""),
            (_SNI, _sni_body()),
            (_SUPPORTED_GROUPS, _u16_vector((0x2A2A, 0x001D))),
            (_SUPPORTED_VERSIONS, _supported_versions_body([0x0304, 0x4A4A])),
        ),
    )


def test_grease_is_counted_separately_and_never_reaches_a_list() -> None:
    found = _features(_greased_hello())

    assert found.grease_values == (0x0A0A, 0x1A1A, 0x2A2A, 0x4A4A)
    assert found.cipher_suites == (0x1301,)
    assert found.extensions == (_SNI, _SUPPORTED_GROUPS, _SUPPORTED_VERSIONS)
    assert found.elliptic_curves == (0x001D,)
    assert found.supported_versions == (0x0304,)


def test_grease_changes_no_fingerprint() -> None:
    """The whole point of removing GREASE: it varies per connection by design.

    A GREASE supported_version is larger than any real one, so this also pins
    that the version is chosen from the non-GREASE values.
    """
    clean = _features(_grease_free_hello())
    greased = _features(_greased_hello())

    assert greased.ja3 == clean.ja3
    assert greased.ja4_a == clean.ja4_a
    assert greased.ja4_b == clean.ja4_b
    assert greased.ja4_c == clean.ja4_c
    assert greased.ja4 == clean.ja4


# ---------------------------------------------------------------------------
# ALPN, including the published examples and their one contradiction
# ---------------------------------------------------------------------------


def _alpn_field(protocol: bytes) -> str:
    hello = build_client_hello(
        extensions=((_SNI, _sni_body()), (_ALPN, _alpn_body([protocol]))),
    )
    return _features(hello).ja4_a[-2:]


@pytest.mark.parametrize(
    ("protocol", "expected"),
    [
        (b"h2", "h2"),
        (b"http/1.1", "h1"),
        (b"h3", "h3"),
        (b"x", "xx"),
        (b"", "00"),
        (b"\xab", "ab"),
        (b"\xab\xcd", "ad"),
        (b"\x30\xab", "3b"),
        (b"\x61\x20", "60"),
        (b"\x30\x31\xab\xcd", "3d"),
        # Both ends are alphanumeric -- '0' and '1' -- so no hex conversion
        # happens and the published field is "01", which reads like a hex pair
        # but is not one.
        (b"\x30\xab\xcd\x31", "01"),
    ],
)
def test_the_alpn_field_matches_the_published_examples(protocol: bytes, expected: str) -> None:
    assert _alpn_field(protocol) == expected


def test_an_empty_signature_algorithm_extension_still_changes_the_extension_hash() -> None:
    """JA4 appends ``_`` whenever the extension is present, even with no algorithms.

    "Present but empty" is a client choice. Hashing the extension list alone
    would report it as absent, which is a different client.
    """
    with_extension = _features(
        build_client_hello(
            extensions=(
                (_SNI, _sni_body()),
                (_ALPN, _alpn_body([b"h2"])),
                (_SIGNATURE_ALGORITHMS, _u16(0)),
            )
        )
    )
    without_extension = _features(
        build_client_hello(
            extensions=((_SNI, _sni_body()), (_ALPN, _alpn_body([b"h2"]))),
        )
    )

    assert without_extension.ja4_c == "000000000000"
    # The extension 0x000d is part of the sorted list, and the empty algorithm
    # list still appends its underscore: sha256("000d_").
    assert with_extension.ja4_c == "176fa2dad4eb"
    assert with_extension.ja4_c != without_extension.ja4_c


def test_no_alpn_extension_is_00() -> None:
    found = _features(build_client_hello(extensions=((_SNI, _sni_body()),)))

    assert found.alpn_protocols == ()
    assert found.ja4_a[-2:] == "00"


# ---------------------------------------------------------------------------
# Strictness: a partial parse is refused, never reported as a fact
# ---------------------------------------------------------------------------


def test_no_truncation_of_a_valid_hello_yields_a_fingerprint() -> None:
    valid = ja4_vector_hello()

    parsed = [n for n in range(len(valid)) if fingerprint_client_hello(valid[:n]) is not None]

    assert parsed == [], f"a truncated hello produced a fingerprint at prefix lengths {parsed}"


@pytest.mark.parametrize(
    "broken",
    [
        pytest.param({"cipher_list_length": 3}, id="odd-cipher-list-length"),
        pytest.param({"cipher_list_length": 64}, id="cipher-list-past-the-buffer"),
        pytest.param({"extension_block_length": 999}, id="extensions-past-the-buffer"),
        pytest.param({"extension_block_length": 1}, id="extensions-short-of-the-buffer"),
    ],
)
def test_a_structurally_broken_hello_is_refused(broken: dict[str, int]) -> None:
    assert fingerprint_client_hello(build_client_hello(**broken)) is None


def test_a_record_that_is_not_a_handshake_is_refused() -> None:
    hello = bytearray(build_client_hello())
    hello[0] = 0x17  # application_data

    assert fingerprint_client_hello(bytes(hello)) is None


def test_a_record_version_outside_tls_is_refused() -> None:
    hello = bytearray(build_client_hello())
    hello[1:3] = b"\x02\x00"

    assert fingerprint_client_hello(bytes(hello)) is None


def test_a_handshake_length_that_exceeds_the_capture_is_refused() -> None:
    hello = bytearray(build_client_hello())
    hello[6:9] = _u24(len(hello))

    assert fingerprint_client_hello(bytes(hello)) is None


def test_an_alpn_body_that_does_not_match_its_declared_length_is_refused() -> None:
    hello = build_client_hello(
        extensions=((_SNI, _sni_body()), (_ALPN, _u16(0) + b"h2")),
    )

    assert fingerprint_client_hello(hello) is None


def test_an_odd_signature_algorithm_list_is_refused() -> None:
    hello = build_client_hello(
        extensions=((_SIGNATURE_ALGORITHMS, _u16(3) + b"abc"),),
    )

    assert fingerprint_client_hello(hello) is None


def test_the_handshake_type_byte_is_enforced_not_inferred_from_the_body() -> None:
    """A ClientHello body behind a ServerHello type byte is not a ClientHello.

    The body is byte-identical and parses perfectly, so this is the case that
    distinguishes a checked type from one that merely happened to fail later.
    """
    disguised = bytearray(build_client_hello())
    disguised[5] = 0x02  # server_hello
    assert fingerprint_client_hello(bytes(disguised)) is None

    server = bytearray(build_server_hello())
    server[5] = 0x01  # client_hello
    assert fingerprint_server_hello(bytes(server)) is None


def test_a_handshake_that_overruns_its_record_is_refused() -> None:
    """A record claiming less than its handshake is a truncated message.

    Every byte is present in the capture, so nothing downstream notices: only the
    record boundary says the message is incomplete.
    """
    hello = bytearray(build_client_hello())
    record_length = int.from_bytes(hello[3:5], "big")
    hello[3:5] = (record_length - 16).to_bytes(2, "big")

    assert fingerprint_client_hello(bytes(hello)) is None


def test_a_server_hello_is_not_a_client_hello() -> None:
    assert fingerprint_client_hello(build_server_hello()) is None


def test_a_client_hello_is_not_a_server_hello() -> None:
    assert fingerprint_server_hello(build_client_hello()) is None


def test_the_length_argument_is_a_window_and_a_truncation_is_not_hidden() -> None:
    valid = ja4_vector_hello()

    assert fingerprint_client_hello(valid, len(valid)) is not None
    assert fingerprint_client_hello(valid + b"\xff" * 16, len(valid)) is not None
    assert fingerprint_client_hello(valid, len(valid) - 1) is None
    assert fingerprint_client_hello(valid, 0) is None
    assert fingerprint_client_hello(valid, -1) is None


def _with_handshake_length(hello: bytes, handshake_length: int) -> bytes:
    """Keep the record intact but declare a shorter handshake message."""
    patched = bytearray(hello)
    patched[6:9] = _u24(handshake_length)
    return bytes(patched)


# Each value is the handshake length of the default hello cut at a different
# field boundary: 43 bytes is the whole body, so 0/36/39/40/42 stop before the
# version, the cipher-suite length, the compression method, the extension block
# and the extension block length respectively.
@pytest.mark.parametrize(
    "handshake_length",
    [
        pytest.param(0, id="before-the-version"),
        pytest.param(36, id="before-the-cipher-suite-length"),
        pytest.param(39, id="before-the-compression-method-length"),
        pytest.param(40, id="before-the-extension-block-length"),
        pytest.param(42, id="before-the-extension-block"),
    ],
)
def test_a_client_hello_cut_at_each_field_boundary_is_refused(handshake_length: int) -> None:
    hello = _with_handshake_length(build_client_hello(), handshake_length)

    assert fingerprint_client_hello(hello) is None


def test_a_client_hello_whose_session_id_runs_past_the_body_is_refused() -> None:
    hello = bytearray(_with_handshake_length(build_client_hello(), 36))
    hello[43] = 32  # the session-id length byte, with only 1 byte left in the body

    assert fingerprint_client_hello(bytes(hello)) is None


@pytest.mark.parametrize(
    "handshake_length",
    [
        pytest.param(0, id="before-the-version"),
        pytest.param(37, id="before-the-cipher-suite"),
        pytest.param(39, id="before-the-extension-block-length"),
    ],
)
def test_a_server_hello_cut_at_each_field_boundary_is_refused(handshake_length: int) -> None:
    hello = _with_handshake_length(build_server_hello(), handshake_length)

    assert fingerprint_server_hello(hello) is None


def test_a_server_hello_whose_extension_block_does_not_fill_the_body_is_refused() -> None:
    # Two extensions (8 bytes of block) with a handshake length that stops 7
    # bytes short of it: the block length is readable, the block does not fit.
    hello = build_server_hello(extensions=((_SUPPORTED_GROUPS, b""), (0x0033, b"")))

    assert fingerprint_server_hello(_with_handshake_length(hello, 41)) is None


def test_a_server_hello_whose_session_id_runs_past_the_body_is_refused() -> None:
    hello = bytearray(_with_handshake_length(build_server_hello(), 36))
    hello[43] = 32

    assert fingerprint_server_hello(bytes(hello)) is None


def test_a_server_extension_that_overruns_its_block_is_refused() -> None:
    # One empty extension: 9 + 2 + 32 + 1 + 2 + 1 + 2 + 4 = 53 is the end of the
    # body, the block declares 4 bytes, and the extension's type/length sit at
    # 49..53. Rewriting its declared length to 10 makes the body overrun.
    hello = bytearray(build_server_hello(extensions=((_SUPPORTED_GROUPS, b""),)))
    hello[51:53] = _u16(10)

    assert fingerprint_server_hello(bytes(hello)) is None


@pytest.mark.parametrize(
    ("extension_type", "body"),
    [
        pytest.param(_SUPPORTED_GROUPS, b"", id="groups-shorter-than-their-length-field"),
        pytest.param(_SUPPORTED_GROUPS, _u16(0) + b"\x00", id="groups-vector-not-consumed"),
        pytest.param(_EC_POINT_FORMATS, b"", id="point-formats-shorter-than-their-length-field"),
        pytest.param(_EC_POINT_FORMATS, b"\x05\x00", id="point-formats-vector-not-consumed"),
        pytest.param(_ALPN, b"\x00", id="alpn-shorter-than-its-length-field"),
        pytest.param(_ALPN, _u16(3) + b"\x05ab", id="alpn-entry-overruns-the-list"),
        pytest.param(_SIGNATURE_ALGORITHMS, b"", id="signature-algorithms-shorter-than-their-length-field"),
        pytest.param(_SUPPORTED_VERSIONS, _byte_vector(b"\x03"), id="supported-versions-not-16-bit"),
    ],
)
def test_a_known_extension_with_a_malformed_body_is_refused(
    extension_type: int, body: bytes
) -> None:
    hello = build_client_hello(extensions=((extension_type, body),))

    assert fingerprint_client_hello(hello) is None


@pytest.mark.parametrize(
    ("block", "why"),
    [
        pytest.param(b"\x00\x0a", "the extension header does not fit", id="header-truncated"),
        pytest.param(_u16(0x000A) + _u16(10), "the extension body does not fit", id="body-truncated"),
    ],
)
def test_an_extension_block_that_overruns_itself_is_refused(block: bytes, why: str) -> None:
    hello = build_client_hello(raw_extension_block=block)

    assert fingerprint_client_hello(hello) is None, why


# ---------------------------------------------------------------------------
# The server side
# ---------------------------------------------------------------------------


def test_ja3s_is_the_md5_of_the_decimal_triple() -> None:
    hello = build_server_hello(
        cipher=0x1301,
        extensions=(
            (_SUPPORTED_VERSIONS, _server_version(0x0304)),
            (0x0033, b""),
        ),
    )

    found = fingerprint_server_hello(hello)
    assert found is not None
    assert found.server_version == 0x0303
    assert found.cipher_suite == 0x1301
    assert found.extensions == (0x002B, 0x0033)
    assert found.ja3s_string == "771,4865,43-51"
    assert found.ja3s == "f4febc55ea12b31ae17cfb7e614afda8"


def test_ja4s_hashes_the_extension_arrival_order() -> None:
    """Unlike JA4, JA4S does not sort: the server's ordering is the signal."""
    forward = build_server_hello(
        extensions=(
            (_SUPPORTED_VERSIONS, _server_version(0x0304)),
            (0x0033, b""),
        ),
    )
    reverse = build_server_hello(
        extensions=(
            (0x0033, b""),
            (_SUPPORTED_VERSIONS, _server_version(0x0304)),
        ),
    )

    a = fingerprint_server_hello(forward)
    b = fingerprint_server_hello(reverse)
    assert a is not None and b is not None
    assert a.ja4s_c == "a56c5b993250"
    assert a.ja4s_c != b.ja4s_c


def test_ja4_sorts_both_lists_so_arrival_order_does_not_change_it() -> None:
    extensions = [
        (_SNI, _sni_body()),
        (_ALPN, _alpn_body([b"h2"])),
        (_SIGNATURE_ALGORITHMS, _u16_vector((0x0403, 0x0804))),
        (_SUPPORTED_VERSIONS, _supported_versions_body([0x0304])),
    ]

    forward = _features(build_client_hello(extensions=extensions))
    reverse = _features(build_client_hello(extensions=list(reversed(extensions))))

    assert forward.ja4 == reverse.ja4
    assert forward.ja3 != reverse.ja3


def test_a_server_hello_without_extensions_is_not_an_error() -> None:
    found = fingerprint_server_hello(
        build_server_hello(cipher=0xC030, include_extensions=False)
    )

    assert found is not None
    assert found.extensions == ()
    assert found.ja3s_string == "771,49200,"
    assert (found.ja4s_a, found.ja4s_b, found.ja4s_c) == (
        "t120000",
        "c030",
        "000000000000",
    )


# ---------------------------------------------------------------------------
# SNI presence: the extension, not the hostname (`T5-02`)
# ---------------------------------------------------------------------------


def test_the_sni_extension_is_a_feature_even_when_no_hostname_is_legible() -> None:
    """`extract_sni` answers "which hostname"; this answers "did it offer one".

    They are different questions and the empty string conflated them: a client
    that sends no SNI extension, and a client that sends the extension with an
    empty name list, both give `extract_sni` nothing -- but only the first told
    the server it has no name to offer. `sni_present` is that fact.
    """
    with_hostname = build_client_hello(
        extensions=((_SNI, _sni_body()), (_ALPN, _alpn_body([b"h2"])))
    )
    without = build_client_hello(extensions=((_ALPN, _alpn_body([b"h2"])),))
    empty_list = build_client_hello(extensions=((_SNI, b"\x00\x00"),))

    assert _features(with_hostname).sni_present is True
    assert _features(without).sni_present is False
    assert _features(empty_list).sni_present is True

    assert extract_sni(with_hostname) == "example.com"
    assert extract_sni(without) is None
    assert extract_sni(empty_list) is None


def test_the_ja4_dash_or_i_marker_is_the_same_fact_as_the_flag() -> None:
    for payload in (
        build_client_hello(extensions=((_SNI, _sni_body()),)),
        build_client_hello(extensions=((_ALPN, _alpn_body([b"h2"])),)),
    ):
        features = _features(payload)
        assert (features.ja4_a[3] == "d") is features.sni_present


# ---------------------------------------------------------------------------
# Property: arbitrary bytes never raise, and never produce a malformed claim
# ---------------------------------------------------------------------------

_CLIENT_SHAPE = re.compile(r"^t(?:s2|s3|10|11|12|13|d1|d2|d3|00)[di]\d{2}\d{2}[0-9A-Za-z]{2}$")


def _flip(base: bytes, seed: bytes) -> bytes:
    """A mostly-valid hello with bytes flipped, so the fuzzer reaches the parser."""
    data = bytearray(base)
    for index, byte in enumerate(seed):
        if index < len(data):
            data[index] ^= byte
    return bytes(data)


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    arbitrary=st.binary(min_size=0, max_size=600),
    flipped=st.binary(min_size=1, max_size=24).map(lambda seed: _flip(ja4_vector_hello(), seed)),
)
def test_arbitrary_and_near_valid_bytes_never_raise_and_stay_well_formed(
    arbitrary: bytes, flipped: bytes
) -> None:
    for payload in (arbitrary, flipped):
        client = fingerprint_client_hello(payload)
        if client is not None:
            assert re.fullmatch(r"[0-9a-f]{32}", client.ja3)
            assert _CLIENT_SHAPE.match(client.ja4_a), client.ja4_a
            assert len(client.ja4_b) == 12 and len(client.ja4_c) == 12
            assert client.ja4 == f"{client.ja4_a}_{client.ja4_b}_{client.ja4_c}"
            assert client.sni_present == (0 in client.extensions)
            assert not any(c in (0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
                                 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
                                 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA,
                                 0xFAFA) for c in client.cipher_suites)
            assert fingerprint_client_hello(payload) == client

        server = fingerprint_server_hello(payload)
        if server is not None:
            assert re.fullmatch(r"[0-9a-f]{32}", server.ja3s)
            assert re.fullmatch(r"t(?:s2|s3|10|11|12|13|d1|d2|d3|00)\d{2}[0-9A-Za-z]{2}", server.ja4s_a)
            assert re.fullmatch(r"[0-9a-f]{0,4}", server.ja4s_b)
            assert len(server.ja4s_c) == 12
            assert server.ja4s == f"{server.ja4s_a}_{server.ja4s_b}_{server.ja4s_c}"
            assert fingerprint_server_hello(payload) == server


def test_the_modules_docstring_names_the_method_it_implements() -> None:
    """A cheap guard against the source of truth drifting silently."""
    import dpi_engine.tls_fingerprint as module

    doc = module.__doc__ or ""
    for name in ("JA3", "JA3S", "JA4", "JA4S"):
        assert name in doc
    assert "technical_details/JA4.md" in doc
