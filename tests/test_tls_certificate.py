"""The server's certificate (`T5-02`): issuer, subject and validity.

Why the bytes below are not built here
-------------------------------------
A DER parser checked against a DER writer written by the same hand proves that
the two agree, not that either reads X.509. So the three certificates embedded
below were generated once with the `cryptography` package (an OpenSSL binding)
and are pasted here as base64; nothing in this file imports it, and the expected
names and dates are the ones **OpenSSL reported for these exact bytes**, not the
ones this parser produced. The pinned expectations are therefore an external
oracle:

* the CA, a self-signed RSA-2048 certificate (2019-01-01 .. 2049-01-01), used as
  the issuer of the other two;
* a leaf, RSA-2048, with a six-RDN subject in DER order and a
  UTCTime-to-UTCTime validity (2024-03-01 .. 2026-03-01);
* a deliberately awkward leaf, ECDSA P-256, whose subject carries a UTF-8
  common name containing a comma, an organization containing a semicolon, and
  an ``emailAddress`` attribute (a multi-byte OID, and an IA5String), and whose
  validity mixes a UTCTime (2024) with a GeneralizedTime (2051) -- the two
  encodings X.509 allows.

What is a fact, and what is only what the capture shows
------------------------------------------------------
TLS 1.3 carries the Certificate message **after** the ServerHello, under the
handshake traffic keys, so it is ciphertext on the wire. This module reads the
plaintext handshake only: for TLS 1.3 it returns ``None``, which means "no
certificate was visible", *not* "the server sent no certificate". The same
``None`` covers a truncated capture and a stream that does not start with a
handshake. Callers that need the distinction already have the ServerHello
fingerprint to tell them which case they are in.

Rendering rules, pinned by the tests below
------------------------------------------
* RDNs are joined in **DER order** with ``, `` -- the order the certificate
  encodes, which is the reverse of the usual display order. The subject above
  therefore begins with ``C=``, not ``CN=``.
* A multi-valued RDN joins its attributes with ``+``.
* Values are escaped as RFC 4514 section 2.4 requires, so a comma inside a name
  cannot be mistaken for an RDN separator.
* Known attribute OIDs become their short names (`C`, `ST`, `L`, `O`, `OU`,
  `CN`, `emailAddress`, ...); an unmapped OID is rendered dotted.
* Times are timezone-aware UTC datetimes, exactly as encoded: no expiry
  judgement and no ordering check is made here.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from dpi_engine.tls_certificate import CertificateFeatures, extract_server_certificate

# ---------------------------------------------------------------------------
# The certificates: real DER, generated outside this parser
# ---------------------------------------------------------------------------

#: Self-signed CA. Subject = issuer = C=US, O=Example Root Authority,
#: CN=Example Root CA; valid 2019-01-01 .. 2049-01-01.
_CA_DER = base64.b64decode(
    "MIIDIzCCAgugAwIBAgIGChssPU5fMA0GCSqGSIb3DQEBCwUAMEgxCzAJBgNVBAYTAlVTMR8wHQYD"
    "VQQKDBZFeGFtcGxlIFJvb3QgQXV0aG9yaXR5MRgwFgYDVQQDDA9FeGFtcGxlIFJvb3QgQ0EwHhcN"
    "MTkwMTAxMDAwMDAwWhcNNDkwMTAxMDAwMDAwWjBIMQswCQYDVQQGEwJVUzEfMB0GA1UECgwWRXhh"
    "bXBsZSBSb290IEF1dGhvcml0eTEYMBYGA1UEAwwPRXhhbXBsZSBSb290IENBMIIBIjANBgkqhkiG"
    "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs1KRitfVBjMnNGDOXC4z9j22uXBAmEPrCnt/3L4YB9w9YQog"
    "I1GkWl4w57xN0o9+W3EoCfkQiOFRD+bbUfK/kmQObHhqPzGxumSJQUMUViOAoay5AVcDznPxGh6x"
    "WmLhdRyAWk/mkomSbb4pJSAeajao87uOX/RaMGRZQ0XfqK5CDwNXAQwuTf+wp8kncuphYVjTjyrE"
    "/qRqTGMyQEFTtk6eya2/TS7zElHXFC/6J21juwvKU0kP5yMzBL27bNSY9e8x0OOh57UYpm3KDl4L"
    "1JuUShbGe/733VA4iKqD3+E03oB0pOMIEXQ/Mk9j/68Eie0zDHbvNneIOCdJyjnHbwIDAQABoxMw"
    "ETAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBhjDa+nxcumknoA7eGfBCHcqOP"
    "Fqdtvugf2Fp22K4wZ16tilKtAvLMXKVr4J5tX27RcVy3t3ZikRwrHVXzlXgrm1P+dGVWlqxAq87R"
    "pBqofyr5fYK8BUBaOxDFQwvJr92vnNJSNwYGnGQ+4P0X4xlIyZFNm/XjskTZiCPQFWDZO1+s5hu4"
    "tq0EYjgClPGzzfoVI6tPe05xYR9p6O2UevG5trcfJfAoYZye9a124b/hsinS3mZK/5mdXQSmUkEF"
    "DTR5f/hCzQzq8yfM+TejfaIXischoaIVWArXhvFes8qa1iYCEAvANFqaF/5CVdNvYMlbqjEhYVuw"
    "cD1J5721trI/"
)

#: Leaf issued by the CA above; subject in DER order is
#: C=US, ST=California, L=San Francisco, O=Example Corp, OU=Packet Analysis,
#: CN=www.example.com. RSA-2048; valid 2024-03-01 .. 2026-03-01.
_LEAF_DER = base64.b64decode(
    "MIIDcDCCAligAwIBAgIKESIzRFVmd4iZADANBgkqhkiG9w0BAQsFADBIMQswCQYDVQQGEwJVUzEf"
    "MB0GA1UECgwWRXhhbXBsZSBSb290IEF1dGhvcml0eTEYMBYGA1UEAwwPRXhhbXBsZSBSb290IENB"
    "MB4XDTI0MDMwMTAwMDAwMFoXDTI2MDMwMTAwMDAwMFowgYUxCzAJBgNVBAYTAlVTMRMwEQYDVQQI"
    "DApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRUwEwYDVQQKDAxFeGFtcGxlIENv"
    "cnAxGDAWBgNVBAsMD1BhY2tldCBBbmFseXNpczEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMIIB"
    "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3yYGabE2jiCNr0X2ITf7eo9kNXEIVRq9NaKl"
    "CbDGGVVJwF+CGKogQzOjiHpd9PRm9oxYnaaH1X79zuHwHJJg/S3sLCGcefnu+7s149IDBLmwh8iB"
    "UUS+uRael70MEzGISsnvW9mmKnQOv1/SmXh5BpNMsGctDzuNhOdbh0Orf4GOFsLA79tO7AzGeq08"
    "Ub+82OsKIJo+YZhOJXBmSSU8q7g0HD4zY8nAOnTusjMD2nqNTrcfgjNLJaDrqN6GCCP6E25yG8G+"
    "AvkIk/xcu3JgI2X76r86xsJEEHDWmUW4lrHXJ23c0aeeT65kLWGzTOC7c9ozbssJTiOucyyaGWig"
    "cwIDAQABox4wHDAaBgNVHREEEzARgg93d3cuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEB"
    "ACGW5C2+721TeD1/OfB1HpknXLUcRO8GFrt/AJjnIf6aEW9qIpLIMHsa/v0a51PcGY7SvPnZL908"
    "JYcNeWIoU7aG6Jfumebk5O6CoH9vM8UXH+C5GptlVEihVxFhSpU+KdUxevRHdNzyOI/Klg9db5Zr"
    "0B+DWzFKXBQWDja93n5fTcdkrNOxjUwk0NNiQqGzkQIMcfBr3L7lNCIrZjqyQgSm+ooHqG8kmVfL"
    "j2FV0JONbTiAseXvixRb/Zl4LEnsE+MWwEbBwnZEvdBqoj2IOp3v8Lyxp+SEcPQAEw6EqSt0bWk2"
    "r17RiNT1twxBSv3cFs8drDb4cnSufvE9vZRUaQE="
)

#: Issued by the same CA. Subject in DER order is C=DE, O=Acme; Ltd,
#: CN=Ünïcode, Inc., emailAddress=ops@example.com -- a UTF8String with a comma,
#: a PrintableString with a semicolon, and a multi-byte OID. Valid
#: 2024-06-01T12:30:45Z (UTCTime) .. 2051-01-02T03:04:05Z (GeneralizedTime).
_WEIRD_DER = base64.b64decode(
    "MIICUzCCATugAwIBAgIBBzANBgkqhkiG9w0BAQsFADBIMQswCQYDVQQGEwJVUzEfMB0GA1UECgwW"
    "RXhhbXBsZSBSb290IEF1dGhvcml0eTEYMBYGA1UEAwwPRXhhbXBsZSBSb290IENBMCAXDTI0MDYw"
    "MTEyMzA0NVoYDzIwNTEwMTAyMDMwNDA1WjBbMQswCQYDVQQGEwJERTESMBAGA1UECgwJQWNtZTsg"
    "THRkMRgwFgYDVQQDDA/DnG7Dr2NvZGUsIEluYy4xHjAcBgkqhkiG9w0BCQEWD29wc0BleGFtcGxl"
    "LmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHjMsg69mJ5oDwU+aads2/vjF7HP+JYCiWSq"
    "wBxl7Sp7/rILnFpr8YUAfX0AE26X7h1nRRrSShmO/UXwBX2c3v0wDQYJKoZIhvcNAQELBQADggEB"
    "AAto7LqEtLtD9eTGRXq4le96I03E+DfX7NRK3cUcnNUDRn7xmGl3BqzYFnksT2v18Yy0yJQ8T060"
    "L2olTjWEnbPbSAKG9uN2VQxCXeGw8PkZCF+sGn4dZm4hANlz0o7bIB/WUHQGEw1o2aWEoCe5YZos"
    "p491dwhnYz3Re+uNXE5c+Yw+x+vlkgCo1hOXB5vCt6S1jdDh/YmWOi2xqbZEJ6BShU5ljLBVGGs9"
    "wt0ivg/5OtR7LDHkPyOzkAIXZPxKgsWhXH4mUXwfQFHllzqvpBQi3ABa3qC5RNEo7k3BIHWvs/Pz"
    "ojOFDorLjFsPIPpCcDYKJ0vL87VMoqK3dp0D6Pg="
)

_CA_SUBJECT = "C=US, O=Example Root Authority, CN=Example Root CA"
_LEAF_SUBJECT = (
    "C=US, ST=California, L=San Francisco, O=Example Corp, OU=Packet Analysis, "
    "CN=www.example.com"
)
_WEIRD_SUBJECT = "C=DE, O=Acme\\; Ltd, CN=Ünïcode\\, Inc., emailAddress=ops@example.com"

# ---------------------------------------------------------------------------
# Builders -- the TLS framing, written here rather than imported
# ---------------------------------------------------------------------------


def _u16(value: int) -> bytes:
    return bytes([(value >> 8) & 0xFF, value & 0xFF])


def _u24(value: int) -> bytes:
    return bytes([(value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])


def _record(payload: bytes, *, content_type: int = 0x16, version: int = 0x0303) -> bytes:
    return bytes([content_type]) + _u16(version) + _u16(len(payload)) + payload


def _handshake(handshake_type: int, body: bytes) -> bytes:
    return bytes([handshake_type]) + _u24(len(body)) + body


def _certificate_body(*certificates: bytes, declared_total: int | None = None) -> bytes:
    entries = b"".join(_u24(len(d)) + d for d in certificates)
    total = len(entries) if declared_total is None else declared_total
    return _u24(total) + entries


def _certificate_message(*certificates: bytes, declared_total: int | None = None) -> bytes:
    return _handshake(0x0B, _certificate_body(*certificates, declared_total=declared_total))


def _server_hello() -> bytes:
    """A structurally valid ServerHello: TLS 1.2, an empty extension block."""
    body = _u16(0x0303) + b"\x33" * 32 + b"\x00" + _u16(0x1301) + b"\x00" + _u16(0)
    return _handshake(0x02, body)


def _stream(*messages: bytes) -> bytes:
    return b"".join(_record(m) for m in messages)


def _found(der: bytes) -> CertificateFeatures:
    features = extract_server_certificate(_stream(_certificate_message(der)))
    assert features is not None, "the certificate was expected to be readable"
    return features


# ---------------------------------------------------------------------------
# The external oracle
# ---------------------------------------------------------------------------


def test_the_leaf_matches_what_openssl_reports_for_these_bytes() -> None:
    assert _found(_LEAF_DER) == CertificateFeatures(
        issuer=_CA_SUBJECT,
        subject=_LEAF_SUBJECT,
        not_valid_before=datetime(2024, 3, 1, tzinfo=UTC),
        not_valid_after=datetime(2026, 3, 1, tzinfo=UTC),
    )


def test_a_self_signed_certificate_carries_the_same_name_twice() -> None:
    features = _found(_CA_DER)
    assert features.subject == features.issuer == _CA_SUBJECT
    assert features.not_valid_before == datetime(2019, 1, 1, tzinfo=UTC)
    assert features.not_valid_after == datetime(2049, 1, 1, tzinfo=UTC)


def test_the_subject_is_rendered_in_der_order_and_escaped() -> None:
    features = _found(_WEIRD_DER)
    assert features.subject == _WEIRD_SUBJECT
    assert features.issuer == _CA_SUBJECT


def test_both_time_encodings_are_read() -> None:
    features = _found(_WEIRD_DER)
    # UTCTime for 2024, GeneralizedTime for 2051: X.509 uses the second only
    # from 2050 on, and the two are different tags with different widths.
    assert features.not_valid_before == datetime(2024, 6, 1, 12, 30, 45, tzinfo=UTC)
    assert features.not_valid_after == datetime(2051, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_the_validity_is_timezone_aware_utc() -> None:
    features = _found(_LEAF_DER)
    assert features.not_valid_before.tzinfo is UTC
    assert features.not_valid_after.tzinfo is UTC


# ---------------------------------------------------------------------------
# The framing around the certificate
# ---------------------------------------------------------------------------


def test_a_chain_yields_the_leaf_not_the_issuer() -> None:
    stream = _stream(_certificate_message(_LEAF_DER, _CA_DER))
    features = extract_server_certificate(stream)
    assert features is not None
    assert features.subject == _LEAF_SUBJECT
    # The CA's validity is 2019..2049; the leaf's is 2024..2026, so this cannot
    # be satisfied by having read the second entry.
    assert features.not_valid_after == datetime(2026, 3, 1, tzinfo=UTC)


def test_a_server_hello_before_the_certificate_is_skipped() -> None:
    stream = _stream(_server_hello(), _certificate_message(_LEAF_DER))
    assert extract_server_certificate(stream) == _found(_LEAF_DER)


@pytest.mark.parametrize("split", [1, 2, 4, 5, 7, 100, 400, 800])
def test_a_certificate_message_that_spans_two_records_is_reassembled(split: int) -> None:
    message = _certificate_message(_LEAF_DER)
    assert 0 < split < len(message)
    stream = _record(message[:split]) + _record(message[split:])
    assert extract_server_certificate(stream) == _found(_LEAF_DER)


def test_a_record_that_is_not_a_handshake_ends_the_scan() -> None:
    # A ChangeCipherSpec is the last plaintext record of a TLS 1.2 handshake.
    stream = _stream(_server_hello(), b"\x14") + _record(b"\x01", content_type=0x14)
    assert extract_server_certificate(stream) is None


def test_a_tls13_shaped_stream_yields_no_certificate_but_is_not_an_error() -> None:
    # ServerHello, then ciphertext: the Certificate message is inside it.
    stream = _stream(_server_hello()) + _record(b"\x9f" * 64, content_type=0x17)
    assert extract_server_certificate(stream) is None


def test_an_encrypted_record_before_any_handshake_yields_none() -> None:
    assert extract_server_certificate(_record(b"\x17" * 32, content_type=0x17)) is None


def test_a_certificate_shaped_payload_in_an_encrypted_record_is_not_believed() -> None:
    # Ciphertext that happens to start with a Certificate handshake is still
    # ciphertext: the content type, not the bytes' shape, decides.
    stream = _record(_certificate_message(_LEAF_DER), content_type=0x17)
    assert extract_server_certificate(stream) is None


def test_a_message_with_bytes_after_its_certificate_list_is_refused() -> None:
    body = _certificate_body(_LEAF_DER) + b"\x00" * 10
    assert extract_server_certificate(_stream(_handshake(0x0B, body))) is None


def test_a_server_hello_alone_is_not_a_certificate() -> None:
    assert extract_server_certificate(_stream(_server_hello())) is None


# ---------------------------------------------------------------------------
# Refusals: no certificate is better than half of one
# ---------------------------------------------------------------------------


def test_every_prefix_of_the_stream_yields_no_certificate() -> None:
    stream = _stream(_certificate_message(_LEAF_DER))
    assert extract_server_certificate(stream) is not None
    for cut in range(len(stream)):
        assert extract_server_certificate(stream[:cut]) is None, f"prefix of {cut} bytes"


def test_every_truncation_of_the_certificate_is_refused() -> None:
    for cut in range(len(_LEAF_DER)):
        stream = _stream(_certificate_message(_LEAF_DER[:cut]))
        assert extract_server_certificate(stream) is None, f"der prefix of {cut} bytes"


def test_trailing_bytes_after_the_certificate_are_refused() -> None:
    der = _LEAF_DER + b"\x00"
    assert extract_server_certificate(_stream(_certificate_message(der))) is None


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(b"", id="no-body"),
        pytest.param(_u24(0), id="empty-list"),
        pytest.param(_u24(1) + b"\x00", id="one-byte-list"),
        pytest.param(_u24(3) + _u24(0), id="zero-length-entry"),
    ],
)
def test_a_certificate_list_that_does_not_hold_a_certificate_is_refused(body: bytes) -> None:
    assert extract_server_certificate(_stream(_handshake(0x0B, body))) is None


def test_a_declared_list_length_that_disagrees_with_the_body_is_refused() -> None:
    body = _certificate_body(_LEAF_DER)
    for declared in (len(body) - 4, len(body) - 2, len(body) + 1):
        message = _handshake(0x0B, _u24(declared) + body[3:])
        assert extract_server_certificate(_stream(message)) is None, f"declared {declared}"


def test_an_entry_length_that_overruns_the_list_is_refused() -> None:
    der = _LEAF_DER
    entry = _u24(len(der) + 1) + der
    body = _u24(len(entry)) + entry
    assert extract_server_certificate(_stream(_handshake(0x0B, body))) is None


@pytest.mark.parametrize(
    "der",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"\x30", id="header-only"),
        pytest.param(b"\x30\x80\x00\x00", id="indefinite-length"),
        pytest.param(b"\x30\x03\x02\x01\x00", id="not-enough-fields"),
        pytest.param(b"\x02\x01\x00", id="not-a-sequence"),
        pytest.param(b"\x30\x02\x30\x00", id="empty-tbs"),
        pytest.param(b"\x30\x81", id="long-form-without-bytes"),
        pytest.param(b"\x30\x84\x00\x00\x00\x00", id="four-length-bytes"),
        pytest.param(b"\x1f\x00", id="high-tag-number"),
    ],
)
def test_bytes_that_are_not_a_certificate_are_refused(der: bytes) -> None:
    assert extract_server_certificate(_stream(_certificate_message(der))) is None


def test_a_length_argument_beyond_the_buffer_is_clamped() -> None:
    stream = _stream(_certificate_message(_LEAF_DER))
    assert extract_server_certificate(stream, len(stream) + 1000) == _found(_LEAF_DER)
    assert extract_server_certificate(stream, len(stream) - 1) is None


@given(st.binary(max_size=1024))
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_arbitrary_bytes_never_raise(blob: bytes) -> None:
    features = extract_server_certificate(blob)
    if features is not None:
        assert features.issuer
        assert features.subject
        assert features.not_valid_before.tzinfo is UTC
        assert features.not_valid_after.tzinfo is UTC


# ---------------------------------------------------------------------------
# Synthetic DER: the shapes a real certificate cannot have
# ---------------------------------------------------------------------------
#
# The certificates above prove the reader against an external encoder. These
# bytes are built here on purpose: they are the malformed structures an attacker
# can put on the wire, and no CA will ever issue one for a test fixture. A
# positive case below is a hand-built certificate too, so the builder is checked
# against the real ones rather than trusted.


def _der(tag: int, value: bytes) -> bytes:
    if len(value) < 0x80:
        length = bytes([len(value)])
    elif len(value) < 0x100:
        length = bytes([0x81, len(value)])
    else:
        length = bytes([0x82, len(value) >> 8, len(value) & 0xFF])
    return bytes([tag]) + length + value


_CN_OID = b"\x55\x04\x03"  # 2.5.4.3


def _attribute(oid: bytes, value: bytes, *, tag: int = 0x30) -> bytes:
    return _der(tag, _der(0x06, oid) + value)


def _rdn(*attributes: bytes, tag: int = 0x31) -> bytes:
    return _der(tag, b"".join(attributes))


def _name(*rdns: bytes) -> bytes:
    return _der(0x30, b"".join(rdns))


def _string(value: bytes, tag: int = 0x0C) -> bytes:
    return _der(tag, value)


def _time_element(tag: int, raw: bytes) -> bytes:
    return _der(tag, raw)


def _utc(digits: str) -> bytes:
    return _time_element(0x17, digits.encode("ascii") + b"Z")


def _generalized(digits: str) -> bytes:
    return _time_element(0x18, digits.encode("ascii") + b"Z")


def _validity(before: bytes, after: bytes) -> bytes:
    return _der(0x30, before + after)


_GOOD_CN = _name(_rdn(_attribute(_CN_OID, _string(b"example.test"))))
_GOOD_VALIDITY = _validity(_utc("240101000000"), _utc("260101000000"))


def _certificate(
    *,
    version: bool = True,
    serial: bytes | None = None,
    signature: bytes | None = None,
    issuer: bytes | None = None,
    validity: bytes | None = None,
    subject: bytes | None = None,
) -> bytes:
    parts = [_der(0xA0, _der(0x02, b"\x02"))] if version else []
    parts.append(_der(0x02, b"\x01") if serial is None else serial)
    parts.append(_der(0x30, b"\x05\x00") if signature is None else signature)
    parts.append(_GOOD_CN if issuer is None else issuer)
    parts.append(_GOOD_VALIDITY if validity is None else validity)
    parts.append(_GOOD_CN if subject is None else subject)
    return _der(0x30, _der(0x30, b"".join(parts)))


def _refuses(certificate: bytes) -> None:
    assert extract_server_certificate(_stream(_certificate_message(certificate))) is None


def test_a_v1_certificate_without_the_version_field_is_read() -> None:
    features = extract_server_certificate(
        _stream(_certificate_message(_certificate(version=False)))
    )
    assert features is not None
    assert features.subject == "CN=example.test"


def test_a_multi_valued_rdn_and_an_unknown_oid_are_rendered_as_encoded() -> None:
    subject = _name(
        _rdn(_attribute(_CN_OID, _string(b"first")), _attribute(_CN_OID, _string(b"second"))),
        _rdn(_attribute(b"\x2a\x03\x04", _string(b"mystery"))),
    )
    features = extract_server_certificate(
        _stream(_certificate_message(_certificate(subject=subject)))
    )
    assert features is not None
    assert features.subject == "CN=first+CN=second, 1.2.3.4=mystery"


def test_an_arc_zero_oid_and_a_non_string_value_use_the_documented_forms() -> None:
    subject = _name(_rdn(_attribute(b"\x05", _der(0x03, b"\x00"))))
    features = extract_server_certificate(
        _stream(_certificate_message(_certificate(subject=subject)))
    )
    assert features is not None
    # Arc 0.5 from the one-byte first subidentifier; the BIT STRING has no
    # string codec, so RFC 4514's #hex form carries the whole element.
    assert features.subject == "0.5=#030100"


def test_leading_and_trailing_specials_are_escaped() -> None:
    subject = _name(
        _rdn(_attribute(_CN_OID, _string(b"#hash"))),
        _rdn(_attribute(_CN_OID, _string(b" leading"))),
        _rdn(_attribute(_CN_OID, _string(b"trailing "))),
    )
    features = extract_server_certificate(
        _stream(_certificate_message(_certificate(subject=subject)))
    )
    assert features is not None
    assert features.subject == "CN=\\#hash, CN=\\ leading, CN=trailing\\ "


def test_a_utf8_value_that_is_not_utf8_is_refused() -> None:
    _refuses(_certificate(subject=_name(_rdn(_attribute(_CN_OID, _string(b"\xff\xfe"))))))


def test_a_high_tag_number_element_inside_a_name_is_refused() -> None:
    # X.509 never uses ASN.1's high-tag-number form, and treating 0x1f as an
    # ordinary tag would let an attribute smuggle bytes past the reader.
    _refuses(_certificate(subject=_name(_rdn(_attribute(_CN_OID, _der(0x1F, b""))))))


def test_a_four_byte_length_is_refused_even_when_it_is_correct() -> None:
    # The leaf's own outer header is 30 82 03 70; the same length in the
    # four-byte form is a legal BER encoding that DER does not allow.
    content = _LEAF_DER[4:]
    four_byte = b"\x30\x84" + len(content).to_bytes(4, "big") + content
    _refuses(four_byte)


def test_an_element_that_overruns_its_parent_is_refused_even_inside_a_larger_buffer() -> None:
    # The subject claims eleven bytes of content while its RDN claims more, and
    # the remaining bytes *are* present later in the TBS (as well-formed NULL
    # elements). Only the enclosing bound -- not the buffer's length -- can tell
    # that the RDN is lying, and an absolute check would accept it.
    value = b"\x05\x00" * 20
    rdn = _der(0x31, _der(0x30, _der(0x06, _CN_OID) + _string(value)))
    subject = b"\x30" + bytes([9]) + rdn[:9]
    padding = rdn[9:]
    fields = b"".join(
        (
            _der(0xA0, _der(0x02, b"\x02")),
            _der(0x02, b"\x01"),
            _der(0x30, b"\x05\x00"),
            _GOOD_CN,
            _GOOD_VALIDITY,
            subject,
            padding,
        )
    )
    _refuses(_der(0x30, _der(0x30, fields)))


def test_a_nested_element_that_overruns_its_parent_is_refused() -> None:
    # A TBS whose first child claims more bytes than the TBS holds.
    der = _der(0x30, _der(0x30, b"\x02\x05\x00"))
    _refuses(der)


@pytest.mark.parametrize(
    "certificate",
    [
        pytest.param(_certificate(serial=_der(0x04, b"\x01")), id="serial-not-integer"),
        pytest.param(_certificate(signature=_der(0x04, b"\x01")), id="signature-not-sequence"),
        pytest.param(_certificate(validity=_der(0x04, b"\x01")), id="validity-not-sequence"),
        pytest.param(
            _certificate(
                validity=_der(0x31, _utc("240101000000") + _utc("260101000000"))
            ),
            id="validity-is-a-set",
        ),
        pytest.param(_certificate(validity=_der(0x30, _utc("240101000000"))), id="one-time"),
        pytest.param(
            _certificate(
                validity=_der(
                    0x30,
                    _utc("240101000000") + _utc("250101000000") + _utc("260101000000"),
                )
            ),
            id="three-times",
        ),
        pytest.param(_certificate(subject=_der(0x31, b"")), id="name-not-sequence"),
        pytest.param(_certificate(subject=_der(0x30, b"")), id="empty-name"),
        pytest.param(
            _certificate(subject=_name(_der(0x30, _attribute(_CN_OID, _string(b"x"))))),
            id="rdn-not-set",
        ),
        pytest.param(_certificate(subject=_name(_der(0x31, b""))), id="empty-rdn"),
        pytest.param(
            _certificate(subject=_name(_rdn(_der(0x04, b"x")))),
            id="attribute-not-sequence",
        ),
        pytest.param(
            _certificate(subject=_name(_rdn(_der(0x30, _der(0x06, _CN_OID))))),
            id="attribute-with-one-child",
        ),
        pytest.param(
            _certificate(
                subject=_name(
                    _rdn(_der(0x30, _der(0x06, _CN_OID) + _string(b"a") + _string(b"b")))
                )
            ),
            id="attribute-with-three-children",
        ),
        pytest.param(
            _certificate(subject=_name(_rdn(_der(0x30, _der(0x02, b"\x01") + _string(b"x"))))),
            id="oid-not-an-oid",
        ),
        pytest.param(
            _certificate(subject=_name(_rdn(_der(0x30, _der(0x06, b"") + _string(b"x"))))),
            id="empty-oid",
        ),
        pytest.param(
            _certificate(subject=_name(_rdn(_der(0x30, _der(0x06, b"\x80\x01") + _string(b"x"))))),
            id="oid-first-byte-continuation",
        ),
        pytest.param(
            _certificate(subject=_name(_rdn(_der(0x30, _der(0x06, b"\x2a\x80") + _string(b"x"))))),
            id="oid-dangling-continuation",
        ),
        pytest.param(
            _certificate(
                subject=_name(_rdn(_attribute(_CN_OID, _string(b"x", tag=0x1E))))
            ),
            id="odd-bmp-string",
        ),
        pytest.param(
            _certificate(validity=_validity(_time_element(0x17, b"2401010000Z"), _utc("260101000000"))),
            id="short-utctime",
        ),
        pytest.param(
            _certificate(validity=_validity(_time_element(0x17, b"240101000000"), _utc("260101000000"))),
            id="utctime-without-z",
        ),
        pytest.param(
            _certificate(validity=_validity(_utc("24010100000X"), _utc("260101000000"))),
            id="utctime-not-a-date",
        ),
        pytest.param(
            _certificate(
                validity=_validity(_time_element(0x18, b"2051010203040Z"), _utc("260101000000"))
            ),
            id="short-generalizedtime",
        ),
        pytest.param(
            _certificate(validity=_validity(_time_element(0x19, b"240101000000Z"), _utc("260101000000"))),
            id="unknown-time-tag",
        ),
        pytest.param(
            _certificate(validity=_validity(_utc("240101000000"), _generalized("2051010203040X"))),
            id="generalizedtime-not-a-date",
        ),
    ],
)
def test_a_structurally_broken_certificate_is_refused(certificate: bytes) -> None:
    _refuses(certificate)


def test_a_utctime_before_1950_uses_rfc_5280s_two_digit_window() -> None:
    # "50".."99" is 19xx: without the window this certificate would be dated
    # 2050, a hundred years away from what it says.
    validity = _validity(_utc("500101000000"), _utc("510101000000"))
    features = extract_server_certificate(
        _stream(_certificate_message(_certificate(validity=validity)))
    )
    assert features is not None
    assert features.not_valid_before == datetime(1950, 1, 1, tzinfo=UTC)
    assert features.not_valid_after == datetime(1951, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize("version", [0x0200, 0x0305])
def test_a_record_version_outside_tls_is_refused(version: int) -> None:
    message = _certificate_message(_LEAF_DER)
    stream = b"\x16" + _u16(version) + _u16(len(message)) + message
    assert extract_server_certificate(stream) is None


def test_the_module_names_the_encryption_limit_it_lives_under() -> None:
    import dpi_engine.tls_certificate as module

    assert "TLS 1.3" in (module.__doc__ or "")
