"""The server's certificate, read from the plaintext handshake (`T5-02`).

What is extracted, and why only that
-----------------------------------
`extract_server_certificate` walks a TLS server-to-client byte stream, finds the
first Certificate handshake message (type 11) and reads the **leaf**: its issuer,
its subject and its validity. Nothing else is interpreted -- there is no chain
validation, no signature check and no expiry judgement here. Those are decisions
about trust; the fingerprint layer only records what the server presented, and
T5-04 is where a date becomes evidence.

The handshake messages are accumulated across record boundaries, so a certificate
fragmented over several TLS records is reassembled. The scan stops at the first
record that is not a handshake record, because from that point the stream is
either a change of cipher state or ciphertext, and inventing a structure out of
ciphertext is how a parser reports a fact that was never on the wire.

The TLS 1.3 limit, stated rather than glossed
---------------------------------------------
A TLS 1.3 Certificate message is sent **after** the ServerHello, under the
handshake traffic keys, so it is ciphertext to a passive observer. This module
therefore only ever sees TLS 1.2 and below. ``None`` means "no certificate was
visible in plaintext" -- it does not mean "the server sent no certificate", and
it is also what a truncated capture returns. The engine keeps the ServerHello,
so the two cases are distinguishable one level up.

Hand-rolled DER, deliberately
-----------------------------
X.509 parsing would otherwise mean a new runtime dependency (`cryptography` is a
dev and QUIC extra, not a runtime one), and this project parses TLS by hand so
every bounds check is visible and testable. The ASN.1 reader here is the subset
X.509 actually uses: definite lengths only, tags below the high-tag-number form,
and every offset checked against the enclosing length. Anything a certificate
cannot legally contain is refused rather than guessed at.

Rendering rules
---------------
* RDNs are joined in **DER order** (the encoded order, which is the reverse of
  the usual display order) with ``, ``; a multi-valued RDN joins its attributes
  with ``+``.
* Values are escaped as RFC 4514 section 2.4 requires, so a comma inside a name
  cannot be read as an RDN separator. An attribute whose value is not a
  directory string is rendered in RFC 4514's ``#`` hex form rather than guessed.
* Common attribute OIDs become short names (`C`, `ST`, `L`, `O`, `OU`, `CN`,
  `emailAddress`, ...); an unmapped OID is rendered dotted.
* The validity is returned as timezone-aware UTC datetimes, exactly as encoded.
  Both UTCTime and GeneralizedTime are read; RFC 5280's two-digit-year window
  (``50``..``99`` is 19xx) is applied.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import NamedTuple

_CONTENT_TYPE_HANDSHAKE = 0x16
_HANDSHAKE_CERTIFICATE = 0x0B
_RECORD_HEADER_LEN = 5
_HANDSHAKE_HEADER_LEN = 4

_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31
_TAG_INTEGER = 0x02
_TAG_OID = 0x06
_TAG_UTC_TIME = 0x17
_TAG_GENERALIZED_TIME = 0x18
_TAG_VERSION = 0xA0

_MAX_LENGTH_BYTES = 3
_MAX_RECORD_VERSION = 0x0304

#: Attribute OIDs that get a short name, from RFC 4519 and the commonly used
#: PKIX set. Everything else is rendered dotted, so the table is a display
#: choice and never a filter: an unknown attribute still reaches the output.
_OID_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "street",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.17": "postalCode",
    "0.9.2342.19200300.100.1.1": "UID",
    "0.9.2342.19200300.100.1.25": "DC",
    "1.2.840.113549.1.9.1": "emailAddress",
}

#: The ASN.1 string types a directory name may use, and the codec each needs.
_STRING_CODECS = {
    0x0C: "utf-8",  # UTF8String
    0x12: "ascii",  # NumericString
    0x13: "ascii",  # PrintableString
    0x14: "latin-1",  # TeletexString
    0x16: "ascii",  # IA5String
    0x1A: "ascii",  # VisibleString
    0x1C: "utf-32-be",  # UniversalString
    0x1E: "utf-16-be",  # BMPString
}

#: RFC 4514 section 2.4's mandatory escapes.
_ESCAPED_CHARACTERS = frozenset('"+;<>\\,')


@dataclass(frozen=True)
class CertificateFeatures:
    """The leaf certificate's identity and validity, as encoded.

    `issuer` and `subject` are rendered names, not raw DER; `not_valid_before`
    and `not_valid_after` are UTC datetimes. No ordering is asserted between the
    two: a certificate whose window is inverted is a fact worth keeping, not a
    parse failure.
    """

    issuer: str
    subject: str
    not_valid_before: datetime
    not_valid_after: datetime


class _Tlv(NamedTuple):
    """One ASN.1 element: its tag, its value's span, and where it begins."""

    tag: int
    start: int
    end: int
    raw: int


def _read_u16(data: bytes | bytearray, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def _read_u24(data: bytes | bytearray, offset: int) -> int:
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


def _read_tlv(data: bytes, offset: int, end: int) -> _Tlv | None:
    """One definite-length element that must end inside `end`, or `None`."""
    if offset + 2 > end:
        return None
    tag = data[offset]
    if tag & 0x1F == 0x1F:  # high-tag-number form: not used by X.509
        return None
    first = data[offset + 1]
    position = offset + 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        # 0x80 is BER's indefinite length, which DER forbids; more than three
        # length bytes cannot fit inside anything this parser is given.
        if count == 0 or count > _MAX_LENGTH_BYTES or position + count > end:
            return None
        length = 0
        for byte in data[position : position + count]:
            length = (length << 8) | byte
        position += count
    if length > end - position:
        return None
    return _Tlv(tag, position, position + length, offset)


def _children(data: bytes, parent: _Tlv) -> list[_Tlv] | None:
    """Every element inside `parent`, which must consume it exactly."""
    children: list[_Tlv] = []
    offset = parent.start
    while offset < parent.end:
        child = _read_tlv(data, offset, parent.end)
        if child is None:
            return None
        children.append(child)
        offset = child.end
    return children


def _oid_text(data: bytes, element: _Tlv) -> str | None:
    """An OBJECT IDENTIFIER in dotted form, or `None` if it is malformed."""
    if element.tag != _TAG_OID or element.start == element.end:
        return None
    first = data[element.start]
    if first & 0x80:
        # The first subidentifier packs two arcs and is one byte for every OID
        # that can exist (arc 2 plus a 39-or-less third arc is at most 119).
        return None
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    value = 0
    started = False
    for byte in data[element.start + 1 : element.end]:
        value = (value << 7) | (byte & 0x7F)
        started = True
        if not byte & 0x80:
            arcs.append(value)
            value = 0
            started = False
    if started:  # a continuation bit with no continuation
        return None
    return ".".join(str(arc) for arc in arcs)


def _escape(value: str) -> str:
    """RFC 4514 section 2.4 escaping, so a rendered name stays unambiguous."""
    output: list[str] = []
    last = len(value) - 1
    for index, character in enumerate(value):
        if (
            character in _ESCAPED_CHARACTERS
            or (index == 0 and character in " #")
            or (index == last and character == " ")
        ):
            output.append("\\")
        output.append(character)
    return "".join(output)


def _render_value(data: bytes, element: _Tlv) -> str | None:
    """A directory string escaped for display, or RFC 4514's ``#`` hex form.

    The ``#`` of the hex form is syntax, not a character of the value, so it is
    not escaped -- escaping it would make the two forms indistinguishable.
    """
    codec = _STRING_CODECS.get(element.tag)
    if codec is None:
        return "#" + data[element.raw : element.end].hex()
    try:
        text = data[element.start : element.end].decode(codec)
    except UnicodeDecodeError:
        return None
    return _escape(text)


def _name(data: bytes, element: _Tlv) -> str | None:
    """A Name (SEQUENCE OF RDN SETS) rendered in DER order, or `None`."""
    if element.tag != _TAG_SEQUENCE:
        return None
    rdns = _children(data, element)
    if not rdns:
        return None
    rendered: list[str] = []
    for rdn in rdns:
        if rdn.tag != _TAG_SET:
            return None
        attributes = _children(data, rdn)
        if not attributes:
            return None
        parts: list[str] = []
        for attribute in attributes:
            if attribute.tag != _TAG_SEQUENCE:
                return None
            pair = _children(data, attribute)
            if pair is None or len(pair) != 2:
                return None
            oid = _oid_text(data, pair[0])
            if oid is None:
                return None
            value = _render_value(data, pair[1])
            if value is None:
                return None
            parts.append(f"{_OID_NAMES.get(oid, oid)}={value}")
        rendered.append("+".join(parts))
    return ", ".join(rendered)


def _time(data: bytes, element: _Tlv) -> datetime | None:
    """A UTCTime or GeneralizedTime as an aware UTC datetime, or `None`."""
    raw = data[element.start : element.end]
    if element.tag == _TAG_UTC_TIME:
        if len(raw) != 13 or not raw.endswith(b"Z"):
            return None
        text = raw[:12]
    elif element.tag == _TAG_GENERALIZED_TIME:
        if len(raw) != 15 or not raw.endswith(b"Z"):
            return None
        text = raw[:14]
    else:
        return None
    try:
        digits = text.decode("ascii")
        if element.tag == _TAG_UTC_TIME:
            short_year = int(digits[:2])
            # RFC 5280 section 4.1.2.5.1: 50..99 is 1950..1999, 00..49 is 2000..2049.
            year = 1900 + short_year if short_year >= 50 else 2000 + short_year
            digits = f"{year:04d}" + digits[2:]
        return datetime(
            int(digits[0:4]),
            int(digits[4:6]),
            int(digits[6:8]),
            int(digits[8:10]),
            int(digits[10:12]),
            int(digits[12:14]),
            tzinfo=UTC,
        )
    except (UnicodeDecodeError, ValueError):
        return None


def _parse_certificate(der: bytes) -> CertificateFeatures | None:
    """The leaf fields of one DER Certificate, or `None`."""
    outer = _read_tlv(der, 0, len(der))
    if outer is None or outer.tag != _TAG_SEQUENCE or outer.end != len(der):
        return None
    tbs = _read_tlv(der, outer.start, outer.end)
    if tbs is None or tbs.tag != _TAG_SEQUENCE:
        return None
    fields = _children(der, tbs)
    if fields is None:
        return None

    # [0] EXPLICIT version is optional; when absent the certificate is v1.
    index = 1 if fields and fields[0].tag == _TAG_VERSION else 0
    if len(fields) < index + 5:
        return None
    serial, signature, issuer, validity, subject = fields[index : index + 5]
    if serial.tag != _TAG_INTEGER or signature.tag != _TAG_SEQUENCE:
        return None
    if validity.tag != _TAG_SEQUENCE:
        return None

    issuer_text = _name(der, issuer)
    subject_text = _name(der, subject)
    times = _children(der, validity)
    if issuer_text is None or subject_text is None or times is None or len(times) != 2:
        return None
    not_before = _time(der, times[0])
    not_after = _time(der, times[1])
    if not_before is None or not_after is None:
        return None

    return CertificateFeatures(
        issuer=issuer_text,
        subject=subject_text,
        not_valid_before=not_before,
        not_valid_after=not_after,
    )


def _parse_certificate_body(body: bytes) -> CertificateFeatures | None:
    """The body of a TLS 1.2 Certificate message: a list of DER certificates."""
    if len(body) < 3:
        return None
    total = _read_u24(body, 0)
    if total == 0 or total + 3 != len(body):
        return None
    if len(body) < 6:
        return None
    size = _read_u24(body, 3)
    if size == 0 or size > total - 3:
        return None
    return _parse_certificate(body[6 : 6 + size])


def extract_server_certificate(
    stream: bytes, length: int | None = None
) -> CertificateFeatures | None:
    """The leaf certificate of a server-to-client TLS stream, or `None`.

    The stream may hold the whole connection or any prefix of it; handshake
    messages are accumulated across records, and the first Certificate message
    wins. `length` defaults to ``len(stream)`` and is clamped to it, so a caller
    that claims more than it holds cannot drive a read past the end.
    """
    end = len(stream) if length is None else min(length, len(stream))
    position = 0
    pending = bytearray()

    while position < end:
        if position + _RECORD_HEADER_LEN > end:
            return None
        if stream[position] != _CONTENT_TYPE_HANDSHAKE:
            return None
        version = _read_u16(stream, position + 1)
        if not 0x0300 <= version <= _MAX_RECORD_VERSION:
            return None
        record_length = _read_u16(stream, position + 3)
        body_start = position + _RECORD_HEADER_LEN
        if record_length > end - body_start:
            return None
        pending += stream[body_start : body_start + record_length]
        position = body_start + record_length

        while len(pending) >= _HANDSHAKE_HEADER_LEN:
            message_length = _read_u24(pending, 1)
            if len(pending) < _HANDSHAKE_HEADER_LEN + message_length:
                break  # the rest of this message is in a later record
            message_end = _HANDSHAKE_HEADER_LEN + message_length
            if pending[0] == _HANDSHAKE_CERTIFICATE:
                return _parse_certificate_body(bytes(pending[_HANDSHAKE_HEADER_LEN:message_end]))
            del pending[:message_end]

    return None
