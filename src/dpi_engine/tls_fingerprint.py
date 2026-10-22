"""TLS fingerprints: JA3/JA3S, JA4/JA4S, and the ClientHello features they need.

What is computed, and from where
--------------------------------
* **JA3 / JA3S** -- Salesforce's definition (`salesforce/ja3`, "How it works"):
  the MD5 of ``SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat``
  for a client (five decimal lists) and of ``SSLVersion,Cipher,SSLExtension`` for
  a server.
* **JA4** -- FoxIO's published specification (`technical_details/JA4.md`): the
  human-readable ``a`` part, then the truncated SHA-256 of the sorted cipher list
  (``b``) and of the sorted extension list plus the signature algorithms (``c``).
* **JA4S** -- FoxIO's server method. No prose specification is published for it
  (the technical detail is a diagram), so the construction implemented here is
  the one in FoxIO's reference implementation, and it is checked in the tests
  against a published output: ``t130200_1301_a56c5b993250``.

The feature fields are the lists themselves, not only the hashes: a signature
needs the ordering, and T5-04 matches on features rather than on a 12-character
prefix. Every list is **GREASE-free** (RFC 8701 values are noise that changes on
every connection by design), and the values that were removed are reported in
`ClientHelloFeatures.grease_values`, so "no GREASE" is distinguishable from
"GREASE was present and ignored".

Stricter than `sni_extractor`, deliberately
--------------------------------------------
`extract_sni` tolerates capture truncation: a partial extension block still
yields whatever hostname was legible. A fingerprint cannot do that. A hash over
half a cipher list is a *wrong fact* that looks exactly like a real one, and
T5-04 will treat an exact fingerprint match as evidence. So every length prefix
here must resolve inside the declared message, the extensions block must be
consumed exactly, and anything else returns ``None``. The same rule refuses a
ClientHello split across two TLS records: reassembly is not implemented, and
guessing is worse than abstaining.

Scope
-----
TLS over TCP only (the ``t`` prefix). QUIC terminates TLS in CRYPTO frames and is
handled by `dpi_engine.quic`; DTLS is not parsed. HTTP/2 and certificate
fingerprints (JA4H/JA4X) belong to T5-02 and are absent here.

One source disagreement, resolved and recorded
----------------------------------------------
**The ALPN field for a non-ASCII byte.** JA4.md's documented rule -- the hex
representation of the protocol name when either end is not alphanumeric -- is
what all eight of its worked examples follow, and it is what is implemented here.
FoxIO's Python reference instead substitutes ``9`` for bytes >= 0x80 and keeps
ASCII punctuation as-is. The two agree for every real ALPN value (IANA tokens are
alphanumeric at both ends); the divergence is recorded rather than hidden.

Licensing
---------
JA3 and JA4 are BSD-3-Clause. **JA4S is patent-pending and licensed under the
FoxIO License 1.1**, which is permissive for internal business use but not for
monetisation; shipping JA4S in a sold product needs an OEM licence. This module
is internal tooling today, and the constraint is recorded in the task tracker
rather than assumed away.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field

_CONTENT_TYPE_HANDSHAKE = 0x16
_HANDSHAKE_CLIENT_HELLO = 0x01
_HANDSHAKE_SERVER_HELLO = 0x02

_TLS_RECORD_HEADER_LEN = 5
_HANDSHAKE_HEADER_LEN = 4
_RANDOM_LEN = 32

_EXTENSION_SNI = 0x0000
_EXTENSION_SUPPORTED_GROUPS = 0x000A
_EXTENSION_EC_POINT_FORMATS = 0x000B
_EXTENSION_SIGNATURE_ALGORITHMS = 0x000D
_EXTENSION_ALPN = 0x0010
_EXTENSION_SUPPORTED_VERSIONS = 0x002B

#: RFC 8701's sixteen GREASE values. Removed from every list before a hash or a
#: count, and recorded so their presence is itself a feature.
_GREASE_VALUES = frozenset(
    {
        0x0A0A,
        0x1A1A,
        0x2A2A,
        0x3A3A,
        0x4A4A,
        0x5A5A,
        0x6A6A,
        0x7A7A,
        0x8A8A,
        0x9A9A,
        0xAAAA,
        0xBABA,
        0xCACA,
        0xDADA,
        0xEAEA,
        0xFAFA,
    }
)

#: JA4's two-character version codes, including the DTLS entries so the table is
#: the published one rather than a subset that happens to be reachable today.
_TLS_VERSION_CODES: dict[int, str] = {
    0x0002: "s2",
    0x0300: "s3",
    0x0301: "10",
    0x0302: "11",
    0x0303: "12",
    0x0304: "13",
    0xFEFF: "d1",
    0xFEFD: "d2",
    0xFEFC: "d3",
}

#: The published "no values" hash for JA4's b and c parts.
_NO_VALUES_HASH = "000000000000"
_MAX_COUNT_CODE = 99


@dataclass(frozen=True)
class ClientHelloFeatures:
    """Everything a signature can match on, and the two fingerprints.

    The lists are in **arrival order** and GREASE-free; `ja4` sorts its own
    copies. `supported_versions` is empty when the client did not send the
    extension, while `version_histogram` always describes what was offered --
    falling back to the legacy version, which is the only offer in that case.
    """

    client_version: int
    cipher_suites: tuple[int, ...]
    extensions: tuple[int, ...]
    elliptic_curves: tuple[int, ...]
    ec_point_formats: tuple[int, ...]
    supported_versions: tuple[int, ...]
    version_histogram: tuple[tuple[int, int], ...]
    alpn_protocols: tuple[bytes, ...]
    signature_algorithms: tuple[int, ...]
    grease_values: tuple[int, ...]
    ja3_string: str
    ja3: str
    ja4_a: str
    ja4_b: str
    ja4_c: str

    @property
    def ja4(self) -> str:
        """The published ``a_b_c`` rendering."""
        return f"{self.ja4_a}_{self.ja4_b}_{self.ja4_c}"


@dataclass(frozen=True)
class ServerHelloFeatures:
    """The server's half of the negotiation.

    `extensions` is in arrival order and **not** sorted: JA4S hashes the order the
    server chose, which is the signal that distinguishes server configurations.
    GREASE is not removed here either -- neither definition asks for it, and a
    conforming server does not send it.
    """

    server_version: int
    cipher_suite: int
    extensions: tuple[int, ...]
    supported_versions: tuple[int, ...]
    alpn_protocols: tuple[bytes, ...]
    ja3s_string: str
    ja3s: str
    ja4s_a: str
    ja4s_b: str
    ja4s_c: str

    @property
    def ja4s(self) -> str:
        """The published ``a_b_c`` rendering."""
        return f"{self.ja4s_a}_{self.ja4s_b}_{self.ja4s_c}"


@dataclass
class _ExtensionScan:
    """What one pass over an extension block found, in arrival order."""

    types: list[int] = field(default_factory=list[int])
    grease: list[int] = field(default_factory=list[int])
    alpn: tuple[bytes, ...] = ()
    signature_algorithms: tuple[int, ...] = ()
    groups: tuple[int, ...] = ()
    point_formats: tuple[int, ...] = ()
    supported_versions: tuple[int, ...] = ()
    has_sni: bool = False
    has_signature_algorithms: bool = False


def _read_u16be(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def _read_u24be(data: bytes, offset: int) -> int:
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


def _md5(text: str) -> str:
    # `usedforsecurity=False` because this is a fingerprint, not a MAC: on a
    # FIPS-restricted interpreter MD5 is otherwise refused and JA3 disappears.
    return hashlib.md5(text.encode("ascii"), usedforsecurity=False).hexdigest()


def _sha12(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:12]


def _record_body(
    payload: bytes, length: int | None, handshake_type: int
) -> tuple[int, int] | None:
    """`[start, end)` of one complete handshake message, or `None`.

    The message must sit wholly inside a single TLS record: a ClientHello split
    across two records is refused rather than reassembled. `length` is clamped to
    the bytes present, so a caller that claims more than it holds cannot drive a
    read past the end.
    """
    if length is None:
        length = len(payload)
    length = min(length, len(payload))

    minimum = _TLS_RECORD_HEADER_LEN + _HANDSHAKE_HEADER_LEN
    if length < minimum or payload[0] != _CONTENT_TYPE_HANDSHAKE:
        return None

    record_version = _read_u16be(payload, 1)
    if not 0x0300 <= record_version <= 0x0304:
        return None

    record_length = _read_u16be(payload, 3)
    if record_length > length - _TLS_RECORD_HEADER_LEN:
        return None

    if payload[_TLS_RECORD_HEADER_LEN] != handshake_type:
        return None

    handshake_length = _read_u24be(payload, _TLS_RECORD_HEADER_LEN + 1)
    start = _TLS_RECORD_HEADER_LEN + _HANDSHAKE_HEADER_LEN
    if start + handshake_length > _TLS_RECORD_HEADER_LEN + record_length:
        return None
    return start, start + handshake_length


def _parse_u16_vector(data: bytes, offset: int, length: int) -> tuple[int, ...] | None:
    """A 2-byte-length-prefixed vector of 16-bit values, consumed exactly."""
    if length < 2:
        return None
    inner = _read_u16be(data, offset)
    if inner + 2 != length or inner % 2:
        return None
    return tuple(_read_u16be(data, at) for at in range(offset + 2, offset + 2 + inner, 2))


def _parse_byte_vector(data: bytes, offset: int, length: int) -> bytes | None:
    """A 1-byte-length-prefixed vector of bytes, consumed exactly."""
    if length < 1:
        return None
    inner = data[offset]
    if inner + 1 != length:
        return None
    return data[offset + 1 : offset + 1 + inner]


def _parse_alpn(data: bytes, offset: int, length: int) -> tuple[bytes, ...] | None:
    """The protocol names in an ALPN extension, in the order the client offered."""
    if length < 2:
        return None
    inner = _read_u16be(data, offset)
    if inner + 2 != length:
        return None

    protocols: list[bytes] = []
    position = offset + 2
    limit = position + inner
    while position < limit:
        name_length = data[position]
        position += 1
        if position + name_length > limit:
            return None
        protocols.append(data[position : position + name_length])
        position += name_length
    return tuple(protocols)


def _scan_extensions(data: bytes, offset: int, end: int) -> _ExtensionScan | None:
    """Read an extension block, or `None` if it is not exactly `end - offset` long.

    Unknown extensions are recorded by type and their bodies skipped: a
    fingerprint is built from what the client sent, not from what it meant.
    A known extension with a malformed body is fatal, because its values would
    otherwise be silently reported as absent.
    """
    scan = _ExtensionScan()
    while offset < end:
        if offset + 4 > end:
            return None
        extension_type = _read_u16be(data, offset)
        extension_length = _read_u16be(data, offset + 2)
        offset += 4
        if offset + extension_length > end:
            return None

        scan.types.append(extension_type)
        if extension_type in _GREASE_VALUES:
            scan.grease.append(extension_type)
        elif extension_type == _EXTENSION_SNI:
            scan.has_sni = True
        elif extension_type == _EXTENSION_ALPN:
            protocols = _parse_alpn(data, offset, extension_length)
            if protocols is None:
                return None
            scan.alpn = protocols
        elif extension_type == _EXTENSION_SIGNATURE_ALGORITHMS:
            algorithms = _parse_u16_vector(data, offset, extension_length)
            if algorithms is None:
                return None
            scan.signature_algorithms = algorithms
            scan.has_signature_algorithms = True
            scan.grease.extend(a for a in algorithms if a in _GREASE_VALUES)
        elif extension_type == _EXTENSION_SUPPORTED_GROUPS:
            groups = _parse_u16_vector(data, offset, extension_length)
            if groups is None:
                return None
            scan.groups = groups
            scan.grease.extend(g for g in groups if g in _GREASE_VALUES)
        elif extension_type == _EXTENSION_SUPPORTED_VERSIONS:
            raw = _parse_byte_vector(data, offset, extension_length)
            if raw is None or len(raw) % 2:
                return None
            scan.supported_versions = tuple(_read_u16be(raw, at) for at in range(0, len(raw), 2))
            scan.grease.extend(
                v for v in scan.supported_versions if v in _GREASE_VALUES
            )
        elif extension_type == _EXTENSION_EC_POINT_FORMATS:
            raw = _parse_byte_vector(data, offset, extension_length)
            if raw is None:
                return None
            scan.point_formats = tuple(raw)

        offset += extension_length
    return scan


def _alpn_code(protocols: tuple[bytes, ...]) -> str:
    """JA4's two-character ALPN field.

    The first and last ASCII alphanumeric characters of the *first* protocol; if
    either end is not alphanumeric, the first and last character of that
    protocol's hex representation instead. `00` when there is no usable value.
    """
    if not protocols or not protocols[0]:
        return "00"
    value = protocols[0]
    if _is_alnum(value[0]) and _is_alnum(value[-1]):
        return chr(value[0]) + chr(value[-1])
    encoded = value.hex()
    return encoded[0] + encoded[-1]


def _is_alnum(byte: int) -> bool:
    return 0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A


def fingerprint_client_hello(payload: bytes, length: int | None = None) -> ClientHelloFeatures | None:
    """JA3 and JA4 for a TLS ClientHello, with the features they are built from.

    Returns `None` -- never a partial fingerprint -- for anything that is not a
    complete, structurally consistent ClientHello. `length` defaults to
    ``len(payload)`` and is clamped to it, mirroring `sni_extractor.extract_sni`.
    """
    body = _record_body(payload, length, _HANDSHAKE_CLIENT_HELLO)
    if body is None:
        return None
    start, end = body

    offset = start
    if offset + 2 + _RANDOM_LEN + 1 > end:
        return None
    client_version = _read_u16be(payload, offset)
    offset += 2 + _RANDOM_LEN

    session_length = payload[offset]
    offset += 1
    if offset + session_length > end:
        return None
    offset += session_length

    if offset + 2 > end:
        return None
    cipher_bytes = _read_u16be(payload, offset)
    offset += 2
    if cipher_bytes % 2 or offset + cipher_bytes > end:
        return None
    ciphers = tuple(_read_u16be(payload, at) for at in range(offset, offset + cipher_bytes, 2))
    offset += cipher_bytes

    if offset >= end:
        return None
    compression_length = payload[offset]
    offset += 1
    if offset + compression_length > end:
        return None
    offset += compression_length

    if offset == end:
        scan = _ExtensionScan()
    else:
        if offset + 2 > end:
            return None
        extension_bytes = _read_u16be(payload, offset)
        offset += 2
        if offset + extension_bytes != end:
            return None
        scanned = _scan_extensions(payload, offset, end)
        if scanned is None:
            return None
        scan = scanned

    cipher_suites = tuple(c for c in ciphers if c not in _GREASE_VALUES)
    extensions = tuple(e for e in scan.types if e not in _GREASE_VALUES)
    elliptic_curves = tuple(g for g in scan.groups if g not in _GREASE_VALUES)
    signature_algorithms = tuple(s for s in scan.signature_algorithms if s not in _GREASE_VALUES)
    supported_versions = tuple(v for v in scan.supported_versions if v not in _GREASE_VALUES)
    grease_values = tuple(c for c in ciphers if c in _GREASE_VALUES) + tuple(scan.grease)

    offered = supported_versions or (client_version,)
    histogram = tuple(sorted(Counter(offered).items()))

    ja3_string = ",".join(
        (
            str(client_version),
            "-".join(str(c) for c in cipher_suites),
            "-".join(str(e) for e in extensions),
            "-".join(str(g) for g in elliptic_curves),
            "-".join(str(f) for f in scan.point_formats),
        )
    )

    version = max(supported_versions) if supported_versions else client_version
    version_code = _TLS_VERSION_CODES.get(version, "00")
    ja4_a = (
        f"t{version_code}{'d' if scan.has_sni else 'i'}"
        f"{min(len(cipher_suites), _MAX_COUNT_CODE):02d}"
        f"{min(len(extensions), _MAX_COUNT_CODE):02d}"
        f"{_alpn_code(scan.alpn)}"
    )

    sorted_ciphers = ",".join(f"{c:04x}" for c in sorted(cipher_suites))
    ja4_b = _sha12(sorted_ciphers) if sorted_ciphers else _NO_VALUES_HASH

    # SNI and ALPN are already in the `a` part; leaving them here would make the
    # same client hash differently depending on where it connected.
    material = ",".join(
        f"{e:04x}"
        for e in sorted(extensions)
        if e not in (_EXTENSION_SNI, _EXTENSION_ALPN)
    )
    if scan.has_signature_algorithms:
        material = f"{material}_{','.join(f'{s:04x}' for s in signature_algorithms)}"
    ja4_c = _sha12(material) if material else _NO_VALUES_HASH

    return ClientHelloFeatures(
        client_version=client_version,
        cipher_suites=cipher_suites,
        extensions=extensions,
        elliptic_curves=elliptic_curves,
        ec_point_formats=scan.point_formats,
        supported_versions=supported_versions,
        version_histogram=histogram,
        alpn_protocols=scan.alpn,
        signature_algorithms=signature_algorithms,
        grease_values=grease_values,
        ja3_string=ja3_string,
        ja3=_md5(ja3_string),
        ja4_a=ja4_a,
        ja4_b=ja4_b,
        ja4_c=ja4_c,
    )


def fingerprint_server_hello(payload: bytes, length: int | None = None) -> ServerHelloFeatures | None:
    """JA3S and JA4S for a TLS ServerHello.

    Returns `None` for anything that is not a complete, structurally consistent
    ServerHello, under the same rule as `fingerprint_client_hello`.
    """
    body = _record_body(payload, length, _HANDSHAKE_SERVER_HELLO)
    if body is None:
        return None
    start, end = body

    offset = start
    if offset + 2 + _RANDOM_LEN + 1 > end:
        return None
    server_version = _read_u16be(payload, offset)
    offset += 2 + _RANDOM_LEN

    session_length = payload[offset]
    offset += 1
    if offset + session_length > end:
        return None
    offset += session_length

    # The chosen cipher and the compression method. The compression byte is
    # required by the message and used by no fingerprint.
    if offset + 3 > end:
        return None
    cipher_suite = _read_u16be(payload, offset)
    offset += 2 + 1

    if offset == end:
        scan = _ExtensionScan()
    else:
        if offset + 2 > end:
            return None
        extension_bytes = _read_u16be(payload, offset)
        offset += 2
        if offset + extension_bytes != end:
            return None
        scanned = _scan_extensions(payload, offset, end)
        if scanned is None:
            return None
        scan = scanned

    supported_versions = tuple(v for v in scan.supported_versions if v not in _GREASE_VALUES)
    ja3s_string = f"{server_version},{cipher_suite},{'-'.join(str(e) for e in scan.types)}"

    version = max(supported_versions) if supported_versions else server_version
    version_code = _TLS_VERSION_CODES.get(version, "00")
    ja4s_a = (
        f"t{version_code}"
        f"{min(len(scan.types), _MAX_COUNT_CODE):02d}"
        f"{_alpn_code(scan.alpn)}"
    )

    # Arrival order, not sorted: the server's ordering is the fingerprint.
    extensions_material = ",".join(f"{e:04x}" for e in scan.types)
    ja4s_c = _sha12(extensions_material) if extensions_material else _NO_VALUES_HASH

    return ServerHelloFeatures(
        server_version=server_version,
        cipher_suite=cipher_suite,
        extensions=tuple(scan.types),
        supported_versions=supported_versions,
        alpn_protocols=scan.alpn,
        ja3s_string=ja3s_string,
        ja3s=_md5(ja3s_string),
        ja4s_a=ja4s_a,
        ja4s_b=f"{cipher_suite:04x}",
        ja4s_c=ja4s_c,
    )
