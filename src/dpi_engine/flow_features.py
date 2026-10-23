"""The per-flow feature vector (`T5-03`): one frozen row of what a flow showed.

**Why this module exists.** `T5-01` computes JA3/JA3S and JA4/JA4S from a
ClientHello and a ServerHello, and `T5-02` extracts the certificate, the
SNI-absence fact and the HTTP/2 SETTINGS fingerprint. Both were contracts with
no consumer: nothing carried their results out of the packet that produced them,
so nothing could be stored, queried, or matched. This module is the carrier --
a frozen value that a flow accumulates, a row stores, and `T5-04`'s signature
matcher reads.

What the vector holds, and what it deliberately does not
--------------------------------------------------------
The ten client fields come from **one** ClientHello; the five server fields come
from **one** ServerHello; `certificate` and `http2_settings` are independent
facts that may arrive separately. Nothing here is derived twice: a cipher-suite
*count* and an extension *count* are not stored, because they are `len()` of the
lists below and JA4's ``a`` part already encodes them. One home per fact is what
keeps a signature from matching a number that disagrees with the list it came
from.

Two encodings are choices rather than accidents:

* **ALPN tokens are latin-1 strings.** They are bytes on the wire (RFC 7301 does
  not require ASCII), and latin-1 maps every byte to exactly one code point and
  back, so the round trip through JSON loses nothing and no token becomes ``"?"``.
* **`http2_settings` is `str | None`.** `None` is "no SETTINGS frame was
  observed"; `""` is the fingerprint of a SETTINGS frame that carried no
  entries. A plain string would merge those two and let a flow read as
  fingerprinted when it was not -- the same trap `sni_present` exists to avoid.

Direction, which a payload does not carry
-----------------------------------------
A flow is folded (`DEC-05`), so the client's hello and the server's flight land
on one row and the vector is assembled from both. But a TCP payload on its own
does not say which side sent it, so `observe_flow_features` uses the handshake
itself as the direction signal, and a certificate is attributed **only when the
same buffer also carries the ServerHello that opened the flight**. A
`Certificate` record arriving alone could equally be the client's (mutual TLS);
calling it the server's would be a wrong fact that looks exactly like a right
one, so it is treated as an absence instead.

Merging is **first observation wins, per half**. A retransmitted hello is
identical, and a renegotiation's hello must not rewrite the row that describes
how the connection opened. The rule is per *half* and not per field on purpose:
a cipher list from one hello beside an ALPN offer from another would describe a
client that never existed. `ja3` being non-empty is the client half's presence
flag, and `ja3s` the server half's, because every parsed hello has a hash.

Reachability, stated where the wiring makes it matter
-----------------------------------------------------
* An observation is taken from a **packet's** TCP payload, so a hello split
  across segments or records yields nothing (no reassembly yet -- the same rule
  `T5-01` documents), and a certificate is lost when the server's first flight
  spans more than one packet.
* A TLS 1.3 `Certificate` is ciphertext, so `certificate is None` means "not
  visible", never "absent". The server half's JA4S is still plaintext and is
  still recorded.
* A TLS 1.2 `Certificate` is plaintext, which is where the certificate fields
  are reachable at all.
* The HTTP/2 preface is inside the encrypted stream for h2, so
  `http2_settings` is populated for cleartext h2c (or a decrypted stream) only.

The codec lives here rather than in the run store because it is the shape's
own; the store calls `to_json`/`from_json` the way it calls the five-tuple's.
Both directions are strict: a missing key is an error, not a default, so a v1
row cannot be read as a vector that observed nothing.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from dpi_engine.http2 import fingerprint_http2_settings
from dpi_engine.tls_certificate import CertificateFeatures, extract_server_certificate
from dpi_engine.tls_fingerprint import (
    ClientHelloFeatures,
    ServerHelloFeatures,
    fingerprint_client_hello,
    fingerprint_server_hello,
)

__all__ = ["FlowFeatures", "observe_flow_features"]

_CONTENT_TYPE_HANDSHAKE = 0x16
_TLS_RECORD_HEADER_LEN = 5
_HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


@dataclass(frozen=True, slots=True)
class FlowFeatures:
    """What one flow showed, as a value a row can hold.

    The client fields are the ClientHello's; the server fields are the
    ServerHello's; the last three are independent observations. An empty
    instance means "nothing fingerprintable was observed" and is the default
    for every row, so a capture without TLS or cleartext HTTP/2 says nothing
    rather than something false.
    """

    # -- the client half: one ClientHello ---------------------------------
    ja3: str = ""
    ja4: str = ""
    sni_present: bool | None = None
    client_version: int | None = None
    tls_versions: tuple[tuple[int, int], ...] = ()
    cipher_suites: tuple[int, ...] = ()
    extensions: tuple[int, ...] = ()
    alpn: tuple[str, ...] = ()
    grease: tuple[int, ...] = ()

    # -- the server half: one ServerHello ----------------------------------
    ja3s: str = ""
    ja4s: str = ""
    server_cipher_suite: int | None = None
    server_extensions: tuple[int, ...] = ()
    selected_alpn: str = ""

    # -- independent observations ------------------------------------------
    certificate: CertificateFeatures | None = None
    http2_settings: str | None = None

    @property
    def is_empty(self) -> bool:
        """True when nothing was observed, which is the hot path's common case."""
        return self == _EMPTY

    def merged(self, other: FlowFeatures) -> FlowFeatures:
        """This vector with whatever `other` adds, first observation winning.

        Per half, not per field: see the module docstring for why mixing halves
        would be worse than dropping the second observation.
        """
        client = self if self.ja3 else other
        server = self if self.ja3s else other
        return FlowFeatures(
            ja3=client.ja3,
            ja4=client.ja4,
            sni_present=client.sni_present,
            client_version=client.client_version,
            tls_versions=client.tls_versions,
            cipher_suites=client.cipher_suites,
            extensions=client.extensions,
            alpn=client.alpn,
            grease=client.grease,
            ja3s=server.ja3s,
            ja4s=server.ja4s,
            server_cipher_suite=server.server_cipher_suite,
            server_extensions=server.server_extensions,
            selected_alpn=server.selected_alpn,
            certificate=(
                self.certificate if self.certificate is not None else other.certificate
            ),
            http2_settings=(
                self.http2_settings
                if self.http2_settings is not None
                else other.http2_settings
            ),
        )

    def to_json(self) -> dict[str, Any]:
        """The row's JSON object. Plain types only, so `json.dumps` accepts it."""
        return {
            "ja3": self.ja3,
            "ja4": self.ja4,
            "sni_present": self.sni_present,
            "client_version": self.client_version,
            "tls_versions": [list(pair) for pair in self.tls_versions],
            "cipher_suites": list(self.cipher_suites),
            "extensions": list(self.extensions),
            "alpn": list(self.alpn),
            "grease": list(self.grease),
            "ja3s": self.ja3s,
            "ja4s": self.ja4s,
            "server_cipher_suite": self.server_cipher_suite,
            "server_extensions": list(self.server_extensions),
            "selected_alpn": self.selected_alpn,
            "certificate": (
                None if self.certificate is None else _certificate_to_json(self.certificate)
            ),
            "http2_settings": self.http2_settings,
        }

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> FlowFeatures:
        """Decode `to_json`'s output. Every key is required; a wrong type raises."""
        if not isinstance(raw, Mapping):
            raise ValueError(f"features must be an object, got {type(raw).__name__}")
        certificate_raw = _mapping(raw, "certificate", optional=True)
        return cls(
            ja3=_text(raw, "ja3"),
            ja4=_text(raw, "ja4"),
            sni_present=_optional_bool(raw, "sni_present"),
            client_version=_optional_int(raw, "client_version"),
            tls_versions=_int_pairs(raw, "tls_versions"),
            cipher_suites=_ints(raw, "cipher_suites"),
            extensions=_ints(raw, "extensions"),
            alpn=_texts(raw, "alpn"),
            grease=_ints(raw, "grease"),
            ja3s=_text(raw, "ja3s"),
            ja4s=_text(raw, "ja4s"),
            server_cipher_suite=_optional_int(raw, "server_cipher_suite"),
            server_extensions=_ints(raw, "server_extensions"),
            selected_alpn=_text(raw, "selected_alpn"),
            certificate=(
                None if certificate_raw is None else _certificate_from_json(certificate_raw)
            ),
            http2_settings=_optional_text(raw, "http2_settings"),
        )


#: The canonical empty vector. Frozen, so one shared instance is safe, and it is
#: what `is_empty` compares against.
_EMPTY = FlowFeatures()


def observe_flow_features(payload: bytes) -> FlowFeatures:
    """What one TCP payload shows, or the empty vector.

    The first byte decides the parse: ``0x16`` is a TLS handshake record, and the
    HTTP/2 preface is a 24-byte constant. Application data (``0x17``) and every
    other byte are rejected by that one comparison, which is what keeps this
    affordable on the hot path.
    """
    if len(payload) >= _TLS_RECORD_HEADER_LEN and payload[0] == _CONTENT_TYPE_HANDSHAKE:
        client = fingerprint_client_hello(payload)
        if client is not None:
            return _from_client_hello(client)
        server = fingerprint_server_hello(payload)
        if server is not None:
            # Same buffer only: the ServerHello is the direction signal, so a
            # client's Certificate message can never be read as the server's.
            return _from_server_hello(server, extract_server_certificate(payload))
        return _EMPTY

    if payload.startswith(_HTTP2_PREFACE):
        settings = fingerprint_http2_settings(payload)
        if settings is not None:
            return FlowFeatures(http2_settings=settings.fingerprint)
    return _EMPTY


def _from_client_hello(features: ClientHelloFeatures) -> FlowFeatures:
    return FlowFeatures(
        ja3=features.ja3,
        ja4=features.ja4,
        sni_present=features.sni_present,
        client_version=features.client_version,
        tls_versions=features.version_histogram,
        cipher_suites=features.cipher_suites,
        extensions=features.extensions,
        alpn=tuple(protocol.decode("latin-1") for protocol in features.alpn_protocols),
        grease=features.grease_values,
    )


def _from_server_hello(
    features: ServerHelloFeatures, certificate: CertificateFeatures | None
) -> FlowFeatures:
    return FlowFeatures(
        ja3s=features.ja3s,
        ja4s=features.ja4s,
        server_cipher_suite=features.cipher_suite,
        server_extensions=features.extensions,
        selected_alpn=(
            features.alpn_protocols[0].decode("latin-1")
            if features.alpn_protocols
            else ""
        ),
        certificate=certificate,
    )


# ---------------------------------------------------------------------------
# The certificate half of the codec
# ---------------------------------------------------------------------------


def _certificate_to_json(certificate: CertificateFeatures) -> dict[str, str]:
    return {
        "issuer": certificate.issuer,
        "subject": certificate.subject,
        "not_before": certificate.not_valid_before.isoformat(),
        "not_after": certificate.not_valid_after.isoformat(),
    }


def _certificate_from_json(raw: Mapping[str, Any]) -> CertificateFeatures:
    return CertificateFeatures(
        issuer=_text(raw, "issuer", prefix="certificate."),
        subject=_text(raw, "subject", prefix="certificate."),
        not_valid_before=_instant(raw, "not_before"),
        not_valid_after=_instant(raw, "not_after"),
    )


# ---------------------------------------------------------------------------
# Strict field readers
#
# They are local rather than shared with the run store's because each describes
# one shape, and a generic "read a JSON field" helper is where type softening
# starts. Every message names the field, so a refused record says what to fix.
# ---------------------------------------------------------------------------


def _field(raw: Mapping[str, Any], key: str, prefix: str = "") -> Any:
    if key not in raw:
        raise ValueError(f"features is missing the {prefix}{key} field")
    return raw[key]


def _text(raw: Mapping[str, Any], key: str, *, prefix: str = "") -> str:
    value = _field(raw, key, prefix)
    if not isinstance(value, str):
        raise ValueError(f"{prefix}{key} must be a string, got {type(value).__name__}")
    return value


def _optional_text(raw: Mapping[str, Any], key: str, *, prefix: str = "") -> str | None:
    value = _field(raw, key, prefix)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{prefix}{key} must be a string or null, got {type(value).__name__}")
    return value


def _optional_bool(raw: Mapping[str, Any], key: str, *, prefix: str = "") -> bool | None:
    value = _field(raw, key, prefix)
    if value is None or isinstance(value, bool):
        return value
    raise ValueError(f"{prefix}{key} must be a boolean or null, got {type(value).__name__}")


def _int_in(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{where} must be an integer, got {type(value).__name__}")
    return value


def _optional_int(raw: Mapping[str, Any], key: str, *, prefix: str = "") -> int | None:
    value = _field(raw, key, prefix)
    if value is None:
        return None
    return _int_in(value, f"{prefix}{key}")


def _ints(raw: Mapping[str, Any], key: str, *, prefix: str = "") -> tuple[int, ...]:
    value = _field(raw, key, prefix)
    if not isinstance(value, list):
        raise ValueError(f"{prefix}{key} must be a list, got {type(value).__name__}")
    return tuple(_int_in(item, f"{prefix}{key}[{index}]") for index, item in enumerate(value))


def _texts(raw: Mapping[str, Any], key: str, *, prefix: str = "") -> tuple[str, ...]:
    value = _field(raw, key, prefix)
    if not isinstance(value, list):
        raise ValueError(f"{prefix}{key} must be a list, got {type(value).__name__}")
    decoded: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ValueError(
                f"{prefix}{key}[{index}] must be a string, got {type(item).__name__}"
            )
        decoded.append(item)
    return tuple(decoded)


def _int_pairs(
    raw: Mapping[str, Any], key: str, *, prefix: str = ""
) -> tuple[tuple[int, int], ...]:
    value = _field(raw, key, prefix)
    if not isinstance(value, list):
        raise ValueError(f"{prefix}{key} must be a list, got {type(value).__name__}")
    pairs: list[tuple[int, int]] = []
    for index, item in enumerate(value):
        where = f"{prefix}{key}[{index}]"
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError(f"{where} must be a two-element list")
        pairs.append((_int_in(item[0], where), _int_in(item[1], where)))
    return tuple(pairs)


def _mapping(
    raw: Mapping[str, Any], key: str, *, prefix: str = "", optional: bool = False
) -> Mapping[str, Any] | None:
    value = _field(raw, key, prefix)
    if value is None and optional:
        return None
    if not isinstance(value, Mapping):
        raise ValueError(f"{prefix}{key} must be an object, got {type(value).__name__}")
    return value


def _instant(raw: Mapping[str, Any], key: str, *, prefix: str = "certificate.") -> datetime:
    value = _field(raw, key, prefix)
    if not isinstance(value, str):
        raise ValueError(f"{prefix}{key} must be an ISO-8601 string, got {type(value).__name__}")
    try:
        moment = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{prefix}{key} is not an ISO-8601 timestamp: {value!r}") from exc
    if moment.tzinfo is None:
        raise ValueError(f"{prefix}{key} must carry a UTC offset: {value!r} is naive")
    return moment.astimezone(UTC)
