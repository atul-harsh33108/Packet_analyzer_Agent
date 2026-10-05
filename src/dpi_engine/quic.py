"""QUIC Initial packet detection and ClientHello (SNI) extraction.

Replaces the OSC `QUICSNIExtractor` (OSC/include/sni_extractor.h:74-82,
OSC/src/sni_extractor.cpp:263-300), which the first version of this port
omitted entirely.

=============================================================================
Why the original could not work, and what is actually possible
=============================================================================
QUIC encrypts everything after the long header. A passive observer cannot
find a ClientHello by scanning for a `0x01` byte -- the original's
`for (i = 0; ...; i++) if (payload[i] == 0x01) extract(payload + i - 5, ...)`
heuristic had no chance, and was additionally an out-of-bounds read before the
buffer start whenever `i < 5`. None of that is reproduced here.

There is exactly *one* part of a QUIC connection a passive observer can
decrypt: the **Initial** packet, whose keys are derived solely from the
Destination Connection ID -- which is itself sent in cleartext. That is the
whole of the "QUIC decryption" trick used by real passive DPI. So:

  * Handshake / 1-RTT / 0-RTT packets: genuinely unreadable. Traffic is
    reported as QUIC, never classified from a name. This is a protocol
    property, not a gap in this code.
  * Initial packets: decryptable, and this module does so properly.

=============================================================================
The decryption path, in order (RFC 9000 / RFC 9001)
=============================================================================
1. Parse the long header: version, DCID, SCID, token, length, packet-number
   offset.
2. Derive Initial secrets with HKDF-SHA256 from the version's *initial salt*
   and the DCID (`client_initial_salt` in RFC 9001 s.5.2).
3. Remove **header protection**: AES-128-ECB over the 16-byte sample starting
   at (pn_offset + 4) gives a 5-byte mask that un-protects the low 4 bits of
   the first byte and the packet number. This must precede step 4, because it
   changes where the packet number starts and how long it is.
4. Reconstruct the full packet number from the truncated one, using the
   largest previously seen packet number for that direction (QUIC varints are
   deliberately truncated, so this is inherently stateful).
5. Remove **payload protection**: AES-128-GCM over the ciphertext, with the
   nonce XORed with the packet number and the unprotected long header as AAD.
   A tag failure is authoritative: the packet is not an Initial we can read.
6. Parse frames, reassemble CRYPTO frames by offset (they may be split across
   packets and arrive out of order), and hand the contiguous reassembled TLS
   stream to `sni_extractor.extract_sni`.

Handshake keys are never derived: the ClientHello always fits inside the
first flight, so reassembly stops as soon as a ClientHello is parseable.

=============================================================================
Dependency gate
=============================================================================
Steps 2-5 need AES and HKDF. HKDF/SHA-256 are stdlib (`hmac`, `hashlib`), but
AES is not, and this project does not hand-roll block ciphers. So
`cryptography` is an **optional** extra:

    pip install dpi-engine[quic]      # or: uv sync --extra quic

With it absent, detection still works and nothing else in the tool is
affected; only SNI extraction from QUIC is unavailable. That degradation is
*reported*, never silently swallowed: `quic_sni_supported()` is False,
`unsupported_reason()` explains why, `dpi-engine inspect` prints it, and the
pipeline counts such packets separately (`PipelineResult.quic_packets` /
`quic_undecryptable`) so "we saw QUIC but could not read it" can never be
mistaken for "there was no QUIC".

Scope: v1 and v2 Initial packets are decrypted. Draft-29+ versions are
*detected* (they are still deployed) but not decrypted, because their salt
differs from v1's and guessing it would silently produce garbage -- they are
reported as undecryptable instead. Version Negotiation and Retry packets are
detected and carry no ClientHello.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Final

from dpi_engine.sni_extractor import extract_sni

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LONG_HEADER_FORM: Final = 0x80
FIXED_BIT: Final = 0x40
SPIN_BIT: Final = 0x20  # v2 only; unused here but documents the reserved bit

QUIC_VERSION_1: Final = 0x00000001
QUIC_VERSION_2: Final = 0x6B3343CF

#: Initial salts, keyed by QUIC version (RFC 9001 s.5.2, RFC 9369 s.3.3.1).
#: A version absent from this table is never decrypted -- see module docstring.
_INITIAL_SALTS: Final[dict[int, bytes]] = {
    QUIC_VERSION_1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    QUIC_VERSION_2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}

#: draft-29 marker used by is_quic()/is_quic_initial(). Draft versions are
#: encoded as 0xff0000NN where NN is the draft number, so draft-29 is
#: 0xff00001d. Drafts *before* 29 (draft-0/17/22/25/27/28) used incompatible
#: framing and are deliberately not recognised -- claiming them would produce
#: confidently wrong parses.
_DRAFT_29_MIN_VERSION: Final = 0xFF00001D

# Long-header packet types, from the first byte's type field (0x30).
_PKT_INITIAL: Final = 0x00
_PKT_0RTT: Final = 0x01
_PKT_HANDSHAKE: Final = 0x02
_PKT_RETRY: Final = 0x03

# Frame types (RFC 9000 s.19).
_FRAME_PADDING: Final = 0x00
_FRAME_PING: Final = 0x01
_FRAME_ACK: Final = 0x02
_FRAME_ACK_ECN: Final = 0x03
_FRAME_CRYPTO: Final = 0x06

#: Upper bound on reassembled CRYPTO bytes buffered per connection. The
#: ClientHello fits in a few KB (large ones with many extensions approach
#: 4 KB); this ceiling stops a hostile peer from inducing unbounded buffering
#: with a stream of tiny out-of-order CRYPTO frames at huge offsets.
MAX_CRYPTO_BUFFER: Final = 64 * 1024

#: Largest UDP payload considered for QUIC parsing at all.
MAX_QUIC_DATAGRAM: Final = 65_535

#: AES-128-GCM authentication tag length (RFC 9001 s.5.3).
_GCM_TAG_LEN: Final = 16

_TLS13_LABEL_PREFIX: Final = b"tls13 "


class QuicError(Exception):
    """Raised for structurally malformed QUIC input.

    Deliberately *not* raised on "no SNI found" -- that is a `None` return.
    The public entry point (`QuicFlowInspector.feed`, and the functional
    `extract_quic_sni`) never raises, because they run on attacker-controlled
    bytes inside a hot loop; this exception exists for tests and for strict
    validation of hand-built fixtures.
    """


def _probe_crypto_backend() -> str | None:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return (
            "QUIC SNI extraction needs the optional 'cryptography' package. "
            "Install it with: pip install 'dpi-engine[quic]'"
        )
    return None


_UNSUPPORTED_REASON: Final = _probe_crypto_backend()

#: True when the crypto backend required to decrypt QUIC Initial packets is
#: importable. Evaluated once, at import time.
QUIC_SNI_SUPPORTED: Final = _UNSUPPORTED_REASON is None

#: Why SNI extraction is unavailable, or None when it is available.
QUIC_SNI_UNSUPPORTED_REASON: Final = _UNSUPPORTED_REASON


def quic_sni_supported() -> bool:
    """True when `extract_quic_sni` can actually decrypt Initial packets."""
    return QUIC_SNI_SUPPORTED


def unsupported_reason() -> str | None:
    """Human-readable reason QUIC SNI extraction is unavailable, else None.

    Surfaced by `dpi-engine inspect` so the limitation is discoverable without
    reading this file.
    """
    return _UNSUPPORTED_REASON


# ---------------------------------------------------------------------------
# varint (RFC 9000 s.16)
# ---------------------------------------------------------------------------


def decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Decodes a QUIC variable-length integer. Returns (value, next_offset).

    RFC 9000 s.16 defines four encodings selected by a 2-bit prefix:
    00 -> 1 byte, 01 -> 2 bytes, 10 -> 4 bytes, 11 -> 8 bytes. All four
    prefixes are valid (unlike TLS's, QUIC reserves none), and the largest
    representable value is 2**62 - 1. Raises QuicError on truncation or on a
    value that does not fit its encoding.
    """
    if offset >= len(data):
        raise QuicError("truncated QUIC varint")
    length = 1 << (data[offset] >> 6)
    if offset + length > len(data):
        raise QuicError("truncated QUIC varint")
    value = data[offset] & 0x3F
    for i in range(1, length):
        value = (value << 8) | data[offset + i]
    if value >= 1 << 62:
        raise QuicError("QUIC varint value out of range")
    return value, offset + length


def encode_varint(value: int) -> bytes:
    """Inverse of `decode_varint`. Used to build test fixtures."""
    if value < 0:
        raise ValueError("varint cannot encode a negative value")
    if value < 1 << 6:
        return value.to_bytes(1, "big")
    if value < 1 << 14:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 1 << 30:
        return (value | 0x80000000).to_bytes(4, "big")
    if value < 1 << 62:
        return (value | 0xC000000000000000).to_bytes(8, "big")
    raise ValueError("varint cannot encode a value >= 2**62")


# ---------------------------------------------------------------------------
# Long header
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class QuicLongHeader:
    """A parsed QUIC long header, before header-protection removal.

    `packet_type` is the *protected* value: header protection masks the low 4
    bits of the first byte, not the 0x30 type field, so the type read here is
    already correct and safe to branch on.
    """

    version: int
    dcid: bytes
    scid: bytes
    token: bytes
    #: Encoded length of (packet number + protected payload). 0 for Version
    #: Negotiation, which has no length field.
    length: int
    pn_offset: int
    packet_type: int

    @property
    def is_version_negotiation(self) -> bool:
        return self.version == 0


def parse_long_header(payload: bytes) -> QuicLongHeader:
    """Parses a QUIC long header. Raises QuicError if `payload` is not one."""
    if len(payload) < 7:
        raise QuicError("QUIC datagram too short for a long header")

    first = payload[0]
    if not first & LONG_HEADER_FORM:
        raise QuicError("not a QUIC long header (form bit clear)")

    version = int.from_bytes(payload[1:5], "big")

    dcid_len = payload[5]
    offset = 6
    if offset + dcid_len > len(payload):
        raise QuicError("truncated DCID")
    dcid = payload[offset : offset + dcid_len]
    offset += dcid_len

    if offset >= len(payload):
        raise QuicError("truncated SCID length")
    scid_len = payload[offset]
    offset += 1
    if offset + scid_len > len(payload):
        raise QuicError("truncated SCID")
    scid = payload[offset : offset + scid_len]
    offset += scid_len

    if version == 0:
        # Version Negotiation (RFC 9000 s.17.2.1): no token, no length, no PN.
        return QuicLongHeader(
            version=version,
            dcid=dcid,
            scid=scid,
            token=b"",
            length=0,
            pn_offset=offset,
            packet_type=0xFF,
        )

    token_len, offset = decode_varint(payload, offset)
    if token_len > len(payload) - offset:
        raise QuicError("truncated token")
    token = payload[offset : offset + token_len]
    offset += token_len

    length, offset = decode_varint(payload, offset)
    if offset >= len(payload):
        raise QuicError("no packet number in QUIC long header")

    return QuicLongHeader(
        version=version,
        dcid=dcid,
        scid=scid,
        token=token,
        length=length,
        pn_offset=offset,
        packet_type=(first & 0x30) >> 4,
    )


def _plausible_version(version: int) -> bool:
    return version in _INITIAL_SALTS or version >= _DRAFT_29_MIN_VERSION


def is_quic(payload: bytes) -> bool:
    """True if `payload` looks like *any* QUIC long-header packet.

    Broader than `is_quic_initial`: this is what lets QUIC traffic show up in
    reports as QUIC even when its SNI is unreadable, instead of as
    "unknown". Checks the version too, so an unrelated protocol that happens
    to set the form bit is not misclassified.
    """
    if not 6 <= len(payload) <= MAX_QUIC_DATAGRAM:
        return False
    if not payload[0] & LONG_HEADER_FORM:
        return False
    if not payload[0] & FIXED_BIT:
        return False
    return _plausible_version(int.from_bytes(payload[1:5], "big"))


def is_quic_initial(payload: bytes) -> bool:
    """True if `payload` is a QUIC **Initial** packet.

    OSC's `QUICSNIExtractor::isQUICInitial` (sni_extractor.cpp:263-278) only
    checked `length >= 5` and the long-header form bit, with a comment
    conceding it was "lenient" about the version. That is far too permissive:
    it accepted Version Negotiation, Retry, 0-RTT, Handshake, and every
    unsupported version as "QUIC Initial". This checks the packet type (safe
    pre-protection, as noted on `QuicLongHeader`) and the version.
    """
    if not is_quic(payload):
        return False
    return ((payload[0] & 0x30) >> 4) == _PKT_INITIAL


# ---------------------------------------------------------------------------
# Key derivation (RFC 9001 s.5.2)
# ---------------------------------------------------------------------------


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract with SHA-256."""
    return hmac.new(salt, ikm, sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand with SHA-256."""
    out = bytearray()
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), sha256).digest()
        out += block
        counter += 1
    return bytes(out[:length])


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """RFC 8446 HKDF-Expand-Label, as specialised by RFC 9001 s.5.2."""
    full_label = _TLS13_LABEL_PREFIX + label
    info = (
        length.to_bytes(2, "big")
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    return _hkdf_expand(secret, info, length)


def derive_initial_secrets(dcid: bytes, version: int) -> tuple[bytes, bytes]:
    """Derives (client_initial_secret, server_initial_secret) for a v1/v2
    Initial packet. Both are needed: a capture may contain either direction
    of a connection's first flight, and only the GCM tag tells them apart."""
    salt = _INITIAL_SALTS.get(version)
    if salt is None:
        raise QuicError(f"no initial salt known for QUIC version 0x{version:08x}")
    initial_secret = hkdf_extract(salt, dcid)
    return (
        hkdf_expand_label(initial_secret, b"client in", b"", 32),
        hkdf_expand_label(initial_secret, b"server in", b"", 32),
    )


@dataclass(frozen=True, slots=True)
class _QuicKeys:
    key: bytes
    iv: bytes
    hp: bytes


def _initial_keys(secret: bytes) -> _QuicKeys:
    return _QuicKeys(
        key=hkdf_expand_label(secret, b"quic key", b"", 16),
        iv=hkdf_expand_label(secret, b"quic iv", b"", 12),
        hp=hkdf_expand_label(secret, b"quic hp", b"", 16),
    )


# ---------------------------------------------------------------------------
# Packet numbers (RFC 9000 Appendix A)
# ---------------------------------------------------------------------------


def _pn_nbits(first_byte: int) -> int:
    """Packet-number length in bytes, from the (unprotected) first byte."""
    return (first_byte & 0x03) + 1


def reconstruct_packet_number(truncated: int, nbits: int, largest_seen: int) -> int:
    """RFC 9000 Appendix A.2 DecodePacketNumber.

    `largest_seen` is the largest packet number already seen for this
    connection *in this direction*; pass -1 for the first packet.
    """
    expected = max(largest_seen + 1, 0)
    window = 1 << nbits
    half_window = window // 2
    mask = window - 1
    candidate = (expected & ~mask) | truncated
    if candidate <= expected - half_window and candidate < (1 << 62) - window:
        return candidate + window
    if candidate > expected + half_window and candidate >= window:
        return candidate - window
    return candidate


# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------


def decrypt_initial(
    payload: bytes,
    header: QuicLongHeader,
    keys: _QuicKeys,
    largest_pn: int,
) -> tuple[bytes, int] | None:
    """Removes header and payload protection from one Initial packet.

    Returns (plaintext, full_packet_number), or None if the packet is too
    short to carry a header-protection sample or the GCM tag does not
    authenticate. A tag failure is the *expected*, non-exceptional outcome --
    it simply means this is not an Initial we can read.
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    sample_offset = header.pn_offset + 4
    if sample_offset + 16 > len(payload):
        return None
    sample = payload[sample_offset : sample_offset + 16]

    encryptor = Cipher(algorithms.AES(keys.hp), modes.ECB()).encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()

    first_byte = payload[0] ^ (mask[0] & 0x0F)
    pn_len = _pn_nbits(first_byte)
    pn_offset = header.pn_offset
    if pn_offset + pn_len > len(payload):
        return None

    truncated = 0
    for i in range(pn_len):
        truncated = (truncated << 8) | (payload[pn_offset + i] ^ mask[1 + i])
    full_pn = reconstruct_packet_number(truncated, pn_len * 8, largest_pn)

    # AAD is the long header up to (not including) the packet number, with
    # the packet-number length bits already restored by `first_byte`.
    aad = bytearray(payload[:pn_offset])
    aad[0] = first_byte

    ciphertext = payload[pn_offset + pn_len :]
    if header.length:
        # header.length covers packet number + protected payload. Trust it to
        # bound the ciphertext; ignore it if it overruns the datagram (a
        # coalesced or padded capture can legitimately do that).
        declared = header.length - pn_len
        if 0 <= declared <= len(ciphertext):
            ciphertext = ciphertext[:declared]

    nonce = bytearray(keys.iv)
    pn_xor = full_pn.to_bytes(12, "big")
    for i in range(12):
        nonce[i] ^= pn_xor[i]

    # AES-128-GCM's authentication tag is 16 bytes and is the tail of the
    # protected payload. It is passed to `modes.GCM(..., tag=...)` rather than
    # left appended to the ciphertext: cryptography >= 42 requires the tag to
    # be supplied explicitly, and splitting it here is clearer than relying
    # on either convention.
    if len(ciphertext) < _GCM_TAG_LEN:
        return None
    body, tag = ciphertext[:-_GCM_TAG_LEN], ciphertext[-_GCM_TAG_LEN:]

    try:
        decryptor = Cipher(
            algorithms.AES(keys.key), modes.GCM(bytes(nonce), tag)
        ).decryptor()
        decryptor.authenticate_additional_data(bytes(aad))
        plaintext = decryptor.update(body) + decryptor.finalize()
    except InvalidTag:
        return None
    return plaintext, full_pn


# ---------------------------------------------------------------------------
# Frame parsing
# ---------------------------------------------------------------------------


def extract_crypto_frames(plaintext: bytes) -> list[tuple[int, bytes]]:
    """Extracts (offset, data) for each CRYPTO frame in a decrypted Initial
    packet.

    This is a real frame walk, not a scan: frame lengths are field-specific, so
    the frames that can legitimately precede CRYPTO in a client's first packet
    (PADDING, PING, ACK, ACK_ECN) are skipped with their correct lengths. An
    unrecognised frame type ends the walk and returns what was collected --
    safe and cheap, and in practice CRYPTO comes first anyway.
    """
    frames: list[tuple[int, bytes]] = []
    offset = 0
    length = len(plaintext)

    while offset < length:
        try:
            frame_type, offset = decode_varint(plaintext, offset)
        except QuicError:
            break

        if frame_type == _FRAME_PADDING:
            # PADDING has no length field; consume the whole run at once.
            while offset < length and plaintext[offset] == _FRAME_PADDING:
                offset += 1
            continue

        if frame_type == _FRAME_PING:
            continue  # no payload

        if frame_type in (_FRAME_ACK, _FRAME_ACK_ECN):
            try:
                _largest, offset = decode_varint(plaintext, offset)
                _delay, offset = decode_varint(plaintext, offset)
                range_count, offset = decode_varint(plaintext, offset)
                _first_range, offset = decode_varint(plaintext, offset)
                for _ in range(range_count):
                    _gap, offset = decode_varint(plaintext, offset)
                    _range, offset = decode_varint(plaintext, offset)
                if frame_type == _FRAME_ACK_ECN:
                    for _ in range(3):  # ect0, ect1, ce counters
                        _, offset = decode_varint(plaintext, offset)
            except QuicError:
                break
            continue

        if frame_type == _FRAME_CRYPTO:
            try:
                crypto_offset, offset = decode_varint(plaintext, offset)
                crypto_len, offset = decode_varint(plaintext, offset)
            except QuicError:
                break
            # Clamp rather than reject: a datagram truncated mid-frame is
            # normal, and a short final CRYPTO chunk is still useful.
            crypto_len = min(crypto_len, length - offset)
            if crypto_len > 0:
                frames.append((crypto_offset, plaintext[offset : offset + crypto_len]))
            offset += crypto_len
            continue

        # Unknown frame type: its length is undefined to us, so stop
        # collecting rather than guessing.
        break

    return frames


# ---------------------------------------------------------------------------
# Per-connection inspector
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class QuicFlowInspector:
    """Per-flow QUIC Initial decryptor.

    QUIC packet numbers and the ClientHello's CRYPTO stream both span packets,
    so decryption cannot be stateless. The pipeline keeps one of these per
    five-tuple and calls `feed` for each UDP payload on that flow -- see
    `pipeline.QuicFlowTable`. Keeping the state in a class (rather than
    threading a state tuple through every call) is what makes the call site a
    single line and keeps the mutation rules in one place.
    """

    version: int = 0
    dcid: bytes = b""
    client_keys: _QuicKeys | None = None
    server_keys: _QuicKeys | None = None
    #: Largest packet number seen, per direction (False = client->server).
    largest_pn: dict[bool, int] = field(default_factory=lambda: {False: -1, True: -1})
    #: Sparse CRYPTO stream: bytes, plus a parallel "is present" mask.
    crypto: bytearray = field(default_factory=bytearray)
    crypto_present: bytearray = field(default_factory=bytearray)

    # ---- counters, for honest reporting ----
    initial_packets: int = 0
    undecryptable_packets: int = 0
    client_hello_seen: bool = False

    def _bind(self, header: QuicLongHeader) -> bool:
        """Derives and installs keys for `header`'s connection. Returns False
        if the version has no known salt (nothing is guessed)."""
        if self.client_keys is not None and self.dcid == header.dcid:
            return True
        try:
            client_secret, server_secret = derive_initial_secrets(
                header.dcid, header.version
            )
        except QuicError:
            return False
        self.version = header.version
        self.dcid = header.dcid
        self.client_keys = _initial_keys(client_secret)
        self.server_keys = _initial_keys(server_secret)
        self.largest_pn = {False: -1, True: -1}
        self.crypto = bytearray()
        self.crypto_present = bytearray()
        return True

    def _buffer_crypto(self, offset: int, data: bytes) -> None:
        """Records CRYPTO bytes at `offset`, growing the sparse buffer as
        needed and never past MAX_CRYPTO_BUFFER."""
        if offset >= MAX_CRYPTO_BUFFER:
            return
        end = min(offset + len(data), MAX_CRYPTO_BUFFER)
        needed = end - len(self.crypto)
        if needed > 0:
            self.crypto.extend(b"\x00" * needed)
            self.crypto_present.extend(b"\x00" * needed)
        self.crypto[offset:end] = data[: end - offset]
        self.crypto_present[offset:end] = b"\x01" * (end - offset)

    def _contiguous_prefix(self) -> bytes:
        """The reassembled CRYPTO stream from offset 0 up to the first hole."""
        for i, present in enumerate(self.crypto_present):
            if not present:
                return bytes(self.crypto[:i])
        return bytes(self.crypto)

    def feed_counted(self, payload: bytes) -> tuple[str | None, bool]:
        """Feeds one payload and reports `(sni, undecryptable)` for **this packet**.

        `undecryptable_packets` is a *cumulative* counter: it is incremented once
        per packet that genuinely fails and never reset. A caller that wants a
        per-packet answer must therefore not test it directly -- `if
        inspector.undecryptable_packets:` is true whenever the flow has *ever*
        failed, so every later Initial on that flow would be misreported as
        undecryptable even when it decrypted cleanly. That inflated the
        pipeline's QUIC coverage figure towards 100% failure on any long-lived
        flow.

        `feed()` remains for callers that only want the SNI (and for the one-shot
        `extract_quic_sni` wrapper); this method exists so that asking the
        per-packet question has an obvious, correct spelling.
        """
        before = self.undecryptable_packets
        sni = self.feed(payload)
        return sni, self.undecryptable_packets > before

    def feed(self, payload: bytes) -> str | None:
        """Processes one UDP payload from this flow.

        Returns the SNI as soon as the reassembled ClientHello contains one,
        else None. `client_hello_seen` and `initial_packets` /
        `undecryptable_packets` are updated so the caller can report coverage
        honestly.

        Never raises: all structural problems are absorbed into the counters.
        """
        if not is_quic_initial(payload):
            return None

        self.initial_packets += 1

        if not QUIC_SNI_SUPPORTED:
            self.undecryptable_packets += 1
            return None

        try:
            header = parse_long_header(payload)
        except QuicError:
            self.undecryptable_packets += 1
            return None

        if header.is_version_negotiation or not self._bind(header):
            self.undecryptable_packets += 1
            return None

        # A bare datagram does not say which direction it is; the GCM tag is
        # what decides. Try client first, then server, and only commit state
        # for the direction that authenticates.
        for is_server, keys in ((False, self.client_keys), (True, self.server_keys)):
            assert keys is not None
            result = decrypt_initial(payload, header, keys, self.largest_pn[is_server])
            if result is None:
                continue
            plaintext, full_pn = result
            self.largest_pn[is_server] = max(self.largest_pn[is_server], full_pn)
            for offset, data in extract_crypto_frames(plaintext):
                self._buffer_crypto(offset, data)
            break
        else:
            self.undecryptable_packets += 1
            return None

        contiguous = self._contiguous_prefix()
        if not contiguous:
            return None

        sni = extract_sni(contiguous)
        if sni is not None:
            self.client_hello_seen = True
        return sni


def extract_quic_sni(
    payload: bytes, inspector: QuicFlowInspector | None = None
) -> str | None:
    """One-shot convenience wrapper: extract the SNI from a single QUIC
    Initial packet.

    Correct for a self-contained first packet, which is the normal case. For a
    ClientHello fragmented across several packets, keep a `QuicFlowInspector`
    per flow and call `feed` on every payload instead -- that is what the
    pipeline does.
    """
    return (inspector or QuicFlowInspector()).feed(payload)
