"""SNI (TLS Client Hello), HTTP Host header, and DNS query-name extraction.

Ports OSC/include/sni_extractor.h + OSC/src/sni_extractor.cpp to Python.

This is the layer with the most security-relevant bugs in the original (see
DESIGN_DECISIONS.md "Bugs fixed during the port", items 1-3), and is kept
hand-rolled rather than delegated to a library specifically so every bounds
check can be made explicit and directly comparable to the original's logic
(see DESIGN_DECISIONS.md "Library choices").

The governing rule applied throughout this module, which the original did
NOT consistently apply: every "skip N bytes" step validates that N bytes
actually remain in the buffer *before* advancing the offset, not just that
the length *prefix* itself was readable. Concretely:

- The original (sni_extractor.cpp) skipped the 2-byte client version and the
  32-byte random with NO bounds check at all (fixed offset arithmetic:
  `offset += 2; offset += 32;`), then immediately read `payload[offset]` for
  the session ID length. On a Client Hello shorter than 43 bytes (but still
  >= 9, so it passes `isTLSClientHello`'s coarse check), this reads past the
  end of the buffer. This port checks `offset <= length` immediately before
  every subsequent length-prefix read, closing that gap.
- The original's session-ID/cipher-suites/compression-methods skips checked
  only that the *length byte itself* was in bounds, then unconditionally
  added the attacker-controlled length to `offset` with no check that that
  many bytes actually existed. This port validates the full skip region
  (`offset + skip_len <= length`) before advancing, every time.

QUIC SNI extraction is NOT handled here. The original's QUICSNIExtractor::extract
computed `payload + i - 5` inside a loop starting at `i = 0`, which is an
out-of-bounds read whenever `i < 5` -- and the original itself described that
implementation as "simplified" and a placeholder, not a real QUIC parser (QUIC
Initial packets carry the Client Hello inside *encrypted* CRYPTO frames, which
cannot be scanned for byte patterns at all without first performing QUIC's
header-protection removal). Porting that heuristic was the wrong move.

QUIC is therefore implemented properly and separately, in `dpi_engine.quic`:
the full RFC 9000/9001 path (Initial decryption, header-protection removal,
packet-number reconstruction, AES-128-GCM, CRYPTO-frame reassembly). See
DESIGN_DECISIONS.md "Gap analysis" item 16. `quic.py` is the only place QUIC
SNI extraction happens; this module stays free of it so the TLS/HTTP/DNS
parsers keep their own self-contained bounds guarantees.
"""

from __future__ import annotations

# --- TLS constants (matches OSC's SNIExtractor private constants) -----------------

_CONTENT_TYPE_HANDSHAKE = 0x16
_HANDSHAKE_CLIENT_HELLO = 0x01
_EXTENSION_SNI = 0x0000
_SNI_TYPE_HOSTNAME = 0x00

_TLS_RECORD_HEADER_LEN = 5  # content type (1) + version (2) + length (2)
_HANDSHAKE_HEADER_LEN = 4  # handshake type (1) + length (3)
_CLIENT_VERSION_LEN = 2
_RANDOM_LEN = 32


def _read_u16be(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def is_tls_client_hello(payload: bytes, length: int | None = None) -> bool:
    """Checks whether `payload` looks like the start of a TLS Client Hello.

    `length` defaults to len(payload) when omitted; accepting it explicitly
    mirrors the original's (payload, length) signature for callers that pass
    a buffer larger than the logical packet.

    `length` is clamped to the bytes actually present. Without the clamp a
    caller that claimed a length larger than its buffer got two wrong answers:
    the `length >= 9` gate below was satisfied by bytes that did not exist, and
    the fixed-offset reads ran past the end of the buffer. This function
    promises a bool for any input, so it must never raise -- see `extract_sni`.
    """
    if length is None:
        length = len(payload)
    length = min(length, len(payload))

    # Minimum TLS record: 5 bytes header + 4 bytes handshake header.
    if length < 9:
        return False

    if payload[0] != _CONTENT_TYPE_HANDSHAKE:
        return False

    version = _read_u16be(payload, 1)
    if version < 0x0300 or version > 0x0304:
        return False

    record_length = _read_u16be(payload, 3)
    if record_length > length - 5:
        return False

    # Byte 5 is the handshake type; only a Client Hello is of interest.
    return payload[5] == _HANDSHAKE_CLIENT_HELLO


def extract_sni(payload: bytes, length: int | None = None) -> str | None:
    """Extracts the SNI hostname from a TLS Client Hello.

    Returns None for anything that isn't a well-formed-enough Client Hello
    to safely parse, or that doesn't contain an SNI extension. Never raises
    on malformed/truncated/adversarial input -- every offset advance is
    bounds-checked first, and `length` is clamped to the bytes actually
    present so a caller that claims more than it holds cannot drive a read
    past the end of the buffer.
    """
    if length is None:
        length = len(payload)
    length = min(length, len(payload))

    if not is_tls_client_hello(payload, length):
        return None

    offset = _TLS_RECORD_HEADER_LEN

    # Handshake header: type (1, already checked) + length (3). We don't
    # need the handshake length value itself (the original read it into an
    # unused variable); only the fixed 4-byte skip matters here.
    if offset + _HANDSHAKE_HEADER_LEN > length:
        return None
    offset += _HANDSHAKE_HEADER_LEN

    # Client version (2 bytes) + Random (32 bytes). The original skipped
    # these with NO bounds check at all before reading the session ID length
    # next -- this is the exact bug being fixed here.
    if offset + _CLIENT_VERSION_LEN + _RANDOM_LEN > length:
        return None
    offset += _CLIENT_VERSION_LEN + _RANDOM_LEN

    # Session ID: 1-byte length prefix + that many bytes.
    if offset >= length:
        return None
    session_id_length = payload[offset]
    offset += 1
    if offset + session_id_length > length:
        return None
    offset += session_id_length

    # Cipher suites: 2-byte length prefix + that many bytes.
    if offset + 2 > length:
        return None
    cipher_suites_length = _read_u16be(payload, offset)
    offset += 2
    if offset + cipher_suites_length > length:
        return None
    offset += cipher_suites_length

    # Compression methods: 1-byte length prefix + that many bytes.
    if offset >= length:
        return None
    compression_methods_length = payload[offset]
    offset += 1
    if offset + compression_methods_length > length:
        return None
    offset += compression_methods_length

    # Extensions: 2-byte length prefix + that many bytes (possibly
    # truncated -- the original tolerated a truncated extensions block by
    # clamping to `length` and trying to parse what's there; preserved here
    # since none of the subsequent reads can go out of bounds as a result of
    # this clamp, they're all separately checked against extensions_end).
    if offset + 2 > length:
        return None
    extensions_length = _read_u16be(payload, offset)
    offset += 2

    extensions_end = offset + extensions_length
    if extensions_end > length:
        extensions_end = length

    while offset + 4 <= extensions_end:
        extension_type = _read_u16be(payload, offset)
        extension_length = _read_u16be(payload, offset + 2)
        offset += 4

        if offset + extension_length > extensions_end:
            break

        if extension_type == _EXTENSION_SNI:
            if extension_length < 5:
                break

            sni_list_length = _read_u16be(payload, offset)
            if sni_list_length < 3:
                break

            sni_type = payload[offset + 2]
            sni_length = _read_u16be(payload, offset + 3)

            if sni_type != _SNI_TYPE_HOSTNAME:
                break
            if sni_length > extension_length - 5:
                break
            # Belt-and-suspenders: extension_length was already validated to
            # fit within extensions_end/length above, and sni_length was
            # just validated against extension_length, so this slice cannot
            # read out of bounds -- but Python slicing would simply return a
            # short result rather than crash even if it somehow could.
            sni_bytes = payload[offset + 5 : offset + 5 + sni_length]
            try:
                return sni_bytes.decode("ascii")
            except UnicodeDecodeError:
                return sni_bytes.decode("latin-1")

        offset += extension_length

    return None


# --- HTTP Host header extraction ---------------------------------------------------

_HTTP_METHODS: tuple[bytes, ...] = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")


def is_http_request(payload: bytes) -> bool:
    """Checks whether `payload` starts with a recognized HTTP method prefix.

    Note (inherited from the original, kept for behavioral parity): methods
    are matched on their first 4 bytes only, so "DELETE" is recognized via
    the "DELE" prefix and "OPTIONS" via "OPTI" -- meaning any payload merely
    *starting* with those 4 bytes is classified as HTTP, even if it isn't
    really a DELETE/OPTIONS request. This is a classification-accuracy nit,
    not a memory-safety issue (kept for behavioral parity with the
    original; see README known limitations).
    """
    if len(payload) < 4:
        return False
    prefix = payload[:4]
    return prefix in _HTTP_METHODS


def extract_http_host(payload: bytes) -> str | None:
    """Extracts the value of the first "Host:" header from an HTTP request.

    Case-insensitive header name match, port suffix (":8080") stripped from
    the returned host, matching the original's behavior.
    """
    if not is_http_request(payload):
        return None

    length = len(payload)
    host_header_len = 6  # len("Host: ") -- matches original's constant, used only as a loop bound

    i = 0
    while i + host_header_len < length:
        if (
            payload[i] in (ord("H"), ord("h"))
            and payload[i + 1] in (ord("o"), ord("O"))
            and payload[i + 2] in (ord("s"), ord("S"))
            and payload[i + 3] in (ord("t"), ord("T"))
            and payload[i + 4] == ord(":")
        ):
            start = i + 5
            while start < length and payload[start] in (ord(" "), ord("\t")):
                start += 1

            end = start
            while end < length and payload[end] not in (ord("\r"), ord("\n")):
                end += 1

            if end > start:
                host = payload[start:end].decode("ascii", errors="replace")
                colon_pos = host.find(":")
                if colon_pos != -1:
                    host = host[:colon_pos]
                return host

        i += 1

    return None


# --- DNS query extraction -----------------------------------------------------------


def is_dns_query(payload: bytes) -> bool:
    """Checks whether `payload` looks like a DNS query (not a response)."""
    if len(payload) < 12:
        return False

    flags = payload[2]
    if flags & 0x80:  # QR bit set => response
        return False

    # A query with no question section has nothing to extract.
    return _read_u16be(payload, 4) != 0


def extract_dns_query(payload: bytes) -> str | None:
    """Extracts the queried domain name from a DNS query packet.

    DNS name compression pointers (a label length byte with its top two
    bits set, i.e. >= 0xC0) are not resolved -- matching the original's
    behavior, this simply stops parsing at that point rather than following
    the pointer, returning whatever labels were accumulated so far (or None
    if none). This is a documented accuracy limitation, not a safety bug:
    it cannot loop or read out of bounds, it just may return a truncated or
    empty name for a compressed query name (rare in practice for the
    question section, but legal).
    """
    if not is_dns_query(payload):
        return None

    length = len(payload)
    offset = 12
    labels: list[str] = []

    while offset < length:
        label_length = payload[offset]

        if label_length == 0:
            break

        if label_length > 63:
            # Compression pointer (top two bits set) or invalid length byte.
            break

        offset += 1
        if offset + label_length > length:
            break

        labels.append(payload[offset : offset + label_length].decode("ascii", errors="replace"))
        offset += label_length

    if not labels:
        return None
    return ".".join(labels)
