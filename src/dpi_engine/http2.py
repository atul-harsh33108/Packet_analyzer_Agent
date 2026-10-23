"""The HTTP/2 client preface and SETTINGS fingerprint (`T5-02`).

What the string is
------------------
RFC 9113 section 3.4 requires a client to open an HTTP/2 connection with the
24-byte preface ``PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n`` followed immediately by
a SETTINGS frame. `fingerprint_http2_settings` checks both and renders the
frame's entries in **arrival order** as ``id:value`` pairs joined with ``;`` --
the settings half of the "Akamai" HTTP/2 fingerprint. Order is part of the value:
two clients that send the same settings in a different order are different
clients.

Half a published fingerprint, and it says so
--------------------------------------------
The Akamai fingerprint is commonly quoted as SETTINGS **plus** the connection
WINDOW_UPDATE increment **plus** the PRIORITY frames that follow. Only the first
part is produced here, because that is the piece this task's gate names. A
consumer must not mistake the value for the whole Akamai string, so the rest is
not silently dropped: `Http2Settings.settings` is the tuple it was built from,
and the fingerprints that need the other frames can extend it from there.

Reachability
------------
Over TLS the preface is inside the encrypted stream, so a passive observer sees
this on cleartext h2c only -- and on a decrypted stream where a caller holds the
keys. ``None`` means "no preface and SETTINGS here", never "not HTTP/2".

The refusals are RFC 9113 section 6.5's: the first client frame must be a
SETTINGS frame, on stream 0, without the ACK flag, and its payload is a whole
number of six-byte entries. A frame that overruns the bytes present is refused
rather than clamped, for the same reason the TLS parsers abstain: half a
fingerprint is a wrong fact that looks like a right one.
"""

from __future__ import annotations

from dataclasses import dataclass

_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_FRAME_HEADER_LEN = 9
_FRAME_SETTINGS = 0x04
_FLAG_ACK = 0x01
_SETTINGS_ENTRY_LEN = 6
_STREAM_ID_MASK = 0x7FFFFFFF


@dataclass(frozen=True)
class Http2Settings:
    """A client's SETTINGS entries, in the order the frame carried them."""

    settings: tuple[tuple[int, int], ...]

    @property
    def fingerprint(self) -> str:
        """The published ``id:value;id:value`` rendering (empty when none)."""
        return ";".join(f"{identifier}:{value}" for identifier, value in self.settings)


def _read_u16(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def _read_u24(data: bytes, offset: int) -> int:
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


def _read_u32(data: bytes, offset: int) -> int:
    return (
        (data[offset] << 24)
        | (data[offset + 1] << 16)
        | (data[offset + 2] << 8)
        | data[offset + 3]
    )


def fingerprint_http2_settings(
    stream: bytes, length: int | None = None
) -> Http2Settings | None:
    """The client's SETTINGS fingerprint, or `None` if this is not one.

    `length` defaults to ``len(stream)`` and is clamped to it. Frames after the
    first SETTINGS are not read: they are the other half of the Akamai string and
    are deliberately out of scope.
    """
    end = len(stream) if length is None else min(length, len(stream))
    if end < len(_PREFACE) + _FRAME_HEADER_LEN:
        return None
    if stream[: len(_PREFACE)] != _PREFACE:
        return None

    header = len(_PREFACE)
    frame_length = _read_u24(stream, header)
    frame_type = stream[header + 3]
    flags = stream[header + 4]
    # The reserved high bit of the stream identifier is ignored on receipt.
    stream_id = _read_u32(stream, header + 5) & _STREAM_ID_MASK
    payload_start = header + _FRAME_HEADER_LEN

    if frame_type != _FRAME_SETTINGS or flags & _FLAG_ACK or stream_id != 0:
        return None
    if frame_length % _SETTINGS_ENTRY_LEN or frame_length > end - payload_start:
        return None

    settings = tuple(
        (
            _read_u16(stream, offset),
            _read_u32(stream, offset + 2),
        )
        for offset in range(payload_start, payload_start + frame_length, _SETTINGS_ENTRY_LEN)
    )
    return Http2Settings(settings=settings)
