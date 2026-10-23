"""The HTTP/2 SETTINGS fingerprint (`T5-02`).

What the string is, and what it is not
-------------------------------------
RFC 9113 section 3.4 requires a client to open an HTTP/2 connection with the
24-byte preface ``PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n`` followed immediately by
a SETTINGS frame. The fingerprint below is that frame's entries in **arrival
order**, rendered ``id:value`` and joined with ``;`` -- the settings half of the
"Akamai" HTTP/2 fingerprint, which is how the value is published (for example a
Chrome client's ``1:65536;2:0;3:1000;4:6291456;6:262144``). Order is part of the
value: two clients that send the same six settings in a different order are
different clients.

The rest of that published fingerprint -- the connection-level WINDOW_UPDATE
increment and the PRIORITY frames -- is **not** included, because this task's
gate names the SETTINGS frame. A consumer that needs the full Akamai string must
not mistake this prefix for it, so the module says so in its docstring.

Reachability
------------
Over TLS the preface is inside the encrypted stream, so this is cleartext h2c
(and a decrypted stream, where a caller has keys) only. ``None`` therefore means
"no preface and SETTINGS here", not "this was not HTTP/2".
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from dpi_engine.http2 import Http2Settings, fingerprint_http2_settings

#: The client connection preface, written out independently of the module.
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

#: A published Chrome SETTINGS set, in the order Chrome sends it.
CHROME = ((1, 65536), (2, 0), (3, 1000), (4, 6291456), (6, 262144))
CHROME_FINGERPRINT = "1:65536;2:0;3:1000;4:6291456;6:262144"


def _u16(value: int) -> bytes:
    return bytes([(value >> 8) & 0xFF, value & 0xFF])


def _u24(value: int) -> bytes:
    return bytes([(value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])


def _u32(value: int) -> bytes:
    return bytes([(value >> 24) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])


def _settings_payload(entries: tuple[tuple[int, int], ...]) -> bytes:
    return b"".join(_u16(identifier) + _u32(value) for identifier, value in entries)


def _frame(
    payload: bytes,
    *,
    frame_type: int = 0x04,
    flags: int = 0x00,
    stream: int = 0,
    declared_length: int | None = None,
) -> bytes:
    length = len(payload) if declared_length is None else declared_length
    return _u24(length) + bytes([frame_type, flags]) + _u32(stream) + payload


def _http2(*frames: bytes, preface: bytes = PREFACE) -> bytes:
    return preface + b"".join(frames)


def _fingerprint(stream: bytes) -> Http2Settings:
    found = fingerprint_http2_settings(stream)
    assert found is not None, "the preface and SETTINGS were expected to parse"
    return found


# ---------------------------------------------------------------------------
# The published shape
# ---------------------------------------------------------------------------


def test_chrome_settings_render_as_the_published_string() -> None:
    found = _fingerprint(_http2(_frame(_settings_payload(CHROME))))
    assert found.settings == CHROME
    assert found.fingerprint == CHROME_FINGERPRINT


def test_the_arrival_order_is_the_fingerprint() -> None:
    reordered = tuple(reversed(CHROME))
    found = _fingerprint(_http2(_frame(_settings_payload(reordered))))
    assert found.settings == reordered
    assert found.fingerprint == "6:262144;4:6291456;3:1000;2:0;1:65536"
    assert found.fingerprint != CHROME_FINGERPRINT


def test_an_empty_settings_frame_is_a_fact_not_an_absence() -> None:
    found = _fingerprint(_http2(_frame(b"")))
    assert found.settings == ()
    assert found.fingerprint == ""


def test_unknown_setting_identifiers_are_kept_as_sent() -> None:
    entries = ((0xFFFF, 1), (0x0007, 0))
    found = _fingerprint(_http2(_frame(_settings_payload(entries))))
    assert found.fingerprint == "65535:1;7:0"


def test_the_reserved_bit_of_the_stream_identifier_is_ignored() -> None:
    # RFC 9113 section 4.1: the high bit is reserved and must be ignored on
    # receipt, so a frame on stream 0 with it set is still the client's SETTINGS.
    frame = _frame(_settings_payload(CHROME), stream=0x80000000)
    assert _fingerprint(_http2(frame)).fingerprint == CHROME_FINGERPRINT


def test_a_frame_after_the_settings_is_out_of_scope_and_changes_nothing() -> None:
    window_update = _frame(_u32(15663105), frame_type=0x08)
    found = _fingerprint(_http2(_frame(_settings_payload(CHROME)), window_update))
    assert found.fingerprint == CHROME_FINGERPRINT


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "preface",
    [
        pytest.param(b"", id="no-preface"),
        pytest.param(PREFACE[:-1], id="truncated"),
        pytest.param(PREFACE.replace(b"SM", b"SN"), id="one-byte-wrong"),
        pytest.param(PREFACE + b"X", id="one-byte-long"),
    ],
)
def test_a_wrong_preface_is_refused(preface: bytes) -> None:
    stream = preface + _frame(_settings_payload(CHROME))
    assert fingerprint_http2_settings(stream) is None


def test_a_preface_without_a_frame_is_not_a_fingerprint() -> None:
    assert fingerprint_http2_settings(PREFACE) is None


def test_a_settings_ack_is_not_a_client_fingerprint() -> None:
    stream = _http2(_frame(b"", flags=0x01))
    assert fingerprint_http2_settings(stream) is None


def test_the_first_frame_must_be_on_stream_zero() -> None:
    stream = _http2(_frame(_settings_payload(CHROME), stream=1))
    assert fingerprint_http2_settings(stream) is None


def test_a_frame_other_than_settings_is_refused() -> None:
    stream = _http2(_frame(b"", frame_type=0x08))
    assert fingerprint_http2_settings(stream) is None


def test_a_settings_length_that_is_not_a_multiple_of_six_is_refused() -> None:
    stream = _http2(_frame(_settings_payload(CHROME), declared_length=5))
    assert fingerprint_http2_settings(stream) is None


def test_a_frame_that_overruns_the_stream_is_refused() -> None:
    stream = _http2(_frame(_settings_payload(CHROME), declared_length=100))
    assert fingerprint_http2_settings(stream) is None


def test_every_truncation_of_the_preface_and_frame_is_refused() -> None:
    stream = _http2(_frame(_settings_payload(CHROME)))
    for cut in range(len(stream)):
        assert fingerprint_http2_settings(stream[:cut]) is None, f"prefix of {cut} bytes"


def test_a_length_argument_beyond_the_buffer_is_clamped() -> None:
    stream = _http2(_frame(_settings_payload(CHROME)))
    assert fingerprint_http2_settings(stream, len(stream) + 1000) is not None
    assert fingerprint_http2_settings(stream, len(stream) - 1) is None


@given(st.binary(max_size=512))
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_arbitrary_bytes_never_raise(blob: bytes) -> None:
    found = fingerprint_http2_settings(blob)
    if found is not None:
        assert found.fingerprint == ";".join(f"{i}:{v}" for i, v in found.settings)


def test_the_module_says_the_akamai_string_is_only_half_produced() -> None:
    import dpi_engine.http2 as module

    text = module.__doc__ or ""
    assert "WINDOW_UPDATE" in text
    assert "PRIORITY" in text
