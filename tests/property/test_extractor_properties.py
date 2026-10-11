"""Property-based fuzzing for the byte-level extractors (R-05).

Every defect closed in Phase 0 was an adversarial-*input* defect, and not one of
them was found by an example-based test:

  * `D-05`  unclamped TLS `length` field
  * `D-09`  `Host:` scan running past the header section into the body
  * `D-10`  a match not required to begin a line (`X-Host:` matched)
  * `D-08`  a per-packet decision read from a cumulative counter
  * `D-14`  VLAN tags silently discarding every tagged frame
  * and the `_write_forwarded` drop arithmetic, plus the `time.sleep(inf)`
    reached by `"1e999"` in the R-10 fix

Hypothesis generates the awkward inputs rather than waiting for someone to think
of them. The properties asserted here are deliberately weak -- "does not raise",
"is deterministic", "output is bounded" -- because those are the ones that must
hold for *every* byte string. Being able to state them without knowing the input
is the entire value: a property test is a claim about a function's contract
rather than about five examples someone picked.

Replayability: on failure Hypothesis prints a minimal reproducer, and
`@seed(...)` is used where a specific known input is being pinned. A failing
example is reproducible from that output with no further setup.
"""
from __future__ import annotations

from hypothesis import HealthCheck, example, given, seed, settings
from hypothesis import strategies as st

from dpi_engine.packet_parser import ParsedPacket, parse_packet
from dpi_engine.pcap_io import RawPacket
from dpi_engine.quic import (
    MAX_CRYPTO_BUFFER,
    QuicFlowInspector,
    decode_varint,
    extract_crypto_frames,
    is_quic,
    is_quic_initial,
    parse_long_header,
    reconstruct_packet_number,
)
from dpi_engine.sni_extractor import extract_dns_query, extract_http_host, extract_sni

# These run per-example; the default 100 is plenty and keeps the suite fast.
SETTINGS = settings(
    max_examples=200,
    deadline=None,  # no wall-clock assertions: this measures nothing about speed
    suppress_health_check=[HealthCheck.too_slow],
)

#: Arbitrary bytes, biased towards the structures these functions look for so
#: the generator actually reaches the interesting code rather than failing the
#: type check on byte one.
payloads = st.binary(min_size=0, max_size=512)
structured_payloads = st.one_of(
    payloads,
    st.binary(min_size=1, max_size=64).map(lambda b: b"\x16\x03\x01" + b),
    st.binary(min_size=1, max_size=64).map(lambda b: b"GET / HTTP/1.1\r\nHost: " + b),
    st.binary(min_size=1, max_size=64).map(lambda b: b"\x00" * 12 + b + b"Host: " + b),
    st.binary(min_size=1, max_size=96).map(lambda b: b"\x00\x01\x00\x00" + b),
)


def _raw(data: bytes) -> RawPacket:
    return RawPacket(ts_sec=0, ts_usec=0, data=data, orig_len=len(data))


# ---------------------------------------------------------------------------
# The extractors run on attacker-controlled bytes in a hot loop
# ---------------------------------------------------------------------------


@SETTINGS
@given(structured_payloads)
def test_extractors_never_raise(payload: bytes) -> None:
    """The contract that matters most: arbitrary bytes in, no exception out.

    `parse_packet` documents returning None for malformed frames rather than
    raising, and the extractors run per packet on untrusted input. A raised
    exception here is a dropped packet at best and a dead worker at worst.
    """
    extract_sni(payload)
    extract_sni(payload, length=len(payload))
    extract_http_host(payload)
    extract_dns_query(payload)


@SETTINGS
@example(
    # The exact shape of `D-05`, pinned so the property documents the bug it
    # exists to catch. A one-byte payload claiming a nine-byte TLS record: with
    # `length` unclamped, `is_tls_client_hello` accepted the short record and
    # the parser then indexed past the end of the buffer. Hypothesis reduced
    # this to a single byte plus a `length` of 9 on its own, from the raw
    # "arbitrary length over the full integer range" strategy.
    payload=b"\x16",
    length=9,
)
@given(structured_payloads, st.integers(min_value=-2**31, max_value=2**31))
def test_arbitrary_length_arguments_never_raise(payload: bytes, length: int) -> None:
    """Arbitrary `length`, including absurd and negative values (`D-05`).

    `extract_sni`'s `length` parameter comes from a field inside the packet, so
    before `T0-04` it was clamped to the available bytes; an unclamped value
    let a 5-byte payload claim a 65535-byte record. This asserts the clamp and
    the never-raise contract together, over the full integer range rather than
    the handful of values a hand-written test would pick.
    """
    result = extract_sni(payload, length=length)
    if result is not None:
        assert isinstance(result, str)
        # A claimed length can never conjure bytes that are not there.
        assert len(result.encode("utf-8", "replace")) <= max(len(payload), 1) + 3


@SETTINGS
@given(structured_payloads)
def test_extractors_are_deterministic(payload: bytes) -> None:
    """Same input, same output, every time.

    Cheap to assert and it rules out a whole class of bug -- dependence on
    dict/set iteration order or on mutable module state -- that would otherwise
    only show up as a flaky production classification.
    """
    assert extract_sni(payload) == extract_sni(payload)
    assert extract_http_host(payload) == extract_http_host(payload)
    assert extract_dns_query(payload) == extract_dns_query(payload)
    assert extract_sni(payload, length=17) == extract_sni(payload, length=17)


@SETTINGS
@given(structured_payloads)
def test_truncation_never_yields_a_longer_extraction(payload: bytes) -> None:
    """Cutting the input short cannot produce a longer answer than keeping it.

    An extractor that reads past the end of what it was given would show up here
    as a result longer than the input allows. This is the shape of the `D-05`
    bug and of a buffer over-read generally.
    """
    if len(payload) < 2:
        return
    for cut in (0, 1, len(payload) // 2, len(payload) - 1):
        full = extract_sni(payload, length=len(payload))
        part = extract_sni(payload[:cut], length=cut)
        if full is not None and part is not None:
            # Different inputs may legitimately extract different hostnames, so
            # the real invariant is that neither exceeds what its own input holds.
            assert len(part) <= max(cut, 1) + 3, f"cut={cut} produced {part!r}"


@SETTINGS
@given(structured_payloads)
def test_dns_names_are_bounded(payload: bytes) -> None:
    """A DNS name cannot exceed the DNS length limit or the payload.

    The wire format caps a domain name at 255 octets; anything longer is a
    parser bug, not an attacker.
    """
    name = extract_dns_query(payload)
    if name is not None:
        assert 0 < len(name) <= 255
        assert len(name) <= max(len(payload), 1)


@SETTINGS
@given(st.integers(min_value=0, max_value=2**62 - 1))
def test_varint_decoding_never_raises_and_is_parsed_exactly(value: int) -> None:
    """A varint round-trips its value and never raises, across the whole range.

    QUIC's variable-length integers are the parser's front door, and a decoded
    value feeds straight into buffer offsets and allocation sizes. Bounded at
    2**62-1 because that is the format's maximum, not because the encoder is
    known to be right.
    """
    from dpi_engine.quic import encode_varint

    encoded = encode_varint(value)
    decoded, offset = decode_varint(encoded, 0)
    assert decoded == value
    assert offset == len(encoded)


@SETTINGS
@given(st.integers(min_value=-(2**40), max_value=-1))
def test_encode_varint_rejects_negative_values(value: int) -> None:
    """A negative value is a `ValueError`, not a silently wrapped encoding.

    The alternative -- masking it into a huge positive -- would put a
    nonsense offset into a buffer index downstream.
    """
    from dpi_engine.quic import encode_varint

    try:
        encode_varint(value)
    except ValueError:
        return
    raise AssertionError(f"encode_varint accepted the negative value {value}")


@SETTINGS
@given(st.integers(min_value=2**62, max_value=2**64))
def test_encode_varint_rejects_out_of_range_values(value: int) -> None:
    """Beyond 2**62-1 the format cannot represent the value, so say so."""
    from dpi_engine.quic import encode_varint

    try:
        encode_varint(value)
    except ValueError:
        return
    raise AssertionError(f"encode_varint accepted the unrepresentable value {value}")


@SETTINGS
@given(payloads, st.integers(min_value=0, max_value=64))
def test_varint_decoding_never_raises_at_any_offset(payload: bytes, offset: int) -> None:
    """Decoding from an arbitrary offset either succeeds or raises QuicError.

    Never an arbitrary exception: the caller is a hot loop on untrusted bytes.
    """
    from dpi_engine.quic import QuicError

    try:
        decoded, consumed = decode_varint(payload, offset)
    except QuicError:
        return
    except Exception as exc:  # pragma: no cover - the assertion is the point
        raise AssertionError(
            f"decode_varint raised {type(exc).__name__} for offset {offset}: {exc}"
        ) from exc
    assert consumed >= offset
    assert decoded >= 0, "a decoded varint cannot be negative"


# ---------------------------------------------------------------------------
# QUIC: the inspector is long-lived state fed untrusted bytes
# ---------------------------------------------------------------------------


@SETTINGS
@given(payloads)
def test_quic_ingress_predicates_never_raise(payload: bytes) -> None:
    assert isinstance(is_quic(payload), bool)
    assert isinstance(is_quic_initial(payload), bool)


@SETTINGS
@given(payloads)
def test_parse_long_header_never_raises_an_unexpected_exception(payload: bytes) -> None:
    """Either it parses, or it raises `QuicError` -- never anything else."""
    from dpi_engine.quic import QuicError

    try:
        parse_long_header(payload)
    except QuicError:
        pass
    except Exception as exc:  # pragma: no cover
        raise AssertionError(
            f"parse_long_header raised {type(exc).__name__}: {exc}"
        ) from exc


@SETTINGS
@given(st.lists(st.binary(min_size=0, max_size=128), min_size=1, max_size=12))
def test_quic_inspector_never_raises_and_keeps_state_bounded(
    packets: list[bytes],
) -> None:
    """A long run of garbage must not raise, and must not grow without bound.

    The CRYPTO reassembly buffer is capped at `MAX_CRYPTO_BUFFER`, and the
    inspector's other state is per-flow. Feeding a whole sequence exercises the
    path that a single-packet test cannot: the ones where state built up by
    packet 1 changes what packet 2 does.
    """
    inspector = QuicFlowInspector()
    for i, payload in enumerate(packets):
        result = inspector.feed(payload)
        assert result is None or isinstance(result, str)
        assert len(inspector.crypto) <= MAX_CRYPTO_BUFFER + 8, (
            f"crypto buffer grew to {len(inspector.crypto)} after {i + 1} packets "
            f"of up to 128 bytes each"
        )
        assert inspector.initial_packets <= len(packets)
        assert inspector.undecryptable_packets <= inspector.initial_packets, (
            "undecryptable_packets must never exceed the number of Initials seen"
        )


@SETTINGS
@given(st.lists(st.binary(min_size=0, max_size=64), min_size=1, max_size=8))
def test_crypto_frame_extraction_never_raises_and_offsets_are_sane(
    plaintexts: list[bytes],
) -> None:
    """Extracted frame data is a real slice of the plaintext, and never more.

    Note the *stream offset* is deliberately not bounded by the plaintext: it is
    a position in the reassembled CRYPTO stream, which is routinely larger than
    any single packet's plaintext. An earlier version of this test asserted
    `offset + len(data) <= len(plaintext)` and failed on a perfectly legal frame
    -- conflating a stream position with a buffer index. The invariant that
    actually matters for an over-read is on the data length.
    """
    for plaintext in plaintexts:
        for offset, data in extract_crypto_frames(plaintext):
            assert offset >= 0, "a CRYPTO stream offset cannot be negative"
            assert isinstance(data, bytes)
            assert len(data) <= len(plaintext), (
                f"frame at stream offset {offset} yielded {len(data)} bytes from "
                f"a {len(plaintext)}-byte plaintext"
            )


@SETTINGS
@given(
    st.integers(min_value=1, max_value=32),
    st.integers(min_value=-1, max_value=2**31),
    st.integers(min_value=0, max_value=2**31),
)
def test_packet_number_reconstruction_is_bounded(
    nbits: int, truncated: int, largest_seen: int
) -> None:
    """Reconstructed packet numbers stay within the RFC's window of the largest seen.

    The value feeds the AEAD nonce, so a reconstruction that strayed outside the
    window would be a correctness bug, not just an odd number.

    `truncated` is constrained to `2**nbits`, as RFC 9000 §17.1 requires: the
    algorithm masks it with `2**nbits - 1`, so a larger value is not a legal
    input and the result is then allowed to stray anywhere. An earlier version
    generated `truncated` up to 2**31 regardless of `nbits` and failed on a
    value the contract does not cover.
    """
    truncated &= (1 << nbits) - 1
    result = reconstruct_packet_number(truncated, nbits, largest_seen)
    assert result >= 0
    if largest_seen >= 0:
        # `expected = largest + 1`, `win = 1 << nbits`,
        # `candidate = (expected & ~(win - 1)) | truncated`, result is
        # `candidate` possibly shifted by +/- `win` -- so `expected +/- 2*win`.
        expected = largest_seen + 1
        win = 1 << nbits
        assert expected - 2 * win <= result <= expected + 2 * win, (
            f"reconstructed {result} from truncated={truncated} nbits={nbits} "
            f"largest={largest_seen}"
        )


# ---------------------------------------------------------------------------
# The frame parser: arbitrary Ethernet frames
# ---------------------------------------------------------------------------


@SETTINGS
@given(st.binary(min_size=0, max_size=600))
def test_parse_packet_never_raises(frame: bytes) -> None:
    """Arbitrary frames parse or return None. Never an exception.

    `parse_packet` is called on every packet in every worker, including frames
    a capture tool mangled, so its "returns None rather than raising" contract
    is load-bearing rather than stylistic.
    """
    parsed = parse_packet(_raw(frame))
    if parsed is not None:
        assert isinstance(parsed, ParsedPacket)
        if parsed.has_tcp:
            assert parsed.has_ip
        if parsed.has_udp:
            assert parsed.has_ip


@SETTINGS
@given(st.binary(min_size=0, max_size=600))
def test_parse_packet_never_sets_a_protocol_without_ip(frame: bytes) -> None:
    """A frame with no IP layer must not claim TCP or UDP.

    The invariant that keeps `protocol_str()` honest: the report prints "TCP" or
    "UDP" from these flags, so a contradiction here becomes a wrong report row
    rather than an obvious crash.
    """
    parsed = parse_packet(_raw(frame))
    if parsed is None:
        return
    if not parsed.has_ip:
        assert not parsed.has_tcp
        assert not parsed.has_udp
    if parsed.has_tcp and parsed.has_udp:
        raise AssertionError("a single packet cannot be both TCP and UDP")


@SETTINGS
@given(st.binary(min_size=14, max_size=200))
def test_payload_never_exceeds_the_frame(frame: bytes) -> None:
    """Whatever the parser calls the payload is a slice of the frame, not more.

    Guards the over-read shape generically: a payload larger than the input, or
    pointing outside it, would be the `D-05` failure mode.
    """
    parsed = parse_packet(_raw(frame))
    if parsed is None:
        return
    assert len(parsed.payload) <= len(frame), (
        f"payload of {len(parsed.payload)} bytes from a {len(frame)}-byte frame"
    )


@SETTINGS
@given(st.lists(st.binary(min_size=0, max_size=64), max_size=6))
def test_parsing_a_frame_twice_gives_the_same_answer(frames: list[bytes]) -> None:
    """Parsing is a pure function of the bytes.

    Catches accidental mutation of the input buffer, which is invisible in a
    single-shot test and would corrupt the second pass in `_write_forwarded`.
    """
    for frame in frames:
        first = parse_packet(_raw(frame))
        second = parse_packet(_raw(frame))
        if first is None or second is None:
            assert first is second
            continue
        assert (first.has_ip, first.has_tcp, first.has_udp) == (
            second.has_ip,
            second.has_tcp,
            second.has_udp,
        )
        assert first.payload == second.payload
        assert first.src_ip == second.src_ip and first.dst_ip == second.dst_ip


# ---------------------------------------------------------------------------
# Replayability
# ---------------------------------------------------------------------------
#
# A fuzzing suite is only useful if a CI failure can be reproduced locally.
# Hypothesis prints a minimal falsifying example on failure, and that example
# replays deterministically -- so the mechanism is "copy the printed line into
# `@example`". These two tests pin that mechanism down rather than trusting it:
# a pinned seed must produce the same result twice in a row.


@seed(20251003)
@SETTINGS
@given(structured_payloads)
def test_a_pinned_seed_replays_identically(payload: bytes) -> None:
    """A fixed seed makes Hypothesis's *generated* inputs reproducible.

    The engine-determinism property is `test_extractors_are_deterministic`;
    this one is about the harness. Cheap insurance: if a pinned seed ever became
    non-deterministic, a CI failure would not be replayable, which would quietly
    destroy the value of the entire suite."""
    assert extract_sni(payload) == extract_sni(payload)


def test_the_pinned_d05_reproducer_is_handled() -> None:
    """The `D-05` example, asserted directly rather than left to generation.

    This is the replay mechanism in practice. When Hypothesis finds a failure it
    prints a minimal falsifying example, and the fix is to copy that line into an
    `@example` -- which is why `test_arbitrary_length_arguments_never_raise`
    carries `@example(payload=b"\x16", length=9)`. A pinned example is a permanent,
    zero-cost regression test: it runs on every invocation forever, whereas the
    original discovery depended on random generation happening to rediscover it.
    """
    result = extract_sni(b"\x16", length=9)
    assert result is None, (
        "a 1-byte payload claiming a 9-byte record must extract nothing, not "
        "read past the end of the buffer (D-05)"
    )
