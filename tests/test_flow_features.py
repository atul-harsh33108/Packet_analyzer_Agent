"""The per-flow feature vector (`T5-03`).

What this file is for
---------------------
`T5-01` computes a ClientHello's features and `T5-02` the certificate, the
SNI-absence fact and the HTTP/2 SETTINGS fingerprint, but nothing **carried**
them anywhere: they were contracts with no consumer. This task is the wiring,
and the wiring is the whole claim -- *a flow's features are attached to its
row, the store's schema says so, and an old record is refused rather than read
through new field meanings*.

So the tests come in three layers and none of them is redundant:

1. **The observation.** One TCP payload goes in; the vector comes out. The bytes
   are built here, frame by frame, and the expected values that could come from
   somewhere other than the implementation do: the certificate's names and dates
   are what OpenSSL reported for those DER bytes (the fixture lives in
   `tests/test_tls_certificate.py`, imported rather than copied so the two
   cannot drift), and the chrome-shaped HTTP/2 string is the published one.
2. **The row.** `Connection` -> `to_flow_records` -> `FlowRecord` -> the store's
   JSON codec, including the one thing a vector in a row must not do: read as
   "empty" when it was never recorded.
3. **The run.** Synthetic pcaps through `run_pipeline`, because a feature can be
   extracted correctly, stored correctly, and still never reach a row if the
   hot path does not call the observer. This layer is the only one that would
   catch that.

Two facts about direction
------------------------
A flow is folded (`DEC-05`), so the client's hello and the server's flight land
on **one** row, and the vector is assembled from both. But a payload on its own
does not say which side sent it, so a certificate is only attributed when the
same buffer also carries the ServerHello that opened the flight. A `Certificate`
record arriving alone could be the client's (mutual TLS) and calling it the
server's would be a wrong fact; the cost is that a flight split across packets
yields no certificate, which is recorded rather than guessed.

Reachability, restated for the wired-up version
-----------------------------------------------
* A TLS 1.3 `Certificate` is ciphertext: `certificate is None` means "not
  visible", never "absent".
* An HTTP/2 SETTINGS frame over TLS is ciphertext too, so `http2_settings` is
  populated for cleartext h2c (or a decrypted stream) only.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from dpi_engine.connection_tracker import to_flow_records
from dpi_engine.flow_features import FlowFeatures, observe_flow_features
from dpi_engine.pcap_io import PcapWriter, RawPacket
from dpi_engine.pipeline import run_pipeline
from dpi_engine.run_store import flow_from_json, flow_to_json
from dpi_engine.tls_certificate import CertificateFeatures
from dpi_engine.tls_fingerprint import fingerprint_client_hello, fingerprint_server_hello
from dpi_engine.types import Connection, FiveTuple, FlowRecord
from test_tls_certificate import _CA_SUBJECT, _LEAF_DER, _LEAF_SUBJECT, _WEIRD_DER
from test_tls_fingerprint import ja4_vector_hello

# ---------------------------------------------------------------------------
# Byte builders -- the TLS framing, written here
# ---------------------------------------------------------------------------


def _u16(value: int) -> bytes:
    return bytes([(value >> 8) & 0xFF, value & 0xFF])


def _u24(value: int) -> bytes:
    return bytes([(value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])


def _u32(value: int) -> bytes:
    return bytes(
        [(value >> 24) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF]
    )


def _record(payload: bytes, *, content_type: int = 0x16, version: int = 0x0303) -> bytes:
    return bytes([content_type]) + _u16(version) + _u16(len(payload)) + payload


def _handshake(handshake_type: int, body: bytes) -> bytes:
    return bytes([handshake_type]) + _u24(len(body)) + body


def _extension(extension_type: int, body: bytes = b"") -> bytes:
    return _u16(extension_type) + _u16(len(body)) + body


def _u16_vector(values: tuple[int, ...]) -> bytes:
    raw = b"".join(_u16(v) for v in values)
    return _u16(len(raw)) + raw


def _byte_vector(raw: bytes) -> bytes:
    return bytes([len(raw)]) + raw


def _sni_body(hostname: str = "example.com") -> bytes:
    raw = hostname.encode("ascii")
    entry = b"\x00" + _u16(len(raw)) + raw
    return _u16(len(entry)) + entry


def _alpn_body(protocols: tuple[bytes, ...]) -> bytes:
    entries = b"".join(bytes([len(p)]) + p for p in protocols)
    return _u16(len(entries)) + entries


def _client_hello(
    *,
    hostname: str | None = "example.com",
    alpn: tuple[bytes, ...] = (b"h2", b"http/1.1"),
    grease: bool = True,
) -> bytes:
    """A TLS 1.3-shaped ClientHello with the extensions a browser sends.

    The extension order is deliberately **not** ascending, because arrival order
    is part of the feature and a builder that happened to sort would let a
    sorting bug pass.
    """
    ciphers = (0xC02B, 0x1301, 0x1302)
    if grease:
        ciphers = (0x0A0A, *ciphers)
    extensions = b""
    if hostname is not None:
        extensions += _extension(0x0000, _sni_body(hostname))
    if alpn:
        extensions += _extension(0x0010, _alpn_body(alpn))
    versions = (0x0304, 0x0303)
    extensions += _extension(0x002B, _byte_vector(b"".join(_u16(v) for v in versions)))
    extensions += _extension(0x000A, _u16_vector((0x001D, 0x0017)))
    extensions += _extension(0x000D, _u16_vector((0x0403, 0x0804)))
    extensions += _extension(0x000B, _byte_vector(b"\x00"))

    body = _u16(0x0303) + b"\x11" * 32 + b"\x00" + _u16_vector(ciphers) + b"\x01\x00"
    body += _u16(len(extensions)) + extensions
    return _record(_handshake(0x01, body))


def _server_hello_body(*, tls13: bool, alpn: bytes | None = None) -> bytes:
    body = _u16(0x0303) + b"\x22" * 32 + b"\x00" + _u16(0xC02F) + b"\x00"
    extensions = b""
    if alpn is not None:
        extensions += _extension(0x0010, _alpn_body((alpn,)))
    if tls13:
        # RFC 8446 4.2.1: in a ServerHello, supported_versions carries the
        # selected version as a bare uint16 -- NOT the client's vector form.
        extensions += _extension(0x002B, _u16(0x0304))
        extensions += _extension(0x0033, _u16(0x001D) + b"\x00\x20" + b"\x99" * 32)
    body += _u16(len(extensions)) + extensions
    return body


def _certificate_message(der: bytes = _LEAF_DER) -> bytes:
    entry = _u24(len(der)) + der
    return _handshake(0x0B, _u24(len(entry)) + entry)


def _server_flight(
    *,
    tls13: bool = False,
    certificate: bytes | None = _LEAF_DER,
    alpn: bytes | None = None,
) -> bytes:
    """One TLS record carrying ServerHello, then (for TLS 1.2) the Certificate."""
    messages = _handshake(0x02, _server_hello_body(tls13=tls13, alpn=alpn))
    if certificate is not None:
        messages += _certificate_message(certificate)
    return _record(messages)


#: The client connection preface, and a published Chrome SETTINGS set.
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
CHROME_SETTINGS = ((1, 65536), (2, 0), (3, 1000), (4, 6291456), (6, 262144))
CHROME_FINGERPRINT = "1:65536;2:0;3:1000;4:6291456;6:262144"


def _http2_stream(entries: tuple[tuple[int, int], ...] = CHROME_SETTINGS) -> bytes:
    payload = b"".join(_u16(identifier) + _u32(value) for identifier, value in entries)
    frame = _u24(len(payload)) + b"\x04\x00" + _u32(0) + payload
    return PREFACE + frame


# ---------------------------------------------------------------------------
# Section A -- the client half
# ---------------------------------------------------------------------------


def test_a_client_hello_fills_the_client_half_and_only_it() -> None:
    hello = _client_hello()
    observed = observe_flow_features(hello)
    expected = fingerprint_client_hello(hello)
    assert expected is not None

    assert observed.ja3 == expected.ja3
    assert observed.ja4 == expected.ja4
    assert observed.sni_present is True
    assert observed.client_version == 0x0303
    assert observed.tls_versions == expected.version_histogram
    assert observed.cipher_suites == expected.cipher_suites
    # Arrival order as sent -- deliberately not ascending -- because the order is
    # part of what a signature matches.
    assert observed.extensions == (0x0000, 0x0010, 0x002B, 0x000A, 0x000D, 0x000B)
    assert observed.alpn == ("h2", "http/1.1")
    assert observed.grease == expected.grease_values

    # The server and transport halves stay empty: nothing was observed for them.
    assert observed.ja3s == ""
    assert observed.ja4s == ""
    assert observed.server_cipher_suite is None
    assert observed.server_extensions == ()
    assert observed.certificate is None
    assert observed.http2_settings is None


def test_the_published_ja4_hello_carries_its_published_value_into_the_vector() -> None:
    """FoxIO's worked example, through the observer, still says `t13d1516h2_...`."""
    observed = observe_flow_features(ja4_vector_hello())
    assert observed.ja4 == "t13d1516h2_8daaf6152771_e5627efa2ab1"


def test_a_hello_without_sni_is_a_false_flag_not_a_missing_one() -> None:
    without = observe_flow_features(_client_hello(hostname=None))
    assert without.sni_present is False
    assert without.ja3 != ""


def test_grease_is_removed_from_the_lists_and_kept_as_a_fact() -> None:
    observed = observe_flow_features(_client_hello(grease=True))
    assert 0x0A0A in observed.grease
    assert 0x0A0A not in observed.cipher_suites


def test_a_client_that_offers_no_alpn_has_an_empty_offer() -> None:
    observed = observe_flow_features(_client_hello(alpn=()))
    assert observed.alpn == ()


def test_a_non_ascii_alpn_is_carried_byte_for_byte() -> None:
    """ALPN tokens are bytes; latin-1 is the encoding that loses none of them."""
    observed = observe_flow_features(_client_hello(alpn=(b"\x80x",)))
    assert observed.alpn == ("\x80x",)


# ---------------------------------------------------------------------------
# Section B -- the server half
# ---------------------------------------------------------------------------


def test_a_server_flight_fills_the_server_half_and_only_it() -> None:
    flight = _server_flight(tls13=False, certificate=None)
    observed = observe_flow_features(flight)
    expected = fingerprint_server_hello(flight)
    assert expected is not None

    assert observed.ja3s == expected.ja3s
    assert observed.ja4s == expected.ja4s
    assert observed.server_cipher_suite == 0xC02F
    assert observed.server_extensions == expected.extensions

    assert observed.ja3 == ""
    assert observed.ja4 == ""
    assert observed.sni_present is None


def test_a_real_tls13_server_hello_reaches_the_vector() -> None:
    """The shape almost all modern traffic has, so the vector must not miss it.

    `T5-01` read the ServerHello's supported_versions with the ClientHello's
    vector form and refused every conformant TLS 1.3 ServerHello; wiring the
    server half is what exposed it. The parser-level regression is in
    `tests/test_tls_fingerprint.py`; here it is the row's half that is pinned.
    """
    flight = _server_flight(tls13=True, certificate=None)
    observed = observe_flow_features(flight)

    assert observed.ja3s != ""
    assert observed.ja4s != ""
    assert observed.server_extensions == (0x002B, 0x0033)


# ---------------------------------------------------------------------------
# Section C -- the certificate
# ---------------------------------------------------------------------------


def test_the_certificate_from_the_server_flight_reaches_the_vector() -> None:
    observed = observe_flow_features(_server_flight())
    certificate = observed.certificate
    assert certificate is not None
    # The names are OpenSSL's rendering of these DER bytes, not this parser's.
    assert certificate.issuer == _CA_SUBJECT
    assert certificate.subject == _LEAF_SUBJECT
    assert certificate.not_valid_before == datetime(2024, 3, 1, tzinfo=UTC)
    assert certificate.not_valid_after == datetime(2026, 3, 1, tzinfo=UTC)


def test_a_certificate_in_a_later_record_of_the_same_buffer_is_found() -> None:
    stream = _record(_handshake(0x02, _server_hello_body(tls13=False)))
    stream += _record(_certificate_message())
    observed = observe_flow_features(stream)
    assert observed.certificate is not None
    assert observed.ja3s != ""


def test_a_certificate_record_alone_is_not_attributed_to_the_server() -> None:
    """Without the ServerHello in the same buffer, the sender is unknown.

    A `Certificate` record arriving on its own could equally be the client's
    (mutual TLS). Attributing it to the server would be a wrong fact that looks
    exactly like a right one.
    """
    observed = observe_flow_features(_record(_certificate_message()))
    assert observed.is_empty


def test_a_server_hello_records_the_alpn_it_selected() -> None:
    """The server's choice is a different fact from the client's offer."""
    selected = observe_flow_features(_server_flight(tls13=False, alpn=b"h2"))
    assert selected.selected_alpn == "h2"

    silent = observe_flow_features(_server_flight(tls13=False))
    assert silent.selected_alpn == ""


def test_a_server_hello_without_a_certificate_still_fills_the_server_half() -> None:
    observed = observe_flow_features(_server_flight(tls13=True, certificate=None))
    assert observed.certificate is None
    assert observed.ja4s != ""


# ---------------------------------------------------------------------------
# Section D -- HTTP/2
# ---------------------------------------------------------------------------


def test_the_published_http2_string_reaches_the_vector() -> None:
    observed = observe_flow_features(_http2_stream())
    assert observed.http2_settings == CHROME_FINGERPRINT
    assert observed.is_empty is False


def test_an_empty_settings_frame_is_a_fingerprint_that_is_empty() -> None:
    """A client that sent SETTINGS with no entries still sent SETTINGS.

    `None` is "nothing was observed"; `""` is the fingerprint of an empty frame.
    Collapsing the two would let a flow read as fingerprinted when it was not.
    """
    observed = observe_flow_features(_http2_stream(()))
    assert observed.http2_settings == ""
    assert observed.is_empty is False
    assert FlowFeatures().http2_settings is None


def test_a_preface_without_a_settings_frame_is_not_a_fingerprint() -> None:
    assert observe_flow_features(PREFACE).is_empty


# ---------------------------------------------------------------------------
# Section E -- what must not be mistaken for a feature
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"\x17\x03\x03\x00\x10" + b"\x00" * 16, id="application-data"),
        pytest.param(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", id="http-1-1"),
        pytest.param(b"\x16\x03\x03", id="tls-header-only"),
        pytest.param(_client_hello()[:-1], id="truncated-client-hello"),
        pytest.param(_server_flight()[:-1], id="truncated-server-flight"),
        pytest.param(_http2_stream()[:-1], id="truncated-settings"),
        pytest.param(b"\x16\x03\x09\x00\x04\x01\x00\x00\x00", id="impossible-version"),
    ],
)
def test_nothing_observed_means_an_empty_vector(payload: bytes) -> None:
    assert observe_flow_features(payload).is_empty


def test_a_client_hello_split_across_records_is_refused_rather_than_guessed() -> None:
    """Reassembly is not implemented (`T5-01`'s rule), so neither is this."""
    hello = _client_hello()
    body = hello[5:]
    half = len(body) // 2
    split = _record(body[:half]) + _record(body[half:])
    assert observe_flow_features(split).is_empty


# ---------------------------------------------------------------------------
# Section F -- merging both directions onto one folded row
# ---------------------------------------------------------------------------


def test_an_empty_vector_merges_as_the_identity() -> None:
    observed = observe_flow_features(_client_hello())
    assert FlowFeatures().merged(observed) == observed
    assert observed.merged(FlowFeatures()) == observed


def test_the_two_halves_compose() -> None:
    client = observe_flow_features(_client_hello())
    server = observe_flow_features(_server_flight())

    merged = client.merged(server)
    assert merged.ja3 == client.ja3
    assert merged.ja4s == server.ja4s
    assert merged.server_extensions == server.server_extensions
    assert merged.certificate is not None
    assert merged.sni_present is True


def test_the_first_client_hello_wins_whole() -> None:
    """A retransmission is identical; a renegotiation must not rewrite the row.

    First-observation-wins is per *half*, not per field: mixing a cipher list
    from one hello with an ALPN offer from another would describe a client that
    never existed.
    """
    first = observe_flow_features(_client_hello(alpn=(b"h2",)))
    second = observe_flow_features(_client_hello(alpn=(b"http/1.1",), grease=False))

    merged = first.merged(second)
    assert merged.alpn == ("h2",)
    assert merged.ja3 == first.ja3
    assert merged.grease == first.grease


def test_the_first_server_flight_wins_whole() -> None:
    first = observe_flow_features(_server_flight())
    second = observe_flow_features(_server_flight(certificate=_WEIRD_DER))

    merged = first.merged(second)
    assert merged.ja3s == first.ja3s
    assert merged.server_extensions == first.server_extensions
    assert merged.server_cipher_suite == first.server_cipher_suite
    # Both flights carry a certificate, and they are different ones: the row
    # keeps the one the connection opened with.
    assert merged.certificate == first.certificate
    assert merged.certificate is not None
    assert merged.certificate.subject == _LEAF_SUBJECT


def test_the_first_http2_settings_win() -> None:
    first = observe_flow_features(_http2_stream())
    second = observe_flow_features(_http2_stream(((1, 65536), (4, 65535))))
    assert second.http2_settings == "1:65536;4:65535"

    assert first.merged(second).http2_settings == CHROME_FINGERPRINT


def test_http2_settings_fill_independently_of_the_tls_halves() -> None:
    tls = observe_flow_features(_server_flight(tls13=True, certificate=None))
    h2 = observe_flow_features(_http2_stream())
    merged = tls.merged(h2)
    assert merged.ja4s == tls.ja4s
    assert merged.http2_settings == CHROME_FINGERPRINT


# ---------------------------------------------------------------------------
# Section G -- the codec
# ---------------------------------------------------------------------------


def _full_vector() -> FlowFeatures:
    return FlowFeatures(
        ja3="f" * 32,
        ja4="t13d1516h2_8daaf6152771_e5627efa2ab1",
        ja3s="e" * 32,
        ja4s="t130200_1301_a56c5b993250",
        sni_present=True,
        client_version=0x0303,
        tls_versions=((0x0303, 1), (0x0304, 2)),
        cipher_suites=(0x1301, 0x1302),
        extensions=(0x0000, 0x0010),
        alpn=("h2", "http/1.1"),
        grease=(0x0A0A,),
        server_cipher_suite=0xC02F,
        server_extensions=(0x002B, 0x0033),
        selected_alpn="h2",
        certificate=CertificateFeatures(
            issuer=_CA_SUBJECT,
            subject=_LEAF_SUBJECT,
            not_valid_before=datetime(2024, 3, 1, tzinfo=UTC),
            not_valid_after=datetime(2026, 3, 1, tzinfo=UTC),
        ),
        http2_settings=CHROME_FINGERPRINT,
    )


def test_an_empty_vector_round_trips() -> None:
    empty = FlowFeatures()
    assert FlowFeatures.from_json(empty.to_json()) == empty


def test_a_full_vector_round_trips() -> None:
    vector = _full_vector()
    assert FlowFeatures.from_json(vector.to_json()) == vector


def test_the_encoding_is_plain_json() -> None:
    payload = _full_vector().to_json()
    assert json.loads(json.dumps(payload)) == payload
    assert payload["certificate"] == {
        "issuer": _CA_SUBJECT,
        "subject": _LEAF_SUBJECT,
        "not_before": "2024-03-01T00:00:00+00:00",
        "not_after": "2026-03-01T00:00:00+00:00",
    }


def test_a_missing_key_is_refused_rather_than_defaulted() -> None:
    payload = _full_vector().to_json()
    del payload["ja3"]
    with pytest.raises(ValueError, match="ja3"):
        FlowFeatures.from_json(payload)


@pytest.mark.parametrize(
    ("key", "bad"),
    [
        pytest.param("ja3", 7, id="int-for-string"),
        pytest.param("client_version", "771", id="string-for-int"),
        pytest.param("client_version", True, id="bool-for-int"),
        pytest.param("sni_present", "yes", id="string-for-bool"),
        pytest.param("cipher_suites", [1, "2"], id="string-inside-a-list"),
        pytest.param("cipher_suites", "1301", id="string-for-a-list-of-ints"),
        pytest.param("alpn", ["h2", 2], id="int-inside-a-list-of-strings"),
        pytest.param("tls_versions", [0x0304], id="pair-of-the-wrong-shape"),
        pytest.param("tls_versions", [[0x0303, 1, 2]], id="three-element-pair"),
        pytest.param("tls_versions", "0304", id="string-for-a-list-of-pairs"),
        pytest.param("alpn", "h2", id="string-for-a-list"),
        pytest.param("http2_settings", 7, id="int-for-the-optional-string"),
        pytest.param("certificate", [], id="list-for-the-certificate"),
    ],
)
def test_a_wrongly_typed_field_is_refused(key: str, bad: object) -> None:
    payload = _full_vector().to_json()
    payload[key] = bad
    with pytest.raises(ValueError, match=key):
        FlowFeatures.from_json(payload)


def test_a_vector_that_is_not_an_object_is_refused() -> None:
    with pytest.raises(ValueError, match="object"):
        FlowFeatures.from_json([])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "moment",
    [
        pytest.param("2024-03-01T00:00:00", id="naive-no-zone"),
        pytest.param("not-a-date", id="unparseable"),
        pytest.param(0, id="not-a-string"),
    ],
)
def test_a_certificate_time_that_is_not_an_instant_is_refused(moment: object) -> None:
    payload = _full_vector().to_json()
    payload["certificate"]["not_before"] = moment
    with pytest.raises(ValueError, match="not_before"):
        FlowFeatures.from_json(payload)


def test_a_certificate_time_in_another_zone_is_normalised_to_utc() -> None:
    payload = _full_vector().to_json()
    payload["certificate"]["not_before"] = "2024-03-01T02:00:00+02:00"
    decoded = FlowFeatures.from_json(payload)
    assert decoded.certificate is not None
    assert decoded.certificate.not_valid_before == datetime(2024, 3, 1, tzinfo=UTC)


def test_a_certificate_with_a_missing_field_is_refused() -> None:
    payload = _full_vector().to_json()
    del payload["certificate"]["issuer"]
    with pytest.raises(ValueError, match="issuer"):
        FlowFeatures.from_json(payload)


# ---------------------------------------------------------------------------
# Section H -- the row
# ---------------------------------------------------------------------------


def _connection(features: FlowFeatures | None = None) -> Connection:
    return Connection(
        tuple=FiveTuple(src_ip=1, dst_ip=2, src_port=3, dst_port=4, protocol=6),
        features=FlowFeatures() if features is None else features,
    )


def test_a_flow_row_carries_the_connection_features() -> None:
    vector = observe_flow_features(_client_hello())
    rows = to_flow_records([_connection(vector)])
    assert rows[0].features == vector


def test_a_row_without_an_observation_has_an_empty_vector() -> None:
    assert _connection().features.is_empty
    assert FlowRecord(src_ip=1, dst_ip=2, src_port=3, dst_port=4, protocol=6, app="TLS", state="NEW").features.is_empty


def test_rows_stay_hashable_and_comparable_with_a_vector_on_them() -> None:
    vector = _full_vector()
    row = FlowRecord(
        src_ip=1,
        dst_ip=2,
        src_port=3,
        dst_port=4,
        protocol=6,
        app="TLS",
        state="NEW",
        features=vector,
    )
    clone = FlowRecord(**{name: getattr(row, name) for name in row.__slots__})
    assert clone == row
    assert hash(clone) == hash(row)


def test_the_vector_survives_the_process_boundary() -> None:
    """`Connection` is pickled to the parent by the multiprocess pipeline.

    The vector is therefore part of a transport contract, not only of a row: a
    field that cannot be pickled would fail the worker's result queue rather than
    the row, which is much harder to read.
    """
    import pickle

    vector = _full_vector()
    connection = Connection(
        tuple=FiveTuple(src_ip=1, dst_ip=2, src_port=3, dst_port=4, protocol=6),
        features=vector,
    )

    restored = pickle.loads(pickle.dumps(connection))

    assert restored.features == vector


def test_the_row_codec_carries_the_vector_into_json() -> None:
    vector = _full_vector()
    row = FlowRecord(
        src_ip=1,
        dst_ip=2,
        src_port=3,
        dst_port=4,
        protocol=6,
        app="TLS",
        state="NEW",
        features=vector,
    )
    payload = flow_to_json(row)
    assert payload["features"] == vector.to_json()
    assert flow_from_json(payload) == row


def test_a_row_json_without_features_is_refused() -> None:
    """The row codec is not a place to invent an empty vector."""
    payload = flow_to_json(
        FlowRecord(src_ip=1, dst_ip=2, src_port=3, dst_port=4, protocol=6, app="TLS", state="NEW")
    )
    del payload["features"]
    with pytest.raises(ValueError, match="features"):
        flow_from_json(payload)


# ---------------------------------------------------------------------------
# Section I -- the run: features on a real pipeline's rows
# ---------------------------------------------------------------------------

CLIENT = (192, 168, 1, 100)
SERVER = (142, 250, 185, 110)


def _ipv4(payload: bytes, *, src: tuple[int, int, int, int], dst: tuple[int, int, int, int]) -> bytes:
    header = bytes([0x45, 0x00]) + _u16(20 + len(payload))
    header += _u16(1) + _u16(0x4000) + bytes([64, 6]) + _u16(0)
    return header + bytes(src) + bytes(dst) + payload


def _frame(
    payload: bytes,
    *,
    sport: int,
    dport: int,
    flags: int,
    src: tuple[int, int, int, int] = CLIENT,
    dst: tuple[int, int, int, int] = SERVER,
    from_server: bool = False,
) -> RawPacket:
    if from_server:
        src, dst = dst, src
    tcp = _u16(sport) + _u16(dport) + _u32(1) + _u32(1) + bytes([0x50, flags]) + _u16(8192)
    tcp += _u16(0) + _u16(0) + payload
    frame = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + _ipv4(
        tcp, src=src, dst=dst
    )
    return RawPacket(ts_sec=1_700_000_000, ts_usec=0, data=frame, orig_len=len(frame))


def _capture(path: Path, packets: list[RawPacket]) -> Path:
    with PcapWriter(path) as writer:
        for packet in packets:
            writer.write(packet)
    return path


def _tls_flow(hello: bytes, flight: bytes) -> list[RawPacket]:
    return [
        _frame(b"", sport=48200, dport=443, flags=0x02),
        _frame(b"", sport=443, dport=48200, flags=0x12, from_server=True),
        _frame(hello, sport=48200, dport=443, flags=0x18),
        _frame(flight, sport=443, dport=48200, flags=0x18, from_server=True),
    ]


def test_a_folded_flow_carries_both_halves_on_one_row(tmp_path: Path) -> None:
    hello = ja4_vector_hello()
    flight = _server_flight()
    source = _capture(tmp_path / "tls.pcap", _tls_flow(hello, flight))

    result = run_pipeline(source, tmp_path / "out.pcap", with_flow_table=True)

    assert result.flow_table is not None
    assert len(result.flow_table) == 1, "the two directions must fold onto one row"
    row = result.flow_table[0]

    client = fingerprint_client_hello(hello)
    server = fingerprint_server_hello(flight)
    assert client is not None and server is not None

    assert row.features.ja4 == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    assert row.features.ja3 == client.ja3
    assert row.features.ja4s == server.ja4s
    assert row.features.sni_present is True
    assert row.features.alpn == ("h2",)
    assert row.features.certificate is not None
    assert row.features.certificate.subject == _LEAF_SUBJECT
    assert row.features.certificate.issuer == _CA_SUBJECT


def test_a_flow_that_sent_nothing_fingerprintable_has_an_empty_vector(tmp_path: Path) -> None:
    packets = [
        _frame(b"", sport=48201, dport=8080, flags=0x02),
        _frame(b"GET / HTTP/1.1\r\nHost: plain.example\r\n\r\n", sport=48201, dport=8080, flags=0x18),
    ]
    source = _capture(tmp_path / "http.pcap", packets)

    result = run_pipeline(source, tmp_path / "out.pcap", with_flow_table=True)

    assert result.flow_table is not None
    assert len(result.flow_table) == 1
    assert result.flow_table[0].features.is_empty


def test_a_cleartext_http2_flow_carries_the_published_settings_string(tmp_path: Path) -> None:
    packets = [
        _frame(b"", sport=48202, dport=80, flags=0x02),
        _frame(_http2_stream(), sport=48202, dport=80, flags=0x18),
    ]
    source = _capture(tmp_path / "h2c.pcap", packets)

    result = run_pipeline(source, tmp_path / "out.pcap", with_flow_table=True)

    assert result.flow_table is not None
    assert result.flow_table[0].features.http2_settings == CHROME_FINGERPRINT


def test_a_flow_where_only_the_server_was_seen_carries_only_the_server_half(
    tmp_path: Path,
) -> None:
    packets = [
        _frame(b"", sport=48203, dport=443, flags=0x02),
        _frame(
            _server_flight(tls13=True, certificate=None),
            sport=443,
            dport=48203,
            flags=0x18,
            from_server=True,
        ),
    ]
    source = _capture(tmp_path / "serveronly.pcap", packets)

    result = run_pipeline(source, tmp_path / "out.pcap", with_flow_table=True)

    assert result.flow_table is not None
    row = result.flow_table[0]
    assert row.features.ja4s != ""
    assert row.features.ja3 == ""
    assert row.features.sni_present is None


# ---------------------------------------------------------------------------
# Section J -- property: arbitrary bytes are never a feature
# ---------------------------------------------------------------------------


@given(st.binary(max_size=1024))
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_arbitrary_bytes_never_raise_and_never_invent_a_vector(blob: bytes) -> None:
    observed = observe_flow_features(blob)
    if observed.ja3:
        assert len(observed.ja3) == 32
        assert observed.certificate is None or observed.ja3s != ""
    if observed.http2_settings:
        assert observed.ja3 == "" and observed.ja3s == ""
    assert FlowFeatures.from_json(observed.to_json()) == observed
