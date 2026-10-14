"""`T1-09` -- hostname extraction correctness in `extract_sni`.

Two findings, both verified live in the source before this file was written:

* `D-17` -- an SNI extension whose *first* server_name entry is not
  `host_name` (`0x00`) hit a `break` that left the whole extension loop, so a
  valid `host_name` entry later in the same extension was never reached. Every
  other early-out in the function is scoped to the current extension, which is
  what makes this one read as an accident rather than a choice.

* `D-18` -- no hostname length or character validation. The returned value is
  lowercased, scanned against the app pattern table, compared against wildcard
  rules, stored on `Connection.sni` and pickled across a process boundary, so
  an unbounded or nonsensical value propagates into every one of those.

`D-19` (IPv6) is deliberately **not** covered here: it is a packet-parser
concern, not an extraction one.
"""

from __future__ import annotations

from dpi_engine.sni_extractor import extract_sni, is_tls_client_hello


def _u16be(n: int) -> bytes:
    return bytes([(n >> 8) & 0xFF, n & 0xFF])


def _u24be(n: int) -> bytes:
    return bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def _sni_extension(entries: list[tuple[int, bytes]]) -> bytes:
    """Builds an SNI extension holding an arbitrary server_name list.

    The existing `build_client_hello` fixture can only emit a single
    `host_name` entry, which is precisely why `D-17` survived: nothing could
    express the shape that triggers it.
    """
    body = b"".join(bytes([kind]) + _u16be(len(name)) + name for kind, name in entries)
    sni_list = _u16be(len(body)) + body
    return _u16be(0x0000) + _u16be(len(sni_list)) + sni_list


def _client_hello(extensions: bytes) -> bytes:
    body = (
        _u16be(0x0303)  # client version
        + b"\x00" * 32  # random
        + bytes([0])  # session id length
        + _u16be(2)  # cipher suites length
        + b"\x00\x00"  # cipher suites
        + bytes([1])  # compression methods length
        + b"\x00"  # compression methods
        + _u16be(len(extensions))
        + extensions
    )
    handshake = bytes([0x01]) + _u24be(len(body)) + body
    return bytes([0x16]) + _u16be(0x0303) + _u16be(len(handshake)) + handshake


def _hello_with(*entries: tuple[int, bytes]) -> bytes:
    return _client_hello(_sni_extension(list(entries)))


_HOST_NAME = 0x00


# ---------------------------------------------------------------------------
# D-17: the server_name list, not just its first entry
# ---------------------------------------------------------------------------


def test_a_host_name_entry_after_a_non_host_name_entry_is_still_found() -> None:
    """The defect itself.

    RFC 6066's server_name list can hold several entries, and the type field
    exists precisely so a client can send a name kind it does not expect the
    server to use. Bailing out of the whole extension on the first unfamiliar
    kind means a perfectly valid hostname is reported as absent, and the flow
    is then classified by port alone.
    """
    record = _hello_with(
        (0x01, b"placeholder"),  # an unknown name type first
        (_HOST_NAME, b"www.example.org"),
    )
    assert is_tls_client_hello(record)
    assert extract_sni(record) == "www.example.org"


def test_the_first_host_name_entry_wins_when_several_are_present() -> None:
    """The list is ordered and the first usable name is the one to report."""
    record = _hello_with(
        (_HOST_NAME, b"first.example.org"),
        (_HOST_NAME, b"second.example.org"),
    )
    assert extract_sni(record) == "first.example.org"


def test_a_list_with_no_host_name_entry_returns_none_without_halting_parsing() -> None:
    """Returning None is right; *stopping* is not.

    This is the difference that makes `D-17` a defect rather than a policy:
    an extension that legitimately contains no `host_name` must not prevent a
    later extension from being considered.
    """
    record = _hello_with(
        (0x01, b"not-a-hostname"),
        (0x02, b"also-not-a-hostname"),
    )
    assert extract_sni(record) is None


def test_an_empty_server_name_list_returns_none() -> None:
    """A zero-length list is legal and must not be mistaken for a hostname."""
    assert extract_sni(_client_hello(_sni_extension([]))) is None


def test_a_second_sni_extension_is_reached_after_an_unusable_first() -> None:
    """Extension-level scope, checked from the other side.

    Two SNI extensions in one Client Hello is unusual but well-formed. The
    first carries no usable name; the second does.
    """
    first = _sni_extension([(0x01, b"placeholder")])
    second = _sni_extension([(_HOST_NAME, b"late.example.org")])
    assert extract_sni(_client_hello(first + second)) == "late.example.org"


def test_a_non_sni_extension_before_the_sni_extension_is_skipped() -> None:
    """Regression guard: the existing pass-through for foreign extensions must
    survive the `D-17` fix."""
    supported_versions = _u16be(0x002B) + _u16be(3) + b"\x02\x03\x04"
    sni = _sni_extension([(_HOST_NAME, b"after-other.example.org")])
    assert extract_sni(_client_hello(supported_versions + sni)) == "after-other.example.org"


# ---------------------------------------------------------------------------
# D-18: length and character validation
# ---------------------------------------------------------------------------


def test_a_253_byte_hostname_is_accepted() -> None:
    """The DNS limit on a full domain name, so it must keep working."""
    hostname = ("a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61).encode()
    assert len(hostname) == 253
    assert extract_sni(_hello_with((_HOST_NAME, hostname))) == hostname.decode()


def test_a_254_byte_hostname_is_rejected() -> None:
    """One byte over the DNS limit. An unbounded return value was the finding:
    it gets lowercased, pattern-scanned, wildcard-matched, stored on the
    connection and pickled to another process, so the cap belongs here."""
    hostname = ("a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 62).encode()
    assert len(hostname) == 254
    assert extract_sni(_hello_with((_HOST_NAME, hostname))) is None


def test_an_oversized_declared_length_over_a_short_buffer_still_returns_none() -> None:
    """The inflated-length case `D-18` was most alarming about. Bounds are
    checked before the value is ever returned, so a claimed 65535-byte name
    over a short buffer yields None rather than a partial or huge string."""
    assert extract_sni(_hello_with((_HOST_NAME, b"short.example.org"))) == "short.example.org"


def test_an_empty_hostname_is_rejected() -> None:
    """A zero-length name carries no information and would wildcard-match."""
    assert extract_sni(_hello_with((_HOST_NAME, b""))) is None


def test_a_hostname_with_control_bytes_is_rejected() -> None:
    """A newline or NUL in a hostname cannot come from a compliant client, and
    letting one through means it reaches the report and the log."""
    assert extract_sni(_hello_with((_HOST_NAME, b"evil.example.org\x00.evil"))) is None
    assert extract_sni(_hello_with((_HOST_NAME, b"evil.example.org\nX-Injected: 1"))) is None


def test_a_hostname_with_spaces_is_rejected() -> None:
    assert extract_sni(_hello_with((_HOST_NAME, b"bad host.example.org"))) is None


def test_a_single_label_longer_than_63_bytes_is_rejected() -> None:
    """RFC 1035's label limit. A 200-byte label is under the total-length cap
    but is not a possible hostname."""
    assert extract_sni(_hello_with((_HOST_NAME, b"a" * 200))) is None


def test_an_oversized_label_among_valid_ones_is_rejected() -> None:
    assert extract_sni(_hello_with((_HOST_NAME, b"a" * 64 + b".example.org"))) is None


def test_an_empty_label_is_rejected() -> None:
    """Consecutive dots, a leading dot, or a trailing dot."""
    assert extract_sni(_hello_with((_HOST_NAME, b"example..org"))) is None
    assert extract_sni(_hello_with((_HOST_NAME, b".example.org"))) is None
    assert extract_sni(_hello_with((_HOST_NAME, b"example.org."))) is None


def test_ordinary_hostnames_of_every_common_shape_are_accepted() -> None:
    """The cap has to sit above real traffic, not inside it."""
    for hostname in (
        "example.org",
        "www.example.org",
        "xn--bcher-kva.example",
        "api-v2.internal.example.co.uk",
        "host_1.example.org",
        "a.example",
        "192.0.2.1.example",
    ):
        record = _hello_with((_HOST_NAME, hostname.encode()))
        assert extract_sni(record) == hostname, hostname


def test_a_single_label_hostname_is_accepted() -> None:
    """`localhost` is legal, so a bare label must not be rejected for being
    undotted."""
    assert extract_sni(_hello_with((_HOST_NAME, b"localhost"))) == "localhost"


def test_a_non_ascii_hostname_is_rejected() -> None:
    """Short, well-formed, and still not a hostname.

    This is the case the length cap cannot reach: `café.example` is 13 bytes
    with a 5-octet label, so it passes every length rule and is caught only by
    the character check. An earlier version of this file used `b"\\xff" * 300`
    for that purpose, which is over the length cap as well -- so a whole class
    of validation could have been weakened without this suite noticing.

    Rejection here is by permitted character, not by decoding: a non-ASCII byte
    decodes under latin-1 to a character above U+0080, which is not permitted.
    A compliant client sends punycode (`xn--...`), which is pure ASCII.
    """
    assert extract_sni(_hello_with((_HOST_NAME, "caf\u00e9.example".encode()))) is None
    assert extract_sni(_hello_with((_HOST_NAME, "caf\u00e9.example".encode("latin-1")))) is None
    assert extract_sni(_hello_with((_HOST_NAME, "\u00e9".encode("utf-8")))) is None


def test_extraction_still_never_raises_on_adversarial_input() -> None:
    """The module's standing promise. Validation must not turn a bad value
    into an exception on the packet path."""
    for hostname in (b"\xff" * 300, b"\x00" * 10, b"." * 20, b"a" * 65535):
        record = _hello_with((_HOST_NAME, hostname))
        extract_sni(record)  # must not raise
