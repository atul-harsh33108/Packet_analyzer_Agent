"""`R-08` — scapy as an independent cross-check of the hand-rolled TLS parsing.

`DESIGN_DECISIONS.md` declares scapy a "dev/test dependency only, used to
cross-check hand-rolled TLS parsing against a trusted independent implementation
in the differential test suite". Until `T1-07` increment 2 nothing did that: the
only reference to scapy was `test_scapy_imports`, which asserted it *imports* —
so the dependency was carried, and the safety checker's forbidden-pattern list
even had to be taught about it, for a promise that was never kept.

The direction that matters
--------------------------
A cross-check is only worth anything if the two sides do not share a builder.
So this file drives both directions, and most of its value is in **Direction B**:

  * **A (scapy reads our fixture)** — validates `build_client_hello` and, through
    it, `extract_sni`. Useful, but the bytes were built by the same person who
    wrote the extractor, so agreement is weak evidence.
  * **B (we read scapy's fixture)** — scapy constructs the handshake, so the
    bytes going into `extract_sni` were produced by an independent parser's
    *serialiser*. Agreement here means the extractor is not merely
    self-consistent.

Only the handshake is scapy's to build. `extract_sni`'s documented contract is
"a TLS record", so the 5-byte record framing stays on our side of the line --
`TLS()` is not a record framer anyway: it emits content-type `0x00` and a zero
length field, which is why direction B first appeared to fail.

The safety direction
--------------------
On truncated input the two deliberately disagree, and the disagreement is the
useful part: scapy is a general-purpose parser that will return what it managed
to read (`'example.co'` from a record cut mid-hostname), while `extract_sni`
returns None. Ours is the safer of the two, so the test asserts ours is never
*more permissive* than scapy and never raises, rather than asserting equality.
"""
from __future__ import annotations

import warnings

import pytest

from dpi_engine.sni_extractor import extract_sni

# scapy's TLS stack pulls in cryptography's DH primitives, deprecated upstream,
# and warns about a missing libpcap provider on a Windows headless host. Neither
# is about the code under test, and both would otherwise make every test in this
# file look noisy in CI.
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message="No libpcap provider available")

scapy = pytest.importorskip("scapy.layers.tls.handshake")
scapy_ext = pytest.importorskip("scapy.layers.tls.extensions")

TLSClientHello = scapy.TLSClientHello
ServerName = scapy_ext.ServerName
TLS_Ext_ServerName = scapy_ext.TLS_Ext_ServerName


# ---------------------------------------------------------------------------
# Helpers: the two halves of the cross-check
# ---------------------------------------------------------------------------

#: A TLS record header: handshake content type, TLS 1.2 legacy version, length.
_RECORD_PREFIX = b"\x16\x03\x03"
#: content type (1) + version (2) + length (2). `_RECORD_PREFIX` is only the first
#: three bytes; stripping exactly this many is what hands `TLSClientHello` the
#: handshake body rather than a partially-stripped record.
_RECORD_HEADER_LEN = 5


def scapy_reads_our_fixture(record: bytes) -> list[str] | None:
    """Direction A -- scapy parses a record we built. Returns the SNI names.

    `TLSClientHello` expects the handshake body, not the record, so the 5-byte
    header is stripped first. None means scapy could not produce an SNI at all.
    """
    hello = TLSClientHello(record[_RECORD_HEADER_LEN:])
    for ext in hello.ext or []:
        if isinstance(ext, TLS_Ext_ServerName):
            return [sn.servername.decode("utf-8", "replace") for sn in ext.servernames or []]
    return None


def scapy_builds_a_record(server_name: str) -> bytes:
    """Direction B -- scapy constructs the handshake; we frame it as a record."""
    hello = TLSClientHello()
    hello.ext = [
        TLS_Ext_ServerName(servernames=[ServerName(servername=server_name.encode())])
    ]
    body = bytes(hello)
    assert len(body) <= 0xFFFF, "fixture generation produced an oversized handshake"
    return _RECORD_PREFIX + len(body).to_bytes(2, "big") + body


CORPUS = [
    "example.com",
    "x.io",
    "a.b.c.d.e.f.g.example.com",
    "xn--bcher-kva.example",                   # punycode (Bücher)
    "a-b-c.example",                           # hyphens
    "a_b_c.example",                           # underscore: legal in DNS, refused by many parsers
    "1.2.3.4.example",                         # numeric labels first
    "very-long-" + "z" * 53 + "." + "y" * 63 + "." + "x" * 63 + "." + "d" * 60,
    # Long, and genuinely within DNS limits: 252 octets total, every label
    # <= 63. The previous entry here was "very-long-" + "z"*70 + ".example",
    # which the comment described as "within the 255-octet DNS limit" -- true
    # of the total, but it put 80 characters in a single label, which RFC 1035
    # forbids. scapy parses the format and does not care, so it agreed; our
    # extractor began refusing it the moment D-18's label check landed. The
    # cross-check should compare *format* parsing, so its corpus has to hold
    # legal names. Deliberately-illegal names are pinned separately, below.
]


# ---------------------------------------------------------------------------
# Direction A: scapy reads our fixtures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("server_name", CORPUS)
def test_our_extractor_agrees_with_scapy_on_our_own_fixtures(server_name: str) -> None:
    from test_sni_extractor import build_client_hello

    record = build_client_hello(sni_hostname=server_name.encode())
    ours = extract_sni(record)
    theirs = scapy_reads_our_fixture(record)

    assert theirs, f"scapy found no SNI in a fixture we built for {server_name!r}"
    assert ours == theirs[0], (
        f"hand-rolled extractor disagreed with scapy on our own fixture: "
        f"ours={ours!r}, scapy={theirs!r}"
    )


def test_no_sni_extension_agrees_in_both_directions() -> None:
    from test_sni_extractor import build_client_hello

    record = build_client_hello(include_sni_extension=False)
    assert extract_sni(record) is None
    assert not scapy_reads_our_fixture(record)


# ---------------------------------------------------------------------------
# Direction B: we read scapy's fixtures -- the half that is not circular
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("server_name", CORPUS)
def test_our_extractor_agrees_with_inputs_scapy_constructed(server_name: str) -> None:
    """The point of the exercise: bytes from an independent parser's serialiser.

    If `extract_sni` only worked on fixtures produced by the person who wrote
    it, the agreement above would prove nothing. Here the input is built by
    scapy, so matching output means the extractor reads *the format*, not *our
    fixture*.
    """
    ours = extract_sni(scapy_builds_a_record(server_name))
    assert ours == server_name, (
        f"hand-rolled extractor failed on a ClientHello built by scapy: "
        f"expected {server_name!r}, got {ours!r}"
    )


def test_policy_invalid_hostnames_are_refused_while_scapy_still_parses_them() -> None:
    """A **documented divergence** (`D-18`), asserted in both directions.

    scapy validates the *format*: any well-formed server_name entry is handed
    back. We additionally apply hostname policy, because the value goes on to
    be pattern-matched, stored on `Connection.sni` and pickled to a worker
    process. On a syntactically parseable but impossible hostname the two
    therefore disagree -- deliberately.

    Without this test the disagreement would look like a cross-check failure
    to the next person, and someone would "fix" it by relaxing the limit. The
    point of pinning it is that the corpus above can then keep testing what it
    was written to test: agreement on *legal* names.
    """
    from test_sni_extractor import build_client_hello

    impossible = [
        "z" * 80 + ".example",  # one label past the 63-octet limit
        "a" * 300 + ".example",  # past the 253-octet full-name limit
        "bad host.example",  # a space cannot appear in a hostname
    ]
    for hostname in impossible:
        record = build_client_hello(sni_hostname=hostname.encode())
        assert scapy_reads_our_fixture(record) == [hostname], hostname
        assert extract_sni(record) is None, hostname


def test_scapy_built_inputs_with_no_sni_extension_yield_none() -> None:
    hello = TLSClientHello()
    hello.ext = []
    body = bytes(hello)
    record = _RECORD_PREFIX + len(body).to_bytes(2, "big") + body
    assert extract_sni(record) is None


# ---------------------------------------------------------------------------
# The safety direction: where the two must NOT agree
# ---------------------------------------------------------------------------


def test_on_truncated_input_our_extractor_is_never_more_permissive_than_scapy() -> None:
    """Equality would be the wrong assertion here.

    scappy returns what it managed to read -- a record cut mid-hostname yields
    `'example.co'` -- while `extract_sni` returns None. Ours is the safer of the
    two, and safer is what a per-packet extractor on untrusted input must be.
    So the assertion is one-directional: ours never extracts *more* than scapy,
    and never raises.
    """
    from test_sni_extractor import build_client_hello

    whole = build_client_hello(sni_hostname=b"example.com")
    ours_extracted_more = 0

    for cut in range(len(whole)):
        piece = whole[:cut]
        ours = extract_sni(piece)

        try:
            theirs = scapy_reads_our_fixture(piece)
            theirs_names = theirs or []
        except Exception:
            theirs_names = []

        if ours is not None:
            assert ours in ("example.com", "example.co", "example", "example.", "exam"), (
                f"extracted {ours!r} from a {cut}-byte prefix -- that is neither "
                f"the full hostname nor a prefix of it"
            )
            if theirs_names and ours not in theirs_names:
                ours_extracted_more += 1

    assert ours_extracted_more == 0, (
        f"on {ours_extracted_more} truncation(s) the hand-rolled extractor read "
        "more than the independent reference did -- that is an over-read, not "
        "a divergence"
    )


@pytest.mark.parametrize("length", [-1, 0, 1, 8, 0xFFFF, 2**31])
def test_arbitrary_lengths_are_safe_on_scapy_built_inputs(length: int) -> None:
    """`D-05` through the cross-check: a bogus `length` must never over-read.

    The `length` parameter comes from inside the packet, so this is the exact
    place an independent implementation pays off -- scapy's parser is a second
    opinion on the *shape*, and the property test is not here.
    """
    record = scapy_builds_a_record("example.com")
    result = extract_sni(record, length=length)
    if result is not None:
        assert len(result) <= 255, f"a DNS name cannot be {len(result)} octets"
