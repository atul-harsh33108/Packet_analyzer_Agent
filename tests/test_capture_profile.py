"""`CaptureProfile` and `profile_capture` (`T3-03`).

The point of these tests is not that a dataclass holds some numbers. It is that
`inspect_capture` reports **two byte counts that are genuinely different quantities** --
`captured_bytes` (the sum of every record's `orig_len`, what the engine will process)
and `file_bytes` (the size on disk, headers included) -- and that `dpi-engine inspect`
and the MCP tool cannot drift apart, because there is one implementation.

On this repository's fixture those differ by 21% (5738 vs 6994). A single field named
`total_bytes` would have been authoritative-looking and wrong, which is why the key set
is pinned rather than trusted to review.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from conftest import TEST_DPI_PCAP
from dpi_engine.capture_profile import CaptureProfile, capture_digest, profile_capture
from dpi_engine.cli import main
from dpi_engine.pcap_io import PcapError, PcapLimitExceededError, PcapngUnsupportedError

#: Taken from the original OSC engine's own sample report (`OSC/README.md`), the same
#: figures `tests/test_cli_inspect.py` pins. Cross-checked rather than self-derived:
#: a profile that agrees only with itself would pass every test here and still be wrong.
ORIGINAL_ENGINE_PACKETS = 77
ORIGINAL_ENGINE_BYTES = 5738

#: Every key the profile exposes. Pinned so that a rename cannot quietly re-collapse the
#: two byte counts, which is the defect this module's docstring is about.
PROFILE_KEYS = {
    "path",
    "sha256",
    "file_bytes",
    "linktype",
    "snaplen",
    "packet_count",
    "captured_bytes",
    "min_packet_length",
    "max_packet_length",
}


@pytest.fixture(scope="module")
def profile() -> CaptureProfile:
    return profile_capture(TEST_DPI_PCAP)


def test_the_fixture_matches_the_original_engines_own_report(profile: CaptureProfile) -> None:
    assert profile.packet_count == ORIGINAL_ENGINE_PACKETS
    assert profile.captured_bytes == ORIGINAL_ENGINE_BYTES
    assert profile.linktype == 1
    assert profile.snaplen == 65535
    # The length range is pinned to figures obtained from an independent hand-parse of the
    # fixture (struct, no engine code): min 54 / max 142. It cannot be cross-checked
    # against the OSC sample report, which does not print it, and the CLI comparison below
    # would agree with the profile even if both were wrong -- so without a pinned value a
    # swapped `min`/`max` would pass the whole file.
    assert profile.min_packet_length == 54
    assert profile.max_packet_length == 142


def test_on_disk_size_and_captured_bytes_are_different_quantities(profile: CaptureProfile) -> None:
    """The trap this module exists to make un-collapsible."""
    assert profile.captured_bytes == ORIGINAL_ENGINE_BYTES
    assert profile.file_bytes == TEST_DPI_PCAP.stat().st_size
    assert profile.file_bytes != profile.captured_bytes, (
        "if these ever coincide on this fixture the test stops proving anything; "
        "pick a fixture where the per-record headers shift the total"
    )
    assert "total_bytes" not in profile.to_dict()


def test_the_exposed_key_set_is_pinned(profile: CaptureProfile) -> None:
    assert set(profile.to_dict()) == PROFILE_KEYS


def test_the_digest_is_the_run_stores_own_function(profile: CaptureProfile) -> None:
    """One home for "sha256 of this capture", asserted by identity rather than equality.

    Equality would pass with two identical implementations, which is the state this
    change removed: the run store's content-addressed ids and the profile an agent reads
    must come from the same function, or they can disagree about truncation.
    """
    from dpi_engine import run_store

    assert run_store.capture_digest is profile_capture.__globals__["capture_digest"]
    assert profile.sha256 == capture_digest(TEST_DPI_PCAP)[0]


def test_the_digest_is_content_addressed(tmp_path: Path) -> None:
    digest, size = capture_digest(TEST_DPI_PCAP)
    assert len(digest) == 32 and all(c in "0123456789abcdef" for c in digest)
    assert size == TEST_DPI_PCAP.stat().st_size

    same = tmp_path / "copy.pcap"
    shutil.copyfile(TEST_DPI_PCAP, same)
    assert capture_digest(same)[0] == digest, "identical bytes must hash identically"

    # Change one byte in the middle of the payload, not a header field, so the file is
    # still recognisably 'the same capture' to a careless reader.
    blob = bytearray(TEST_DPI_PCAP.read_bytes())
    blob[len(blob) // 2] ^= 0xFF
    different = tmp_path / "changed.pcap"
    different.write_bytes(bytes(blob))
    assert capture_digest(different)[0] != digest, "one changed byte must change the digest"


def test_an_empty_capture_reports_no_packet_lengths(tmp_path: Path) -> None:
    """An empty pcap is legal, and `0` would be a length no packet had (`D-25`)."""
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(TEST_DPI_PCAP.read_bytes()[:24])  # the global header only

    profile = profile_capture(empty)
    assert profile.packet_count == 0
    assert profile.captured_bytes == 0
    assert profile.file_bytes == 24
    assert profile.min_packet_length is None
    assert profile.max_packet_length is None
    assert profile.linktype == 1


def _pcap_with_one_truncated_record() -> bytes:
    """A one-packet pcap whose record claims 200 bytes and carries 20.

    This is the **only** shape that distinguishes `orig_len` from `len(data)`. Every
    frame in the repository's real fixtures was captured whole, so on those the two are
    equal and a profile that counted captured bytes instead of original bytes would pass
    every other test in this file. `D-06`/`D-07` are the record-header bugs that make the
    difference load-bearing, so it is pinned here rather than left to a fixture's luck.
    """
    import struct

    global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record_header = struct.pack("<IIII", 0, 0, 20, 200)  # ts_sec, ts_usec, caplen, orig_len
    return global_header + record_header + bytes(20)


def test_captured_bytes_counts_original_length_not_captured_length(tmp_path: Path) -> None:
    truncated = tmp_path / "truncated.pcap"
    truncated.write_bytes(_pcap_with_one_truncated_record())

    profile = profile_capture(truncated)
    assert profile.packet_count == 1
    assert profile.captured_bytes == 200, "orig_len, not caplen"
    assert profile.min_packet_length == 200
    assert profile.max_packet_length == 200
    assert profile.file_bytes == 24 + 16 + 20, "the file really does hold 20 payload bytes"

    # The two figures the module docstring insists are different, in a capture where
    # confusing them is a 3.3x error rather than a 21% one.
    assert profile.captured_bytes == 200
    assert profile.file_bytes == 60
    assert profile.captured_bytes != profile.file_bytes


def test_the_packet_bound_raises_rather_than_truncating_the_profile() -> None:
    """A profile must be true or absent: a count silently reflecting a bound is a lie."""
    with pytest.raises(PcapLimitExceededError):
        profile_capture(TEST_DPI_PCAP, max_total_packets=10)

    # And the same bound, set above the real count, changes nothing.
    assert profile_capture(TEST_DPI_PCAP, max_total_packets=1000).packet_count == 77


def test_the_packet_size_bound_is_the_parsers_own() -> None:
    with pytest.raises(PcapError):
        profile_capture(TEST_DPI_PCAP, max_packet_size=8)


def test_a_missing_file_raises_a_pcap_error(tmp_path: Path) -> None:
    with pytest.raises(PcapError):
        profile_capture(tmp_path / "not-here.pcap")


def test_pcapng_is_refused_with_the_engines_own_diagnostic(tmp_path: Path) -> None:
    """`DEC-02`: pcapng is refused, not partially read -- and the tool inherits that."""
    pcapng = tmp_path / "capture.pcapng"
    pcapng.write_bytes(b"\x0a\x0d\x0d\x0a" + bytes(24))
    with pytest.raises(PcapngUnsupportedError):
        profile_capture(pcapng)


def test_to_json_is_the_dictionary(profile: CaptureProfile) -> None:
    assert json.loads(profile.to_json()) == profile.to_dict()
    assert json.loads(profile.to_json(indent=None))["sha256"] == profile.sha256


def test_the_cli_and_the_tool_report_the_same_figures(capsys: pytest.CaptureFixture[str]) -> None:
    """The `I1` claim, proven end to end rather than asserted in prose.

    `dpi-engine inspect` used to compute these numbers inline. If it still did, this test
    would pass -- so it is not the guard for that. What it guards is the *output*: the two
    front doors must keep printing the same figures as the profile returns, whichever one
    changes next.
    """
    assert main(["inspect", str(TEST_DPI_PCAP)]) == 0
    out = capsys.readouterr().out
    profile = profile_capture(TEST_DPI_PCAP)

    assert f"Packet count:    {profile.packet_count}" in out
    assert f"Total bytes:     {profile.captured_bytes}" in out
    assert f"Min pkt length:  {profile.min_packet_length}" in out
    assert f"Max pkt length:  {profile.max_packet_length}" in out
