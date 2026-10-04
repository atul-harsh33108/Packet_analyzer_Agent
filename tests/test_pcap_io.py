"""Tests for dpi_engine.pcap_io.

Covers: reading the real OSC sample capture, malformed/truncated files
failing cleanly (not crashing), oversized-packet/oversized-file rejection,
linktype validation, and the writer's refuse-to-overwrite-input safety
check.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from dpi_engine.pcap_io import (
    ETHERNET_LINKTYPE,
    PcapError,
    PcapFormatError,
    PcapLimitExceededError,
    PcapLinktypeError,
    PcapReader,
    PcapWriter,
    RawPacket,
)

FIXTURES = Path(__file__).parent / "fixtures"
TEST_DPI_PCAP = FIXTURES / "test_dpi.pcap"


# --- Reading the real OSC sample -------------------------------------------------


def test_reads_real_sample_capture() -> None:
    with PcapReader(TEST_DPI_PCAP) as reader:
        packets = list(reader)

    assert len(packets) > 0
    assert reader.packets_read == len(packets)
    for pkt in packets:
        assert isinstance(pkt, RawPacket)
        assert len(pkt.data) == pkt.orig_len
        assert pkt.orig_len > 0


def test_linktype_is_ethernet_for_sample() -> None:
    with PcapReader(TEST_DPI_PCAP) as reader:
        assert reader.linktype == ETHERNET_LINKTYPE


def test_snaplen_is_positive_for_sample() -> None:
    with PcapReader(TEST_DPI_PCAP) as reader:
        assert reader.snaplen > 0


# --- Malformed / truncated input --------------------------------------------------


def test_empty_file_raises_format_error(tmp_path: Path) -> None:
    bad = tmp_path / "empty.pcap"
    bad.write_bytes(b"")
    with pytest.raises(PcapFormatError):
        PcapReader(bad)


def test_garbage_magic_raises_format_error(tmp_path: Path) -> None:
    bad = tmp_path / "garbage.pcap"
    bad.write_bytes(b"NOT-A-PCAP-FILE-AT-ALL-1234567890")
    with pytest.raises(PcapFormatError):
        PcapReader(bad)


def test_truncated_global_header_raises_format_error(tmp_path: Path) -> None:
    # A valid pcap global header is 24 bytes; write only the first 4 (magic).
    bad = tmp_path / "truncated_header.pcap"
    bad.write_bytes(struct.pack("<I", 0xA1B2C3D4))
    with pytest.raises(PcapFormatError):
        PcapReader(bad)


def test_truncated_packet_data_does_not_crash(tmp_path: Path) -> None:
    """A valid global header + a packet header claiming more bytes than are
    actually present must fail cleanly (empty read) rather than raise an
    unhandled/uncaught low-level exception."""
    bad = tmp_path / "truncated_packet.pcap"
    global_header = struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,  # magic (native byte order)
        2,
        4,  # version major/minor
        0,  # thiszone
        0,  # sigfigs
        65535,  # snaplen
        ETHERNET_LINKTYPE,  # network
    )
    # Packet header claims incl_len=100 but we provide 0 bytes of data.
    packet_header = struct.pack("<IIII", 0, 0, 100, 100)
    bad.write_bytes(global_header + packet_header)

    with PcapReader(bad) as reader:
        # dpkt's reader will read an empty/short buf; this must not raise
        # an unhandled low-level exception. Either zero packets are yielded
        # or iteration stops cleanly.
        packets = list(reader)
        assert isinstance(packets, list)


# --- Safety bounds -----------------------------------------------------------------


def test_oversized_packet_is_rejected(tmp_path: Path) -> None:
    out = tmp_path / "big.pcap"
    with PcapWriter(out) as writer:
        writer.write(RawPacket(ts_sec=0, ts_usec=0, data=b"\x00" * 100, orig_len=100))

    with pytest.raises(PcapLimitExceededError):
        with PcapReader(out, max_packet_size=50) as reader:
            list(reader)


def test_total_packet_cap_is_enforced(tmp_path: Path) -> None:
    out = tmp_path / "many.pcap"
    with PcapWriter(out) as writer:
        for _ in range(5):
            writer.write(RawPacket(ts_sec=0, ts_usec=0, data=b"\x00" * 20, orig_len=20))

    with pytest.raises(PcapLimitExceededError):
        with PcapReader(out, max_total_packets=3) as reader:
            list(reader)


def test_non_ethernet_linktype_rejected(tmp_path: Path) -> None:
    out = tmp_path / "raw_ip.pcap"
    # linktype 101 = DLT_RAW (raw IP, no link-layer header)
    with PcapWriter(out, linktype=101) as writer:
        writer.write(RawPacket(ts_sec=0, ts_usec=0, data=b"\x45" * 20, orig_len=20))

    with pytest.raises(PcapLinktypeError):
        PcapReader(out, require_ethernet=True)

    # But it's readable if the caller explicitly opts out of the check.
    with PcapReader(out, require_ethernet=False) as reader:
        packets = list(reader)
    assert len(packets) == 1


# --- Writer round-trip and overwrite protection -------------------------------------


def test_write_then_read_round_trip(tmp_path: Path) -> None:
    out = tmp_path / "roundtrip.pcap"
    original = [
        RawPacket(ts_sec=1000, ts_usec=500, data=b"\xaa\xbb\xcc", orig_len=3),
        RawPacket(ts_sec=1001, ts_usec=0, data=b"\x01\x02\x03\x04\x05", orig_len=5),
    ]

    with PcapWriter(out) as writer:
        for pkt in original:
            writer.write(pkt)
        assert writer.packets_written == 2

    with PcapReader(out) as reader:
        read_back = list(reader)

    assert len(read_back) == 2
    assert read_back[0].data == original[0].data
    assert read_back[1].data == original[1].data


def test_writer_refuses_to_overwrite_input(tmp_path: Path) -> None:
    src = tmp_path / "input.pcap"
    src.write_bytes(b"placeholder")

    with pytest.raises(PcapError, match="same path as the input file"):
        PcapWriter(src, source_path=src)


def test_writer_allows_distinct_output_path(tmp_path: Path) -> None:
    src = TEST_DPI_PCAP
    out = tmp_path / "filtered.pcap"
    # Should not raise.
    writer = PcapWriter(out, source_path=src)
    writer.close()
    assert out.exists()


# --- D-04: PcapWriter open failure must raise PcapError, like PcapReader does ------
#
# `PcapReader._open` wraps `open()` in try/except OSError. `PcapWriter.__init__`
# did not, so every filesystem failure escaped as a bare OSError subclass. That
# contradicts the module's own error contract, and because `cli.py` catches only
# `(PcapError, ValueError)` the user got a raw traceback instead of the intended
# `error: ...` message and exit code 1.
#
# The asymmetry is the tell: the four failure modes below are all handled
# correctly by PcapReader and all leaked by PcapWriter.


def _unopenable_paths(tmp_path: Path) -> dict[str, Path]:
    """Four distinct ways an output path can be unwritable, so the fix is
    proven against the whole OSError family rather than one lucky errno."""
    regular_file = tmp_path / "regular-file"
    regular_file.write_bytes(b"i am a file, not a directory")

    return {
        "missing-parent-directory": tmp_path / "no-such-dir" / "out.pcap",
        "deep-missing-path": tmp_path / "a" / "b" / "c" / "out.pcap",
        "parent-is-a-regular-file": regular_file / "out.pcap",
        "target-is-a-directory": tmp_path,
    }


def test_writer_open_failure_raises_pcaperror_not_oserror(tmp_path: Path) -> None:
    """Every unopenable output path must surface as PcapError."""
    for case, path in _unopenable_paths(tmp_path).items():
        with pytest.raises(PcapError) as excinfo:
            PcapWriter(path)
        assert "out.pcap" in str(excinfo.value) or str(path) in str(excinfo.value), (
            f"{case}: message should name the offending path, got {excinfo.value!s}"
        )


def test_reader_and_writer_raise_the_same_exception_type(tmp_path: Path) -> None:
    """Reader/Writer symmetry. PcapReader already did this correctly for all
    four cases, so any divergence is a bug in the writer."""
    for case, path in _unopenable_paths(tmp_path).items():
        reader_exc = writer_exc = None
        try:
            PcapReader(path).close()
        except BaseException as exc:
            reader_exc = exc
        try:
            PcapWriter(path).close()
        except BaseException as exc:
            writer_exc = exc

        assert reader_exc is not None, f"{case}: reader unexpectedly succeeded"
        assert writer_exc is not None, f"{case}: writer unexpectedly succeeded"
        assert type(writer_exc) is type(reader_exc), (
            f"{case}: writer raised {type(writer_exc).__name__} but reader "
            f"raised {type(reader_exc).__name__}"
        )


def test_writer_open_failure_preserves_the_oserror_as_cause(tmp_path: Path) -> None:
    """The original OSError must survive as `__cause__`. Wrapping without
    `from exc` would discard the errno and the real path, which is the
    information a user needs to act on the failure."""
    path = _unopenable_paths(tmp_path)["missing-parent-directory"]

    with pytest.raises(PcapError) as excinfo:
        PcapWriter(path)

    assert isinstance(excinfo.value.__cause__, OSError), (
        "PcapError must chain the underlying OSError via `from exc`"
    )
    assert excinfo.value.__cause__.errno is not None


def test_writer_open_failure_leaves_no_file_behind(tmp_path: Path) -> None:
    """A failed open must not leave a truncated or empty artifact that a later
    run could mistake for real output."""
    path = tmp_path / "no-such-dir" / "out.pcap"

    with pytest.raises(PcapError):
        PcapWriter(path)

    assert not path.exists()
    assert not path.parent.exists()


def test_writer_open_failure_message_is_actionable(tmp_path: Path) -> None:
    """The message should say what failed and where, so the CLI's
    `error: ...` line is useful rather than decorative."""
    path = _unopenable_paths(tmp_path)["deep-missing-path"]

    with pytest.raises(PcapError) as excinfo:
        PcapWriter(path)

    message = str(excinfo.value).lower()
    assert "open" in message or "cannot" in message
    assert "output" in message, f"message should identify this as an output failure: {message}"
    assert str(path).lower() in message or "out.pcap" in message


def test_writer_still_opens_valid_paths(tmp_path: Path) -> None:
    """Guard: the fix must not disturb the happy path, including reopening an
    existing file for truncation."""
    out = tmp_path / "out.pcap"

    writer = PcapWriter(out)
    writer.write(RawPacket(ts_sec=1, ts_usec=0, data=b"\x00" * 20, orig_len=20))
    writer.close()
    assert out.stat().st_size > 0

    reopened = PcapWriter(out)
    reopened.close()
    assert out.stat().st_size == 24  # global header only after truncation
