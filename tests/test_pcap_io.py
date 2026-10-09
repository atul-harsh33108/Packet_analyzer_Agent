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

from conftest import TEST_DPI_PCAP
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

# --- Reading the real OSC sample -------------------------------------------------


def test_reads_real_sample_capture() -> None:
    with PcapReader(TEST_DPI_PCAP) as reader:
        packets = list(reader)

    assert len(packets) > 0
    assert reader.packets_read == len(packets)
    for pkt in packets:
        assert isinstance(pkt, RawPacket)
        # `orig_len` is the record header's on-wire length (D-06). It is
        # >= len(data) always, and strictly greater when the capture was
        # truncated. This previously asserted equality, which was only true
        # because `orig_len` was assigned `len(buf)` -- i.e. the test locked the
        # bug in place.
        assert pkt.orig_len >= len(pkt.data)
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


# --- D-06 / D-07: record header read directly ------------------------------------
#
# dpkt's Reader.__iter__ does `buf = self.__f.read(hdr.caplen)` internally and
# then yields only `(ts, buf)` -- discarding `hdr.len`. Delegating to it meant
# (D-07) the payload was allocated before max_packet_size could be checked, and
# (D-06) orig_len had to be faked as len(buf).
#
# Note the original did neither: pcap_reader.cpp:88-93 checked
# `incl_len > snaplen || incl_len > 65535` *before* `resize()` on line 96. Both
# were regressions introduced by the move to dpkt, not inherited defects.

def _write_raw_pcap(
    path: Path,
    records: list[tuple[int, int, int, int, bytes]],
    *,
    endian: str = "<",
) -> Path:
    """Build a pcap byte-for-byte, bypassing PcapWriter.

    PcapWriter cannot express incl_len != orig_len (dpkt's writepkt_time packs
    `n, n`), so a truncated capture has to be assembled by hand to test D-06 at
    all. This is exactly the limitation `test_writer_cannot_preserve_a_truncated_orig_len`
    pins.
    """
    magic = 0xA1B2C3D4
    out = bytearray(
        struct.pack(f"{endian}IHHiIII", magic, 2, 4, 0, 0, 65535, ETHERNET_LINKTYPE)
    )
    for ts_sec, ts_usec, incl_len, orig_len, data in records:
        out += struct.pack(f"{endian}IIII", ts_sec, ts_usec, incl_len, orig_len)
        out += data
    path.write_bytes(bytes(out))
    return path


# --- D-06: orig_len must come from the record header, not len(data) --------------


def test_orig_len_is_the_on_wire_length_not_the_captured_length(tmp_path: Path) -> None:
    """A snaplen-truncated packet: 60 bytes on the wire, 20 captured.

    Before the fix `orig_len` was assigned `len(buf)`, so this reported 20 and
    every byte counter in the engine under-reported on truncated captures."""
    path = _write_raw_pcap(
        tmp_path / "truncated.pcap",
        [(1_700_000_000, 500_000, 20, 60, b"\xaa" * 20)],
    )

    with PcapReader(path) as reader:
        packets = list(reader)

    assert len(packets) == 1
    assert len(packets[0].data) == 20
    assert packets[0].orig_len == 60, (
        "orig_len must be the record header's on-wire length; "
        f"got {packets[0].orig_len}, expected 60"
    )
    assert packets[0].orig_len > len(packets[0].data)


def test_orig_len_is_preserved_for_untruncated_packets_too(tmp_path: Path) -> None:
    """Guard: the common case must be unaffected -- incl_len == orig_len."""
    path = _write_raw_pcap(
        tmp_path / "full.pcap",
        [(1_700_000_000, 0, 32, 32, b"\xbb" * 32)],
    )

    with PcapReader(path) as reader:
        packets = list(reader)

    assert packets[0].orig_len == 32
    assert packets[0].orig_len == len(packets[0].data)


def test_writer_cannot_preserve_a_truncated_orig_len(tmp_path: Path) -> None:
    """Pins a real limitation rather than leaving it implicit.

    dpkt's writer packs caplen and origlen as the same `n`, so writing a
    truncated packet back out records it as complete. This is why fixing D-06
    does not also fix the write side, and why the byte counters in a filtered
    output pcap reflect what was captured, not what was on the wire.
    """
    source = _write_raw_pcap(
        tmp_path / "in.pcap",
        [(1_700_000_000, 0, 20, 60, b"\xcc" * 20)],
    )
    dest = tmp_path / "out.pcap"

    with PcapReader(source) as reader:
        packets = list(reader)
    assert packets[0].orig_len == 60

    writer = PcapWriter(dest)
    for pkt in packets:
        writer.write(pkt)
    writer.close()

    with PcapReader(dest) as reader:
        rewritten = list(reader)

    assert rewritten[0].orig_len == 20, (
        "documented dpkt limitation: the writer cannot express "
        "incl_len < orig_len, so truncation is lost on write"
    )


def test_timestamps_are_unaffected_by_the_record_header_change(tmp_path: Path) -> None:
    """The rewrite reads ts_sec/ts_usec directly instead of dpkt's normalized
    float, so the arithmetic must reproduce dpkt's exactly -- including how it
    carried an out-of-range fraction into the seconds field."""
    path = _write_raw_pcap(
        tmp_path / "ts.pcap",
        [
            (1_700_000_000, 500_000, 4, 4, b"\x01\x02\x03\x04"),
            (1_700_000_001, 0, 4, 4, b"\x05\x06\x07\x08"),
            # out-of-range fraction: 4294967295 usec == 4294.967295 s
            (5, 4_294_967_295, 4, 4, b"\x09\x0a\x0b\x0c"),
        ],
    )

    with PcapReader(path) as reader:
        packets = list(reader)

    assert (packets[0].ts_sec, packets[0].ts_usec) == (1_700_000_000, 500_000)
    assert (packets[1].ts_sec, packets[1].ts_usec) == (1_700_000_001, 0)
    assert (packets[2].ts_sec, packets[2].ts_usec) == (5 + 4294, 967_295)


def test_little_and_big_endian_captures_agree(tmp_path: Path) -> None:
    """Byte order now drives our own struct unpacking, so both orders must be
    read correctly -- the real fixture is little-endian, so a wrong endianness
    would otherwise pass silently everywhere else."""
    payload = b"\x11\x22\x33\x44"
    le = _write_raw_pcap(tmp_path / "le.pcap", [(100, 250_000, 4, 4, payload)], endian="<")
    be = _write_raw_pcap(tmp_path / "be.pcap", [(100, 250_000, 4, 4, payload)], endian=">")

    with PcapReader(le) as r:
        little = list(r)
    with PcapReader(be) as r:
        big = list(r)

    for packets in (little, big):
        assert len(packets) == 1
        assert packets[0].data == payload
        assert packets[0].ts_sec == 100
        assert packets[0].ts_usec == 250_000
        assert packets[0].orig_len == 4


# --- D-07: incl_len must be validated before the payload is read ----------------


def test_oversized_incl_len_is_rejected_without_reading_the_payload(
    tmp_path: Path,
) -> None:
    """A record header declaring incl_len = 0xFFFFFFF0 must be rejected on the
    declared length alone.

    Before the fix dpkt performed the multi-gigabyte read inside its own
    iterator, so by the time max_packet_size was consulted the allocation had
    already been attempted. The file below is 16 bytes long, so a correct
    implementation never touches the missing payload at all."""
    path = _write_raw_pcap(
        tmp_path / "hostile.pcap",
        [(1, 0, 0xFFFFFFF0, 0xFFFFFFF0, b"")],
    )
    assert path.stat().st_size == 24 + 16  # global header + record header only

    with PcapReader(path, max_packet_size=65535) as reader, pytest.raises(
        PcapLimitExceededError
    ) as excinfo:
        list(reader)

    assert "incl_len" in str(excinfo.value)
    assert "max_packet_size" in str(excinfo.value)


@pytest.mark.parametrize("declared", [65536, 1 << 20, 0xFFFFFFF0])
def test_any_incl_len_above_the_bound_is_rejected(
    tmp_path: Path, declared: int
) -> None:
    path = _write_raw_pcap(tmp_path / f"big-{declared}.pcap", [(1, 0, declared, declared, b"")])

    with PcapReader(path, max_packet_size=65535) as reader, pytest.raises(
        PcapLimitExceededError
    ):
        list(reader)


def test_incl_len_exactly_at_the_bound_is_accepted(tmp_path: Path) -> None:
    """The bound is inclusive, matching the original's `incl_len > 65535`."""
    path = _write_raw_pcap(
        tmp_path / "exact.pcap",
        [(1, 0, 65535, 65535, b"\x00" * 65535)],
    )

    with PcapReader(path, max_packet_size=65535) as reader:
        packets = list(reader)

    assert len(packets[0].data) == 65535


def test_bound_is_reported_against_the_declared_length_not_the_bytes_present(
    tmp_path: Path,
) -> None:
    """The error must name incl_len, not len(data). On a hostile record those
    differ by gigabytes and only the former explains the rejection."""
    path = _write_raw_pcap(tmp_path / "lie.pcap", [(7, 0, 999_999, 999_999, b"\x00" * 10)])

    with PcapReader(path, max_packet_size=100) as reader, pytest.raises(
        PcapLimitExceededError
    ) as excinfo:
        list(reader)

    message = str(excinfo.value)
    assert "999999" in message
    assert "Packet #0" in message


# --- truncated payloads -------------------------------------------------------------


def test_capture_cut_mid_packet_ends_iteration_cleanly(tmp_path: Path) -> None:
    """A capture truncated mid-payload is normal, not corrupt. Iteration must
    stop without raising and without emitting a phantom short packet --
    matching `readNextPacket`'s `if (!file_.good()) return false`, and stricter
    than dpkt, which yields a zero-byte packet the pipeline would process."""
    path = _write_raw_pcap(
        tmp_path / "cut.pcap",
        [
            (1, 0, 4, 4, b"\x01\x02\x03\x04"),
            (2, 0, 100, 100, b"\x05\x06"),  # only 2 of 100 bytes present
            (3, 0, 4, 4, b"\x07\x08\x09\x0a"),  # unreachable
        ],
    )

    with PcapReader(path) as reader:
        packets = list(reader)

    assert len(packets) == 1
    assert packets[0].data == b"\x01\x02\x03\x04"
    assert reader.packets_read == 1


def test_truncated_record_header_ends_iteration_cleanly(tmp_path: Path) -> None:
    """A capture ending mid-header (1-15 bytes) must stop cleanly rather than
    raise or unpack garbage."""
    complete = _write_raw_pcap(tmp_path / "full.pcap", [(1, 0, 4, 4, b"\x01\x02\x03\x04")])
    raw = bytearray(complete.read_bytes())
    raw += b"\x00" * 9  # partial record header
    cut = tmp_path / "cut-header.pcap"
    cut.write_bytes(bytes(raw))

    with PcapReader(cut) as reader:
        packets = list(reader)

    assert len(packets) == 1


def test_incl_len_zero_is_a_valid_empty_packet(tmp_path: Path) -> None:
    """A zero-length capture is legal and is used by the test suite itself."""
    path = _write_raw_pcap(tmp_path / "empty-pkt.pcap", [(1, 0, 0, 0, b"")])

    with PcapReader(path) as reader:
        packets = list(reader)

    assert len(packets) == 1
    assert packets[0].data == b""
    assert packets[0].orig_len == 0


def test_byte_counters_report_bytes_read_not_on_wire_length(tmp_path: Path) -> None:
    """Pins a deliberate decision that is easy to "fix" in the wrong direction.

    `RawPacket.orig_len` is now the true on-wire length (D-06), so on a
    snaplen-truncated capture it exceeds `len(data)`. Byte counters must still
    use the captured length, because:
      - the CLI labels the figure "Total bytes read";
      - the C++ original does `flow.bytes += raw.data.size()`
        (main_working.cpp:184), and parity with it is what the differential
        suite exists to prove.

    Using `orig_len` here would silently change every byte total relative to
    the reference on any truncated capture."""
    import struct as _struct

    from dpi_engine.pipeline import run_pipeline

    source = tmp_path / "trunc.pcap"
    frame = b"\x45" + b"\x00" * 19 + b"\x06\x00" + b"\x00" * 14 + b"payload"
    out = bytearray(
        _struct.pack(
            "<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, ETHERNET_LINKTYPE
        )
    )
    # incl_len 54 captured, orig_len 9000 on the wire.
    out += _struct.pack("<IIII", 1_700_000_000, 0, len(frame), 9000)
    out += frame
    source.write_bytes(bytes(out))

    dest = tmp_path / "out.pcap"
    result = run_pipeline(source, dest)

    assert result.stats.total_bytes == len(frame), (
        "byte counters must report captured bytes (incl_len), matching the "
        f"C++ original; got {result.stats.total_bytes}, expected {len(frame)}"
    )


# --- D-15: pcapng gets a precise diagnostic, not "invalid pcap" -------------
#
# pcapng is a different container format, not a pcap variant: no 24-byte global
# header, no fixed-length per-packet records. A pcap reader cannot parse it, and
# before this the only symptom was dpkt's bare ValueError surfacing as
# "'x.pcapng' is not a valid pcap file" -- telling someone with a perfectly good
# capture that their capture is invalid. Roughly a third of real-world captures
# are pcapng, so that message was both common and wrong.


def _minimal_pcapng() -> bytes:
    """A minimal, structurally valid pcapng Section Header Block (28 bytes).

    Block Type 0x0A0D0D0A, Block Total Length, Byte-Order Magic, version,
    Section Length (-1 = unspecified), and the trailing Block Total Length.
    """
    return (
        bytes.fromhex("0a0d0d0a")            # block type
        + (28).to_bytes(4, "little")          # block total length
        + bytes.fromhex("1a2b3c4d")           # byte-order magic
        + (1).to_bytes(2, "little")           # major version
        + (0).to_bytes(2, "little")           # minor version
        + b"\xff" * 8                         # section length: unspecified
        + (28).to_bytes(4, "little")          # trailing block total length
    )


def test_pcapng_raises_a_precise_diagnostic_naming_a_conversion_command(
    tmp_path: Path,
) -> None:
    from dpi_engine.pcap_io import PcapngUnsupportedError, PcapReader

    p = tmp_path / "in.pcapng"
    p.write_bytes(_minimal_pcapng())

    with pytest.raises(PcapngUnsupportedError) as excinfo:
        PcapReader(p)

    message = str(excinfo.value)
    assert "pcapng" in message, message
    assert "editcap" in message, (
        f"the diagnostic must name a conversion command so the user can act on "
        f"it, not just report that the file is unsupported: {message}"
    )
    assert "-F pcap" in message, message


def test_pcapng_error_is_catchable_as_pcap_error(tmp_path: Path) -> None:
    """It subclasses PcapError so the CLI's existing handler reports it cleanly
    rather than it escaping as an unhandled exception."""
    from dpi_engine.pcap_io import PcapError, PcapngUnsupportedError, PcapReader

    assert issubclass(PcapngUnsupportedError, PcapError)

    p = tmp_path / "in.pcapng"
    p.write_bytes(_minimal_pcapng())
    with pytest.raises(PcapError):
        PcapReader(p)


def test_the_cli_reports_pcapng_as_an_error_not_a_traceback(tmp_path: Path, capsys) -> None:
    """End to end through `main`: a clean exit code and a readable message."""
    from dpi_engine.cli import main

    p = tmp_path / "in.pcapng"
    p.write_bytes(_minimal_pcapng())

    exit_code = main(["run", str(p), str(tmp_path / "out.pcap")])

    # The CLI reports errors on stderr, not stdout.
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert exit_code != 0, f"expected a non-zero exit code, got {exit_code}"
    assert "pcapng" in text, text
    assert "editcap" in text, text
    assert "Traceback" not in text, text


def test_a_corrupt_file_is_still_reported_as_invalid_pcap(tmp_path: Path) -> None:
    """Detection must not over-match: garbage is still 'invalid', not 'pcapng'."""
    from dpi_engine.pcap_io import PcapFormatError, PcapReader

    p = tmp_path / "garbage.pcap"
    p.write_bytes(b"\x00" * 64)

    with pytest.raises(PcapFormatError) as excinfo:
        PcapReader(p)

    assert "pcapng" not in str(excinfo.value).lower(), str(excinfo.value)


def test_an_empty_file_is_still_reported_as_invalid_pcap(tmp_path: Path) -> None:
    from dpi_engine.pcap_io import PcapFormatError, PcapReader

    p = tmp_path / "empty.pcap"
    p.write_bytes(b"")

    with pytest.raises(PcapFormatError):
        PcapReader(p)
