"""PCAP file reading and writing.

Ports OSC/include/pcap_reader.h + OSC/src/pcap_reader.cpp to Python, using
dpkt.pcap.Reader/Writer for the actual byte-level parsing (see
DESIGN_DECISIONS.md for why dpkt was chosen over hand-rolling this layer).

Bounds-checking / safety additions on top of what dpkt provides on its own
(dpkt's Reader does not enforce any of these itself):

- max_packet_size: rejects any single captured packet larger than this many
  bytes, so a corrupted/adversarial `caplen` field cannot trigger an
  unbounded read or allocation. Mirrors the original's hardcoded 65535
  sanity check (pcap_reader.cpp), but is configurable here rather than a
  silent magic number.
- max_total_packets: caps how many packets a single file may contain, so an
  adversarial file with a huge number of tiny packets cannot exhaust time or
  memory in the caller (the original had no such cap at all).
- linktype validation: the original silently assumed Ethernet framing for
  every packet with no check of the pcap global header's declared linktype.
  This port validates linktype == DLT_EN10MB (Ethernet) up front and raises
  a clear error otherwise, rather than silently misparsing.

Safety: this module only ever opens files the caller names explicitly. It
never opens a live network interface, never opens a raw socket, and makes no
network calls. See DESIGN_DECISIONS.md "Safety constraints".
"""

from __future__ import annotations

import io
import os
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

import dpkt.pcap

# Matches the original's hardcoded 65535 sanity bound (pcap_reader.cpp), kept
# as the default here but made an explicit, named, overridable constant
# instead of a bare magic number.
DEFAULT_MAX_PACKET_SIZE = 65535

# The original had no cap on total packet count at all. A conservative but
# generous default that still protects against a maliciously huge capture
# without impacting realistic captures.
DEFAULT_MAX_TOTAL_PACKETS = 10_000_000

ETHERNET_LINKTYPE = dpkt.pcap.DLT_EN10MB  # 1

# Per-packet record header: ts_sec, ts_frac, incl_len (caplen), orig_len.
_RECORD_HEADER_LEN = 16

# Which on-disk byte patterns mean "this capture is little-endian".
#
# Per the pcap spec the byte order is determined by the first four bytes
# directly, which is host-independent -- unlike dpkt's own check, which reads
# the magic as a *native* uint32 and therefore depends on the host's byte order.
#
#   a1 b2 c3 d4  big-endian, microsecond
#   d4 c3 b2 a1  little-endian, microsecond
#   a1 b2 3c 4d  big-endian, nanosecond
#   4d 3c b2 a1  little-endian, nanosecond
_LITTLE_ENDIAN_MAGIC_BYTES = frozenset(
    {bytes.fromhex("d4c3b2a1"), bytes.fromhex("4d3cb2a1")}
)
_BIG_ENDIAN_MAGIC_BYTES = frozenset(
    {bytes.fromhex("a1b2c3d4"), bytes.fromhex("a1b23c4d")}
)
_NANOSECOND_MAGIC_BYTES = frozenset(
    {bytes.fromhex("a1b23c4d"), bytes.fromhex("4d3cb2a1")}
)
_KNOWN_MAGIC_BYTES = _LITTLE_ENDIAN_MAGIC_BYTES | _BIG_ENDIAN_MAGIC_BYTES

#: The pcapng Section Header Block magic. pcapng is a *different container
#: format*, not a pcap with a different magic -- it has no 24-byte global header
#: and no fixed-length per-packet records, so a pcap reader cannot parse it at
#: all. The symptom without this check is dpkt raising a bare ValueError which
#: became "not a valid pcap file", telling someone with a perfectly good capture
#: that their capture is invalid. pcapng is roughly a third of real-world
#: captures, so that message is common and wrong (`D-15`).
_PCAPNG_MAGIC_BYTES = bytes.fromhex("0a0d0d0a")


class PcapError(Exception):
    """Base class for all PCAP I/O errors raised by this module."""


class PcapFormatError(PcapError):
    """Raised when a file is not a valid/parseable pcap (bad magic, truncated header, etc.)."""


class PcapngUnsupportedError(PcapError):
    """Raised when the input is a valid pcapng file, which this reader cannot parse.

    A distinct type rather than a `PcapFormatError` with nicer wording, because
    "this is not a pcap, and here is how to convert it" and "this file is
    corrupt" call for different responses from the caller. See `DEC-02`: the
    choice was an honest refusal over a partial pcapng reader, since a wrong
    reader is worse than a precise diagnostic (`D-15`).
    """


class PcapLinktypeError(PcapError):
    """Raised when the pcap's declared linktype is not Ethernet."""


class PcapLimitExceededError(PcapError):
    """Raised when a configured safety bound (packet size or count) is exceeded."""


@dataclass(slots=True)
class RawPacket:
    """A single packet as read from a pcap file, before any protocol parsing.

    Mirrors OSC's RawPacket (pcap_reader.h): a timestamp plus the captured
    bytes. `orig_len` is the record header's on-wire length, so it is preserved
    even when the capture was truncated (`len(data) < orig_len`), matching the
    original's incl_len/orig_len distinction.

    Note that `PcapWriter` cannot represent that distinction: dpkt's writer
    emits caplen == origlen for every packet, so a truncated packet written back
    out is recorded as complete. That is a dpkt limitation, not a silent fix --
    see `test_writer_cannot_preserve_a_truncated_orig_len`.
    """

    ts_sec: int
    ts_usec: int
    data: bytes
    orig_len: int


class _PrefixedStream(io.RawIOBase):
    """Re-prepends bytes already read from a non-rewindable stream.

    `PcapReader` peeks four bytes to identify the capture format and then needs to
    start again from byte zero. On a file that is `seek(0)`; on a pipe or socket
    there is nothing to seek with, so the peeked bytes are pushed back in front.

    Subclasses `io.RawIOBase` rather than standing alone so it presents the same
    protocol as any other binary stream (`dpkt` is typed against `BinaryIO`), and
    so `readable()`/`seekable()` answer correctly without being hand-written.
    """

    def __init__(self, prefix: bytes, stream: BinaryIO) -> None:
        super().__init__()
        self._prefix = prefix
        self._offset = 0
        self._stream = stream

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            rest = self._stream.read()
            out = self._prefix[self._offset :] + rest
            self._offset = len(self._prefix)
            return out

        if self._offset < len(self._prefix):
            take = min(size, len(self._prefix) - self._offset)
            head = self._prefix[self._offset : self._offset + take]
            self._offset += take
            remaining = size - take
            if remaining <= 0:
                return head
            return head + self._stream.read(remaining)
        return self._stream.read(size)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def close(self) -> None:
        # Deliberately does not close the wrapped stream: this object holds four
        # borrowed bytes, and the caller owns the pipe. `PcapReader.close()` guards
        # its own handle on the same principle.
        super().close()


class PcapReader:
    """Reads packets from a pcap file with explicit safety bounds.

    Usage:
        with PcapReader(path) as reader:
            for raw in reader:
                ...

    Raises PcapFormatError / PcapLinktypeError / PcapLimitExceededError for
    malformed or out-of-bounds input; never raises an unguarded exception
    from the underlying byte parsing without wrapping it in one of these.
    """

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
        max_total_packets: int = DEFAULT_MAX_TOTAL_PACKETS,
        require_ethernet: bool = True,
        stream: BinaryIO | None = None,
    ) -> None:
        """Reads from `path`, or from `stream` when one is given.

        `stream` is how `T1-02`'s `CapSource` feeds a live capture without
        duplicating this parser. It is deliberately **not** a general-purpose
        option: every byte still goes through the code below, so the bounds, the
        pcapng diagnostic and the linktype check apply identically to a piped
        stream and to a file. A second parser would be a second set of bugs.

        `path` becomes `None` when streaming, and every diagnostic then names
        `name` instead -- a stream has no path to quote, and printing an empty
        string would produce messages like "Cannot open pcap file ''".
        """
        if path is None and stream is None:
            raise ValueError("PcapReader needs either a path or a stream")

        self.path = Path(path) if path is not None else None
        self.max_packet_size = max_packet_size
        self.max_total_packets = max_total_packets
        self.require_ethernet = require_ethernet
        #: What diagnostics call this input. The path when there is one.
        self.name = str(self.path) if self.path is not None else "<stream>"

        # Not `BinaryIO`: a caller-supplied non-rewindable stream gets wrapped in
        # `_PrefixedStream` during format detection, so this holds either a real
        # binary stream or that adapter. Both expose the same `read`/`close`.
        self._file: BinaryIO | _PrefixedStream | None = None
        self._reader: dpkt.pcap.Reader | None = None
        self._packets_read = 0
        self._endian = "<"
        self._ts_divisor = 1_000_000
        self._ts_scale = 1
        #: Whether the input supports `seek`. Files always do; a pipe or socket does
        #: not, and rewind is then done by re-prepending the bytes already read.
        self._rewindable = True

        self._open(stream)

    def _open(self, stream: BinaryIO | None = None) -> None:
        if stream is not None:
            # Owned by the caller: `close()` must not close a stream the caller may
            # still be using (a pipe is not ours to shut down), so this is the one
            # handle whose lifetime differs from the file case.
            self._file = stream
            try:
                self._rewindable = stream.seekable()
            except (AttributeError, OSError, ValueError):
                # Anything that does not clearly say it can seek is treated as
                # non-rewindable, which is the safe direction: re-prepending four
                # bytes is always correct, whereas seeking a pipe that claims to be
                # seekable and then is not fails mid-read.
                self._rewindable = False
        else:
            assert self.path is not None
            try:
                # Long-lived handle owned by this object and released in `close()`;
                # PcapReader is itself a context manager, so the `with` form is the
                # intended usage at every call site.
                self._file = open(self.path, "rb")  # noqa: SIM115
            except OSError as exc:
                raise PcapError(f"Cannot open pcap file '{self.path}': {exc}") from exc

        # Byte order and timestamp precision come from the magic, read before
        # dpkt consumes the global header. `__iter__` unpacks the 16-byte
        # per-packet record header itself rather than iterating dpkt, because
        # dpkt's iterator performs `read(hdr.caplen)` internally and then
        # discards `hdr.len` -- so delegating to it both allocates before the
        # size bound can be checked and throws away the on-wire length. dpkt
        # still validates the global header here, so format checking is
        # unchanged.
        magic = self._file.read(4)
        if not self._rewindable:
            # A stream (pipe, socket, or an iterator wrapped in a BufferedReader
            # that cannot seek) cannot be rewound, so the four bytes just read are
            # pushed back in front of the stream instead. `T1-02`'s `CapSource`
            # needs this: without it, every stream source would die on the magic
            # peek with an `io.UnsupportedOperation` rather than on anything
            # meaningful about the capture.
            self._file = _PrefixedStream(magic, self._file)
        else:
            self._file.seek(0)
        if magic == _PCAPNG_MAGIC_BYTES:
            # Checked before dpkt, which would otherwise fail with a bare
            # ValueError and produce a misleading "not a valid pcap file".
            if self.path is not None:
                self._file.close()
            self._file = None
            raise PcapngUnsupportedError(
                f"'{self.name}' is a pcapng capture, which this engine does not "
                "read yet. pcapng is a different container format, not a pcap "
                "variant. Convert it with Wireshark's editcap: "
                "    editcap -F pcap in.pcapng out.pcap"
            )
        if magic in _LITTLE_ENDIAN_MAGIC_BYTES:
            self._endian = "<"
        elif magic in _BIG_ENDIAN_MAGIC_BYTES:
            self._endian = ">"
        if magic in _NANOSECOND_MAGIC_BYTES:
            self._ts_divisor = 1_000_000_000
            self._ts_scale = 1_000

        try:
            self._reader = dpkt.pcap.Reader(self._file)
        except Exception as exc:  # dpkt raises bare ValueError on bad magic/truncated header
            if self.path is not None:
                self._file.close()
            self._file = None
            raise PcapFormatError(
                f"'{self.name}' is not a valid pcap file: {exc}"
            ) from exc

        if self.require_ethernet and self._reader.datalink() != ETHERNET_LINKTYPE:
            linktype = self._reader.datalink()
            if self.path is not None:
                self._file.close()
            self._file = None
            raise PcapLinktypeError(
                f"'{self.name}' declares linktype {linktype}, expected "
                f"Ethernet (DLT_EN10MB = {ETHERNET_LINKTYPE}). This port "
                "only supports Ethernet-framed captures; the original C++ "
                "engine silently assumed Ethernet for every linktype, which "
                "is a bug this port intentionally does not carry forward."
            )

    @property
    def linktype(self) -> int:
        assert self._reader is not None
        # dpkt is untyped; these are documented to return int.
        return int(self._reader.datalink())

    @property
    def snaplen(self) -> int:
        assert self._reader is not None
        return int(self._reader.snaplen)

    def __enter__(self) -> PcapReader:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        if self._file is not None:
            # Only a handle *this* object opened. A caller-supplied stream is left
            # open: closing a pipe or a caller's file object on their behalf would
            # be a side effect outside the reader's remit, and `StreamSource`
            # reuses one stream across several `PcapReader`s when a capture is
            # re-read.
            if self.path is not None:
                self._file.close()
            self._file = None
            self._reader = None

    def __iter__(self) -> Iterator[RawPacket]:
        if self._file is None:
            raise PcapError("PcapReader is closed")

        unpack_record = struct.Struct(f"{self._endian}IIII").unpack
        divisor = self._ts_divisor
        scale = self._ts_scale
        name = self.name

        while True:
            header = self._file.read(_RECORD_HEADER_LEN)
            if not header:
                break
            if len(header) != _RECORD_HEADER_LEN:
                # The capture ends mid-record. Same phenomenon as a capture cut
                # mid-payload below, and handled the same way: stop cleanly.
                # Matches `readNextPacket`, which returns false when the 16-byte
                # header read does not leave the stream good
                # (pcap_reader.cpp:74-78). Strictly better than dpkt, which
                # would hand a short buffer to `PktHdr` and raise struct.error.
                break

            raw_sec, raw_frac, incl_len, orig_len = unpack_record(header)

            if self._packets_read >= self.max_total_packets:
                raise PcapLimitExceededError(
                    f"'{name}' exceeds max_total_packets="
                    f"{self.max_total_packets}; refusing to read further "
                    "packets to bound memory/time on adversarial input."
                )

            # Checked against the declared length BEFORE any payload bytes are
            # read, so a corrupted caplen cannot trigger the allocation this
            # bound exists to prevent.
            if incl_len > self.max_packet_size:
                raise PcapLimitExceededError(
                    f"Packet #{self._packets_read} in '{name}' declares "
                    f"incl_len={incl_len}, exceeding max_packet_size="
                    f"{self.max_packet_size}."
                )

            data = self._file.read(incl_len)
            if len(data) != incl_len:
                # A capture cut mid-packet is normal, not corrupt, so this stops
                # iteration rather than raising. That matches the original's
                # `readNextPacket`, which did `resize(incl_len)`, read, then
                # `if (!file_.good()) return false` (pcap_reader.cpp:96-101) --
                # end of capture, no partial packet emitted. It is also stricter
                # than dpkt, which yields a zero-byte packet the pipeline would
                # then process as if it were real.
                break

            # Reproduces dpkt's `ts_sec + ts_frac/divisor` arithmetic exactly,
            # including how it silently carried an out-of-range fraction into
            # the seconds field, so no timestamp shifts.
            ts_sec = raw_sec
            if raw_frac >= divisor:
                carry, raw_frac = divmod(raw_frac, divisor)
                ts_sec += carry

            self._packets_read += 1
            yield RawPacket(
                ts_sec=ts_sec,
                ts_usec=raw_frac // scale,
                data=data,
                orig_len=orig_len,
            )

    @property
    def packets_read(self) -> int:
        return self._packets_read


class PcapWriter:
    """Writes packets to a pcap file, refusing to silently overwrite the input.

    The "never overwrite the input path" safety constraint (DESIGN_DECISIONS.md)
    is enforced here at the primitive level via `source_path`, in addition to
    any CLI-level check added later in Task 11/12.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        linktype: int = ETHERNET_LINKTYPE,
        snaplen: int = DEFAULT_MAX_PACKET_SIZE,
        source_path: str | os.PathLike[str] | None = None,
    ) -> None:
        self.path = Path(path)

        if source_path is not None:
            source = Path(source_path)
            try:
                same_file = self.path.exists() and source.exists() and self.path.samefile(source)
            except OSError:
                same_file = False
            if same_file or self.path.resolve() == source.resolve():
                raise PcapError(
                    f"Refusing to write output to '{self.path}': it is the "
                    "same path as the input file. Choose a different output "
                    "path."
                )

        # Long-lived handle owned by this object and released in `close()`;
        # PcapWriter is itself a context manager, so the `with` form is the
        # intended usage at every call site.
        #
        # `open()` is wrapped for the same reason it is in `PcapReader._open`:
        # every filesystem failure arrives here as a bare OSError subclass
        # (FileNotFoundError, PermissionError, NotADirectoryError, ...), and
        # `cli.py` catches only `(PcapError, ValueError)`. Unwrapped, a bad
        # output path escaped `main()` as a raw traceback instead of the
        # intended `error: ...` line and exit code 1 -- contradicting this
        # module's error contract and `PcapReader`'s own behaviour on the
        # identical failure.
        try:
            self._file = open(self.path, "wb")  # noqa: SIM115
        except OSError as exc:
            raise PcapError(f"Cannot open output pcap file '{self.path}': {exc}") from exc

        self._writer = dpkt.pcap.Writer(self._file, snaplen=snaplen, linktype=linktype)
        self._packets_written = 0

    def write(self, packet: RawPacket) -> None:
        ts = packet.ts_sec + packet.ts_usec / 1_000_000
        self._writer.writepkt(packet.data, ts=ts)
        self._packets_written += 1

    @property
    def packets_written(self) -> int:
        return self._packets_written

    def __enter__(self) -> PcapWriter:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        if self._file is not None and not self._file.closed:
            self._file.close()
