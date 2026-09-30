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

import os
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


class PcapError(Exception):
    """Base class for all PCAP I/O errors raised by this module."""


class PcapFormatError(PcapError):
    """Raised when a file is not a valid/parseable pcap (bad magic, truncated header, etc.)."""


class PcapLinktypeError(PcapError):
    """Raised when the pcap's declared linktype is not Ethernet."""


class PcapLimitExceededError(PcapError):
    """Raised when a configured safety bound (packet size or count) is exceeded."""


@dataclass(slots=True)
class RawPacket:
    """A single packet as read from a pcap file, before any protocol parsing.

    Mirrors OSC's RawPacket (pcap_reader.h): a timestamp plus the captured
    bytes. `orig_len` preserves the original on-wire length even when the
    capture is truncated (caplen < origlen), matching the original's
    incl_len/orig_len distinction.
    """

    ts_sec: int
    ts_usec: int
    data: bytes
    orig_len: int


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
        path: str | os.PathLike[str],
        *,
        max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
        max_total_packets: int = DEFAULT_MAX_TOTAL_PACKETS,
        require_ethernet: bool = True,
    ) -> None:
        self.path = Path(path)
        self.max_packet_size = max_packet_size
        self.max_total_packets = max_total_packets
        self.require_ethernet = require_ethernet

        self._file: BinaryIO | None = None
        self._reader: dpkt.pcap.Reader | None = None
        self._packets_read = 0

        self._open()

    def _open(self) -> None:
        try:
            # Long-lived handle owned by this object and released in `close()`;
            # PcapReader is itself a context manager, so the `with` form is the
            # intended usage at every call site.
            self._file = open(self.path, "rb")  # noqa: SIM115
        except OSError as exc:
            raise PcapError(f"Cannot open pcap file '{self.path}': {exc}") from exc

        try:
            self._reader = dpkt.pcap.Reader(self._file)
        except Exception as exc:  # dpkt raises bare ValueError on bad magic/truncated header
            self._file.close()
            self._file = None
            raise PcapFormatError(
                f"'{self.path}' is not a valid pcap file: {exc}"
            ) from exc

        if self.require_ethernet and self._reader.datalink() != ETHERNET_LINKTYPE:
            linktype = self._reader.datalink()
            self._file.close()
            self._file = None
            raise PcapLinktypeError(
                f"'{self.path}' declares linktype {linktype}, expected "
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
            self._file.close()
            self._file = None
            self._reader = None

    def __iter__(self) -> Iterator[RawPacket]:
        if self._reader is None:
            raise PcapError("PcapReader is closed")

        for ts, buf in self._reader:
            if self._packets_read >= self.max_total_packets:
                raise PcapLimitExceededError(
                    f"'{self.path}' exceeds max_total_packets="
                    f"{self.max_total_packets}; refusing to read further "
                    "packets to bound memory/time on adversarial input."
                )

            if len(buf) > self.max_packet_size:
                raise PcapLimitExceededError(
                    f"Packet #{self._packets_read} in '{self.path}' is "
                    f"{len(buf)} bytes, exceeding max_packet_size="
                    f"{self.max_packet_size}."
                )

            self._packets_read += 1
            # dpkt yields seconds as a float with a fractional part; pcap stores
            # whole seconds plus microseconds, so split it here. `round` already
            # returns an int for a single-argument call.
            ts_sec = int(ts)
            ts_usec = round((ts - ts_sec) * 1_000_000)
            yield RawPacket(
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                data=buf,
                orig_len=len(buf),
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
        self._file: BinaryIO = open(self.path, "wb")  # noqa: SIM115
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
