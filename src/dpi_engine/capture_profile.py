"""What a capture *is*, before anything inside it is inspected (`T3-03`).

`AGENTIC_ARCHITECTURE.md`'s Layer 2 specifies `inspect_capture(path, bounds…) ->
CaptureProfile`, and the ingest agent's stop condition is "file validated & hashed".
The engine has no `CaptureProfile`, so this module is where one is defined -- **in the
engine rather than in the MCP package**, because `dpi-engine inspect` already computes
exactly these facts inline. Two implementations of one fact is the failure `D-16`
names, so the CLI adopts this function instead of keeping a private copy and the tool
layer becomes a validating wrapper over it.

Two fields need their names read carefully, because they are **different quantities**
that a careless port collapses into one:

* `captured_bytes` is the sum of each record's `orig_len` -- the bytes this engine
  actually processes. `dpi-engine inspect` has always printed it as "Total bytes".
* `file_bytes` is the size of the file on disk, which additionally counts the global
  header, every per-record header and any trailing padding.

On this repository's own fixture they differ by 21% (5738 vs 6994), so a single field
named `total_bytes` would be authoritative-looking and wrong.

Hashing lives here for the same reason. A capture's digest is a property of the
capture, and the run store's content-addressed run ids depend on it being computed
*one* way; `dpi_mcp.run_store.capture_digest` re-exports this function rather than
keeping a second copy of the algorithm.

**Cost, stated rather than hidden:** `profile_capture` reads the file twice -- once
through `PcapReader` for the packet figures, once to hash it. Both passes stream, so
neither holds the capture in memory, but a caller profiling a 10 GB capture pays two
reads. That is the honest price of `inspect_capture` promising "validated & hashed";
merging them would mean hashing bytes the parser had already buffered, which is a
worse trade than it looks.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any

from dpi_engine.pcap_io import (
    DEFAULT_MAX_PACKET_SIZE,
    DEFAULT_MAX_TOTAL_PACKETS,
    PcapError,
    PcapReader,
)

__all__ = ["CaptureProfile", "capture_digest", "profile_capture"]

#: Hex characters of sha256 retained. 128 bits is far past collision resistance for
#: identifying a capture within one run store, and short enough to read aloud. The run
#: store used exactly this width before this function moved here, so ids already
#: written to disk still match.
_DIGEST_CHARS = 32
_READ_CHUNK = 1024 * 1024


def capture_digest(path: str | Path) -> tuple[str, int]:
    """Returns `(sha256[:32], size-in-bytes-on-disk)` for the file at `path`.

    Streamed rather than read whole: the engine is built to handle captures that do not
    fit in memory, and a store that loaded one entirely just to hash it would undo that.

    An unreadable file is reported as `PcapError` rather than as the `OSError` that
    `open` raises, matching `PcapReader`. Both callers are asking a question about a
    *capture*, and `PcapError` is this project's vocabulary for "I could not read your
    capture"; leaving it as `FileNotFoundError` would make the CLI print a traceback and
    force every other caller to translate the same exception its own way. That regression
    was caught by `test_inspect_missing_file_reports_clean_error` the moment this function
    moved ahead of the parser.
    """
    digest = hashlib.sha256()
    total = 0
    try:
        with Path(path).open("rb") as handle:
            for chunk in iter(lambda: handle.read(_READ_CHUNK), b""):
                digest.update(chunk)
                total += len(chunk)
    except OSError as exc:
        raise PcapError(f"Cannot open capture file '{path}': {exc}") from exc
    return digest.hexdigest()[:_DIGEST_CHARS], total


@dataclasses.dataclass(frozen=True, slots=True)
class CaptureProfile:
    """A capture's identity and shape, safe to hand to an agent.

    Frozen and slotted for the same reason as `FlowRecord` (`T3-06`): it outlives the
    reader that produced it and may be serialised into a tool response.

    `min_packet_length` and `max_packet_length` are `None` for a capture with **no
    records** -- an empty pcap is legal and parses fine. Reporting `0` there would be a
    length no packet had, which is exactly the kind of invented figure `D-25` argues
    against.
    """

    path: str
    sha256: str
    #: Size of the file on disk, headers included.
    file_bytes: int
    linktype: int
    snaplen: int
    packet_count: int
    #: Sum of every record's `orig_len`. See the module docstring: *not* `file_bytes`.
    captured_bytes: int
    min_packet_length: int | None
    max_packet_length: int | None

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)


def profile_capture(
    path: str | Path,
    *,
    max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
    max_total_packets: int = DEFAULT_MAX_TOTAL_PACKETS,
) -> CaptureProfile:
    """Reads `path` once to describe it, within the standard parser bounds.

    The bounds are the same ones every other reader in this project applies, and they
    are **passed through rather than defaulted silently**: a profile that claimed a
    packet count while quietly stopping at a bound would be a lie about the capture.
    `PcapReader` raises `PcapLimitExceededError` instead, so the profile is either true
    or absent.

    Engine-wide capabilities (`quic_sni_supported()`) are deliberately *not* part of the
    profile. They describe this build, not this capture, and `dpi-engine inspect`
    prints them as their own section.
    """
    packet_count = 0
    captured_bytes = 0
    min_len: int | None = None
    max_len: int | None = None
    with PcapReader(
        path,
        max_packet_size=max_packet_size,
        max_total_packets=max_total_packets,
    ) as reader:
        linktype = reader.linktype
        snaplen = reader.snaplen
        for packet in reader:
            packet_count += 1
            captured_bytes += packet.orig_len
            if min_len is None or packet.orig_len < min_len:
                min_len = packet.orig_len
            if max_len is None or packet.orig_len > max_len:
                max_len = packet.orig_len

    # Hashing comes *after* the parse, deliberately: a missing, malformed, pcapng or
    # over-bound capture is diagnosed by the parser that understands capture formats,
    # before a second full read is spent on it. Hashing first would mean reading a whole
    # pcapng file only to refuse it.
    digest_sha, file_bytes = capture_digest(path)

    return CaptureProfile(
        path=str(path),
        sha256=digest_sha,
        file_bytes=file_bytes,
        linktype=linktype,
        snaplen=snaplen,
        packet_count=packet_count,
        captured_bytes=captured_bytes,
        min_packet_length=min_len,
        max_packet_length=max_len,
    )
