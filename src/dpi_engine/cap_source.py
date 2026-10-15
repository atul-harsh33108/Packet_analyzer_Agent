"""Capture sources for live and rotating input (`T1-02`, `A-01`).

Every pipeline variant starts from `PcapReader(path)`, which suits a capture
already on disk and nothing else. Three real cases it does not cover:

- a capture still being written, to be tailed as it grows;
- a capture arriving over a pipe -- `tcpdump -w - | engine`;
- a directory of rotating captures to be picked up as they appear.

This module adds those, and the whole design rests on one decision: **a source is
an iterable of `RawPacket` and nothing more.** That is the shape
`pipeline._iter_inspectable` already consumes, so no pipeline changes, and every
source delegates the actual parsing to `PcapReader`.

That delegation is the load-bearing part. A source that parsed bytes itself would
be a second parser, and a second parser carries its own bounds, its own pcapng
handling and its own truncation behaviour — three bug surfaces where the rest of
the engine has exactly one. So the sources here decide *where bytes come from*,
and `PcapReader` remains the only thing that decides *what they mean*.

The safety invariants survive for the same reason. `PcapWriter`'s
never-overwrite-the-input guard needs a path to compare against, so `path` is
`None` for a stream rather than an invented string — the guard is skipped for
streams because there is nothing to collide with, and still enforced for file
sources.
"""

from __future__ import annotations

import contextlib
import io
import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Protocol, runtime_checkable

from dpi_engine.pcap_io import (
    DEFAULT_MAX_PACKET_SIZE,
    DEFAULT_MAX_TOTAL_PACKETS,
    PcapError,
    PcapLimitExceededError,
    PcapReader,
    RawPacket,
)

#: Suffixes a capture directory is expected to hold. Anything else in the
#: directory is skipped: a rotating capture directory also holds lock files,
#: logs and archives, and one unreadable neighbour must not end the watch.
CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap")

#: Default gap between directory scans. Short enough to feel live, long enough
#: that a watch costs nothing measurable while a pipeline is running.
DEFAULT_POLL_INTERVAL = 0.5


@runtime_checkable
class CapSource(Protocol):
    """A source of `RawPacket`s.

    Implemented by every source here, and satisfied by anything iterable that
    yields `RawPacket` — including a bare `PcapReader`. That is the point: the
    pipeline already iterates a `PcapReader`, so making this structural rather
    than a nominal base class is what lets the existing path keep working
    untouched.
    """

    @property
    def path(self) -> Path | None:
        """The file this source reads, or `None` if it has no single file.

        `None` for streams and for directory watchers, and it is passed to
        `PcapWriter(source_path=...)` so the never-overwrite-the-input guard is
        enforced when there is something to compare and skipped when there is not.
        """
        ...

    def describe(self) -> str:
        """A short human-readable label for logs and error messages."""
        ...

    def __iter__(self) -> Iterator[RawPacket]:
        ...


class FileSource:
    """A single capture already on disk.

    Exists mainly as the explicit, intention-revealing form of what every
    existing call site already does -- `PcapReader(path)` satisfies `CapSource`
    structurally, so this is not required to use the abstraction. It is here so
    that code which wants a `CapSource` has one that says what it means.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def describe(self) -> str:
        return str(self.path)

    def __iter__(self) -> Iterator[RawPacket]:
        # A fresh reader per iteration, so the source behaves like the file it
        # names and can be iterated more than once.
        with PcapReader(self.path) as reader:
            yield from reader


class StreamSource:
    """A capture arriving over a pipe, socket or any readable binary stream.

    Two properties are worth stating because they are what a caller gets wrong
    otherwise:

    - **The stream is not closed.** It belongs to the caller; closing a pipe on
      their behalf is not this class's decision. `PcapReader.close()` respects
      the same rule.
    - **It is read once.** A stream is consumed by reading it, so a second
      iteration yields nothing. `describe()` says so, and callers who need
      repeated reads should use `FileSource`.
    """

    def __init__(self, stream: io.RawIOBase | object) -> None:
        self._stream = stream

    @property
    def path(self) -> Path | None:
        """Always `None`: a stream has no path, and inventing one would let the
        writer's overwrite guard compare against a file that was never read."""
        return None

    def describe(self) -> str:
        return "<stream> (read-once)"

    def __iter__(self) -> Iterator[RawPacket]:
        yield from PcapReader(stream=self._stream)  # type: ignore[arg-type]


class WatchSource:
    """Picks up capture files from a directory as they appear.

    For rotating captures: a tool writes `capture-001.pcap`, renames it and starts
    `capture-002.pcap`. Reading a fixed list at startup misses everything written
    afterwards, which is most of them.

    Each file is read **once**, tracked by identity rather than by name so that a
    rename is not mistaken for a new file and a replacement at the same path *is*.
    `stop_when_idle_after` bounds the wait for a quiet directory, which is what
    makes this usable from a test or a batch job; the default of `None` watches
    forever, which is what a live engine wants.
    """

    def __init__(
        self,
        directory: str | os.PathLike[str],
        *,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        stop_when_idle_after: float | None = None,
        pattern: str = "*",
        max_total_packets: int | None = None,
        max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
    ) -> None:
        self.directory = Path(directory)
        self.poll_interval = poll_interval
        self.stop_when_idle_after = stop_when_idle_after
        self.pattern = pattern
        self.max_packet_size = max_packet_size
        #: `Path` -> (size, mtime) as last *successfully* consumed.
        self._consumed: dict[Path, tuple[int, float]] = {}
        #: Packet budget for the whole watch, not per file.
        #:
        #: `max_total_packets` is enforced *inside* `PcapReader`, and this source
        #: reads through one `PcapReader` per file. Left alone, every file would get
        #: a fresh budget and the run-wide bound would be `files` times `limit` — which a
        #: directory watcher makes trivially reachable, since a rotation produces
        #: exactly the many-small-files shape that defeats it. So the budget is
        #: tracked here and spent as files are read, and the per-file readers are
        #: given the *remaining* allowance.
        self._max_total_packets = max_total_packets
        self._packets_read = 0

    @property
    def max_total_packets(self) -> int | None:
        """Run-wide packet budget, settable after construction.

        Public because `run_pipeline` owns the bound, not the source: a caller
        invokes the pipeline with `max_total_packets=N` and the pipeline is the
        thing that must push that down here, exactly as it passes the same bound to
        a `PcapReader` for a file input.
        """
        return self._max_total_packets

    @max_total_packets.setter
    def max_total_packets(self, value: int | None) -> None:
        # Reset the counter too, so tightening the bound after some packets have
        # been read means "in total", not "from here on" -- the latter would let a
        # caller lower the bound mid-run and still read a full allowance.
        self._max_total_packets = value
        self._packets_read = 0

    @property
    def path(self) -> Path | None:
        """Always `None`: the source spans a directory, so there is no single input
        file for the writer to be protected from."""
        return None

    def describe(self) -> str:
        suffix = "forever" if self.stop_when_idle_after is None else f"{self.stop_when_idle_after}s idle"
        return f"watch {self.directory} (poll {self.poll_interval}s, stop: {suffix})"

    def _candidates(self) -> list[Path]:
        if not self.directory.is_dir():
            raise PcapError(f"Cannot watch '{self.directory}': not a directory")
        found = []
        for path in sorted(self.directory.glob(self.pattern)):
            if not path.is_file():
                continue
            if path.suffix.lower() not in CAPTURE_SUFFIXES:
                continue
            found.append(path)
        return found

    @staticmethod
    def _stamp(path: Path) -> tuple[int, float]:
        stat = path.stat()
        return (stat.st_size, stat.st_mtime)

    def __iter__(self) -> Iterator[RawPacket]:
        while True:
            yielded_any = False

            for path in self._candidates():
                try:
                    stamp = self._stamp(path)
                except OSError:
                    # Vanished between the glob and the stat (a rotation in
                    # progress). Next poll will not see it, so nothing to report.
                    continue

                # Identity, not name: a file already consumed is skipped, but one
                # replaced at the same path -- different size or mtime -- is read
                # again, which is what a rotating writer does.
                if self._consumed.get(path) == stamp:
                    continue

                try:
                    # Spend from the run-wide budget, and hand the per-file reader
                    # whatever is left. Without this the bound would silently
                    # multiply by the number of rotations.
                    if (
                        self._max_total_packets is not None
                        and self._packets_read >= self._max_total_packets
                    ):
                        raise PcapLimitExceededError(
                            f"'{self.directory}' exceeds max_total_packets="
                            f"{self._max_total_packets}; refusing to read further "
                            "packets to bound memory/time on adversarial input."
                        )
                    remaining = (
                        self._max_total_packets - self._packets_read
                        if self._max_total_packets is not None
                        # No run-wide budget: each file gets the reader's own
                        # default, which is the same bound a direct file read gets.
                        else DEFAULT_MAX_TOTAL_PACKETS
                    )
                    reader = PcapReader(
                        path,
                        max_packet_size=self.max_packet_size,
                        max_total_packets=remaining,
                    )
                    with reader:
                        for packet in reader:
                            self._packets_read += 1
                            yield packet
                except PcapLimitExceededError:
                    # A resource bound is not "this file was not a capture".
                    # `PcapLimitExceededError` subclasses `PcapError`, so the
                    # handler below would swallow it and the watch would skip the
                    # remaining files as if they were junk -- turning a bound into
                    # a silent truncation. Propagate instead.
                    raise
                except PcapError:
                    # Not readable as a capture: still being written, or simply
                    # not one. Skipped rather than fatal, because the directory
                    # will hold other files and the valuable one may not have
                    # arrived yet.
                    #
                    # Recorded as *attempted* with its current stamp, which is what
                    # stops a permanently-unreadable file from holding a bounded
                    # watch open forever. It is still retried if the stamp changes
                    # -- so a capture being written is picked up once complete,
                    # without needing a "still growing" flag to special-case it.
                    with contextlib.suppress(OSError):
                        self._consumed[path] = self._stamp(path)
                    continue

                try:
                    self._consumed[path] = self._stamp(path)
                except OSError:
                    continue
                yielded_any = True

            if self.stop_when_idle_after is None:
                # Live watch. Sleep unconditionally so a quiet directory does not
                # spin the CPU for the lifetime of the process.
                time.sleep(self.poll_interval)
                continue

            if yielded_any:
                # Reset the idle clock on progress: a directory that is actively
                # producing should not be abandoned between files.
                time.sleep(self.poll_interval)
                continue

            # Nothing new. Wait out the idle window before giving up, since a file
            # may still be arriving -- this is the difference between "quiet" and
            # "finished".
            time.sleep(self.poll_interval)
            if not self._has_unconsumed():
                return

    def _has_unconsumed(self) -> bool:
        """Whether a file appeared that has not been consumed yet.

        "Consumed" means *dealt with*, not necessarily *read successfully*. An
        unreadable file is recorded with its stamp once it has been attempted, so
        it does not keep the watch alive forever -- but because its stamp is
        recorded rather than a completion flag, a file that is still being written
        changes stamp as it grows and is retried automatically, which is the case
        this has to get right. Marking a mid-write file as finished would lose
        everything appended to it afterwards.

        A vanished *directory* propagates `PcapError` rather than being swallowed.
        An earlier version caught it here and reported "nothing left", which
        contradicted the main loop -- where the same condition raises -- and would
        have made a watch silently finish because its directory was unmounted. A
        missing directory is a real condition the caller needs to see.
        """
        candidates = self._candidates()
        return any(self._consumed.get(p) != self._stamp(p) for p in candidates)
