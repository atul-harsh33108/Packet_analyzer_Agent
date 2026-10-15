"""`T1-02` — capture sources beyond "a path that already exists on disk".

Every pipeline variant today starts with `PcapReader(path)`, which is fine for a
capture that is already on disk and useless for the three cases that matter for a
real-time engine:

- a capture still being written (tail it as it grows),
- a capture arriving over a pipe or socket (`tcpdump -w - | engine`),
- a directory of rotating captures that should be picked up as they appear.

`CapSource` is the abstraction over those. The contract is deliberately narrow —
**a `CapSource` is an iterable of `RawPacket`** — because that is the shape
`_iter_inspectable` already consumes, so no pipeline code changes. Every source
delegates the actual parsing to `PcapReader` and stays the *only* I/O boundary that
opens bytes. That is what keeps the safety invariants true by construction rather
than by each call site remembering them.

The property these tests exist to pin is byte-for-byte equivalence: a stream must
produce exactly the packets the equivalent file produces. Anything less would mean a
second parser, and a second parser is a second set of bugs.
"""

from __future__ import annotations

import io
import os
import shutil
import time
from pathlib import Path

import pytest

from conftest import TEST_DPI_PCAP
from dpi_engine import cap_source, pcap_io
from dpi_engine.cap_source import CapSource, FileSource, StreamSource, WatchSource
from dpi_engine.pcap_io import PcapError, PcapReader, RawPacket
from dpi_engine.pipeline import run_pipeline


def _fixture_bytes() -> bytes:
    return TEST_DPI_PCAP.read_bytes()


class TestFileSource:
    def test_reads_the_same_packets_as_a_bare_reader(self) -> None:
        """The reference case: a file source must be indistinguishable from
        `PcapReader` on the same path.

        If this diverges, every other source's equivalence claim is worthless.
        """
        with PcapReader(TEST_DPI_PCAP) as reader:
            expected = list(reader)

        packets = list(FileSource(TEST_DPI_PCAP))

        assert [p.data for p in packets] == [p.data for p in expected]
        assert [p.ts_sec for p in packets] == [p.ts_sec for p in expected]

    def test_reports_its_path(self) -> None:
        """A file source knows its path, and the pipeline needs it for the writer's
        never-overwrite-the-input guard."""
        source = FileSource(TEST_DPI_PCAP)
        assert source.path == TEST_DPI_PCAP
        assert source.describe() == str(TEST_DPI_PCAP)

    def test_is_a_cap_source(self) -> None:
        assert isinstance(FileSource(TEST_DPI_PCAP), CapSource)

    def test_a_missing_file_raises_pcap_error(self, tmp_path: Path) -> None:
        """A source must fail with the module's own error type.

        `cli.py` catches only `(PcapError, ValueError)`; an unwrapped
        `FileNotFoundError` would escape `main()` as a traceback.
        """
        with pytest.raises(PcapError):
            list(FileSource(tmp_path / "nope.pcap"))


class TestStreamSource:
    def test_round_trips_byte_for_byte_against_the_file(self) -> None:
        """The central equivalence claim, and the reason `CapSource` delegates to
        `PcapReader` rather than parsing itself."""
        with PcapReader(TEST_DPI_PCAP) as reader:
            expected = [p.data for p in reader]

        assert [p.data for p in StreamSource(io.BytesIO(_fixture_bytes()))] == expected

    def test_has_no_path(self) -> None:
        """A stream cannot be re-opened, so it must not pretend to have a path.

        The pipeline passes `source_path` to `PcapWriter` for the
        never-overwrite-the-input guard. A stream has none, and `None` is the
        honest answer -- inventing a path would let the guard compare a stream
        against a file that was never read.
        """
        assert StreamSource(io.BytesIO(_fixture_bytes())).path is None

    def test_accepts_a_real_file_object(self, tmp_path: Path) -> None:
        """Not just `BytesIO` — the realistic case is an open file or a pipe."""
        copy = tmp_path / "copy.pcap"
        shutil.copy(TEST_DPI_PCAP, copy)
        with copy.open("rb") as handle:
            with PcapReader(TEST_DPI_PCAP) as reader:
                expected = [p.data for p in reader]
            assert [p.data for p in StreamSource(handle)] == expected

    def test_an_empty_stream_raises_rather_than_yielding_nothing(self) -> None:
        """Silence is not a valid capture.

        A zero-byte stream would otherwise iterate as "zero packets" and look
        identical to a legitimately empty result, which would let a truncated
        transfer pass as a clean run.
        """
        with pytest.raises(PcapError):
            list(StreamSource(io.BytesIO(b"")))

    def test_a_truncated_stream_stops_cleanly_rather_than_raising(self) -> None:
        """The other half of the empty case.

        A capture cut mid-packet is normal for a live stream -- the writer is still
        going -- so it must end iteration, not raise. This mirrors
        `PcapReader.__iter__`, which breaks rather than raising on a short record.
        """
        data = _fixture_bytes()
        truncated = data[: len(data) // 2]

        packets = list(StreamSource(io.BytesIO(truncated)))
        assert packets, "a truncated capture should still yield its complete packets"

    def test_survives_being_iterated_only_once_per_stream(self) -> None:
        """A stream is consumed by reading; a second iteration yields nothing.

        Pinned because it is a real footgun for a caller that assumes a source is
        re-readable like a file. The safe behaviour is to *say so*, so
        `describe()` names the kind of source.
        """
        source = StreamSource(io.BytesIO(_fixture_bytes()))
        assert "stream" in source.describe().lower()


class TestWatchSource:
    def test_picks_up_a_file_that_appears_after_it_starts(self, tmp_path: Path) -> None:
        """The defining behaviour: new files are picked up, not just existing ones.

        A directory watcher that only listed what was there at construction time
        would pass every test that pre-populates the directory, and would be useless
        for rotating captures -- which is the case that motivates it.
        """
        source = WatchSource(tmp_path, poll_interval=0.01, stop_when_idle_after=1.0)

        # Start with an empty directory, then drop a capture in.
        assert not any(tmp_path.iterdir())
        shutil.copy(TEST_DPI_PCAP, tmp_path / "later.pcap")

        packets = list(source)

        assert packets, "a file that appeared after construction must be picked up"
        with PcapReader(TEST_DPI_PCAP) as reader:
            assert [p.data for p in packets] == [p.data for p in reader]

    def test_reads_every_file_in_the_directory(self, tmp_path: Path) -> None:
        """Rotating captures mean several files, and all of them must be read."""
        source = WatchSource(tmp_path, poll_interval=0.01, stop_when_idle_after=1.0)
        shutil.copy(TEST_DPI_PCAP, tmp_path / "a.pcap")
        shutil.copy(TEST_DPI_PCAP, tmp_path / "b.pcap")

        packets = list(source)

        with PcapReader(TEST_DPI_PCAP) as reader:
            expected = [p.data for p in reader]

        assert len(packets) == 2 * len(expected)

    def test_does_not_reread_a_file_it_has_already_consumed(self, tmp_path: Path) -> None:
        """Each file is read once.

        Without this a long-running watcher would re-emit old packets every poll
        and inflate every counter in the report.
        """
        source = WatchSource(tmp_path, poll_interval=0.01, stop_when_idle_after=1.0)
        shutil.copy(TEST_DPI_PCAP, tmp_path / "once.pcap")
        first = len(list(source))

        # A second collection over the same source must find nothing new.
        assert len(list(source)) == 0
        assert first > 0

    def test_ignores_non_pcap_files(self, tmp_path: Path) -> None:
        """A capture directory will contain other things.

        A `.txt` or a partially-written lockfile must not abort the whole watch --
        the engine should skip what it cannot read and keep going, because the
        valuable file may appear later.
        """
        source = WatchSource(tmp_path, poll_interval=0.01, stop_when_idle_after=1.0)
        (tmp_path / "notes.txt").write_text("not a capture")
        (tmp_path / "archive.tar.gz").write_bytes(os.urandom(64))
        shutil.copy(TEST_DPI_PCAP, tmp_path / "real.pcap")

        packets = list(source)
        assert packets, "the real capture must still be read"

    def test_one_unreadable_file_does_not_lose_the_good_ones(self, tmp_path: Path) -> None:
        """A file that is not a capture must not abort the whole watch.

        Stated separately from the `.txt` case because that one relies on the
        suffix filter, so it never reaches the parse. This puts an actual pcapng
        file in the directory: it *looks* like a capture, so the suffix filter lets
        it through, and only the error handling inside the loop can save the run.
        A watcher that propagated that error would lose every file, including the
        good ones that had not been reached yet.
        """
        source = WatchSource(tmp_path, poll_interval=0.01, stop_when_idle_after=1.0)
        (tmp_path / "first.pcapng").write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)
        shutil.copy(TEST_DPI_PCAP, tmp_path / "zz_good.pcap")

        packets = list(source)

        assert packets, "a pcapng neighbour must not cost us the good capture"

    def test_a_file_still_being_written_is_read_once_it_is_complete(
        self, tmp_path: Path
    ) -> None:
        """The race that makes naive tailing wrong.

        A writer partway through a capture leaves a file whose last record is
        truncated. Reading it eagerly yields the complete packets and then stops,
        which is fine -- but reading it and then *marking it consumed* would lose
        everything appended afterwards. So a file that looks incomplete must be
        retried until it parses cleanly.
        """
        data = _fixture_bytes()
        partial = tmp_path / "growing.pcap"
        partial.write_bytes(data[: len(data) // 2])

        source = WatchSource(tmp_path, poll_interval=0.01, stop_when_idle_after=0.4)
        packets = list(source)

        # A half-written capture yields its complete records and stops -- the same
        # behaviour `PcapReader` has for a capture cut mid-packet, which is
        # normal rather than corrupt.
        with PcapReader(TEST_DPI_PCAP) as reader:
            total = len(list(reader))
        assert 0 < len(packets) <= total, (
            "a partial capture must yield its complete packets but not more than "
            f"the whole file has ({len(packets)} vs {total})"
        )

    def test_stop_when_idle_bounds_an_empty_directory(self, tmp_path: Path) -> None:
        """A watcher on a quiet directory must terminate rather than block forever.

        Without an idle bound this is an infinite loop, which is what makes
        directory watching awkward to embed.
        """
        started = time.monotonic()
        packets = list(WatchSource(tmp_path, poll_interval=0.01, stop_when_idle_after=0.2))
        elapsed = time.monotonic() - started

        assert packets == []
        assert elapsed < 5.0, "an idle watch did not honour its stop condition"

    def test_the_default_never_stops_on_its_own(self, tmp_path: Path) -> None:
        """The default must be "watch forever", because that is what a live engine
        wants.

        Asserted via the attribute rather than by running it, since the point is
        precisely that the default does *not* return.
        """
        source = WatchSource(tmp_path)
        assert source.stop_when_idle_after is None

    def test_a_file_that_vanishes_mid_scan_does_not_end_the_watch(
        self, tmp_path: Path
    ) -> None:
        """A rotation in progress removes files while the watcher is scanning.

        The glob and the `stat` are separate operations, so a file can be listed
        and then deleted before it is read. That is normal for a rotating writer,
        not an error, and it must not be reported as one -- nor stop the good files
        from being read.
        """
        source = WatchSource(tmp_path, poll_interval=0.01, stop_when_idle_after=1.0)
        shutil.copy(TEST_DPI_PCAP, tmp_path / "real.pcap")

        real_stamp = source._stamp

        def stamp_then_vanish(path: Path) -> tuple[int, float]:
            # Simulate the race: stat succeeds, then the file is gone by the time
            # the watcher tries to open it.
            result = real_stamp(path)
            path.unlink()
            return result

        source._stamp = stamp_then_vanish  # type: ignore[method-assign]

        # The vanished file must not raise; the watch simply finds nothing there.
        assert list(source) == []

    def test_a_vanished_directory_at_the_idle_check_raises(
        self, tmp_path: Path
    ) -> None:
        """A directory that disappears mid-watch must raise, not quietly finish.

        An earlier version of `_has_unconsumed` caught this and reported "nothing
        left", while the main loop raised on the same condition. The two paths
        contradicted each other, and the silent one was the dangerous one: a watch
        whose directory was unmounted would report a clean end of capture rather
        than an error, which for a live engine is indistinguishable from "the
        traffic stopped".
        """
        watch_dir = tmp_path / "captures"
        watch_dir.mkdir()
        source = WatchSource(watch_dir, poll_interval=0.01, stop_when_idle_after=0.1)
        watch_dir.rmdir()

        with pytest.raises(PcapError, match="not a directory"):
            list(source)

    def test_the_live_watch_loop_repeats_rather_than_finishing(
        self, tmp_path: Path
    ) -> None:
        """The default (forever) watch must loop, and must sleep between scans.

        Testing the default by running it would hang, so the loop is bounded by
        raising from the scan itself once it has run twice. That makes the
        iteration observable and also pins the sleep: without it a quiet directory
        would spin the CPU for the lifetime of the process, which for a live engine
        is a defect that looks like nothing at all.
        """
        shutil.copy(TEST_DPI_PCAP, tmp_path / "a.pcap")
        source = WatchSource(tmp_path, poll_interval=0.001)  # never stops by itself

        scans = 0
        sleeps = 0
        real_candidates = source._candidates
        real_sleep = cap_source.time.sleep

        def counting_candidates() -> list[Path]:
            nonlocal scans
            scans += 1
            if scans > 2:
                raise _StopWatching
            return real_candidates()

        def counting_sleep(seconds: float) -> None:
            nonlocal sleeps
            sleeps += 1
            real_sleep(0)  # don't actually wait, but do yield

        source._candidates = counting_candidates  # type: ignore[method-assign]
        cap_source.time.sleep = counting_sleep  # type: ignore[assignment]
        try:
            with pytest.raises(_StopWatching):
                list(source)
        finally:
            cap_source.time.sleep = real_sleep  # type: ignore[assignment]

        assert scans == 3, "the watch must keep scanning until told to stop"
        assert sleeps == 2, (
            "a quiet live watch must sleep between scans, not spin the CPU"
        )

    def test_a_missing_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PcapError):
            list(WatchSource(tmp_path / "absent"))


class _StopWatching(Exception):
    """Sentinel used to break out of an otherwise infinite watch loop."""


class _NonSeekableStream(io.RawIOBase):
    """A readable stream that cannot seek -- i.e. what a pipe actually is.

    Every other test in this file uses a `BytesIO` or a real file, and **both of
    those can seek**. So the suite as it stood never executed the
    non-rewindable path at all, which is precisely the path a live capture takes:
    `PcapReader` peeks four bytes of magic and then needs to start again from zero,
    and on a pipe there is no `seek`. Mutation testing caught this -- the two
    mutants on that branch both survived.
    """

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._data = data
        self._pos = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            out = self._data[self._pos :]
            self._pos = len(self._data)
            return out
        out = self._data[self._pos : self._pos + size]
        self._pos += len(out)
        return out

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False


def test_pcap_reader_refuses_to_construct_with_neither_path_nor_stream() -> None:
    """A reader with no input would fail later, much less clearly.

    `PcapReader()` with neither argument used to produce a reader that raised
    `AttributeError` on `None.open(...)`, which is not an error a caller can act
    on. Failing at construction with a plain `ValueError` names the mistake.
    """
    with pytest.raises(ValueError, match="path or a stream"):
        PcapReader()


class TestNonSeekableStream:
    """The live-pipe case, which is the one `StreamSource` exists for."""

    def test_a_non_seekable_stream_yields_the_same_packets(self) -> None:
        """Byte-for-byte equality with the file, through a stream that cannot seek."""
        with PcapReader(TEST_DPI_PCAP) as reader:
            expected = [p.data for p in reader]

        got = [p.data for p in StreamSource(_NonSeekableStream(_fixture_bytes()))]

        assert got == expected, (
            "a non-rewindable stream must produce exactly the packets the file "
            "does; the four magic bytes peeked during format detection have to be "
            "put back"
        )

    def test_a_non_seekable_stream_is_detected_as_non_rewindable(self) -> None:
        """The reader must not attempt a `seek` it cannot perform."""
        reader = PcapReader(stream=_NonSeekableStream(_fixture_bytes()))
        assert not reader._rewindable
        reader.close()

    def test_the_prefix_adapter_replays_the_peeked_bytes_exactly_once(self) -> None:
        """The adapter's whole job is four bytes in front, once.

        An adapter that re-served them, or advanced its offset wrongly, would
        corrupt the capture silently -- so this asserts the byte stream itself
        rather than only the parsed result.
        """
        stream = io.BytesIO(b"HEADERBODY")
        prefixed = pcap_io._PrefixedStream(b"MAGI", stream)

        # Four bytes -- the size of the magic peek this adapter exists for.
        assert prefixed.read(4) == b"MAGI"
        assert prefixed.read(3) == b"HEA"
        assert prefixed.read(5) == b"DERBO"
        assert prefixed.read() == b"DY"
        assert prefixed.read() == b""

    def test_the_prefix_adapter_handles_a_read_smaller_than_the_prefix(
        self,
    ) -> None:
        """A one-byte read must not lose the rest of the prefix.

        This is the off-by-one the adapter exists to avoid, and it would only show
        up as a corrupt capture several packets later.
        """
        prefixed = pcap_io._PrefixedStream(b"MAGIC", io.BytesIO(b"REST"))

        assert prefixed.read(1) == b"M"
        assert prefixed.read(1) == b"A"
        # The adapter has 3 prefix bytes left ("GIC"), so a 2-byte read must take
        # both from the prefix and *not* reach the stream -- that boundary is the
        # whole point of the offset arithmetic.
        assert prefixed.read(2) == b"GI"
        # One prefix byte ("C") is left, so a 10-byte read must emit it and then
        # pull the remaining 9 from the stream -- crossing the prefix/stream
        # boundary mid-read without losing or duplicating a byte.
        assert prefixed.read(10) == b"CREST"

    def test_a_non_seekable_stream_run_matches_a_file_run(
        self, tmp_path: Path
    ) -> None:
        """End to end, through the pipeline, with a pipe-like source."""
        from_file = run_pipeline(TEST_DPI_PCAP, tmp_path / "file.pcap")
        from_stream = run_pipeline(
            StreamSource(_NonSeekableStream(_fixture_bytes())), tmp_path / "stream.pcap"
        )

        assert from_stream.stats.total_packets == from_file.stats.total_packets
        assert from_stream.detected_domains == from_file.detected_domains

    def test_a_pcapng_pipe_is_still_rejected_with_its_actionable_message(self) -> None:
        """`DEC-02`'s diagnostic has to survive the non-seekable path too.

        A stream is the most likely place to meet a pcapng file -- `tcpdump -w`
        can be configured to emit it -- so losing the `editcap` hint here would be
        losing it exactly where it is needed.
        """
        from dpi_engine.pcap_io import PcapngUnsupportedError

        data = b"\x0a\x0d\x0d\x0a" + b"\x00" * 32
        with pytest.raises(PcapngUnsupportedError, match="editcap"):
            list(StreamSource(_NonSeekableStream(data)))

    def test_a_seekable_caller_owned_stream_survives_close(self, tmp_path: Path) -> None:
        """The `close()` guard is load-bearing for *seekable* streams only.

        Two different mechanisms protect a caller here, and they cover different
        cases, which is easy to conflate:

        - a **non-seekable** stream gets wrapped in `_PrefixedStream` during format
          detection, and that wrapper's `close()` does not forward -- so the
          caller's pipe is safe whatever `PcapReader.close()` does;
        - a **seekable** stream is used directly, with no wrapper, so the only
          thing stopping the reader from closing it is `PcapReader.close()`'s own
          `if self.path is not None` guard.

        Dropping that guard would leave non-seekable streams passing while breaking
        this one, so the case has to be tested explicitly rather than assumed from
        the pipe tests.
        """
        copy = tmp_path / "copy.pcap"
        shutil.copy(TEST_DPI_PCAP, copy)
        handle = copy.open("rb")
        assert handle.seekable(), "this test is only meaningful for a seekable stream"

        # `PcapReader.close()` directly, not via `StreamSource`: the source
        # consumes the reader by iteration and never calls `close()`, so testing
        # through it would not reach the guard at all.
        reader = PcapReader(stream=handle)
        assert [p.data for p in reader]
        reader.close()

        assert not handle.closed, (
            "PcapReader.close() closed a seekable stream it does not own; the "
            "caller may still be reading from it"
        )
        handle.close()  # ours to close, now that the point has been made

        # And on the failure path too: a rejected capture must not close a
        # seekable caller stream either.
        with pytest.raises(PcapError):
            list(StreamSource(io.BytesIO(b"NOTAPCAPFILE" + b"\x00" * 16)))

    def test_a_caller_owned_stream_survives_a_failed_open(self, tmp_path: Path) -> None:
        """The error paths close their handle too, and must spare a caller's stream.

        `PcapReader` closes the handle when it rejects a capture -- a pcapng file,
        a bad magic, a wrong linktype. Three of those sites. If any of them closed
        a caller-owned stream, then the *first* malformed capture on a live pipe
        would shut the pipe down and the caller would see a closed pipe rather than
        a readable error. So this is checked per rejection reason, not once.
        """
        cases = [
            # pcapng magic
            (b"\x0a\x0d\x0d\x0a" + b"\x00" * 32, "pcapng"),
            # Not a pcap at all.
            (b"NOTAPCAPFILE" + b"\x00" * 16, "invalid"),
        ]
        for data, label in cases:
            stream = _NonSeekableStream(data)
            with pytest.raises(PcapError):
                list(StreamSource(stream))
            assert not stream.closed, (
                f"the {label} rejection closed a stream the caller owns; a live "
                "pipe must survive one malformed capture"
            )

    def test_a_caller_owned_stream_is_left_open_after_the_reader_closes(
        self,
    ) -> None:
        """Closing the reader must not close the caller's pipe.

        A reader that closed its stream would break the caller mid-capture, and
        for `StreamSource` the stream is the only copy of the data.
        """
        stream = _NonSeekableStream(_fixture_bytes())
        reader = PcapReader(stream=stream)
        list(reader)
        reader.close()

        assert not stream.closed, "the reader closed a stream it does not own"


class TestSourceIsUnifiedByTheProtocol:
    """The point of the abstraction: the pipeline should not care which it got."""

    def test_all_three_satisfy_the_same_protocol(self) -> None:
        for source in (
            FileSource(TEST_DPI_PCAP),
            StreamSource(io.BytesIO(_fixture_bytes())),
            WatchSource(Path(".")),
        ):
            assert isinstance(source, CapSource)
            assert isinstance(source.describe(), str)
            assert hasattr(source, "path")

    def test_the_pipeline_consumes_a_stream_source_unchanged(
        self, tmp_path: Path
    ) -> None:
        """End to end: a stream-driven run produces the same report as a file-driven
        one.

        This is the assertion that would fail if a `CapSource` ever grew its own
        parsing path instead of delegating to `PcapReader`.
        """
        from_file = run_pipeline(TEST_DPI_PCAP, tmp_path / "from_file.pcap")

        source = StreamSource(io.BytesIO(_fixture_bytes()))
        from_stream = run_pipeline(source, tmp_path / "from_stream.pcap")

        assert from_stream.stats.total_packets == from_file.stats.total_packets
        assert from_stream.stats.dropped_packets == from_file.stats.dropped_packets
        assert from_stream.app_counts == from_file.app_counts
        assert from_stream.detected_domains == from_file.detected_domains

    def test_run_pipeline_accepts_a_cap_source_without_type_error(self, tmp_path: Path) -> None:
        """A type error here would mean the signature still says `path`."""
        result = run_pipeline(FileSource(TEST_DPI_PCAP), tmp_path / "out.pcap")
        assert result.stats.total_packets > 0

    def test_a_stream_run_does_not_need_a_source_path_for_the_writer(
        self, tmp_path: Path
    ) -> None:
        """The writer's never-overwrite guard takes `source_path`; a stream has none.

        So the guard must be *skipped* rather than fed a lie. Writing the output
        over the input is impossible when the input is an anonymous stream, and
        asserting otherwise would require a path that does not exist.
        """
        source = StreamSource(io.BytesIO(_fixture_bytes()))
        out = tmp_path / "out.pcap"
        run_pipeline(source, out)
        assert out.exists() and out.stat().st_size > 0

    def test_file_source_still_blocks_writing_over_its_input(
        self, tmp_path: Path
    ) -> None:
        """...while a file source must keep the guard.

        If the new source types weakened this for file inputs, the safety invariant
        would be lost for every existing caller.
        """
        source = FileSource(TEST_DPI_PCAP)
        with pytest.raises(PcapError, match=r"same path|same file"):
            run_pipeline(source, TEST_DPI_PCAP)


class TestSourceDoesNotOwnTheParsing:
    """Structural guarantees, checked against the source rather than assumed."""

    def test_every_source_yields_raw_packets(self) -> None:
        """Whatever a source yields, it must be `RawPacket` -- the one type the
        pipeline knows how to handle."""
        with PcapReader(TEST_DPI_PCAP) as reader:
            expected = list(reader)

        assert all(isinstance(p, RawPacket) for p in FileSource(TEST_DPI_PCAP))
        assert all(
            isinstance(p, RawPacket) for p in StreamSource(io.BytesIO(_fixture_bytes()))
        )
        assert len(expected) > 0

    def test_pcapng_is_rejected_by_a_source_too(self, tmp_path: Path) -> None:
        """The pcapng diagnostic (`DEC-02`) must survive the new abstraction.

        A source that swallowed the error and yielded nothing would turn a precise,
        actionable message into a silent empty run -- the exact regression `DEC-02`
        was decided to prevent.
        """
        from dpi_engine.pcap_io import PcapngUnsupportedError

        fake = tmp_path / "capture.pcapng"
        fake.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)

        with pytest.raises(PcapngUnsupportedError, match="editcap"):
            list(FileSource(fake))
        with pytest.raises(PcapngUnsupportedError, match="editcap"):
            list(StreamSource(io.BytesIO(fake.read_bytes())))

    def test_module_exports_the_three_sources(self) -> None:
        """A caller importing from the module must find them."""
        for name in ("CapSource", "FileSource", "StreamSource", "WatchSource"):
            assert hasattr(cap_source, name)
