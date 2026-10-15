"""Phase 1's fifth exit criterion: memory stays bounded under a streaming run fed
by a directory-watch source.

Stated in Appendix B as *"memory bounded under a streaming run with a
directory-watch source"* -- the combination of everything `T1-03` and `T1-02` were
built for, and the one criterion nothing actually measured. Flow reaping is covered
(`test_integration.py`) and the reorder window is covered (`test_reorder_buffer.py`),
but neither runs against a `WatchSource`, and neither asserts anything about *peak*
memory.

**The measurement is a ratio, not a threshold, and the input deliberately exceeds
the window.** Both details are load-bearing:

- A *ratio* survives a crude instrument. `tracemalloc` counts Python allocations,
  not the process's whole footprint, so an absolute byte threshold would be
  meaningless across machines. What matters is whether peak **scales with input**,
  and that is a shape, not a size.
- The input must be **larger than `reorder_window`** or the test measures nothing.
  With a 1024-slot window and 616 packets, every packet fits in the buffer at once
  -- so peak legitimately grows with input, because the buffer is allowed to hold
  it all. An earlier version of this file compared 77 against 616 packets and
  reported 5.4x growth as if it were a leak. It was not: both sizes were *under* the
  window, so it was measuring "more packets fit in the buffer". Measured properly,
  across 1078 -> 4312 packets at a fixed 1024 window, peak is flat at ~1.62 MB.

Each measurement runs in a **fresh subprocess**, because spawn-based
multiprocessing requires it and because a second measurement in the same process
inherits whatever the first left allocated.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import TEST_DPI_PCAP

REPO_ROOT = Path(__file__).resolve().parents[1]

#: `DEC-01`'s default. Also the window these measurements hold fixed.
WINDOW = 1024

#: One copy of the sample capture is 77 packets, so this is the smallest rotation
#: count that *exceeds* the window -- below it the bound is not engaged and the
#: comparison would prove nothing.
COPIES_ABOVE_WINDOW = 14


def _measure(copies: int, window: int = WINDOW) -> tuple[int, int]:
    """Runs one watch-source streaming pipeline in a fresh process.

    Returns `(packets_seen, peak_bytes)`.
    """
    script = REPO_ROOT / "tests" / "_mem_probe.py"
    proc = subprocess.run(
        [sys.executable, str(script), str(copies), str(window)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=600,
    )
    match = re.search(r"^RESULT (\d+) (\d+)$", proc.stdout, re.MULTILINE)
    if match is None:
        raise AssertionError(
            f"probe produced no RESULT line (rc={proc.returncode})\n"
            f"stdout:\n{proc.stdout[-2000:]}\nstderr:\n{proc.stderr[-2000:]}"
        )
    packets, peak = int(match.group(1)), int(match.group(2))
    return packets, peak


class TestMemoryIsBoundedUnderAWatchSource:
    def test_peak_is_flat_once_the_input_exceeds_the_window(
        self, tmp_path: Path
    ) -> None:
        """The criterion itself: **flat, not growing**.

        Four times the input against a fixed window must not cost four times the
        peak. This is the `D-01` failure mode -- retaining every packet, or
        accumulating results until the end -- and it is the only assertion here
        that would catch it.

        The threshold is loose (under 1.6x for 4x input) because the instrument is
        crude, and deliberately *not* under 3x: the earlier 77-vs-616 comparison
        also sat under 3x once measured correctly, and a bound loose enough to
        admit an unbounded run is not a bound. Here the input genuinely exceeds the
        window, so unbounded accumulation would be ~4x and cannot hide inside 1.6x.
        """
        small_packets, small_peak = _measure(COPIES_ABOVE_WINDOW)
        large_packets, large_peak = _measure(COPIES_ABOVE_WINDOW * 4)

        # Confirm the larger run really did more work, or the ratio means nothing.
        assert large_packets == small_packets * 4
        assert small_packets > WINDOW, (
            f"the smaller run ({small_packets} packets) must exceed the "
            f"{WINDOW}-packet window, or the bound is not engaged"
        )

        ratio = large_peak / small_peak
        assert ratio < 1.6, (
            f"peak memory grew {ratio:.2f}x for 4x the input "
            f"({small_peak} -> {large_peak} bytes, both above the window). "
            "Memory is scaling with the capture, which is the D-01 failure mode "
            "this criterion exists to catch."
        )

    def test_the_reorder_window_is_what_bounds_it(self) -> None:
        """A smaller window must peak lower, which proves the window is the cause.

        Without this, "flat above the window" would also be consistent with some
        unrelated fixed ceiling, and would prove nothing about `DEC-01`. Here the
        peak must actually *respond* to the bound, so the criterion is satisfied by
        construction rather than by coincidence.
        """
        narrow_packets, narrow_peak = _measure(COPIES_ABOVE_WINDOW * 4, window=32)
        wide_packets, wide_peak = _measure(COPIES_ABOVE_WINDOW * 4, window=WINDOW)

        assert narrow_packets == wide_packets
        assert narrow_peak < wide_peak, (
            "a narrower reorder window must retain less, so a lower peak is what "
            f"proves the window actually bounds memory ({narrow_peak} vs {wide_peak})"
        )

    def test_the_watch_source_is_actually_consumed(self) -> None:
        """A flat peak from a source that read nothing would be hollow.

        Pins that every rotation was read, so the flat-peak assertions above are
        about throughput of the reader rather than about it declining to do any.
        """
        from dpi_engine.pcap_io import PcapReader

        with PcapReader(TEST_DPI_PCAP) as reader:
            one_capture = len(list(reader))

        packets, _ = _measure(COPIES_ABOVE_WINDOW)
        assert packets == one_capture * COPIES_ABOVE_WINDOW

    def test_the_packet_bound_still_bounds_a_watch_run(self, tmp_path: Path) -> None:
        """A bound that only worked for file inputs is a bound you can walk past.

        `WatchSource` reads through one `PcapReader` **per file**, so an
        enforcement point inside the reader would give every file a fresh budget
        and the run-wide bound would become `files x limit`. That was a real bug
        found by this criterion: 4 files of 77 packets read 308 packets against
        `max_total_packets=50` without complaint.
        """
        from dpi_engine.cap_source import WatchSource
        from dpi_engine.pcap_io import PcapLimitExceededError
        from dpi_engine.pipeline import run_pipeline

        watched = _capture_dir(tmp_path / "caps")
        shutil.copy(TEST_DPI_PCAP, watched / "a.pcap")
        shutil.copy(TEST_DPI_PCAP, watched / "b.pcap")
        shutil.copy(TEST_DPI_PCAP, watched / "c.pcap")

        with pytest.raises(PcapLimitExceededError):
            run_pipeline(
                WatchSource(watched, poll_interval=0.001, stop_when_idle_after=0.5),
                tmp_path / "out.pcap",
                max_total_packets=50,
            )

    def test_a_bound_above_the_input_does_not_fire(self, tmp_path: Path) -> None:
        """The counterweight: the bound must not fire on legitimate input.

        A bound that always fired would satisfy the test above while making the
        source useless, which is the same shape of bug as a gate that always
        refuses.
        """
        from dpi_engine.cap_source import WatchSource
        from dpi_engine.pipeline import run_pipeline

        watched = _capture_dir(tmp_path / "caps")
        shutil.copy(TEST_DPI_PCAP, watched / "a.pcap")

        result = run_pipeline(
            WatchSource(watched, poll_interval=0.001, stop_when_idle_after=0.5),
            watched.parent / "out.pcap",
            max_total_packets=10_000,
        )
        assert result.stats.total_packets > 0


def _capture_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path
