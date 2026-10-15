"""Measures one watch-source streaming run in a fresh process.

Separate from the test module on purpose: it has to run under `spawn`, which
requires the `__main__` guard, and each measurement must inherit nothing from a
previous run. Prints one machine-readable `RESULT` line for the caller to parse.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import tracemalloc
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))
sys.path.insert(0, str(_REPO / "tests"))


def main() -> None:
    copies = int(sys.argv[1])
    window = int(sys.argv[2]) if len(sys.argv) > 2 else 1024

    from conftest import TEST_DPI_PCAP
    from dpi_engine.cap_source import WatchSource
    from dpi_engine.pipeline import run_pipeline_multiprocess

    tmp = Path(tempfile.mkdtemp())
    captures = tmp / "caps"
    captures.mkdir()
    for i in range(copies):
        shutil.copy(TEST_DPI_PCAP, captures / f"rot-{i:04d}.pcap")

    source = WatchSource(captures, poll_interval=0.001, stop_when_idle_after=0.5)
    tracemalloc.start()
    result = run_pipeline_multiprocess(
        source, tmp / "out.pcap", max_total_packets=1_000_000, reorder_window=window
    )
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"RESULT {result.stats.total_packets} {peak}")


if __name__ == "__main__":
    main()
