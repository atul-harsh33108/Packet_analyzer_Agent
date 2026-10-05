"""End-to-end throughput: how many packets per second does each pipeline variant do?

**Not run by default.** `--benchmark-disable` is in the project's pytest
`addopts`; pytest-benchmark then reports these as *passed* without executing
the body, so "green" here does not mean they ran. Run with:

    uv run pytest tests/benchmarks/test_end_to_end.py --benchmark-enable

`P-15` in `AUDIT.md` flags that the port's per-packet throughput is unmeasured
and probably worse than the C++ original: a `WorkItem` is pickled per packet
across a process boundary, the five-tuple hash is a pure-Python mix, and every
packet currently rides back to the parent inside the `WorkerResult`.

First baseline -- 4000 synthetic packets, Windows, Python 3.13:

    single process    113 ms    35 Kpps
    multiprocess (4)  527 ms     8 Kpps    4.7x SLOWER than single
    staged (2+4)      694 ms     6 Kpps    6.2x SLOWER than single

**The scaling paths are slower than not using them**, which is the concrete
form of `P-15` and of the design note that the staged tier is
queue-decoupling rather than throughput. Two caveats keep this honest: 4000
packets is small, so process spawn and queue setup are a large share of each
measurement and flatter the multiprocess variants; and these synthetic frames
are 54 bytes, so per-record pickling overhead is proportionally larger than it
would be on real traffic. The *direction* is measured even if the magnitude
would shrink on a large capture, and re-measuring after `T0-11` is the point
of keeping the suite.
"""

from __future__ import annotations

import sys
from pathlib import Path

from dpi_engine.pipeline import run_pipeline, run_pipeline_multiprocess, run_pipeline_staged

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_resource_bounds import _build_many_tiny_flows_pcap

# Small enough to keep the benchmark suite quick, large enough that fixed
# process-startup cost is not most of the measurement.
PACKET_COUNT = 4000


def _capture(tmp_path: Path, name: str = "bench.pcap") -> Path:
    path = tmp_path / name
    _build_many_tiny_flows_pcap(path, PACKET_COUNT)
    return path


def test_benchmark_run_pipeline_single_process(benchmark, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """The default path, and the only variant with genuinely bounded memory
    today (`AUDIT.md` D-01) because it streams the output as it goes."""
    source = _capture(tmp_path)
    benchmark(run_pipeline, source, tmp_path / "out.pcap")


def test_benchmark_run_pipeline_multiprocess(benchmark, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """One IPC hop: pickles a `WorkItem` per packet in each direction."""
    source = _capture(tmp_path)
    benchmark(run_pipeline_multiprocess, source, tmp_path / "out.pcap", num_workers=4)


def test_benchmark_run_pipeline_staged(benchmark, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """Two hops. Documented as *not* a throughput optimisation -- the LB tier is
    queue-decoupling and observability. This benchmark exists to keep that
    claim honest rather than assumed."""
    source = _capture(tmp_path)
    benchmark(
        run_pipeline_staged,
        source,
        tmp_path / "out.pcap",
        num_load_balancers=2,
        fps_per_lb=2,
    )
