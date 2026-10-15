# Benchmark baseline

**Published baseline for `T1-08`.** Every number here comes from
[`tests/benchmarks/baseline.json`](tests/benchmarks/baseline.json), which is
committed alongside this file. Nothing below is transcribed by hand — if you
change a benchmark, regenerate the JSON and this document together, or they will
disagree.

## Running them

```powershell
uv run pytest tests/benchmarks --benchmark-enable
```

**`--benchmark-enable` is not optional.** `--benchmark-disable` is in the
project's pytest `addopts`, so a plain `uv run pytest tests/benchmarks` reports
these eight tests as **passed without executing them**. Measured here: the default
run finishes in 3.0 s, the real run in 18–19 s. A green result from the default
invocation is not evidence that anything ran, and that caveat is recorded on
`T1-08` in the task tracker too.

To re-baseline:

```powershell
uv run pytest tests/benchmarks --benchmark-enable --benchmark-save=baseline.json
Move-Item .benchmarks\Windows-CPython-3.13-64bit\0001_baseline.json.json tests\benchmarks\baseline.json
```

Two things that step will surprise you with:

- `--benchmark-save` **rejects any path containing `/`**. Write a bare filename;
  pytest puts it under `.benchmarks/<platform>/`.
- `.benchmarks/` is gitignored. That directory is pytest's *comparison* store, not
  the published artifact — the committed copy is `tests/benchmarks/baseline.json`.

## The headline: the scaling paths are slower than not using them

4000 synthetic packets, Windows, Python 3.13, AMD Ryzen 5 5600H:

| Variant | Mean | Min | Throughput | Relative |
|---|---|---|---|---|
| `run_pipeline` (single process) | **137.5 ms** | 133.1 ms | **29 Kpps** | 1.00x |
| `run_pipeline_multiprocess` (4 workers) | 998.8 ms | 985.0 ms | 4 Kpps | **7.26x slower** |
| `run_pipeline_staged` (2 LB + 4 FP) | 1138.7 ms | 1109.9 ms | 4 Kpps | **8.28x slower** |

**This is `D-23`, and it has got worse, not better.** `D-23` was promoted from
`P-15` when the port was first measured, recording multiprocess at 4.7x and staged
at 6.2x. Re-measured on 2026-10-15 the same benchmark gives **7.26x** and
**8.28x**. The direction was always right — adding process boundaries costs more
than it saves at this workload — but the magnitude has grown by roughly half.

The likely reason is `T0-11`, which is the change these numbers were waiting for.
Bounding worker memory (`D-01`) replaced shipping every packet's bytes back to the
parent with a per-packet *decision bitmap*. That removes memory, not work: each
packet is still pickled as a `WorkItem` across the process boundary, and now each
one also costs a bit-setting on the way back. So the change that made the workers
bounded also made the IPC path slightly heavier per packet, and the IPC path is
exactly what the multiprocess variants are made of.

That is a hypothesis, not a measurement — isolating it would mean benchmarking
with and without the bitmap, which is a different experiment. What *is* measured
is that the ratio moved, and in the wrong direction for the scaling paths.

### What this does and does not establish

Stated plainly, because the previous baseline overstated it:

- **4000 packets is small.** Process spawn and queue setup are a large share of
  each multiprocess measurement, which *flatters* those variants — with a bigger
  capture their fixed costs amortise. The ratio on real traffic would be lower
  than 7.26x, though there is no measurement of that here.
- **The frames are 54 bytes.** Per-record pickling overhead is proportionally
  much larger than on realistic traffic, for the same reason.
- So **the direction is measured; the magnitude is workload-specific** and should
  not be quoted as a property of the engine. Re-measure on a real capture before
  relying on the number.
- The staged variant being slower than the multiprocess one is **by design** and is
  not a defect: `run_pipeline_staged`'s docstring explains that the LB tier is
  queue-decoupling and per-shard observability, not throughput. This benchmark
  exists to keep that claim honest rather than assumed.

## Per-operation costs

| Operation | Mean | Rate |
|---|---|---|
| `parse_packet` | 10.731 us | 93 K ops/s |
| `extract_sni` | 1.569 us | 637 K ops/s |
| `extract_http_host` | 1.609 us | 621 K ops/s |
| `extract_dns_query` | 1.983 us | 504 K ops/s |
| `sni_to_app_type` | 0.593 us | 1.69 M ops/s |

**Packet parsing costs roughly 7x more than SNI extraction**, which is the
interesting result in this table and the opposite of where an intuition about DPI
engines usually starts. The reason is that `extract_sni` is handed a payload that
is already sliced out, while `parse_packet` walks Ethernet, VLAN, IPv4 and TCP
headers with bounds checks at every offset. Most of the per-packet cost of this
engine is header parsing, not payload inspection.

`sni_to_app_type` at 0.593 us is the classification table — the rewrite of OSC's
if-chain into a persisted `AppType.name` (`DEC-04`) plus a dict lookup. It is now
cheap enough to be below the noise floor of the parsing around it.

## Machine

These figures are machine-specific and are not portable. Recorded in
`baseline.json` under `machine_info`:

- Windows, CPython 3.13.11, AMD Ryzen 5 5600H (12 cores visible, 3.30 GHz)
- The C++ original is preserved under `OSC/` for direct comparison; it was not
  benchmarked here, so this document makes **no** claim about the port versus the
  original per packet. That comparison is `P-15`'s original question and remains
  open.