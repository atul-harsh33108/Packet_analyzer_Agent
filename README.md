# dpi-engine

Deep packet inspection over pcap files. Reads a capture, classifies flows by
application (TLS SNI, HTTP `Host`, DNS query name, QUIC ClientHello), applies
blocking rules, and writes a filtered capture plus a report.

A Python port of the C++ engine preserved under [`OSC/`](OSC/). Every
intentional behavioural difference from that original is listed in
[DESIGN_DECISIONS.md](DESIGN_DECISIONS.md) and cross-checked by a differential
test suite that builds and runs the actual C++ binary.

## Quick start

```bash
uv sync                                  # install (Python 3.13)
uv run dpi-engine inspect capture.pcap    # what's in this file?
uv run dpi-engine dump capture.pcap       # every packet's five-tuple
uv run dpi-engine run capture.pcap out.pcap
uv run dpi-engine run capture.pcap out.pcap --block-app YouTube
uv run pytest                            # 377 unit + 14 differential tests
```

`--json` on `run` emits the same report as machine-readable JSON.

## What it classifies

| Protocol | How | Needs SNI/name? |
|---|---|---|
| TLS | ClientHello SNI extension | yes |
| HTTP | request `Host:` header | yes |
| DNS | question-section name | yes |
| QUIC | decrypts the Initial packet, then parses the ClientHello | yes, **Initial only** |

Resolved names are mapped to an application (Google, YouTube, Netflix, …) by an
ordered, hand-audited pattern table in `types.py`.

Anything it cannot read is reported as such rather than silently bucketed. A
QUIC Handshake/1-RTT packet — which is *encrypted by protocol design* and
genuinely unreadable by any passive observer — is classified `QUIC`, counted in
`QUIC datagrams: N seen, M not decryptable`, never as "unknown".

## Pipeline variants

```
run_pipeline                  single process, no IPC                (default)
run_pipeline_multiprocess     reader parses -> N fast-path processes  (--workers N)
run_pipeline_staged           reader -> K load balancers -> K*F fast paths
                                                             (--load-balancers K)
```

All three share one decision engine (`worker.FlowProcessor`) and produce
**byte-identical output pcaps** for the same input and rules. The test suite
asserts this for every staged topology.

Choosing one:

- **Small captures / debugging:** the default. No process startup, easiest to
  reason about.
- **Large captures, many cores:** `--workers N`. One IPC hop.
- **`--load-balancers K --fps-per-lb F`:** reproduces OSC's original two-tier
  topology and reports both tiers separately. It is *not* faster than
  `--workers` — see the "Why the reader still parses" note in `pipeline.py`;
  the LB tier is queue-decoupling and observability, not throughput.

The partitioning invariant all variants rely on: **every packet of a given
five-tuple reaches the same fast-path process**, so per-flow state (TCP
lifecycle, classification, block decisions) is never split.

> On Windows and macOS the multiprocessing start method is `spawn`, so
> `run_pipeline_multiprocess` and `run_pipeline_staged` must be called from a
> `if __name__ == "__main__":` guard. The `dpi-engine` console script already is.

## Blocking rules

```bash
dpi-engine run in.pcap out.pcap \
  --block-app YouTube --block-domain '*.tiktok.com' \
  --block-ip 192.168.1.50 --block-port 8080

dpi-engine rules --load-rules rules.json --unblock-app YouTube --save-rules rules.json
```

Rules are checked in a fixed priority order — **IP, then port, then app, then
domain** — and the first match is reported, so a flow matching several
categories always shows the most specific reason.

### Domain rule semantics

Two forms, both anchored at a domain boundary:

| Rule | Matches | Does not match |
|---|---|---|
| `facebook.com` | `facebook.com` | `www.facebook.com` |
| `*.facebook.com` | `facebook.com`, `www.facebook.com`, `a.b.facebook.com` | `notfacebook.com`, `facebook.com.evil.net` |

A `*` anywhere else (`foo*.com`, `*foo`) is **rejected at insertion time** with
a clear error, rather than becoming a rule that silently never matches — which
is what the C++ original did. All matching is case-insensitive.

> This is stricter than `main_working.cpp`, which did an unanchored substring
> search and so blocked any domain merely *containing* the text. Blocking less
> is the safe direction for a blocking tool, and the intent is spelled out
> explicitly instead. Pinned by a differential test.

### Changing rules during a run

`RuleManager` is thread-safe and copy-on-write. Mutating it bumps a version;
callers hand out immutable `RuleSnapshot`s, which are picklable and lock-free
to read. `run_pipeline_multiprocess(live_rules=True)` opens a per-worker
control channel so a mid-run change takes effect on the next packet.

## Safety

These are binding constraints, not aspirations — see DESIGN_DECISIONS.md and
`tests/test_safety_constraints.py`:

- **Passive and offline.** No raw sockets, no live interface capture, no packet
  injection or replay, no elevated privileges.
- **No network calls** at runtime, in the tool or its workers.
- **Never overwrites the input**, enforced in `PcapWriter` itself, not just at
  the CLI layer.
- **Bounded resources at every untrusted-input boundary:** max packet size,
  max total packets, max tracked flows per process (O(1) LRU), and a stale-flow
  reaper. No input can cause an unbounded loop or allocation.
- **Workers are pure compute.** Only the parent process touches the filesystem.

## Optional QUIC SNI support

QUIC Initial packets are encrypted with keys derived from the cleartext
Destination Connection ID, so a passive observer *can* decrypt them — that is
the whole of the "QUIC decryption" trick real DPI tools use. This port does so
properly: header-protection removal, packet-number reconstruction, AES-128-GCM,
and CRYPTO-frame reassembly across packets.

That needs real AES, and this project will not hand-roll a block cipher, so
`cryptography` is an **optional extra**:

```bash
uv sync --extra quic     # or: pip install 'dpi-engine[quic]'
```

Without it, QUIC detection and classification still work; only SNI extraction is
unavailable, and that degradation is *reported* — `dpi-engine inspect` prints
it, and the run report carries `QUIC datagrams: N seen, M not decryptable`, so
"we saw QUIC but could not read it" can never be mistaken for "there was no
QUIC". Verified against the RFC 9001 Appendix A.1 key-derivation vectors.

## Resource bounds

| Flag | Default | Bounds |
|---|---|---|
| `--max-packet-size` | 65535 | any single captured packet |
| `--max-total-packets` | 10,000,000 | packets per input file |
| `--max-connections` | 100,000 | tracked flows per process (LRU-evicted) |
| `--flow-timeout` | 300 s | idle-flow reaping; `0` disables idle reaping only (closed flows are still reclaimed) |
| `--reap-interval` | 65536 | packets between stale-flow sweeps; `0` disables sweeping |

## Known limitations

- **IPv4/Ethernet only.** IPv6, VLAN tags, and non-Ethernet link types are not
  parsed; a non-Ethernet capture is rejected with a clear error rather than
  silently misparsed. (Same as the original.)
- **TCP only carries a 14-byte Ethernet header assumption** — no
  encapsulation beyond a single Ethernet header (no tunnelling, no
  link-layer types other than plain IPv4).
- **Flows are keyed by exact five-tuple, not by direction-folded pair.** The
  client→server direction carries the ClientHello and gets classified and
  potentially blocked; the server→client direction is a separate entry, so a
  block on one does not apply to the other. Preserved from the original
  deliberately — folding directions would change blocking scope.
- **DNS name-compression pointers are not followed.** A compressed question
  name stops parsing early. Legal but rare in a question section; it cannot
  loop or read out of bounds, it just may return a truncated name.
- **HTTP methods are matched on their first 4 bytes**, so `DELETE` matches via
  `DELE` and `OPTIONS` via `OPTI`. A classification-accuracy nit inherited
  from the original, kept for parity.
- **A recognised-but-unmapped name is labelled `HTTPS`**, even on plain HTTP
  port 80. This matches the original's documented fallback and is preserved
  rather than "fixed" into a different label.
- **Unrecognised SNI is not a "miss".** `example.com` resolves fine and is
  reported as `example.com -> HTTPS`; the name is never discarded.
- **On failure partway through, the output file is left on disk** containing
  whatever was successfully written before the failure. It is a valid, bounded,
  non-corrupt pcap and the failure is reported with a non-zero exit code, but a
  re-run will overwrite it rather than append.

## Layout

```
src/dpi_engine/
  types.py             five-tuples, AppType, Connection, DPIStats, SNI table
  pcap_io.py           pcap reading/writing with explicit safety bounds
  packet_parser.py     Ethernet/IPv4/TCP/UDP dissection (via dpkt)
  sni_extractor.py     hand-rolled TLS SNI / HTTP Host / DNS extraction
  quic.py              QUIC Initial decryption + ClientHello SNI
  connection_tracker.py  flow table, TCP state machine, LRU, reaper
  rule_manager.py      copy-on-write rules + immutable snapshots
  load_balancer.py     two-level hash selection, LB/FP stats, pipeline graph
  worker.py            FlowProcessor: the per-packet decision engine
  pipeline.py          the three pipeline entry points
  report.py            text + JSON reporting
  cli.py               command-line interface
OSC/                   the original C++ engine, preserved
tests/                 unit + integration tests
tests/differential/    differential suite vs. the compiled C++ binary
```

## Testing

```bash
uv run pytest                              # everything
uv run pytest --ignore=tests/differential  # no Docker needed
```

The differential suite builds `OSC/src/main_working.cpp` with `gcc:13` in a
Docker container and runs both implementations against the same fixtures. It
**skips** rather than fails when Docker is unavailable, since it is a
supplementary cross-check; the rest of the suite has no external dependency.

## Design notes

Full project documentation lives in [`docs/`](docs/README.md) — start with the
[documentation index](docs/README.md).

| Document | What it covers |
|---|---|
| [`docs/OPERATING_INSTRUCTIONS.md`](docs/OPERATING_INSTRUCTIONS.md) | How to work in this repo: read order, the five non-negotiable rules, boundaries needing a human decision |
| [`docs/TASK_TRACKER.md`](docs/TASK_TRACKER.md) | Current state — task statuses, decisions, what to do next |
| [`docs/TASK_TRACKER_UPDATE_PROTOCOL.md`](docs/TASK_TRACKER_UPDATE_PROTOCOL.md) | How to keep that tracker consistent across sessions and agents |
| [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) | How the known defects get fixed: 30 tasks, dependency graph, risk register |
| [`docs/AUDIT.md`](docs/AUDIT.md) | The findings — port-vs-C++ verdict, 22 defects, 10 missing engineering rails |
| [`docs/AGENTIC_ARCHITECTURE.md`](docs/AGENTIC_ARCHITECTURE.md) | The agentic product vision and roadmap |
| [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) | *Why* the port is built this way: every bug fixed relative to the original, safety constraints, trade-offs left open |
| [`docs/WORKFLOW.md`](docs/WORKFLOW.md) | Architecture diagrams — ⚠️ stale, scheduled for rewrite |

`DESIGN_DECISIONS.md` records *why*, not just *what*: every bug fixed relative to
the original, every intentional behavioural difference, the concurrency
rationale, and the trade-offs deliberately left open.

> **Starting work on this project?** Read
> [`docs/TASK_TRACKER.md`](docs/TASK_TRACKER.md) §1 — it is 40 lines and tells
> you exactly what to do next.
