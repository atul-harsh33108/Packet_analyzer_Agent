# Implementation Plan — `dpi-engine`

**Status:** Actionable plan derived from [`AUDIT.md`](AUDIT.md)
**Date:** 2026-10-03
**Precondition:** Every task below traces to a finding ID in `AUDIT.md`. If a task here and a finding there disagree, the finding wins.
**Scope:** Phases 0 → 6 of the audit's remediation roadmap, plus a parallel documentation track.

---

## How to use this plan

### Task schema

Every task card carries:

| Field | Meaning |
|---|---|
| **Traces** | Finding ID(s) in `AUDIT.md` this task closes |
| **Files** | Files created or modified |
| **Change** | What to actually do — concrete enough to execute without re-deciding |
| **Test** | The specific test that proves it, added in the same commit as the fix |
| **Verify** | Command(s) that must pass |
| **Effort** | Rough estimate for one developer |

### Rules

1. **One task, one commit.** Every task must leave the tree green: `pytest`, `ruff check`, `mypy`.
2. **The test ships with the fix.** A defect-closing commit without a regression test is not complete. The current suite already contains one anti-pattern to avoid — `tests/test_pcap_io.py:41` asserts the `D-06` bug, locking it in.
3. **Never use whole-file regex substitution for source edits.** See `S-02` — this caused a chain of `F821` regressions. Use targeted patches, and re-run lint immediately.
4. **New findings get a new ID.** Append to `AUDIT.md`; do not renumber. The ID scheme exists to survive edits.
5. **A phase does not start until the previous phase's exit criteria are met.**

### Decision log

Five decisions must be made by a human before the dependent tasks start. They are listed in §2 with their options, blast radius, and who is blocked. **Do not let an agent pick these silently.**

---

## §1 — Dependency graph and critical path

```
                    ┌──────────────────────────────────────────────┐
                    │ DEC-01  ordering guarantee (A-02)           │  ← human
                    └───────────────────┬──────────────────────────┘
                                        │ gates
DEC-02 pcapng  ───────────────┐        │
DEC-03 scapy   ───────┐       │        │
DEC-04 rule keys│      │       │        │
DEC-05 flow fold│      │       │        │
                │      │       │        │
                ▼      ▼       ▼        ▼
        ┌───────────────────────────────────────┐
PHASE 0 │ T0-01 CI  T0-02 conftest  T0-03 timeouts/cov │  no decisions
        │ T0-04 sni clamp  T0-05 PcapWriter  T0-06 pcap hdr │
        │ T0-07 http host  T0-08 quic delta  T0-09 live-rules│
        │ T0-10 teardown  T0-11 ══ D-01/D-22 (decisions) ══   │  ← DEC-01
        └───────────────────────┬───────────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────────┐
PH 0.5  │ T05-01 VLAN  T05-02 pcapng (DEC-02)                │
        └───────────────────────┬───────────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────────┐
PHASE 1 │ T1-01 event bus  T1-02 CapSource  T1-03 streaming out│  ← DEC-01, DEC-05
        │ T1-04 rule DSL+prov  T1-05 CIDR/dstIP (DEC-04)     │
        │ T1-06 ══ simulate_ruleset ══                       │  ← keystone (A-05)
        │ T1-07 hypothesis  T1-08 benchmarks  T1-09 protocols  │
        └───────────────────────┬───────────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────────┐
PHASE 2 │ golden corpus · eval harness · OTel · agent safety  │  no decisions
        └───────────────────────┬───────────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────────┐
PHASE 3 │ MCP server (~300 lines, zero risk)                  │
PHASE 4 │ Explainer + Triage (read-only) · memory · RAG       │
PHASE 5 │ Fingerprinting engine · ClassifierGap               │
PHASE 6 │ Policy agent · RuleStore · human gate · audit log   │
        └───────────────────────────────────────────────────┘
```

**Critical path:** `T0-01` → `T0-02` → `T0-11` → `T1-01`/`T1-03` → `T1-06` → Phase 2 exit. Everything else has slack.

**Why Phase 0 comes before all agentic work:** `D-01` means the engine cannot be run against a large real capture without risking OOM, and `D-22` means it cannot be run against untrusted input without an unbounded-memory exposure. Neither is acceptable as the substrate an agent reasons over. Phase 0 is roughly one week and it unblocks everything.

---

## §2 — Decision log

Each decision has a recommended option, the reason, and what it blocks. **These are the only five places where this plan deliberately stops short of specifying.**

### `DEC-01` — Output-ordering guarantee under streaming · **blocks T1-01, T1-03, T0-11**

The current deterministic output depends on materialising every packet and sorting by `sequence_index`. Fixing `D-01` removes exactly the structure that makes the sort possible, so the choice is forced.

| Option | Guarantee | Cost | Verdict |
|---|---|---|---|
| **A** Per-shard arrival order | Within a shard only | Output differs run-to-run → **breaks the differential suite's byte-comparison** and the "all three variants produce byte-identical output" property | Rejected |
| **B** Bounded reorder window | Deterministic within window size *W*; late packets beyond *W* emitted out of order | Needs *W* as a tunable with a memory/latency trade; needs a defined late-packet policy | **Recommended** |
| **C** Drop byte-order guarantee, compare packet sets | None | Cheapest, but deliberately surrenders the strongest property the project currently has | Fallback if *W* proves impractical |

**Recommendation: B**, with **C as the test-level fallback** (i.e. run both: byte-exact for captures that fit the window, set-equality otherwise).

### `DEC-02` — pcapng: implement or diagnose clearly? · **blocks T05-02**

`D-15`. Option 1: full pcapng reader (SHB/IDB/EPB/SPB, multiple interfaces — ~200 lines). Option 2: detect the `0x0A0D0D0A` magic and raise a precise "not supported, convert with `editcap -F pcap`" diagnostic (~10 lines).

**Recommendation: Option 2 now, Option 1 in Phase 1 if the golden corpus needs it.** pcapng appears in roughly a third of real-world captures, so this will be requested; but a wrong pcapng reader is worse than an honest refusal, and the detection line closes the misleading-diagnostic half of `D-15` immediately.

### `DEC-03` — scapy: implement the cross-check or delete the dependency? · **blocks T1-07**

`R-08`. `DESIGN_DECISIONS.md` justifies scapy as an independent cross-check of hand-rolled TLS parsing. No test does this. Option 1: implement a scapy-vs-port differential test for `extract_sni`/`extract_http_host`/`extract_dns_query` using scapy as the reference parser. Option 2: delete scapy from `pyproject.toml` and strike the claim from `DESIGN_DECISIONS.md`.

**Recommendation: Option 1.** It is genuinely the best available substitute for the fuzzing the project lacks, scapy is already a declared dev dependency, and it directly closes the largest documentation-vs-implementation gap in the repository. If it proves unreliable as a reference, fall back to Option 2 and rewrite the claim.

### `DEC-04` — Rule-file persistence key migration · **blocks T1-05**

`D-16`. Currently keys are display names (`"Twitter/X"`). Options: (a) persist `AppType.name` and accept display names as input-only aliases, with a one-shot migration on load; (b) persist `AppType.name` only, and hard-fail old files with a clear message; (c) persist both, prefer the stable one.

**Recommendation: (a)** with a deprecation warning. Existing users have saved rules files; silently invalidating them is the failure mode `D-16` already describes.

### `DEC-05` — Bidirectional flow folding: default on or off? · **blocks T1-03**

`P-16`. Currently flows are keyed by exact five-tuple, so a block on the client→server direction does not apply to server→client. This is correct for C++ parity and wrong for a product.

**Recommendation: default ON for streaming mode, OFF for differential mode**, with the differential suite pinning the exact-tuple behaviour explicitly. That preserves the property that makes the differential suite meaningful while making the product behave correctly. Requires the differential harness to be able to select the mode — which it currently cannot.

---

## §3 — Phase 0: Harden

**Entry:** none. **Exit:** no unbounded allocation reachable from any documented flag; no hang path that lacks a diagnosable error; green CI; a quotable coverage number.

**Note:** Phase 0 changes nothing user-visible. It is not skippable.

### `T0-01` — CI, coverage, and timeouts · `R-01`, `R-02`, `R-03`

**Files:** `.github/workflows/ci.yml` (new), `pyproject.toml`, `.gitignore`
**Change:**
1. Add `.github/workflows/ci.yml` with two jobs. `lint`: `uv sync --frozen --extra quic` → `uv run ruff check .` → `uv run mypy` → `uv run ruff format --check .`. `test`: same setup → `uv run pytest --ignore=tests/differential`. `differential`: `ubuntu-latest` with the `gcc:13` container → full `uv run pytest`.
2. Add `pytest-cov` and `pytest-timeout` to `[dependency-groups].dev`.
3. Add to `pyproject.toml`: `[tool.coverage.run] source = ["src/dpi_engine"]`, `[tool.coverage.report] fail_under = 85, show_missing = true`.
4. Add `timeout = 60` as a global pytest setting, overridden to `300` for the stress tests via a marker.
5. `.gitignore`: add `manual_test_output.pcap` (`R-09`); `git rm --cached manual_test_output.pcap`.

**Test:** CI itself is the test; confirm a deliberately failing assertion turns the pipeline red.
**Verify:** `uv run pytest --timeout=60 -q` passes; `uv run pytest --cov --cov-report=term -q` reports a number ≥85.
**Effort:** 0.5 d

> **Why first:** every subsequent task is gated by CI. Without it, "the tests still pass" is a memory claim.

### `T0-02` — `conftest.py` and fixture de-duplication · `R-04`, `M-07`

**Files:** `tests/conftest.py` (new), 8 test modules, `tests/differential/README.md`
**Change:** Add `tests/conftest.py` containing the single `FIXTURES` path constant and the `cpp_available` fixture (currently duplicated verbatim across two modules). Import both from there in all affected test files. Correct `tests/differential/README.md:83`, which names a `conftest.py` that does not exist.
**Test:** none needed — this is pure de-duplication. Confirm `pytest --collect-only` count is unchanged at 404.
**Verify:** `rg -c "FIXTURES = Path" tests/` returns a single hit.
**Effort:** 0.5 d

### `T0-03` — Repair the `D-01` test gap before changing `D-01` · `R-06`

**Files:** `tests/test_resource_bounds.py` (new assertions), `tests/fixtures/`
**Change:** Before touching memory behaviour, add a test that **demonstrates** `D-01`: run `run_pipeline_multiprocess` over a synthetic capture of *N* packets and assert peak `ProcessedPacket` accumulation is bounded. Record the current (failing) behaviour as the reproduction, then let `T0-11` turn it green. Also add the benchmark baseline: `pytest-benchmark` for `parse_packet`, `extract_sni`, and an end-to-end Mpps figure, establishing the number `P-15` leaves open.
**Verify:** `pytest tests/test_resource_bounds.py -k accumulation` fails before `T0-11`, passes after.
**Effort:** 0.5 d

### `T0-04` — Clamp `length` in the TLS entry points · `D-05`

**Files:** `src/dpi_engine/sni_extractor.py`, `tests/test_sni_extractor.py`
**Change:** In `is_tls_client_hello` and `extract_sni`, after resolving `length`, add `length = min(length, len(payload))`. Update both docstrings to state the clamp explicitly rather than only promising "never raises".
**Test:** `is_tls_client_hello(b"\x16\x03\x01", length=999) is False`; `extract_sni(b"\x16\x03\x01\x00\x05\x01", length=999) is None`. Neither raises.
**Verify:** `pytest tests/test_sni_extractor.py -q`
**Effort:** 15 min

### `T0-05` — Guard `PcapWriter` open · `D-04`

**Files:** `src/dpi_engine/pcap_io.py`, `tests/test_pcap_io.py`
**Change:** Wrap `open(self.path, "wb")` in `try/except OSError` → `raise PcapError(f"Cannot open output file '{self.path}': {exc}")`, mirroring the existing `PcapReader._open`. Confirm `cli.py`'s `(PcapError, ValueError)` handler then catches it, and add a CLI-level test asserting `error: ...` on stderr and exit code 1 rather than a traceback.
**Test:** `PcapWriter("Z:/nonexistent-dir-xyz/out.pcap")` raises `PcapError`; `dpi-engine run in.pcap Z:/nonexistent/out.pcap` prints `error:` and exits 1.
**Verify:** `pytest tests/test_pcap_io.py tests/test_cli_run.py -q`
**Effort:** 15 min

### `T0-06` — Read the pcap record header directly · `D-06`, `D-07`

**Files:** `src/dpi_engine/pcap_io.py`, `tests/test_pcap_io.py`
**Change:** This single change closes two defects and is the highest-leverage task in Phase 0.

1. Replace the dpkt-delegating iteration with a direct read of the 16-byte per-packet record header (`ts_sec`, `ts_usec`, `incl_len`, `orig_len`, all with the same endianness logic already used for the global header).
2. **Validate `incl_len` against `max_packet_size` *before* reading the payload bytes.** This is what `D-07` requires; the current check happens after dpkt has already allocated.
3. **Populate `RawPacket.orig_len` from the record's `orig_len` field**, not `len(buf)`. This is what `D-06` requires.
4. Retain the existing total-packet-count bound and the linktype validation.
5. Update the `RawPacket.orig_len` docstring to match the now-true behaviour.
6. **Fix the test that locks the bug:** `tests/test_pcap_io.py:41` asserts `len(pkt.data) == pkt.orig_len`. Replace with a fixture that has `incl_len < orig_len` (snaplen-truncated) and assert the two now differ.

**Test:** (a) a record with `incl_len = 0xFFFFFFF0` is rejected *without* attempting the read — assert via a bounded read counter or by confirming the error names `max_packet_size`; (b) a truncated record yields `len(data) == incl_len` and `orig_len > len(data)`.
**Verify:** `pytest tests/test_pcap_io.py tests/test_resource_bounds.py -q`
**Effort:** 0.5 d
**Risk:** Medium — this replaces the I/O hot path. `R-06`'s benchmark from `T0-03` is the guard: if direct reading regresses throughput versus dpkt, record it rather than reverting silently.

### `T0-07` — Bound the HTTP `Host:` scan · `D-09`, `D-10`

**Files:** `src/dpi_engine/sni_extractor.py`, `tests/test_sni_extractor.py`
**Change:**
1. Bound the `Host:` search to the **header block** — stop at the first `\r\n\r\n` (or `\n\n`).
2. Require the match to begin at a line start (offset 0 or immediately after `\n`).
3. Fix the IPv6 literal case: only strip a port suffix on a colon that appears **after** a closing `]`.
4. Add `CONNECT` and `TRACE` to the method prefix list, and document the remaining 4-byte-prefix imprecision (`P-18`) rather than leaving it implicit.
5. Bound the accepted host length (see `D-18`).

**Test:** `GET /?u=http://Host:x HTTP/1.1\r\n\r\n` → `None` (was `"x HTTP/1.1"`). A POST body containing `Host: evil.com` after the header block → `None`. `Host: [2001:db8::1]:8080` → `[2001:db8::1]`. A legitimate `Host: example.com` in a real header → `example.com`.
**Verify:** `pytest tests/test_sni_extractor.py -q` plus the differential suite, since `main_working.cpp` shares this behaviour and the divergence must be allowlisted.
**Effort:** 0.5 d
**Note:** This changes classification output on adversarial input. Update the differential divergence allowlist and pin the new behaviour in a test.

### `T0-08` — Fix `quic_undecryptable` accounting · `D-08`

**Files:** `src/dpi_engine/quic.py`, `src/dpi_engine/worker.py`, `tests/test_quic.py`
**Change:** Have `QuicFlowInspector.feed()` return a per-packet outcome (e.g. `QuicFeedResult(sni: str | None, decrypted: bool, undecryptable: bool)`) instead of the caller inferring status from the cumulative `undecryptable_packets` field. `worker.py:273-274` then increments on the **per-packet** flag.
**Test:** a flow whose first Initial is undecryptable and whose second decrypts cleanly reports `undecryptable == 1`, not `2`. Assert against a constructed QUIC fixture, not a timing accident.
**Verify:** `pytest tests/test_quic.py -q`
**Effort:** 0.5 d

### `T0-09` — Make `--live-rules` honest · `D-03`

**Files:** `src/dpi_engine/cli.py`, `src/dpi_engine/pipeline.py`, `tests/test_cli_run.py`
**Change:** Choose one and implement it fully: (a) thread `live_rules` through `run_pipeline_staged` — create control queues per FP and register them with a broadcaster the parent polls; or (b) reject `--live-rules` together with `--load-balancers` at parse time with an explicit message. **Do not leave the current silent no-op.** Option (a) is more work but matches the flag's documented promise; option (b) is honest and cheap. Whichever is chosen, add a test asserting the documented behaviour.
**Verify:** `pytest tests/test_cli_run.py tests/test_staged_pipeline.py -q`
**Effort:** 0.5 d (option b) / 1 d (option a)

### `T0-10` — Teardown in `finally`; stale docstrings · `D-12`, `S-03`

**Files:** `src/dpi_engine/pipeline.py`, `src/dpi_engine/worker.py`, `src/dpi_engine/quic.py`, `src/dpi_engine/load_balancer.py`, `src/dpi_engine/types.py`
**Change:**
1. Wrap the `_collect` → `join` → `_close_quietly` sequence in **both** MP variants in `try/finally`, so any failure terminates children and closes queues. `D-12`.
2. Fix three docstrings that cite non-existent symbols: `quic.py:603` (`pipeline.QuicFlowTable` → `worker.FlowProcessor._quic_inspectors`), `worker.py:93` (`pipeline.RuleBroadcaster.SnapshotHolder` → `worker.FixedRuleSource`), `pipeline.py:131` (documents a `with_fast_path_stats` parameter that was never added).
3. **Fix `load_balancer.py:20-35`**, which claims the LB stage parses Ethernet/IP/TCP/UDP. `_lb_main` receives pre-parsed `WorkItem`s and only calls `select_fp`. This is the single most actively misleading comment in the codebase, because it directly contradicts `DESIGN_DECISIONS.md` and the root `README.md`.
4. Fix `types.py:257`, which cites `DESIGN_DECISIONS.md` "item 14" (dead-report cleanup) for the terminal-state invariant. Correct references are item 7 and item 11.
5. Add `test_safety_constraints.py` coverage asserting no shipped docstring references a symbol absent from the module — a cheap AST check that would have caught all four.

**Test:** the new AST check; plus a test that injects a `_collect` failure and asserts no child processes survive.
**Verify:** `pytest -q`, `ruff check`, `mypy`
**Effort:** 0.5 d

### `T0-11` — Bound worker memory · `D-01`, `D-02`, `D-22` · **gated on `DEC-01`**

The core task of Phase 0 and the largest single change in the plan.

**Files:** `src/dpi_engine/worker.py`, `src/dpi_engine/pipeline.py`, `tests/test_resource_bounds.py`

**Recommended design — decision bitmap plus a second sequential pass.** The insight: the parent already has the input file, and each packet's bytes are still *in that file*. The workers never needed to ship `RawPacket` back at all. They only need to ship **one bit per packet**: forward or drop.

1. Replace `ProcessedPacket` accumulation with a `bitarray`-backed decision structure indexed by `sequence_index`. Total cost is `⌈total_packets / 8⌉` bytes — 1.25 MB at the 10 M default, versus the current unbounded growth. (`bitarray` is a new dependency; a `bytearray` of packed bits is a viable zero-dependency alternative if preferred.)
2. Workers stop retaining packet bytes entirely. `WorkerResult` shrinks from "every packet" to "one bit per packet" plus the bounded report payload.
3. The parent makes **one additional sequential pass over the input file**, writing packet *N* wherever bit *N* is set. Memory becomes `O(total_packets / 8)` with a single packet in flight.
4. **Preserve output byte-order exactly.** The second pass is sequential over the input, so `DEC-01` option A is available here *for free* — the sort disappears entirely rather than being replaced. This closes `D-01` with **zero change in observable output**, so all 404 tests and the differential suite stay green.
5. Apply `maxsize` to the packet queues (`D-02`) so the dispatch loop applies backpressure instead of exhausting memory.
6. `D-22`: evict `_quic_inspectors` entries with their flows (or give them a bounded LRU at `max_connections`); prune `blocked_tuples` when the corresponding flow leaves the tracker — no correctness loss, since a reappearing flow is re-evaluated by the rule check anyway; cap `blocked_flows` with a documented limit plus an overflow counter.

**Test:** the reproduction from `T0-03` turns green — peak memory stays flat as packet count grows; output pcap is byte-identical to the pre-change output for all three pipeline variants; `blocked_tuples` and `_quic_inspectors` stay bounded under a synthetic run with far more distinct flows than `--max-connections`.
**Verify:** `pytest -q` (all 404 still pass, plus the new bounds tests) and the differential suite.
**Effort:** 2–3 d
**Risk:** High — touches the core data flow of all three variants. Mitigation: land the bitmap change and the backpressure change as **two separate commits**, and keep the second input pass behind a feature flag for the first commit so a bisect is trivial.

**What this deliberately does not do:** it does not make the engine streaming. It makes the batch engine memory-safe, which is the prerequisite for streaming. Streaming is `T1-03`.

### Phase 0 exit criteria

- [ ] No unbounded allocation reachable from any documented flag
- [ ] No hang path without a diagnosable error
- [ ] Green CI on both the lint and test jobs
- [ ] Coverage number reported and ≥ 85
- [ ] All 404 existing tests still pass, plus new regression tests for every closed defect
- [ ] `mypy --strict` clean; `ruff format --check` clean (add the formatter to CI — currently 22 files would be reformatted)

---

## §4 — Phase 0.5: Real captures

**Rationale for placing this before any agent work:** if the golden corpus is built from toy untagged IPv4 traffic, every downstream eval measures the wrong distribution and the agent work is validated against fiction. `D-14` alone currently discards 100% of enterprise VLAN-tagged traffic.

### `T05-01` — VLAN / 802.1Q and QinQ · `D-14`

**Files:** `src/dpi_engine/packet_parser.py`, `tests/test_packet_parser.py`
**Change:** Before EtherType dispatch, peel `0x8100` (802.1Q), `0x88a8` (802.1ad), and `0x9100` (QinQ) in a loop with a bounded iteration count, advancing past the 4-byte tag. Preserve `vlan_id` and `priority` on `ParsedPacket` — the flow key stays L3, so VLAN tagging must **not** partition flows, but the metadata is worth keeping for the fingerprinting engine in Phase 5.
**Test:** single-tagged, double-tagged, and untagged frames over identical inner packets produce identical `FiveTuple` and identical classification. A tag loop bounded against a pathological nesting depth.
**Verify:** `pytest tests/test_packet_parser.py -q`
**Effort:** 0.5 d

### `T05-02` — pcapng · `D-15` · **gated on `DEC-02`**

Option 2 (recommended): detect the `0x0A0D0D0A` magic in `PcapReader._open` and raise `PcapError("pcapng is not supported; convert with: editcap -F pcap in.pcap out.pcap")`. Replaces the current misleading `PcapFormatError("not a valid pcap file")`.
**Test:** a minimal pcapng fixture produces the precise diagnostic, and the message names a conversion command.
**Effort:** 10 min (option 2) / 2 d (option 1)

### Phase 0.5 exit criteria

- [ ] A VLAN-tagged enterprise capture classifies identically to its untagged equivalent
- [ ] pcapng input produces a precise, actionable diagnostic

---

## §5 — Phase 1: Streaming core

**Entry:** Phase 0.5 exit met; `DEC-01` and `DEC-05` decided.

### `T1-01` — Event bus

**Files:** `src/dpi_engine/events.py` (new), `src/dpi_engine/pipeline.py`
**Change:** Introduce a typed event stream replacing `PipelineResult` accumulation as the primary output: `CaptureOpened`, `PacketParsed`, `FlowCreated`, `FlowClassified`, `FlowBlocked`, `FlowEvicted`, `LimitExceeded`, `CaptureClosed`. `PipelineResult` becomes a *derived* summary, computed by folding the event stream — so the batch API is preserved and every existing consumer keeps working. This is the mechanism the roadmap calls the enabler of the dashboard, the live view, and "why was this blocked?" answerability.
**Test:** fold a synthetic event stream and assert the derived `PipelineResult` equals the current batch result for the same capture. **This is the guarantee that makes the refactor safe.**
**Effort:** 1 d

### `T1-02` — `CapSource` abstraction

**Files:** `src/dpi_engine/cap_source.py` (new), `src/dpi_engine/pcap_io.py`
**Change:** Abstract the input behind `CapSource` with three implementations: `FileSource` (current behaviour), `WatchSource` (directory watch, emits new files as they close), `StreamSource` (stdin, length-prefixed). `PcapReader`/`PcapWriter` remain the only I/O boundary — the existing safety invariant is preserved by construction.
**Test:** a `WatchSource` over a temp directory picks up files as they appear; `StreamSource` round-trips against `FileSource` byte-for-byte.
**Effort:** 2 d

### `T1-03` — Streaming output · **gated on `DEC-01`, `DEC-05`**

**Files:** `src/dpi_engine/pipeline.py`, `src/dpi_engine/worker.py`
**Change:** Replace the second sequential input pass (from `T0-11`) with a **bounded reorder buffer** keyed on the next expected `sequence_index`. Packet decisions arrive from workers as they are made; the parent emits in input order within a window of size *W*, and emits out of order beyond it under a documented late-packet policy. Add `--reorder-window`. Apply `DEC-05` (bidirectional flow folding, default on for streaming, off for differential).
**Test:** deterministic byte-identical output for captures that fit the window; documented and tested behaviour beyond it. Differential mode pinned to exact-tuple keying.
**Effort:** 3 d
**Risk:** Medium-high. `T0-11` deliberately kept a second pass so this could be isolated — do not remove that pass in `T0-11`.

### `T1-04` — Streaming rule DSL with provenance

**Files:** `src/dpi_engine/rule_manager.py`, new `rules/` subpackage
**Change:** Rules become versioned objects carrying provenance: `id`, `match` (dst CIDR, port ranges, JA3/JA4, volume thresholds, time-of-day windows), `action`, `provenance` (author, run_id, created, reason, citations), `version`. Provenance is what makes every automated rule auditable and revertible — and is the precondition for granting any auto-apply tier in Phase 6.
**Test:** round-trip through JSON preserves provenance; a rule without provenance cannot be auto-applied.
**Effort:** 3 d

### `T1-05` — CIDR and destination-IP rules · `D-20`, `D-21` · **gated on `DEC-04`**

**Files:** `src/dpi_engine/rule_manager.py`
**Change:** Add CIDR matching (via `ipaddress`, already imported) and destination-IP blocking alongside the existing source-IP rule. Apply the `DEC-04` persistence-key migration in the same change, since both touch the rule schema and `to_dict()`.
**Test:** `10.0.0.0/8` blocks a host inside and not one outside; the migrated persistence key round-trips an old-format rules file with a deprecation warning.
**Effort:** 1 d

### `T1-06` — `simulate_ruleset` counterfactual engine · `A-05` — **the keystone component**

**Files:** new `rules/simulator.py`, `src/dpi_engine/pipeline.py`
**Change:** `simulate_ruleset(ruleset, capture) -> DeltaAnalysis`: what would change, how many flows and bytes, which existing verdicts flip, estimated false-positive rate. Implement by running the deterministic engine twice over the same capture — once with the current ruleset, once with the candidate — and diffing the decision bitmaps that `T0-11` already produces. That makes the counterfactual nearly free, and it inherits the engine's exactness rather than approximating it.

**This is the load-bearing safety component.** Every claim in Layers 3, 7, and 8 of `AGENTIC_ARCHITECTURE.md` that agents cannot cause harm reduces to this capability existing. Without it, "the agent proposes, the human decides" is a policy statement rather than an enforced constraint. Build it before the MCP server, and gate every later phase's exit criteria on it.
**Test:** simulate a ruleset that would block 100% of flows and assert `DeltaAnalysis` reports it; simulate a no-op change and assert zero delta.
**Effort:** 2 d

### `T1-07` — Property-based testing + scapy cross-check · `R-05`, `R-08` · **gated on `DEC-03`**

**Files:** `tests/property/` (new), `pyproject.toml`
**Change:** Add `hypothesis` strategies over every byte-level extractor: arbitrary byte strings, arbitrary truncations, and **arbitrary `length` arguments** (this alone would have caught `D-05`), asserting no exception and bounded output length. Add scapy-backed differential tests for `extract_sni` / `extract_http_host` / `extract_dns_query` if `DEC-03` is Option 1.
**Test:** the strategies are themselves the tests; add a seed-reproducibility check so CI failures are replayable.
**Effort:** 2 d

### `T1-08` — Benchmark suite · `R-06`, `P-15`

**Files:** `tests/benchmarks/` (new)
**Change:** `pytest-benchmark` for `parse_packet`, `extract_sni`, `sni_to_app_type`, and end-to-end Mpps for each pipeline variant. Record the baseline from `T0-03` and publish it. This is the first honest measurement of whether the port is fast enough for real captures.
**Effort:** 1 d

### `T1-09` — Remaining protocol coverage · `D-17`, `D-18`, `D-19`

**Files:** `src/dpi_engine/sni_extractor.py`
**Change:** Fix the SNI extension `break`-vs-`continue` bug (`D-17`); enforce hostname and DNS-name length limits (`D-18`); follow DNS compression pointers within the question section with a bounded jump counter (`D-19`).
**Test:** an SNI extension whose first name entry is not `host_name` but which contains a valid `server_name` later is now found. A 65535-byte claimed hostname is rejected. A compression-pointer loop terminates.
**Effort:** 1 d

### Phase 1 exit criteria

- [ ] All 404 existing tests still pass unchanged
- [ ] Streaming output is deterministic under the chosen `DEC-01` option
- [ ] Differential parity with the C++ reference intact
- [ ] `simulate_ruleset` works and its `DeltaAnalysis` is used in a test
- [ ] Memory bounded under a streaming run with a directory watch as the source

---

## §6 — Phases 2–6 (outline)

Full task decomposition deferred until the prior phase exits, to avoid planning against an architecture that will have changed. Entry criteria and design intent are fixed here.

### Phase 2 — Evaluation harness · *(parallel with Phase 3)*

**Entry:** Phase 1 exit.
**Content:** Golden-capture corpus (30+ labelled pcaps: C2 beaconing, exfiltration, legitimate enterprise, ad traffic, active evasion) with `expected.json` per capture · tool-call, trajectory, and adversarial eval harnesses · rubric scorer, LLM-as-judge with human-agreement tracking (κ > 0.7), cost-per-investigation tracking · OTel tracing with a replayable trajectory · **extend the differential suite from 77 packets to a large generated corpus with an explicit divergence allowlist** · a safety suite for the agent tree (`A-03`).
**Why it gates everything after:** this is what makes prompt changes measurable. Shipping an agent without it means you cannot distinguish hallucination from truth.
**Exit:** every PR is scored automatically; agent-tree safety tests exist and run.

### Phase 3 — MCP server

**Entry:** Phase 1 exit (needs `simulate_ruleset`). Runs parallel to Phase 2.
**Content:** ~300 lines over Layer 1. Tools: `inspect_capture`, `run_dpi`, `stream_dpi_events`, `query_flows`, `get_flow_detail`, `get_fingerprints`, `query_anomalies`, `simulate_ruleset`, `diff_runs`, `list_rule_versions`, `revert_rule`. **Expose `revert_rule`; do not expose `apply_rule`** — application crosses the human gate. Resources and prompts per the roadmap.
**Exit:** an agent host can drive the engine read-only and dry-run rulesets.

### Phase 4 — Read-only agents

**Entry:** Phase 2 exit.
**Content:** Explainer and Triage only — **deliberately not the roadmap's Triage → AnomalyDeep**, because read-only agents need none of the human-gate machinery, so this proves the eval loop with the least new machinery. Episodic and semantic memory with outcome labelling. Citation-enforced RAG with per-node retrieval scoping. Content/data separation with `<untrusted_capture_data>` framing and an injection classifier on ingest.
**Exit:** verdict accuracy against the golden corpus; 100% refusal on injection evals; a full replayable trace for every verdict.

### Phase 5 — Fingerprinting + ClassifierGap

**Entry:** Phase 4 exit.
**Content:** JA3/JA3S and JA4/JA4S, TLS version histogram, cipher-suite ordering and count, extension ordering, ALPN, SNI-absence, cert issuer/subject/validity, GREASE detection, HTTP/2 SETTINGS fingerprint · per-flow feature vectors · `ClassifierGap` agent with ASN correlation and cited evidence · **signature-table maintenance loop**, with every proposal carrying citations.
**Exit:** an unknown app is identified with cited evidence and a proposed signature; the Critic can falsify the proposal.


**Tasks** (the scope of each is in the tracker's records; the gates are here):

| ID | Task | Gate | Effort |
|---|---|---|---|
| `T5-01` | The TLS fingerprint: JA3/JA4 and the ClientHello features | JA3/JA3S and JA4/JA4S are computed from a real ClientHello and ServerHello and match the published definitions; the version histogram, the cipher-suite ordering and count, the extension ordering, ALPN and GREASE are extracted from the same bytes | 1 d |
| `T5-02` | The certificate, SNI-absence and HTTP/2 features | The issuer, the subject and the validity of the server's certificate are extracted, the absence of an SNI is a fact rather than an empty string, and the HTTP/2 SETTINGS frame produces a fingerprint | 1 d |
| `T5-03` | The per-flow feature vector | A flow's features are attached to its row, the run store's schema says so, and an old record is refused rather than read through new field meanings | 1 d |
| `T5-04` | The signature table: a format, a matcher, and the corpus's known apps | A signature says which features make an app an app, the matcher answers with the app it identifies, and an unknown app is reported as unknown rather than as the nearest match | 1 d |
| `T5-05` | The `ClassifierGap` agent: an unknown app, correlated and proposed | An unknown app is turned into a proposed signature with cited evidence, and the proposal names the flows it came from | 1 d |
| `T5-06` | The maintenance loop and the Critic | Every proposal carries citations, a proposal that cannot be cited is refused, and the Critic can falsify a proposal that the corpus contradicts | 1 d |
| `T5-07` | The evaluation and the phase's exit criteria | The classifier's accuracy is measured against the corpus, every proposal is checkable, and the phase's exit criterion is asserted rather than described | 1 d |

**Order:** `T5-01` and `T5-02` are independent and both feed `T5-03`; `T5-03` feeds
`T5-04`, which feeds `T5-05`, which feeds `T5-06`; `T5-07` measures the result.

### Phase 6 — Write path

**Entry:** Phase 5 exit.
**Content:** Policy agent · `RuleStore` with provenance and versioning · blast-radius circuit breaker · durable human-approval queue · tiered auto-apply · immutable audit log (who, when, which agent, which run, which evidence, which prompt version, which model version).
**Exit:** end-to-end *capture → agent proposes a signed ruleset → human approves → applied → revertible*, with a complete audit trail.

---

## §7 — Documentation track (parallel)

Independent of code work; do not wait for Phase 1. Details in `AUDIT.md` §5.

| ID | Task | Ref | Effort | When |
|---|---|---|---|---|
| `DOC-01` | Fix the test count (`377 + 14` → `390 + 14 = 404`); add pcapng, CIDR, dst-IP, and HTTP-host limitations to Known limitations; **add an explicit note that the port is likely slower per packet than the C++ original** | `M-01` | 1 h | Now |
| `DOC-02` | Strike bug-list item 1's QUIC clause (contradicts item 16); fix the stale "efficiency note"; correct the "output left on disk" claim — MP variants leave an **empty** pcap, not a partial one; rewrite §Testing strategy as done-not-planned; add `quic.py`/`report.py` to the inventory | `M-02` | 2 h | Now |
| `DOC-03` | Rewrite `WORKFLOW.md` against the current architecture | `M-03` | 1 d | **After Phase 1** — the architecture it documents will have changed |
| `DOC-04` | Rewrite `AGENTIC_ARCHITECTURE.md` §1–§3 from the stale-claim table; resequence §8 per `AUDIT.md` §4.6; keep §4–§7 and §9 | `M-04` | 3 h | Now |
| `DOC-05` | Add superseded banners to `OSC/README.md` and `OSC/WINDOWS_SETUP.md`; correct the claim that `CMakeLists.txt` builds DPI binaries (it builds only `packet_analyzer`, no `-pthread`) | `M-05`, `M-06` | 30 min | Now |
| `DOC-06` | Fix the `conftest.py` reference | `M-07` | 10 min | With `T0-02` |
| `DOC-07` | Add `AUDIT.md` and this plan to the root `README.md` documentation index | — | 15 min | Now |
| `DOC-08` | Gitignore or delete `session-ses_f0c8.md` / `session-ses_f0d1.md` (453 KB of untracked transcript noise in the repo root) | `S-01` | 5 min | Now |

**Standing rule:** no document in this repository should describe a code symbol by line number alone. `WORKFLOW.md` rotted precisely because it did, and `quic.py:603` cites a symbol that does not exist. Cite the symbol, and add a check (`T0-10`) that fails when a docstring references a missing symbol.

---

## §8 — Test strategy

| Suite | Purpose | Gate |
|---|---|---|
| Unit | Per-module behaviour | Zero regressions, always |
| **Property** (`hypothesis`) | No exception and bounded output for arbitrary bytes and arbitrary `length` arguments | Zero findings, always — this is what would have caught `D-05` and `D-18` |
| **Differential** (C++ via Docker) | Behavioural parity with the original, with an explicit divergence allowlist | Parity or a documented, pinned divergence |
| Integration | All three pipeline variants produce byte-identical output | Zero divergence |
| **Golden corpus** (Phase 2) | Labelled captures, per-class precision/recall | Threshold per class |
| **Adversarial** (Phase 2) | Injection pcaps; absurd rule requests | 100% refusal |
| **Safety** | `test_safety_constraints.py` extended to the agent tree (`A-03`); plus the docstring-symbol check from `T0-10` | Hard gate |
| Benchmarks | Throughput and per-stage cost | Non-regression vs. the `T0-03` baseline |

**Additions to `tests/test_safety_constraints.py`**, all of which the audit found missing: no agent output is ever `eval`'d; no agent reaches the network; no agent writes outside its sandbox; no shipped docstring references a non-existent symbol; the worker-delay test hook (`R-10`) is never set outside tests.

---

## §9 — Risk register

| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| `RK-01` | `T0-11` breaks output ordering and the differential suite | Medium | High | Decision-bitmap design keeps a second sequential input pass, so ordering is preserved by construction. Land as two commits with a bisectable first step. `T1-03` is where streaming risk actually lives, and it is isolated from `T0-11` |
| `RK-02` | `T0-06` (direct pcap header read) regresses I/O throughput | Medium | Medium | `T0-03`'s benchmark is the guard; record the delta rather than reverting silently |
| `RK-03` | `DEC-01` option B proves impractical; bounded reorder cannot preserve determinism cheaply | Medium | Medium | Fall back to option C (set-based comparison). Decide early, in Phase 0, not in Phase 1 |
| `RK-04` | Phase 0 is judged "not progress" because nothing user-visible ships | High | Medium | Phase 0 is ~1 week. Phase 3 (MCP server) is a user-visible demo at roughly week 5 and depends only on Phase 1. Consider pulling it forward to right after Phase 0 to shorten the feedback loop |
| `RK-05` | The golden corpus is built from toy traffic and every downstream eval is invalid | Medium | High | Phase 0.5 precedes Phase 2 by design. Explicitly source at least a third of the corpus from real VLAN-tagged enterprise captures |
| `RK-06` | The safety envelope silently stops being true once agent code lands | Medium | High | `A-03`: separate safety suite for the agent tree, in Phase 2, before any agent code |
| `RK-07` | Phase 5 fingerprinting is attempted with `dpkt` and is subtly wrong | Medium | Medium | Validate against public JA3/JA4 test vectors before trusting any output. If `dpkt` proves insufficient, move to a dedicated ClientHello parser with scapy as the cross-check |
| `RK-08` | Scope creep into Phase 3+ before Phase 2's eval harness exists | High | High | Phase 3 is deliberately small and read-only, which limits the damage if this happens. Everything with write capability is Phase 6 |

---

## §10 — Verification gates

A phase is complete only when all of its boxes are checked. There is no partial credit and no "ship it and see".

**Per-commit:** `uv run ruff check .` · `uv run mypy` · `uv run pytest -q` (all green)
**Per-phase:** exit criteria in the phase section · new regression test for every closed defect · no finding left un-referenced
**Per-release:** `ruff format --check` clean · coverage ≥ 85 · differential suite green · golden-corpus thresholds met · safety suite green · `AUDIT.md` updated with any new IDs

**Definition of done for a defect:** the code is fixed, a test fails without the fix and passes with it, and the finding's row in `AUDIT.md` is marked closed. A defect closed by a code change with no test is not closed — `tests/test_pcap_io.py:41` is the standing example of what that looks like.

---

## Appendix A — Task index

| ID | Task | Traces | Effort | Gate |
|---|---|---|---|---|
| `T0-01` | CI, coverage, timeouts | `R-01`, `R-02`, `R-03`, `R-09` | 0.5 d | — |
| `T0-02` | `conftest.py` + fixture de-dup | `R-04`, `M-07` | 0.5 d | — |
| `T0-03` | Memory reproduction test + benchmarks | `R-06` | 0.5 d | — |
| `T0-04` | Clamp TLS `length` | `D-05` | 15 min | — |
| `T0-05` | Guard `PcapWriter` open | `D-04` | 15 min | — |
| `T0-06` | Direct pcap record-header read | `D-06`, `D-07` | 0.5 d | — |
| `T0-07` | Bound HTTP `Host:` scan | `D-09`, `D-10` | 0.5 d | — |
| `T0-08` | Per-packet QUIC undecryptable | `D-08` | 0.5 d | — |
| `T0-09` | Make `--live-rules` honest | `D-03` | 0.5–1 d | — |
| `T0-10` | Teardown in `finally` + stale docstrings | `D-12`, `S-03` | 0.5 d | — |
| `T0-11` | **Bound worker memory** | `D-01`, `D-02`, `D-22` | 2–3 d | `DEC-01` |
| `T05-01` | VLAN / QinQ | `D-14` | 0.5 d | — |
| `T05-02` | pcapng diagnostic or reader | `D-15` | 10 min / 2 d | `DEC-02` |
| `T1-01` | Event bus | `A-01` | 1 d | `DEC-01` |
| `T1-02` | `CapSource` abstraction | `A-01` | 2 d | — |
| `T1-03` | Streaming output + reorder buffer | `A-02`, `P-16` | 3 d | `DEC-01`, `DEC-05` |
| `T1-04` | Rule DSL with provenance | — | 3 d | — |
| `T1-05` | CIDR + dst-IP rules | `D-20`, `D-21` | 1 d | `DEC-04` |
| `T1-06` | **`simulate_ruleset`** | `A-05` | 2 d | — |
| `T1-07` | Property tests + scapy cross-check | `R-05`, `R-08` | 2 d | `DEC-03` |
| `T1-08` | Benchmark suite | `R-06`, `P-15` | 1 d | — |
| `T1-09` | SNI/DNS parser correctness | `D-17`, `D-18`, `D-19` | 1 d | — |
| `DOC-01`…`DOC-08` | Documentation corrections | `M-01`…`M-07`, `S-01` | ~2 d total | — |

**Phase 0 + 0.5 total: ~9–10 working days.** Phase 1: ~16 working days.

## Appendix B — Decisions required

| ID | Decision | Recommendation | Blocks |
|---|---|---|---|
| `DEC-01` | Output-ordering guarantee under streaming | **B** (bounded reorder window), test-level fallback to **C** | `T0-11`, `T1-01`, `T1-03` |
| `DEC-02` | pcapng: reader or diagnostic | **Diagnostic now**, reader in Phase 1 if needed | `T05-02` |
| `DEC-03` | scapy: implement or delete | **Implement** the cross-check | `T1-07` |
| `DEC-04` | Rule persistence key migration | **`AppType.name`**, display names as aliases, one-shot migration | `T1-05` |
| `DEC-05` | Bidirectional flow folding default | **On for streaming, off for differential** | `T1-03` |