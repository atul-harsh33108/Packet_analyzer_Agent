---
schema: dpi-engine-tracker/v1
status: active
phase: 0
current_task: T0-05
next_action: Wrap `open(self.path, "wb")` in try/except OSError -> PcapError in PcapWriter.__init__ (pcap_io.py ~239); add a PcapWriter + CLI regression test
blockers: [DEC-01 blocks T0-11, T1-01, T1-03; DEC-02 blocks T05-02; DEC-03 blocks T1-07; DEC-04 blocks T1-05; DEC-05 blocks T1-03]
last_updated: 2026-10-03
last_updated_by: claude-opus-5[1m]
session: ses_t0_04
---

# Task Tracker — `dpi-engine`

**Single source of truth for what is done, what was decided, and what happens next.**

This file is **state**. For the *procedure* that governs editing it, read
[`TASK_TRACKER_UPDATE_PROTOCOL.md`](TASK_TRACKER_UPDATE_PROTOCOL.md). For the
session workflow — what to read, in what order, when to stop — read
[`OPERATING_INSTRUCTIONS.md`](OPERATING_INSTRUCTIONS.md).

> **If you are an agent starting cold with no conversation history:** read
> [§1 Current state](#1-current-state) below. It is the only block you need to
> know what to do. Everything else is reference.

**Companion documents (do not duplicate their content here):**

| Document | Contains | Mutable? |
|---|---|---|
| [`AUDIT.md`](AUDIT.md) | The findings. `D-##` `R-##` `A-##` `M-##` `S-##` `P-##` IDs originate there. | Rarely — append new IDs only |
| [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) | Task specifications, dependency graph, risk register | Rarely — see deviation rules |
| `TASK_TRACKER.md` (this file) | State: status, decisions, session history | **Frequently** |

---

## 1. Current state

> One block. Read this, act, come back. Keep it under 40 lines.

| Field | Value |
|---|---|
| **Phase** | 0 — Harden |
| **Phase progress** | 1 / 11 tasks done |
| **Current task** | `T0-05` - Guard `PcapWriter` open |
| **Next action** | Wrap `open(self.path, "wb")` in `try/except OSError` raising `PcapError`, mirroring `PcapReader._open`; add a test that `PcapWriter("Z:/nonexistent-dir/out.pcap")` raises `PcapError` and that the CLI prints `error:` and exits 1 |
| **Blocked by** | nothing - `T0-04` is unblocked |
| **Open decisions** | `DEC-01` `DEC-02` `DEC-03` `DEC-04` `DEC-05` — **all five open.** `DEC-01` is on the critical path |
| **Critical path** | `T0-01` → `T0-02` → `T0-11` → `T1-01`/`T1-03` → `T1-06` → Phase 2 exit |
| **Untracked findings** | `D-13` has no owning task; dead-code items from `S-03` have no IDs yet |
| **Session** | `ses_t0_04` - `T0-04` closed |

**Standing blockers for whoever picks this up:** five decisions need a human. They
are *not* for an agent to choose silently. See [§2](#2-decision-log).

---

## 2. Decision log

Decisions are recorded here permanently. A decided decision is **never** reopened
without a new `DEC-##` row superseding it.

| ID | Question | Status | Decided value | Decided by | Date | Blocks |
|---|---|---|---|---|---|---|
| `DEC-01` | Output-ordering guarantee under streaming | **open** | — | — | — | `T0-11`, `T1-01`, `T1-03` |
| `DEC-02` | pcapng: full reader or precise diagnostic? | **open** | — | — | — | `T05-02` |
| `DEC-03` | scapy: implement the cross-check or delete the dep? | **open** | — | — | — | `T1-07` |
| `DEC-04` | Rule-file persistence key migration | **open** | — | — | — | `T1-05` |
| `DEC-05` | Bidirectional flow folding: default on or off? | **open** | — | — | — | `T1-03` |

### Detail

**`DEC-01` — Output-ordering guarantee under streaming.**
*Why it matters:* the current deterministic output depends on materialising every
packet and sorting by `sequence_index`. Fixing `D-01` removes exactly the structure
that makes the sort possible, so a choice is forced. `T0-11`'s recommended
decision-bitmap design sidesteps this for the batch path (the second input pass is
sequential, so the sort disappears rather than being replaced); `T1-03` cannot
sidestep it.
*Options:* **A** per-shard arrival order — output differs run to run, breaks the
differential byte-comparison and the "all three variants are byte-identical"
property. **B** bounded reorder window of size *W* — deterministic within *W*,
out of order beyond, needs a documented late-packet policy. **C** drop the byte
guarantee, compare packet *sets* in tests.
*Recommendation:* **B**, with **C as the test-level fallback** (byte-exact when the
capture fits the window, set-equality otherwise).
*Recommendation is not a decision.* Record the human's choice here.

**`DEC-02` — pcapng.** `D-15`. Options: full reader (SHB/IDB/EPB/SPB, multi-interface,
~200 lines) or detect `0x0A0D0D0A` and raise a precise diagnostic naming
`editcap -F pcap` (~10 lines). *Recommendation:* Option 2 now, Option 1 in Phase 1
if the golden corpus needs it — pcapng appears in roughly a third of real captures,
but a wrong reader is worse than an honest refusal.

**`DEC-03` — scapy.** `R-08`. `DESIGN_DECISIONS.md` justifies scapy as an independent
cross-check of hand-rolled TLS parsing; no test does this. *Recommendation:* implement
it. It is the best available substitute for the fuzzing the project lacks
(`R-05`), scapy is already a declared dev dependency, and it closes the largest
documentation-vs-implementation gap in the repository. Fall back to deleting the
dependency and striking the claim if scapy proves unreliable as a reference.

**`DEC-04` — Rule persistence key.** `D-16`. Keys are currently display names
(`"Twitter/X"`); renaming a display string silently invalidates saved rules files.
Options: **(a)** persist `AppType.name`, accept display names as input-only aliases,
one-shot migration on load; **(b)** persist `AppType.name` only, hard-fail old files
with a clear message; **(c)** persist both, prefer the stable one.
*Recommendation:* **(a)** with a deprecation warning — existing users have saved
files.

**`DEC-05` — Bidirectional flow folding.** `P-16`. Flows are keyed by exact
five-tuple, so a block on client→server does not apply to server→client. Correct for
C++ parity, wrong for a product. *Recommendation:* default **ON** for streaming mode,
**OFF** for differential mode, with the differential harness able to select the mode
— which it currently cannot.

---

## 3. Phase rollup

| Phase | Scope | Tasks | Done | In progress | Blocked | Pending | Deferred | Exit status |
|---|---|---|---|---|---|---|---|---|
| **0** | Harden | 11 | **1** | 0 | **1** | 9 | 0 | not met |
| **0.5** | Real captures | 2 | 0 | 0 | **1** | 1 | 0 | not met |
| **1** | Streaming core | 9 | 0 | 0 | **4** | 5 | 0 | not met |
| 2 | Eval harness | outline | — | — | — | — | — | not started |
| 3 | MCP server | outline | — | — | — | — | — | not started |
| 4 | Read-only agents | outline | — | — | — | — | — | not started |
| 5 | Fingerprinting + ClassifierGap | outline | — | — | — | — | — | not started |
| 6 | Write path | outline | — | — | — | — | — | not started |
| **DOC** | Documentation track | 8 | **3** | 0 | 0 | 2 | **1** (`DOC-03`) superseded + **1** partial (`DOC-07`) | not met |

**Totals:** 30 tasks — **3** done — 0 in progress — 6 blocked — 18 pending — 2 deferred/partial.
The six blocked tasks are `T0-11`, `T05-02`, `T1-01`, `T1-03`, `T1-05`, `T1-07` —
all gated on the five open decisions. **Six of thirty tasks cannot start until a
human decides.**

**Total specified work:** 30 tasks, ~27 working days (Phases 0 + 0.5 + 1), plus ~2
days of documentation in parallel.

---

## 4. Task board

Status vocabulary is closed (7 values) — see
[§9](#9-status-vocabulary). Only these six values are valid.

| ID | Task | Traces | Status | Gate | Effort |
| `T0-01` | CI, coverage, timeouts, gitignore artifact | `R-01` `R-02` `R-03` `R-09` | pending | — | 0.5 d |
| `T0-02` | `conftest.py` + fixture de-duplication | `R-04` `M-07` | pending | — | 0.5 d |
| `T0-03` | Memory reproduction test + benchmark baseline | `R-06` | pending | — | 0.5 d |
| `T0-04` | Clamp `length` in TLS entry points | `D-05` | done | - | 15 min |
| `T0-05` | Guard `PcapWriter` open | `D-04` | pending | — | 15 min |
| `T0-06` | Direct pcap record-header read | `D-06` `D-07` | pending | — | 0.5 d |
| `T0-07` | Bound the HTTP `Host:` scan | `D-09` `D-10` | pending | — | 0.5 d |
| `T0-08` | Per-packet QUIC `undecryptable` accounting | `D-08` | pending | — | 0.5 d |
| `T0-09` | Make `--live-rules` honest | `D-03` | pending | — | 0.5–1 d |
| `T0-10` | Teardown in `finally`; stale docstrings; dead code | `D-12` `S-03` | pending | — | 0.5 d |
| `T0-11` | **Bound worker memory** | `D-01` `D-02` `D-22` | blocked | **`DEC-01`** | 2–3 d |
| `T05-01` | VLAN / 802.1Q and QinQ | `D-14` | pending | — | 0.5 d |
| `T05-02` | pcapng diagnostic or reader | `D-15` | blocked | **`DEC-02`** | 10 min / 2 d |
| `T1-01` | Event bus | `A-01` | blocked | **`DEC-01`** | 1 d |
| `T1-02` | `CapSource` abstraction | `A-01` | pending | — | 2 d |
| `T1-03` | Streaming output + reorder buffer | `A-02` `P-16` | blocked | **`DEC-01` `DEC-05`** | 3 d |
| `T1-04` | Rule DSL with provenance | — | pending | — | 3 d |
| `T1-05` | CIDR + destination-IP rules | `D-20` `D-21` `D-16` | blocked | **`DEC-04`** | 1 d |
| `T1-06` | **`simulate_ruleset` counterfactual engine** | `A-05` | pending | — | 2 d |
| `T1-07` | Property tests + scapy cross-check | `R-05` `R-08` | blocked | **`DEC-03`** | 2 d |
| `T1-08` | Benchmark suite | `R-06` `P-15` | pending | — | 1 d |
| `T1-09` | SNI / DNS parser correctness | `D-17` `D-18` `D-19` | pending | — | 1 d |
| `DOC-01` | `README.md` corrections | `M-01` | pending | — | 1 h |
| `DOC-02` | `DESIGN_DECISIONS.md` corrections | `M-02` | done | - | 2 h | Now |
| `DOC-03` | Rewrite `WORKFLOW.md` | `M-03` | done | - | 1 d | Now |
| `DOC-04` | `AGENTIC_ARCHITECTURE.md` §1-§3, §8, §10 | `M-04` | done | - | 3 h | Now |
| `DOC-05` | `OSC/` superseded banners + CMake correction | `M-05` `M-06` | pending | — | 30 min |
| `DOC-06` | Fix `conftest.py` reference | `M-07` | pending | `T0-02` | 10 min |
| `DOC-07` | Documentation index (`docs/README.md`) | - | partial | - | 15 min |
| `DOC-08` | Gitignore / delete session transcripts | `S-01` | pending | — | 5 min |

**Unassigned findings — these need owners before the tracker is complete:**

| Finding | Issue | Suggested owner |
|---|---|---|
| `D-13` | An LB process death orphans all its fast-paths forever — only `_lb_main` sends FP sentinels, so the parent discovers it only via the 120 s timeout | Add to `T0-10` (same supervision/teardown family) |
| *(no ID)* | Dead code from `S-03`: `packet_parser.five_tuple_of`, `rule_manager.STATIC_RULES`, `load_balancer.queue_for`, `LoadBalancerStats.packets_unroutable` (declared `:139`, summed `:153`, serialised `:165`, never incremented), `PacketAction.INSPECT`/`LOG_ONLY` | New `D-23`, owned by `T0-10` |
| *(no ID)* | `Connection.packets_in` / `bytes_in` are permanently 0 — `update_connection` is called exactly once, always `is_outbound=True` | New `D-24`; either drive both directions or document the fields as reserved |
| *(no ID)* | `run_pipeline`'s `rule_broadcaster` parameter is never supplied by the CLI — test-only | New `D-25`; wire it or drop it |

---

## 5. Task records

One record per task, filled in **as the work happens**. A record for a `pending`
task contains only its specification pointer. A record for a `done` task contains
what actually happened — which is frequently **not** what the plan predicted.

Record fields, in this order: `Status` · `Claimed by` · `Session` · `Blocked by` ·
`Files` · `Test added` · `How it was tackled` · `Deviations` · `Verification` ·
`Closed findings` · `Follow-ups` · `Notes`.

Fields left blank stay blank. **Never delete a record** — set `Status` to `deferred`
or `dropped` and say why.

---

### `T0-01` — CI, coverage, timeouts, gitignore artifact

- **Status:** pending
- **Claimed by:** —
- **Session:** —
- **Blocked by:** —
- **Files:** `.github/workflows/ci.yml` (new), `pyproject.toml`, `.gitignore`
- **Test added:** the CI pipeline itself; assert a deliberately failing assertion turns it red
- **How it was tackled:** —
- **Deviations:** —
- **Verification:** `uv run pytest --timeout=60 -q` green; `uv run pytest --cov --cov-report=term -q` reports ≥ 85
- **Closed findings:** —
- **Follow-ups:** add `ruff format --check` to CI once the 22 unformatted files are formatted (not enforced today)
- **Notes:** first task deliberately — every subsequent task is gated by it

### `T0-02` — `conftest.py` + fixture de-duplication

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `tests/conftest.py` (new), 8 test modules, `tests/differential/README.md`
- **Test added:** none needed; assert `pytest --collect-only` stays at 404
- **How it was tackled:** —
- **Deviations:** —
- **Verification:** `rg -c "FIXTURES = Path" tests/` returns one hit
- **Closed findings:** — · **Follow-ups:** `DOC-06`
- **Notes:** pure de-duplication; do not change test semantics

### `T0-03` — Memory reproduction test + benchmark baseline

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `tests/test_resource_bounds.py`, `tests/fixtures/`, `tests/benchmarks/`
- **Test added:** a test that **demonstrates** `D-01` (peak `ProcessedPacket` accumulation grows with packet count) — expected to *fail* until `T0-11`; plus `pytest-benchmark` baselines for `parse_packet`, `extract_sni`, `sni_to_app_type`, end-to-end Mpps
- **How it was tackled:** —
- **Deviations:** —
- **Verification:** the reproduction test fails now, passes after `T0-11`
- **Closed findings:** — (R-06 completes at `T1-08`) · **Follow-ups:** —
- **Notes:** do **not** fix anything here; a test that fails is the intended output

### `T0-04` — Clamp `length` in TLS entry points

- **Status:** done - **Claimed by:** claude-opus-5[1m] - **Session:** ses_t0_04 - **Blocked by:** -
- **Files:** `src/dpi_engine/sni_extractor.py`, `tests/test_sni_extractor.py`
- **Test added:** `tests/test_sni_extractor.py` - five tests. `test_oversized_length_does_not_make_a_short_buffer_look_like_a_client_hello` (a 6-byte buffer claimed as 999 bytes must not satisfy the `length >= 9` gate), `test_extract_sni_with_oversized_length_returns_none_instead_of_raising` (the direct IndexError repro), `test_extract_sni_never_raises_for_any_truncation_at_any_inflated_length` (exhaustive: every truncation offset x three inflated lengths), plus two guards - `test_length_argument_still_limits_parsing_when_smaller_than_payload` and `test_length_equal_to_payload_is_unchanged` - proving the clamp is an upper bound only and does not change any existing caller.
- **How it was tackled:** Reproduced first, before touching source. `is_tls_client_hello(b"\x16\x03\x01\x00\x05\x01", 999)` returned `True` and `extract_sni` with the same arguments raised `IndexError` - and the `True` is the more interesting half: a 6-byte buffer satisfied the `length >= 9` Client Hello gate purely on the caller's *claimed* length. Root cause was one line in each of two functions: `if length is None: length = len(payload)` resolved the default but left an explicitly supplied `length` completely unchecked. Fix is `length = min(length, len(payload))` immediately after that branch, in both `is_tls_client_hello` and `extract_sni`. Both docstrings were rewritten to state the clamp and the reason, rather than continuing to promise only that the functions "never raise" - the original promise was true for the omitted-argument path and false for the explicit one, and the docstring did not distinguish them.
- **Deviations:** The task brief said "one line each". Two lines were needed - `extract_sni` clamps independently rather than relying on its call to `is_tls_client_hello`, because `extract_sni` is a public entry point and must not depend on an internal call for its own safety. Both docstrings were also updated, which the brief mentioned but did not cost-justify.
- **Verification:** `pytest tests/test_sni_extractor.py -k` on the new tests: **3 failed before the fix** (IndexError at `sni_extractor.py:78`), **5 passed after**. Full suite **397 passed, 12 skipped** - up from 392, i.e. +5 new tests and **zero regressions**. `ruff check .` clean. `mypy` clean on 13 files. Manual repro now returns `False` / `None`.
- **Closed findings:** `D-05`
- **Follow-ups:** none. This closes the only `D-##` item that property-based testing would also have caught, and the `T1-07` hypothesis strategies should include arbitrary `length` arguments so the class of bug cannot return.
- **Notes:** The existing `test_truncated_client_hello_never_crashes_at_any_offset` gave false confidence - it is a good test, but it calls `extract_sni(truncated)` with **one** argument, so `length` always defaulted to `len(payload)` and the explicit-length path was never reached by any test in the suite. 93% line coverage counted those lines as covered; nothing exercised the bug. Worth remembering that coverage is not evidence of behaviour.
### `T0-05` — Guard `PcapWriter` open

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `src/dpi_engine/pcap_io.py`, `tests/test_pcap_io.py`, `tests/test_cli_run.py`
- **Test added:** `PcapWriter("Z:/nonexistent-dir-xyz/out.pcap")` raises `PcapError`; `dpi-engine run in.pcap Z:/nonexistent/out.pcap` prints `error:` and exits 1, not a traceback
- **How it was tackled:** —
- **Deviations:** —
- **Verification:** `pytest tests/test_pcap_io.py tests/test_cli_run.py -q`
- **Closed findings:** `D-04` · **Follow-ups:** —
- **Notes:** mirror the existing `PcapReader._open`; the asymmetry is the bug

### `T0-06` — Direct pcap record-header read

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `src/dpi_engine/pcap_io.py`, `tests/test_pcap_io.py`
- **Test added:** (a) `incl_len = 0xFFFFFFF0` rejected **without** attempting the read; (b) a snaplen-truncated record yields `len(data) == incl_len` and `orig_len > len(data)` — **and replace `tests/test_pcap_io.py:41`, which currently asserts the `D-06` bug**
- **How it was tackled:** —
- **Deviations:** —
- **Verification:** `pytest tests/test_pcap_io.py tests/test_resource_bounds.py -q`; benchmark delta vs. the `T0-03` baseline
- **Closed findings:** `D-06` `D-07` · **Follow-ups:** —
- **Notes:** highest-leverage task in Phase 0 — one change, two defects. Medium risk: replaces the I/O hot path. If throughput regresses vs dpkt, record the delta in Deviations; do not revert silently

### `T0-07` — Bound the HTTP `Host:` scan

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `src/dpi_engine/sni_extractor.py`, `tests/test_sni_extractor.py`, differential allowlist
- **Test added:** `GET /?u=http://Host:x HTTP/1.1\r\n\r\n` → `None` (was `"x HTTP/1.1"`); POST body `Host: evil.com` after the header block → `None`; `Host: [2001:db8::1]:8080` → `[2001:db8::1]`; legitimate `Host: example.com` still works
- **How it was tackled:** —
- **Deviations:** —
- **Verification:** `pytest tests/test_sni_extractor.py -q` **and** the differential suite
- **Closed findings:** `D-09` `D-10` · **Follow-ups:** —
- **Notes:** changes classification on adversarial input — update the differential divergence allowlist and pin the new behaviour

### `T0-08` — Per-packet QUIC `undecryptable` accounting

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `src/dpi_engine/quic.py`, `src/dpi_engine/worker.py`, `tests/test_quic.py`
- **Test added:** a flow whose first Initial is undecryptable and whose second decrypts cleanly reports `undecryptable == 1`, not `2` — against a constructed fixture, not a timing accident
- **How it was tackled:** —
- **Deviations:** —
- **Verification:** `pytest tests/test_quic.py -q`
- **Closed findings:** `D-08` · **Follow-ups:** —
- **Notes:** have `feed()` return a per-packet outcome; the caller currently infers status from a *cumulative* field

### `T0-09` — Make `--live-rules` honest

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `src/dpi_engine/cli.py`, `src/dpi_engine/pipeline.py`, `tests/test_cli_run.py`
- **Test added:** the chosen documented behaviour — control channel works under `--load-balancers`, **or** the flag combination is rejected at parse time
- **How it was tackled:** —
- **Deviations:** —
- **Verification:** `pytest tests/test_cli_run.py tests/test_staged_pipeline.py -q`
- **Closed findings:** `D-03` · **Follow-ups:** —
- **Notes:** pick (a) thread `live_rules` through `run_pipeline_staged` (1 d, matches the documented promise) or (b) reject the combination (0.5 d, honest). **The current silent no-op is not an option.**

### `T0-10` — Teardown in `finally`, stale docstrings, dead code

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `src/dpi_engine/pipeline.py`, `worker.py`, `quic.py`, `load_balancer.py`, `types.py`, `tests/test_safety_constraints.py`
- **Test added:** inject a `_collect` failure and assert no child processes survive; an AST check asserting no shipped docstring references a symbol absent from the module
- **How it was tackled:** —
- **Deviations:** —
- **Verification:** `pytest -q`, `ruff check`, `mypy`
- **Closed findings:** `D-12`, `D-13` (proposed), `S-03` partially · **Follow-ups:** —
- **Notes:** the four docstring fixes are `quic.py:603` → `worker.FlowProcessor._quic_inspectors`; `worker.py:93` → `worker.FixedRuleSource`; `pipeline.py:131` → remove the non-existent `with_fast_path_stats`; **`load_balancer.py:20-35`**, which falsely claims the LB stage parses Ethernet/IP/TCP/UDP and contradicts `DESIGN_DECISIONS.md` and the root `README.md`. Plus `types.py:257` cites `DESIGN_DECISIONS.md` item 14 where items 7 and 11 are meant

### `T0-11` — Bound worker memory

- **Status:** blocked · **Blocked by:** `DEC-01` · **Claimed by:** — · **Session:** —
- **Files:** `src/dpi_engine/worker.py`, `src/dpi_engine/pipeline.py`, `tests/test_resource_bounds.py`
- **Test added:** the `T0-03` reproduction turns green — peak memory flat as packet count grows; output byte-identical across all three variants; `blocked_tuples` and `_quic_inspectors` bounded under a run with far more distinct flows than `--max-connections`
- **How it was tackled:** —
- **Deviations:** —
- **Verification:** `pytest -q` — **all 404 still pass** — plus the differential suite
- **Closed findings:** `D-01` `D-02` `D-22` · **Follow-ups:** —
- **Notes:** **largest change in Phase 0.** Design: workers emit one *bit* per packet (forward/drop) rather than the full `RawPacket`; the parent makes one additional sequential pass over the input and writes where the bit is set. Because that pass is sequential, **the sort disappears rather than being replaced**, so output is byte-identical and `DEC-01` is not actually needed for this task. Cost is `⌈total_packets / 8⌉` bytes — 1.25 MB at the 10 M default. Set `maxsize` on the queues for backpressure. Land the bitmap change and the backpressure change as **two commits**. **Do not remove the second input pass — `T1-03` depends on it being isolated.**

### `T05-01` — VLAN / 802.1Q and QinQ

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `src/dpi_engine/packet_parser.py`, `tests/test_packet_parser.py`
- **Test added:** single-tagged, double-tagged and untagged frames over identical inner packets yield identical `FiveTuple` and classification; a bounded nesting-depth guard
- **How it was tackled:** —
- **Deviations:** —
- **Verification:** `pytest tests/test_packet_parser.py -q`
- **Closed findings:** `D-14` · **Follow-ups:** —
- **Notes:** peel `0x8100`, `0x88a8`, `0x9100` in a loop. **VLAN tags must not partition flows** — the flow key stays L3 — but keep `vlan_id`/`priority` on `ParsedPacket` for Phase 5 fingerprinting

### `T05-02` — pcapng diagnostic or reader

- **Status:** blocked · **Blocked by:** `DEC-02` · **Claimed by:** — · **Session:** —
- **Files:** `src/dpi_engine/pcap_io.py`, `tests/test_pcap_io.py`
- **Test added:** a minimal pcapng fixture produces a precise diagnostic naming a conversion command
- **How it was tackled:** — · **Deviations:** — · **Verification:** `pytest tests/test_pcap_io.py -q`
- **Closed findings:** `D-15` · **Follow-ups:** — · **Notes:** see `DEC-02`

### `T1-01` — Event bus

- **Status:** blocked · **Blocked by:** `DEC-01` · **Claimed by:** — · **Session:** —
- **Files:** `src/dpi_engine/events.py` (new), `src/dpi_engine/pipeline.py`
- **Test added:** folding a synthetic event stream yields a `PipelineResult` identical to today's batch result for the same capture — **this is the guarantee that makes the refactor safe**
- **How it was tackled:** — · **Deviations:** — · **Verification:** `pytest -q`
- **Closed findings:** — (addresses `A-01`) · **Follow-ups:** —
- **Notes:** `PipelineResult` becomes a *derived* summary so the batch API and every existing consumer keep working

### `T1-02` — `CapSource` abstraction

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `src/dpi_engine/cap_source.py` (new), `src/dpi_engine/pcap_io.py`
- **Test added:** `WatchSource` over a temp directory picks up files as they appear; `StreamSource` round-trips byte-for-byte against `FileSource`
- **How it was tackled:** — · **Deviations:** — · **Verification:** `pytest -q`
- **Closed findings:** — · **Follow-ups:** —
- **Notes:** `PcapReader`/`PcapWriter` stay the only I/O boundary, so the safety invariant holds by construction

### `T1-03` — Streaming output + reorder buffer

- **Status:** blocked · **Blocked by:** `DEC-01` `DEC-05` · **Claimed by:** — · **Session:** —
- **Files:** `src/dpi_engine/pipeline.py`, `src/dpi_engine/worker.py`
- **Test added:** deterministic byte-identical output within the window; documented and tested behaviour beyond it; differential mode pinned to exact-tuple keying
- **How it was tackled:** — · **Deviations:** — · **Verification:** `pytest -q` plus differential
- **Closed findings:** `A-02`, `P-16` · **Follow-ups:** —
- **Notes:** replace `T0-11`'s second input pass with a bounded reorder window; add `--reorder-window`. Medium-high risk — this is where `RK-01` and `RK-03` actually live, which is why `T0-11` deliberately kept the pass

### `T1-04` — Rule DSL with provenance

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `src/dpi_engine/rule_manager.py`, new `rules/` subpackage
- **Test added:** JSON round-trip preserves provenance; a rule without provenance cannot be auto-applied
- **How it was tackled:** — · **Deviations:** — · **Verification:** `pytest -q`
- **Closed findings:** — · **Follow-ups:** —
- **Notes:** provenance is the precondition for any auto-apply tier in Phase 6

### `T1-05` — CIDR + destination-IP rules

- **Status:** blocked · **Blocked by:** `DEC-04` · **Claimed by:** — · **Session:** — · **Blocked by:** —
- **Files:** `src/dpi_engine/rule_manager.py`
- **Test added:** `10.0.0.0/8` blocks a host inside and not one outside; a migrated persistence key round-trips an old-format rules file with a deprecation warning
- **How it was tackled:** — · **Deviations:** — · **Verification:** `pytest tests/test_rule_manager*.py -q`
- **Closed findings:** `D-20` `D-21` `D-16` · **Follow-ups:** —
- **Notes:** do the `DEC-04` key migration in the same change — both touch the rule schema and `to_dict()`. `ipaddress` is already imported

### `T1-06` — `simulate_ruleset` counterfactual engine

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** new `rules/simulator.py`, `src/dpi_engine/pipeline.py`
- **Test added:** simulating a ruleset that would block 100% of flows is reported as such; a no-op change yields zero delta
- **How it was tackled:** — · **Deviations:** — · **Verification:** `pytest -q`
- **Closed findings:** `A-05` · **Follow-ups:** —
- **Notes:** **the keystone component.** Implement by running the engine twice and diffing the decision bitmaps `T0-11` produces — nearly free, and exact rather than approximate. Every safety claim in `AGENTIC_ARCHITECTURE.md` Layers 3/7/8 reduces to this existing

### `T1-07` — Property tests + scapy cross-check

- **Status:** blocked · **Blocked by:** `DEC-03` · **Claimed by:** — · **Session:** —
- **Files:** `tests/property/` (new), `pyproject.toml`
- **Test added:** the `hypothesis` strategies are the tests; add a seed-reproducibility check so CI failures replay
- **How it was tackled:** — · **Deviations:** — · **Verification:** `pytest tests/property -q`
- **Closed findings:** `R-05` `R-08` · **Follow-ups:** —
- **Notes:** include **arbitrary `length` arguments** — that alone would have caught `D-05`. See `DEC-03`

### `T1-08` — Benchmark suite

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `tests/benchmarks/`
- **Test added:** publish the baseline recorded in `T0-03`
- **How it was tackled:** — · **Deviations:** — · **Verification:** `pytest tests/benchmarks -q`
- **Closed findings:** `R-06` `P-15` · **Follow-ups:** —
- **Notes:** first honest measurement of whether the port is fast enough for real captures

### `T1-09` — SNI / DNS parser correctness

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `src/dpi_engine/sni_extractor.py`
- **Test added:** an SNI extension whose first name entry is not `host_name` but which contains a valid `server_name` later is now found; a 65535-byte claimed hostname is rejected; a compression-pointer loop terminates
- **How it was tackled:** — · **Deviations:** — · **Verification:** `pytest tests/test_sni_extractor.py -q`
- **Closed findings:** `D-17` `D-18` `D-19` · **Follow-ups:** —
- **Notes:** the `break`-should-be-`continue` bug is inherited from `sni_extractor.cpp:107,110,115`

### `DOC-01` — root `README.md` corrections

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `../README.md` (repository root — this file's own directory holds the docs)
- **Change:** test count `377 + 14` → `390 + 14 = 404`; add pcapng, CIDR, dst-IP and HTTP-host limitations; **add an explicit note that the port is likely slower per packet than the C++ original**
- **How it was tackled:** — · **Deviations:** — · **Verification:** manual read-through
- **Closed findings:** `M-01` · **Follow-ups:** — · **Notes:** independent of code work; do it now

### `DOC-02` — `DESIGN_DECISIONS.md` corrections

- **Status:** done · **Claimed by:** ses_2026-10-03 · **Session:** ses_2026-10-03 · **Blocked by:** -
- **Files:** `docs/DESIGN_DECISIONS.md`, plus two code docstrings in `src/dpi_engine/`
- **Test added:** `n/a` (documentation). Verified by reading against source.
- **How it was tackled:** Six fixes, all verified against source before editing. **(a)** Struck bug-list item 1, which proposed 'guard the loop start, or omit QUIC heuristic support entirely' and so contradicted item 16 where `quic.py` implements the full RFC 9000/9001 path; rewrote it as a record of the original bug with a cross-reference to item 16. **(b)** Rewrote the testing-strategy section from a forward-looking task plan (Tasks 2-12) into a description of the five layers that exist, added `quic.py` and `report.py` to the inventory, and added an explicit **Known gaps in the test strategy** subsection naming the missing property testing, benchmarks, coverage, CI, scapy cross-check and flaky timing tests. **(c)** Corrected the partial-output limitation: it previously claimed all variants leave a partial file, but only `run_pipeline` does - both multiprocess variants write after `_collect` and `join`, so a mid-dispatch failure leaves an **empty** pcap. Added a per-variant table. **(d)** Corrected the efficiency note: it claimed the overwrite check fires after 'dispatched every packet, and been shut down/joined', but the writer is now opened at the top of the dispatch block, so the check fires before the first packet; only the post-spawn cost remains. **(e)** Added a **New open decisions** table cross-referencing `DEC-01`..`DEC-05`. **(f)** Added a **Known issues in the current port** section so the document does not imply the port is defect-free - unbounded memory, no VLAN, the `--live-rules` no-op, the unfulfilled pcap bounds claims, and the unmeasured throughput.
- **Deviations:** Scope extended beyond the audit's six items. Added the new-decisions and known-issues sections because the document would otherwise imply the port is defect-free, and a reader has no other signal.
- **Verification:** `pytest` green (docstring-only source edits). Each corrected claim re-checked against the cited code.
- **Closed findings:** `M-02` (a-f all) · **Follow-ups:** `M-02e`/`M-02f` were code docstrings and were fixed here rather than deferred to `T0-10`: `sni_extractor.py's module docstring claimed QUIC was "intentionally NOT implemented" while citing a resolved section, and `types.py:257` cited DESIGN_DECISIONS item 14 (dead-report cleanup) where items 7 and 11 were meant.
- **Notes:** The document now opens with a status banner pointing at `AUDIT.md`, and states that the audit supersedes it on any disagreement.

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `DESIGN_DECISIONS.md`
- **Change:** strike bug-list item 1's QUIC clause (contradicts item 16); fix the stale efficiency note; correct the "output left on disk" claim (MP variants leave an **empty** pcap, not a partial one); rewrite §Testing strategy as done-not-planned; add `quic.py`/`report.py` to the inventory
- **How it was tackled:** — · **Deviations:** — · **Verification:** manual read-through
- **Closed findings:** `M-02` · **Follow-ups:** — · **Notes:** `M-02e`/`M-02f` are *code* docstrings and belong to `T0-10`

### `DOC-03` — Rewrite `WORKFLOW.md`

- **Status:** done (was deferred) · **Claimed by:** ses_2026-10-03 · **Session:** ses_2026-10-03 · **Blocked by:** -
- **Files:** `docs/WORKFLOW.md`
- **Test added:** `n/a` (documentation). Every symbol and line number was verified against source before being written.
- **How it was tackled:** Full rewrite, 15 sections. The previous version was beyond patching: it documented the deleted `demo_classify.py` (a module-graph node, five dependency edges and all of its §10), cited five wrong line numbers, omitted 3 of the 13 modules and 7 of the 13 CLI flags, omitted the entire LB tier, omitted the QUIC classification branch, omitted the TCP state machine and `ESTABLISHED`, omitted `reap_if_due`, and **drew the `x.com`/`t.co` check above the whole classification table** - i.e. it diagrammed the exact bug that had already been fixed. The new version covers: the 13-module map with import direction; all three pipeline variants with the partitioning invariant and why the staged tier is not a throughput optimisation; `FlowProcessor.process` as an ordered 10-step flow with the three independent gates explained; `PcapReader` and `parse_packet`; classification with all four extractors and a per-extractor known-gaps table; the name-to-app table with the two anchoring fixes; the flow state machine as a state diagram with the precedence order; the rule engine with its priority order and domain grammar; all three entry points including `_lb_main`; the shutdown protocol with a why-each-piece-exists table; the nine report sections with denominators; a complete CLI flag reference with all 23 flags; the safety envelope **and where it currently does not hold**; end-to-end data flow with a per-boundary bounds table; and a summary table of where the flow differs from the C++ original.
- **Deviations:** Deferred to "after Phase 1" when the tracker was written. Done now instead, because Phase 1 has not started and a stale document describing a removed module is worse than no document. If Phase 1 changes the architecture, this document is rewritten again as part of `T1-01`.
- **Verification:** all 13 modules present; every symbol named exists (`rg` verified each); the classification table matches `_SNI_RULES` order; the CLI table matches `cli.py`; all 23 flags accounted for.
- **Closed findings:** `M-03` · **Follow-ups:** must be re-verified after `T1-01` (event bus) and `T1-03` (streaming output), both of which change the described flow.
- **Notes:** Opens with a banner recording that it was rewritten and why, plus an explicit instruction to cite symbols rather than line numbers - the original rotted because it was built on line numbers.

- **Status:** deferred · **Claimed by:** — · **Session:** — · **Blocked by:** after Phase 1
- **Files:** `WORKFLOW.md`
- **Change:** full rewrite — see `AUDIT.md` §5.3 for the complete defect list
- **How it was tackled:** — · **Deviations:** — · **Verification:** `n/a`
- **Closed findings:** `M-03` · **Follow-ups:** — · **Notes:** **deferred on purpose** — the architecture it documents changes in Phase 1, so rewriting now would be wasted work

### `DOC-04` — Rewrite `AGENTIC_ARCHITECTURE.md`

- **Status:** done · **Claimed by:** ses_2026-10-03 · **Session:** ses_2026-10-03 · **Blocked by:** -
- **Files:** `docs/AGENTIC_ARCHITECTURE.md`
- **Test added:** `n/a` (documentation)
- **How it was tackled:** Four targeted replacements plus two splices, keeping the document's conceptual half intact as planned. **§1** replaced with the corrected state table: 13 modules / ~5,200 lines (was 11/2,900), 404 tests all passing (was 168 with 9 skipped), 6 dev deps (was 2), 4 commits (was 3), mypy-strict clean with `py.typed` (was "no type checking"), ruff clean (was "no linting"), 10 KB README plus a `docs/` set (was "0 bytes"), and format enforcement called out as absent. **§2** restructured into three parts: 2.1 lists the eight previously-reported defects that are now **fixed** so nobody re-reports them; 2.2 lists the eleven still-open defects including the two Critical ones; 2.3 adds **"blockers that are not bugs"** - no VLAN, no pcapng, no IPv6, no CIDR, no dst-IP blocking, no nanosecond timestamps, unmeasured throughput, display-name persistence keys, no HTTP/2/ECH/cert inspection, and unbounded per-worker state outside `--max-connections` - because these block the product harder than several of the bugs. **§3** rewritten to mark the five previously-listed infra gaps that are now **fixed** with strikethrough (`~~No type checking~~`, `~~No linting~~`, `~~No README~~`, `~~Test suite too small~~`, `~~Zero tests for demo_classify~~`) and to keep the eleven that are still true, now cross-referenced to their task IDs. **§7** updated to the real layout with `docs/` and the new `tests/safety/` split. **§8** resequenced to 7 phases with a table stating what moved and why - VLAN/pcapng ahead of all agent work, `simulate_ruleset` into Phase 1 ahead of the MCP server, MCP server pulled forward, Phase 4 changed to read-only agents only, ClassifierGap moved after fingerprinting - and each phase gained explicit exit criteria. **§10** rewritten from "fix defects #1-#4" (two of which were already fixed) to the five blocking decisions, the memory fix, CI, VLAN, and the `simulate_ruleset` + golden-corpus pair, with an explicit **"what is not an immediate move"** subsection warning against starting the fingerprinting engine or anomaly model yet.
- **Deviations:** None. The plan said keep §4-§7 and §9 and resequence §8; that is what happened.
- **Verification:** all 10 sections present and in order; all 11 Layer subsections intact; all five §9 killers intact; section boundaries and `---` separators verified.
- **Closed findings:** `M-04` · **Follow-ups:** §1 and §2.1 are state snapshots and will go stale again - they should be re-derived from `AUDIT.md` rather than edited, per the one-home-per-fact rule
- **Notes:** The document now opens with a dated correction banner naming the root cause (`AUDIT.md` §6: two sessions 2h15m apart with a refactor between them) and stating which parts were corrected and which were kept.

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `AGENTIC_ARCHITECTURE.md`
- **Change:** rewrite §1–§3 from the stale-claim table in `AUDIT.md` §4.2; resequence §8 per `AUDIT.md` §4.6; **keep §4–§7 and §9 essentially verbatim**
- **How it was tackled:** — · **Deviations:** — · **Verification:** manual
- **Closed findings:** `M-04` · **Follow-ups:** — · **Notes:** do it now — the stale content is actively misleading

### `DOC-05` — `OSC/` banners + CMake correction

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `OSC/README.md`, `OSC/WINDOWS_SETUP.md`
- **Change:** superseded banner pointing at the root `README.md`; correct the claim that `CMakeLists.txt` builds DPI binaries (it builds only `packet_analyzer` from three files, no `-pthread`)
- **How it was tackled:** — · **Deviations:** — · **Verification:** manual
- **Closed findings:** `M-05` `M-06` · **Follow-ups:** — · **Notes:** these files are the provenance for every `DESIGN_DECISIONS.md` entry — retain, do not delete

### `DOC-06` — Fix `conftest.py` reference

- **Status:** pending · **Claimed by:** — · **Session:** — · **Blocked by:** `T0-02`
- **Files:** `tests/differential/README.md`
- **Change:** line 83 names a `conftest.py` that does not exist
- **How it was tackled:** — · **Deviations:** — · **Verification:** `n/a`
- **Closed findings:** `M-07` · **Follow-ups:** — · **Notes:** do together with `T0-02`

### `DOC-07` — Documentation index

- **Status:** partial — `docs/README.md` created 2026-10-03; root `README.md` still needs a link to it
- **Claimed by:** ses_init · **Session:** ses_init · **Blocked by:** —
- **Files:** `docs/README.md` (done), `../README.md` (remaining)
- **Test added:** `n/a` — verify by opening `../README.md` and finding a link to `docs/README.md`, and that every link in `docs/README.md` resolves
- **How it was tackled:** Created `docs/README.md` as a navigation index with a read-order table, a one-line purpose per document, a table of the docs that stay beside their own directory (`../README.md`, `../OSC/*.md`, `../tests/differential/README.md`), and the four documentation conventions. All 8 project docs were moved here with `git mv`.
- **Deviations:** Planned as "link new docs from root README.md". Actual scope is larger — all 8 `.md` files moved into `docs/`, root `README.md` kept, and `docs/README.md` added as an index.
- **Verification:** every relative link in `docs/` resolves; `git status` records all 8 files as renames with 0 insertions/deletions
- **Closed findings:** — · **Follow-ups:** add a Documentation section to `../README.md`
- **Notes:** the two `session-ses_*.md` transcripts were removed from the working tree during this work, which also closes the hygiene half of `S-01`

### `DOC-08` — Gitignore / delete session transcripts

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** `.gitignore`
- **Change:** `session-ses_*.md` are 453 KB of untracked transcript noise in the repo root — gitignore or delete
- **How it was tackled:** — · **Deviations:** — · **Verification:** `git status --short` clean of them
- **Closed findings:** `S-01` (hygiene half) · **Follow-ups:** —
- **Notes:** the *analytical* content of `S-01` is already captured in `AUDIT.md` §6 — only the files need handling

---

## 6. Findings status

Findings live in `AUDIT.md`. This table tracks **closure**, not description.

| Group | Total | Closed | Open | Unassigned |
|---|---|---|---|---|
| `P-##` port-vs-C++ | 19 | n/a — characterisation, not a defect | — | — |
| `D-##` defects | 22 | **1** (`D-05`) | 18 | 3 |
| `R-##` rails | 10 | 0 | 10 | 0 |
| `A-##` agentic | 6 | 0 | 6 | 0 |
| `M-##` documentation | 7 | **3** (`M-02` `M-03` `M-04`) | 3 (`M-01` `M-05` `M-06`) + `M-07` (paired with `T0-02`) | 0 |
| `S-##` session | 3 | 0 | 3 | 0 |

**Rules:**
- A finding is `closed` only when its owning task is `done` **and** a regression test exists that fails without the fix.
- The three unassigned `D-##` items are: `D-13` (has an ID, proposed owner `T0-10`),
  plus two `S-03` discoveries that have **no ID yet** — dead code
  (`five_tuple_of`, `STATIC_RULES`, `queue_for`, `packets_unroutable`,
  `PacketAction.INSPECT`/`LOG_ONLY`) and the permanently-zero
  `Connection.packets_in`/`bytes_in`. Per `UPDATE_PROTOCOL.md` §8 these must be given
  IDs in `AUDIT.md` before the tracker is complete. A third, the unused
  `rule_broadcaster` parameter, is a fourth candidate and is listed in §4.
- New findings discovered during implementation get the next free ID in their group. **Never renumber.**

---

## 7. Deviation log

Records where reality differed from `IMPLEMENTATION_PLAN.md`. **Append-only.**
A deviation is not a failure — it is the plan being corrected by evidence.

| Date | Task | Planned | Actual | Reason | Plan updated? |
|---|---|---|---|---|---|
| 2026-10-03 | `T0-04` | `T0-01` (CI) first, then `T0-04` | started at `T0-04` | Requested explicitly: close a defect immediately rather than spend half a day on CI first. `T0-04` is ungated, 15 min, and exercises the whole claim/fix/verify/record loop end to end. | no - task order only, scope unchanged |
| 2026-10-03 | `T0-01` | add coverage floor at 85% | floor verified achievable: **measured 93%** | Ran the measurement instead of leaving the floor as a guess. Per-module: cli 89 · sni_extractor 87 · quic 91 · worker 91 · pipeline 92 · report 95 · rule_manager 95 · packet_parser 95 · pcap_io 97 · connection_tracker 98 · types 98 · load_balancer 100. An 85% gate will not fail on day one. | no - confirms the plan |
| 2026-10-03 | `DOC-02` | fix the six `M-02` items | also added a new-decisions table and a known-issues section | The document would otherwise imply the port is defect-free, and a reader has no other signal. Also fixed two *code* docstrings (`sni_extractor.py`, `types.py:257`) that were nominally assigned to `T0-10`. | yes — `T0-10` narrowed |
| 2026-10-03 | `DOC-03` | deferred until after Phase 1 | rewritten now, before Phase 1 | Phase 1 has not started, and a document describing a deleted module (`demo_classify.py`) is actively misleading. Must be re-verified after `T1-01` and `T1-03`. | yes — see `DOC-03` Follow-ups |
| — | — | — | — | — | — |

**Rule:** if a deviation changes a task's scope, estimate, or gate, also update
`IMPLEMENTATION_PLAN.md` and note it here with `Plan updated? = yes`. Do not let the
two documents diverge silently.

---

## 8. Session log

**Append-only.** One row per working session. This is how continuity works across
sessions and agents — a new session reads this before planning anything.

| Date | Session | Agent | Tasks touched | Outcome | Next action |
|---|---|---|---|---|---|
| 2026-10-03 | `ses_t0_04` | claude-opus-5[1m] | `T0-04` | 1 task completed - `D-05` closed | `T0-05` |
| 2026-10-03 | `ses_2026-10-03` | ses_2026-10-03 | `DOC-02` `DOC-03` `DOC-04` | 3 tasks completed | `T0-01` |
| 2026-10-03 | `ses_init` | — | — | Audit, implementation plan and tracker created. Nothing implemented | `T0-01` |

---

## 9. Status vocabulary

Closed set. Only these six values are valid in any `Status` field.

| Status | Meaning | Requires |
|---|---|---|
| `pending` | Not started | nothing |
| `blocked` | Cannot start | `Blocked by:` naming a `DEC-##` |
| `in_progress` | Claimed, work begun | `Claimed by:` and `Session:` |
| `done` | Complete | `Test added`, `Verification` with passing output, `Closed findings` |
| `deferred` | Consciously moved out of scope | `Follow-ups:` saying when it will be revisited |
| `partial` | Some scope done, the remainder blocked or not started. Only valid alongside a `Follow-ups:` naming what remains | `Files:` must distinguish what is done from what is not |

**Transitions that are forbidden:**
- `done` → anything else. If a fix is reverted, create a new task; do not reopen.
- `blocked` → `pending` without recording a decision in §2.
- `dropped` → `pending` without a new deviation-log entry explaining the reversal.

---

## 10. Definition of done

A task is `done` when **all** of these hold:

- [ ] The specified change is implemented
- [ ] A test exists that **fails without the fix and passes with it**
- [ ] `uv run ruff check .` clean
- [ ] `uv run mypy` clean
- [ ] `uv run pytest -q` green, with **no reduction** in the passing count
- [ ] The task's `Traces` findings are marked closed in §6
- [ ] This record's `How it was tackled` and `Deviations` are filled in — **not left blank**
- [ ] §1 Current state, §4 Task board, §6 Findings status and §8 Session log are all updated
- [ ] If a deviation changed scope, `IMPLEMENTATION_PLAN.md` is updated and §7 records it

**A defect closed by a code change with no test is not closed.**
`tests/test_pcap_io.py:41`, which asserts the `D-06` bug, is the standing example of
what failure looks like.

---

## Appendix A — Task record template

Copy into §5 when adding a task. Keep field order.

```markdown
### `T<n>-<nn>` — <title>

- **Status:** in_progress · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_04 · **Blocked by:** -
- **Files:** <paths>
- **Test added:** <the specific test, or "none needed">
- **How it was tackled:** <what actually happened>
- **Deviations:** <what differed from the plan, and why>
- **Verification:** <commands run + result>
- **Closed findings:** <IDs>
- **Follow-ups:** <anything spawned>
- **Notes:** <non-obvious context>
```

## Appendix B — Phase exit criteria

**Phase 0** — no unbounded allocation reachable from any documented flag · no hang
path without a diagnosable error · green CI on both jobs · coverage ≥ 85 · all 404
tests pass plus new regression tests · `mypy --strict` clean · `ruff format --check`
clean · all 30 tracker task records filled in.

**Phase 0.5** — a VLAN-tagged enterprise capture classifies identically to its
untagged equivalent · pcapng input produces a precise, actionable diagnostic.

**Phase 1** — all 404 existing tests pass unchanged · streaming output deterministic
under the chosen `DEC-01` option · differential parity with the C++ reference intact ·
`simulate_ruleset` working and exercised by a test · memory bounded under a streaming
run with a directory-watch source.

**Per-release** — `ruff format --check` clean · coverage ≥ 85 · differential suite
green · golden-corpus thresholds met · safety suite green · `AUDIT.md` updated with
any new IDs.
