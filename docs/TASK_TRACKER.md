---
schema: dpi-engine-tracker/v1
status: active
phase: 1
current_task: none
next_action: T2-03 - the agent-tree safety suite, which closes A-03. Two things must land together: a SEPARATE safety suite for the agent tree (the existing one scopes src/dpi_engine/ only, so the 'no network' guarantee 'quietly stops being true the moment agent code lands in the same repository, and nothing will report it'), and an explicit written statement that the agent layer WILL need network as a deliberate, documented widening for that layer only. Then T2-04. Still open with the user: a DEC-07 decision on D-27 (bare-substring app matching).
blockers: [zero open decisions - DEC-01..DEC-06 all decided 2026-10-12/13; zero blocked tasks; zero unowned findings; Phase 0, 0.5 and 1 complete and Phase 1 verified (749 passed, 0 skipped incl. differential parity); Phase 2 decomposed into T2-01..T2-04 with T2-01 in progress; ALL DOCUMENTATION FINDINGS M-01..M-07 CLOSED]
last_updated: 2026-10-15
last_updated_by: claude-opus-5[1m]
session: ses_t1_04
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
| **Phase** | 2 — Eval harness (started) |
| **Phase progress** | Phase 0: 11/11 — Phase 0.5: 2/2 — Phase 1: 9/9 (**verified**) — **Phase 2: 2/4** (`T2-01`, `T2-02` done) |
| **Current task** | none — `T2-02` **done**, uncommitted |
| **Next action** | `T2-03` — agent-tree safety suite, closes `A-03`. Still open: a **`DEC-07` decision on `D-27`** |
| **Blocked by** | **nothing.** Zero open decisions and zero blocked tasks — `DEC-06` was the last, 2026-10-13 |
| **Open decisions** | **none.** `DEC-01`–`DEC-03` and `DEC-05` by the user, `DEC-02` ratified in `T05-02`, `DEC-04` in `T1-05`, `DEC-06` in `T1-05` |
| **Critical path** | `T0-01` → `T0-02` → `T0-11` → `T1-01`/`T1-03` → `T1-06` → Phase 2 exit |
| **Untracked findings** | none. `D-13` closed 2026-10-15 (`ses_t1_06b`); `D-23` is re-measurable via `T1-08`, which is its de-facto owner |
| **Documentation** | **all `M-01`–`M-07` closed, and `AUDIT.md` reconciled 2026-10-15.** The three-count contradiction (§2 heading said `D-01`…`D-22`, its intro said "twenty-one", the file held 26) is fixed, and `§0`/`§4.2` — both presented as current — had every numeric row stale, including five that asserted CI, coverage, timeout, property testing and `conftest.py` as *absent* when all five now exist |
| **Session** | `ses_t1_04` - `T1-04` done, **Phase 1 complete (9/9)**, uncommitted |

**Phase 1 is complete — 9/9 — and exited unconditionally (`T1-04`, then
`ses_t1_04b` once Docker was available).** Four of Appendix B's five criteria are met and tested. The fifth,
*memory bounded under a streaming run with a directory-watch source*, **had never
been measured by anything**, so this session measured it and **it found a real
defect**: `WatchSource` reads through one `PcapReader` per file and
`max_total_packets` is enforced inside `PcapReader`, so every file got a fresh
budget — **308 packets read against a limit of 50, raising nothing**. A rotating
capture directory is exactly the many-small-files shape that defeats a per-file
bound. Fixed, and `run_pipeline` now pushes its bounds down through a shared
`_open_source` used by all three variants.

The same criterion also caught **my own test being wrong**: it compared 77 packets
against 616 and called the 5.4× peak growth a `D-01` leak. With a 1024-slot window
both sizes fit in the buffer, so it was measuring "more packets fit". Re-measured
with the input genuinely exceeding the window — 1078 → 4312 packets — peak is flat
at ~1.62 MB.

**Differential parity verified (`ses_t1_04b`).** Once Docker was running the suite
went from 2 passed / 12 skipped to **14 passed / 0 skipped**, and the whole project to
**749 passed with nothing skipped** — the first fully-verified run it has had. The 12
cover total/dropped counts under three rule regimes, detected domains modulo the
documented C++ misclassifications, domain-rule semantics, app-name resolution, three
malformed-input fixtures and two multiprocess-parity runs. `DEC-05`/`DEC-06` remain
deliberate allowlisted divergences; `tests/test_parity_breaks.py` (5 tests) verifies
the port side of each claim, which the differential suite cannot do because it pins
folding off to preserve parity.

**Standing caveat:** `tests/differential` reports 12 skips when Docker is down, and
`tests/benchmarks` reports passed without executing unless `--benchmark-enable` is
passed. Both look green while doing nothing. Do not trust either without them.

**`CapSource` landed (`T1-02`, `ses_t1_02`).** A source is just an iterable of
`RawPacket` — the shape `_iter_inspectable` already consumed — so no pipeline
logic changed and `PcapReader` stays the only thing that parses bytes. `FileSource`,
`StreamSource` and `WatchSource` decide *where bytes come from*; none of them
decides what they mean. A stream has no path, so `PcapWriter`'s
never-overwrite-the-input guard is skipped rather than fed an invented one, and
still enforced for file sources.

Mutation testing found what green tests could not: the suite used `BytesIO` and
real files — **both seekable** — so the non-rewindable path, which is the entire
reason `StreamSource` exists, was never executed, and both mutants on that branch
survived. `PcapReader` peeks four bytes of magic and then `seek(0)`, which a pipe
cannot do; `_PrefixedStream` re-prepends them instead.

**The benchmark baseline is published (`T1-08`, `ses_t1_08`):**
[``docs/BENCHMARKS.md`](BENCHMARKS.md) + `tests/benchmarks/baseline.json`, kept in
agreement by `tests/test_benchmark_baseline.py`, which recomputes the document's
figures from the JSON and fails on drift. **Re-measuring `D-23` made it worse:**
the multiprocess paths are **7.26x** slower than single-process and staged
**8.28x**, against the 4.7x/6.2x the finding recorded — so `T0-11` removed the
per-packet *bytes* without removing the per-packet *pickle*, which is what the
multiprocess variants are actually made of. `D-23` stays open, narrowed to
establishing the crossover point on a realistic capture.

**`D-13` closed 2026-10-15 (`ses_t1_06b`).** It had no owner because its proposed
owner (`T0-10`) landed without taking it — a task can close a finding only by
actually fixing it. The fix is in the parent's collection loop rather than in the
load balancer: `_collect_streaming` now polls the result queue in
`_LIVENESS_POLL_SECONDS` (1 s) slices and re-checks liveness on each empty poll.
A dead load balancer is therefore named in about a second rather than after
`_RESULT_TIMEOUT_SECONDS`, and the message says *which process died* instead of
describing the fast paths — which are innocent, since only `_lb_main` sends their
sentinels. `T0-10`'s distinction survives deliberately: a worker that exited 0 is
done, not dead, and a healthy-but-slow worker still gets the whole budget.

**Standing blockers for whoever picks this up: none.** This paragraph used to say
five decisions needed a human and were "not for an agent to choose silently". All
six were decided between 2026-10-12 and 2026-10-13 — four by you, two taken as the
code already behaved. There is nothing waiting on a human. See
[§2](#2-decision-log) if a new one arises.

---

## 2. Decision log

Decisions are recorded here permanently. A decided decision is **never** reopened
without a new `DEC-##` row superseding it.

| ID | Question | Status | Decided value | Decided by | Date | Blocks |
|---|---|---|---|---|---|---|
| `DEC-01` | Output-ordering guarantee under streaming | **decided** | Bounded reorder window (`T1-01`/`T1-03`) | user | 2026-10-12 | `T0-11`, `T1-01`, `T1-03` | `T0-11` (done), `T1-01`, `T1-03` 
| `DEC-02` | pcapng: full reader or precise diagnostic? | **decided** | Option 2: precise diagnostic, not a reader (`T05-02`) | claude (ratified from the recommendation) | 2026-10-12 | `T05-02` | `T05-02` (done) 
| `DEC-03` | scapy: implement the cross-check or delete the dep? | **decided** | Implement the scapy cross-check (`T1-07`) | user | 2026-10-12 | `T1-07` | `T1-07` 
| `DEC-04` | Rule-file persistence key migration | **decided** | (a) Persist `AppType.name` + migration (`T1-05`) | user | 2026-10-12 | `T1-05` | `T1-05` (done) 
| `DEC-05` | Bidirectional flow folding: default on or off? | **decided** | Bidirectional flow folding: default ON (`T1-03`) | user | 2026-10-12 | `T1-03` | `T1-03` (done), plus unblocks `D-25` 
| `DEC-06` | IP rules: source only, either endpoint, or a separate destination set? | **decided** | Match **either endpoint** (`T1-05`) | user | 2026-10-13 | `T1-05` | `T1-05` (done) — parity break, differential allowlist entry 8 

### Detail

**`DEC-01` — Output-ordering guarantee under streaming.** **Decided 2026-10-12: bounded reorder window.**

Output is deterministic within a window of size *W*; a packet arriving later than *W* is emitted out of order rather than held. *W* is a tunable with a memory/latency trade-off, which is the IP-defragmentation analogue.

Why this over the alternatives: per-shard arrival order (A) makes output non-deterministic across runs and breaks the differential suite's byte-comparison, which is the strongest property the engine currently has — confirmed by `T0-11` producing byte-identical output in all three variants. Dropping the guarantee entirely (C) throws that away permanently. B keeps it for any sane *W* while allowing true streaming.

`T0-11` is unaffected: its second sequential input pass yields byte-identical ordering outright, so this only bites when the engine is actually streaming (`T1-03`).

**`W` is still to be chosen** — that is a `T1-03` design parameter, not a decision. Suggested starting point: large enough to absorb a slow shard's backlog (thousands of packets), small enough that its memory is bounded by a documented figure rather than by the capture size.

**`DEC-02` — pcapng.** `D-15`. Options: full reader (SHB/IDB/EPB/SPB, multi-interface,
~200 lines) or detect `0x0A0D0D0A` and raise a precise diagnostic naming
`editcap -F pcap` (~10 lines). *Recommendation:* Option 2 now, Option 1 in Phase 1
if the golden corpus needs it — pcapng appears in roughly a third of real captures,
but a wrong reader is worse than an honest refusal.

**`DEC-03` — scapy.** **Decided 2026-10-12: implement the cross-check.**

`R-08`. `DESIGN_DECISIONS.md` justifies scapy as an independent cross-check of hand-rolled TLS parsing; no test did this. scapy is already a declared dev dependency, so the only cost is the tests themselves.

This also resolves an inversion worth naming: `R-05` was originally justified *as* the substitute for the missing fuzzing. `R-05` is now closed (`T1-07` increment 1, 20 property tests, proven to catch `D-05`), so the substitute is built and the thing it stood in for is what remains.

Fall back to deleting the dependency and striking the claim only if scapy proves an unreliable reference in practice.

(The third option offered on `DEC-04`-style grounds — deleting the claim without the tests — was not taken: it removes a documented promise rather than checking whether the promise was true.)

**`DEC-04` — Rule persistence key.** **Decided 2026-10-12: option (a), persist `AppType.name`, accept display names as input-only aliases, one-shot migration on load with a deprecation warning.**

`D-16`. Keys are currently display names (`"Twitter/X"`), so renaming a display string silently invalidates saved rules files. `AppType.name` is stable because it is a symbol, not prose.

Rejected (b), persist the name only and hard-fail old files: correct but breaks every existing saved rules file the first time it loads, with no migration path. Rejected (c), persist both and prefer the stable one: most compatible, but two keys that can disagree are a worse invariant than one key, and hand-editing a file can set them to conflicting values.

Migration writes the new form back on load, so the window in which a deprecation warning is visible is one run per file.

**`DEC-05` — Bidirectional flow folding.** **Decided 2026-10-12: default ON.**

`P-16`. Flows are keyed by the packet's exact five-tuple and not folded to its reverse, so a connection's two directions are two independent flow-table entries. This is a deliberate divergence from the C++ original (`main_working.cpp` never calls `FiveTuple::reverse()`) and `AUDIT.md` §1.3 lists it among the quirks carried for parity that are wrong for a product.

Defaulting it on is the product-correct behaviour and it **unblocks `D-25`**: `Connection.packets_in`/`bytes_in` are permanently 0 precisely because `update_connection` is only ever called with `is_outbound=True`, and with flows unfolded there is no shared state to correlate a SYN with the SYN-ACK that answers it. Folding gives that state an owner.

It is a **parity break** and must be recorded in the differential allowlist, exactly as the VLAN peel (`D-14`) was. A fold-aware engine will attribute both directions to one flow, where the reference reports each direction separately.

---

## 3. Phase rollup

| Phase | Scope | Tasks | Done | In progress | Blocked | Pending | Deferred | Exit status |
|---|---|---|---|---|---|---|---|---|
| **0** | Harden | 11 | **11** | 0 | 0 | 0 | 0 | not met |
| **0.5** | Real captures | 2 | **2** | 0 | 0 | 0 | 0 | not met |
| **1** | Streaming core | 9 | **9** | 0 | 0 | 0 | 0 | **met** (all 5 criteria verified, incl. differential parity) |
| **2** | Eval harness | 4 | **2** | 0 | 0 | 2 | 0 | not started |
| 3 | MCP server | outline | — | — | — | — | — | not started |
| 4 | Read-only agents | outline | — | — | — | — | — | not started |
| 5 | Fingerprinting + ClassifierGap | outline | — | — | — | — | — | not started |
| 6 | Write path | outline | — | — | — | — | — | not started |
| **DOC** | Documentation track | 8 | **7** | 0 | 0 | 0 | 1 (`DOC-07` partial) | not met |

**Totals:** 34 tasks - **31** done - 0 in progress - 0 blocked - 2 pending - 1 partial.
The "6 blocked / six tasks cannot start until a human decides" text that stood here
was correct only on 2026-10-03. All six decisions (`DEC-01`…`DEC-06`) were made
between 2026-10-12 and 2026-10-13 and each unblocked its task; **there are now zero
blocked tasks.** (`DOC-03` also stopped being superseded once it was rewritten.)

**Total specified work:** 30 tasks, ~27 working days (Phases 0 + 0.5 + 1), plus ~2
days of documentation in parallel.

---

## 4. Task board

Status vocabulary is closed (7 values) — see
[§9](#9-status-vocabulary). Only these six values are valid.

| ID | Task | Traces | Status | Gate | Effort |
| `T0-01` | CI, coverage, timeouts, gitignore artifacts | `R-01` `R-02` `R-03` `R-09` | done | - | 0.5 d |
| `T0-02` | `conftest.py` + fixture de-duplication | `R-04` `M-07` | done | - | 0.5 d |
| `T0-03` | Memory reproduction test + benchmark baseline | `R-06` | done | - | 0.5 d |
| `T0-04` | Clamp `length` in TLS entry points | `D-05` | done | - | 15 min |
| `T0-05` | Guard `PcapWriter` open | `D-04` | done | - | 15 min |
| `T0-06` | Direct pcap record-header read | `D-06` `D-07` | done | - | 0.5 d |
| `T0-07` | Bound the HTTP `Host:` scan | `D-09` `D-10` | done | - | 0.5 d |
| `T0-08` | Per-packet QUIC `undecryptable` accounting | `D-08` | done | — | 0.5 d |
| `T0-09` | Make `--live-rules` honest | `D-03` | done | — | 0.5–1 d |
| `T0-10` | Teardown in `finally`; stale docstrings; dead code | `D-12` `S-03` | done | — | 0.5 d |
| `T0-11` | **Bound worker memory** | `D-01` `D-02` `D-22` | done | — | 2–3 d |
| `T05-01` | VLAN / 802.1Q and QinQ | `D-14` | done | — | 0.5 d |
| `T05-02` | pcapng diagnostic or reader | `D-15` | done | — | 10 min / 2 d |
| `T1-01` | Event bus | `A-01` | done | — | 1 d |
| `T1-02` | `CapSource` abstraction | `A-01` | done | - | 2 d |
| `T1-03` | Streaming output + reorder buffer | `A-02` `P-16` | done | — | 3 d |
| `T1-04` | Rule DSL with provenance | - | done | - | 3 d |
| `T1-05` | CIDR + destination-IP rules | `D-20` `D-21` `D-16` | done | - | 1 d |
| `T1-06` | **`simulate_ruleset` counterfactual engine** | `A-05` | done | - | 2 d |
| `T1-07` | Property tests + scapy cross-check | `R-05` `R-08` | done | — | 2 d |
| `T1-08` | Benchmark suite | `R-06` `P-15` | done | - | 1 d |
| `T1-09` | SNI / DNS parser correctness | `D-17` `D-18` | done | - | 1 d |
| `DOC-01` | `README.md` corrections | `M-01` | done | — | 1 h |
| `DOC-02` | `DESIGN_DECISIONS.md` corrections | `M-02` | done | - | 2 h | Now |
| `DOC-03` | Rewrite `WORKFLOW.md` | `M-03` | done | - | 1 d | Now |
| `DOC-04` | `AGENTIC_ARCHITECTURE.md` §1-§3, §8, §10 | `M-04` | done | - | 3 h | Now |
| `DOC-05` | `OSC/` superseded banners + CMake correction | `M-05` `M-06` | done | — | 30 min |
| `DOC-06` | Fix `conftest.py` reference | `M-07` | done | `T0-02` | 10 min |
| `DOC-07` | Documentation index (`docs/README.md`) | - | partial | - | 15 min |
| `DOC-08` | Gitignore / delete session transcripts | `S-01` | done | - | 5 min |
| `T2-01` | **Golden-capture corpus + scorer** | - | done | - | 3 d |
| `T2-02` | Differential suite: 77 pkt → generated corpus | - | done | - | 1 d |
| `T2-03` | Agent-tree safety suite + envelope statement | `A-03` | pending | - | 1 d |
| `T2-04` | Eval run history / non-worse CI gate | - | pending | - | 1 d |

All findings now carry an ID and a proposed owner. **Two still need a task** —
`D-24`, `D-25` and `D-26` were closed by `ses_batch1` and `T1-03` and are gone
from this list.

| Finding | Issue | Proposed owner | Priority |
|---|---|---|---|
| `D-13` | An LB process death orphans all its fast-paths forever: only `_lb_main` sends FP sentinels, so the parent discovers it only via the 120 s timeout | **closed 2026-10-15 (`ses_t1_06b`)** — the parent's collection loop now re-checks liveness every `_LIVENESS_POLL_SECONDS` while stalled, so a dead LB is named in ~1 s instead of after 120 s | done |
| `D-23` | **Multiprocess is 7.26x slower than single-process; staged 8.28x slower.** Promoted from `P-15` once measured | **re-measured 2026-10-15 (`T1-08`)** — published in `docs/BENCHMARKS.md` + `tests/benchmarks/baseline.json`. Was 4.7x/6.2x; `T0-11` made it *worse* | **still open** — needs a crossover point on a realistic capture |

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

- **Status:** done — **Claimed by:** claude-opus-5[1m] — **Session:** ses_t0_01 — **Blocked by:** -
- **Files:** `.github/workflows/ci.yml` (new), `pyproject.toml`, `tests/test_worker_stress.py`, `.gitignore`, `uv.lock`
- **Test added:** no new tests — this task adds gates, not behaviour. `pytest-timeout` and `pytest-cov` were each proven against a deliberately hanging test and a deliberately over-budget module rather than assumed to work.
- **How it was tackled:** Four CI jobs, split so that a failure names its own cause: `lint` (ruff + mypy, with `ruff format` reported as a non-blocking warning since 22 files predate it), `test` (suite with coverage and per-test timeout, then a separate coverage-gate step so the message says "coverage dropped" rather than surfacing as an opaque pytest exit), `differential`, and `build` (wheel + a `py.typed` presence assertion, because the package depends on PEP 561 and a wheel without the marker silently strips types for every downstream consumer). Every job command was then executed locally: YAML parses, ruff/mypy/pytest pass, the coverage gate exits 0 at 91%, `uv build` produces a wheel containing `dpi_engine/py.typed`. Timeout sized from data, not a guess: the slowest test is 1.6s, so 30s is ~19x headroom, and `test_worker_stress.py` is marked `slow` with a 120s ceiling since it deliberately slows workers down. `timeout_method` is deliberately left at pytest-timeout's default so Linux CI uses SIGALRM and fails one test rather than killing the process.
- **Deviations:** three. **(a)** Ran this before `T0-02`, against tracker order — rationale above. **(b)** Enabled `branch = true`, which lowered the honest figure from 93% line-only to 91%; the 85% floor was kept rather than raised to the measured value, to leave headroom for genuinely unreachable defensive branches. **(c)** My first draft of the "fail if the parity check did not run" step was convoluted shell that did not do what its comment claimed; replaced with a straightforward assertion on the pytest log that tests actually passed and nothing skipped. pytest exits 0 when every test skips, so without this the parity job would go green on a machine where Docker is missing — which is exactly the state this host is in.
- **Verification:** all four jobs' commands executed locally and pass. YAML validated as parseable with 4 jobs and the expected triggers. **Timeout proven to fire**: a deliberately infinite-loop test under `timeout=2` was killed and pytest exited 1. **`slow` marker proven to override**: a 3s sleep under a 1s global timeout with `@pytest.mark.timeout(6)` passed. Coverage gate exits 0 at 91%. `uv build` succeeds and the wheel contains `dpi_engine/py.typed`. No unknown-marker warnings. Full suite **420 passed, 12 skipped**, ruff clean, mypy clean.
- **Closed findings:** `R-01`, `R-02`, `R-03`, and `R-09` (tracked build artifact gitignored)
- **Follow-ups:** **(1) The `differential` job has never executed.** This host has no Docker daemon, so the workflow itself is unrun; its commands were verified individually but the file has not run on a real runner. Push and confirm. **(2)** `ruff format` is deliberately non-blocking. Run `ruff format`, commit, then flip that step to enforcing — currently 22 files. **(3)** No `.gitattributes`, so git warns `LF will be replaced by CRLF` on every touched file; worth adding `* text=auto` before diffs get noisy. **(4)** Coverage now includes the differential suite's own imports; if that skews the number, scope it.
- **Notes:** The `differential` job's guard exists because of a concrete observation from `T0-06`: on this machine `tests/differential` skips 12 of 14 tests and the suite still reports success. A green CI run must not be able to mean "the parity proof never executed".
### `T0-02` — `conftest.py` + fixture de-duplication

- **Status:** done — **Claimed by:** claude-opus-5[1m] — **Session:** ses_t0_02 — **Blocked by:** -
- **Files:** `tests/conftest.py` (new), `tests/differential/conftest.py` (new), 12 test modules rewritten, `tests/test_environment.py`, `tests/differential/README.md`
- **Test added:** three structural guards in `test_environment.py`, each proven to bite by deliberately re-introducing the violation and watching it fail: `test_no_test_module_redeclares_fixture_paths` (AST-scans every test module for a `FIXTURES`/`DIFF_FIXTURES`/`SHARED_FIXTURES`/`TEST_DPI_PCAP` assignment), `test_cpp_available_fixture_is_defined_exactly_once`, and `test_fixture_paths_point_at_real_directories` (asserts the two directories exist and are *distinct*).
- **How it was tackled:** Surveyed before editing, and the survey changed the design. The brief said "the `FIXTURES` path is duplicated verbatim across 8 test files" — actually **nine** modules used three different expressions for **two** directories, and the name was ambiguous: `FIXTURES` resolved to `tests/fixtures` in `test_differential.py` but to `tests/differential/fixtures` in `test_differential_edge_cases.py`. Same name, different target, one `parents[1]` hop apart. That is not repetition, it is a trap, so the fix was a rename with unambiguous names (`SHARED_FIXTURES` vs `DIFFERENTIAL_FIXTURES`) rather than merely hoisting the old name. Two conftests rather than one: `tests/conftest.py` holds the repo-wide paths, while `cpp_available` went to `tests/differential/conftest.py` because only that package needs it, it is the correct home for a fixture, and the relative import to `cpp_reference` works there. The two old `cpp_available` copies had drifted — both `scope="module"` but each probed Docker with a *different* capture (shared `test_dpi.pcap` vs local `control_normal_capture.pcap`); the unified version is `scope="session"` and probes once. Afterwards ruff auto-fixed 35 findings, almost all imports the removal had orphaned.
- **Deviations:** two. **(a)** Added the three structural guards, which the brief did not ask for. Without them this refactor is a one-time cleanup that the next contributor quietly reverses, and the repo already has precedent for exactly that rot (`WORKFLOW.md` citing a deleted module). **(b)** Replaced `FIXTURES`/`DIFF_FIXTURES`/`SHARED_FIXTURES` with explicit names rather than preserving the old aliases wholesale, because the ambiguity *was* the names. `FIXTURES` is retained as a local alias in the modules that used it so no test body had to change.
- **Verification:** **423 passed, 12 skipped** — up from 420, +3 guards, **zero regressions**. `ruff` clean, `mypy` clean on 13 files. Zero remaining `FIXTURES = Path(__file__)` declarations and zero `def cpp_available` in test modules; 12 modules import from the single source. Cross-variant byte-identity tests re-run specifically, since a fixture-path mix-up would break them: 11 passed. Coverage unchanged at 91%. All three guards were proven to fail on a deliberately re-introduced violation and pass again after restore.
- **Closed findings:** `R-04`, `M-07`
- **Follow-ups:** `R-08` (the `scapy` promise) is still open and still the largest documentation-vs-implementation gap — `test_scapy_imports` in `test_environment.py` still only asserts scapy *imports*, with a comment claiming it is "used to cross-check hand-rolled TLS parsing in the differential test suite", which nothing does. `DEC-03` decides it.
- **Notes:** Two of my own mistakes during this task, both caught by writing the guard before trusting it. The `cpp_available` guard was initially broken because my module helper globbed `test_*.py` and therefore never saw `conftest.py` — it reported zero definitions and failed. And my first version of that assertion embedded a hardcoded line number inside a convoluted expression, which would have broken the moment anyone edited the conftest. Both fixed before the task was called done.
### `T0-03` — Memory reproduction test + benchmark baseline

- **Status:** done — **Claimed by:** claude-opus-5[1m] — **Session:** ses_t0_03 — **Blocked by:** -
- **Files:** `tests/test_resource_bounds.py`, `tests/benchmarks/test_micro_benchmarks.py` (new), `tests/benchmarks/test_end_to_end.py` (new), `pyproject.toml`, `uv.lock`, `.gitignore`
- **Test added:** two `xfail(strict=True)` reproductions and eight benchmarks. `test_worker_results_do_not_carry_packet_payloads` measures the pickled size of everything the workers send back and compares it to the capture size. `test_processor_state_stays_bounded_by_max_connections` drives `FlowProcessor` directly over 1000 distinct flows against a 50-connection bound. Both were confirmed to fail with precise assertion messages (`worker results total 99894 bytes for a 28024-byte capture`; `blocked_tuples holds 1000 entries for 1000 flows against a 50-connection bound`), not errors.
- **How it was tackled:** Chose the *observable* rather than RSS, so the test is deterministic on any machine: `_collect` is the single point where the parent receives results, so hooking it captures them without touching pipeline behaviour. First attempt asserted on `WorkerResult.connections` and **XPASSed immediately** — those are bounded by the tracker, so they proved nothing. `D-22`'s unbounded containers (`_quic_inspectors`, `blocked_tuples`) live on `FlowProcessor`, which is discarded when a worker exits and never crosses the boundary, so the test was rewritten to drive the processor directly. Benchmarks are opt-in via `--benchmark-disable` in `addopts`, which `--benchmark-enable` forcibly overrides.
- **Deviations:** two. **(a)** Used `xfail(strict=True)` rather than a plain failing test as the brief specified, because a red suite breaks CI; `strict=True` means the fix cannot land silently. **(b)** Measured `P-15`, which the brief only asked to set up. The result is stronger than "unmeasured" and is recorded below.
- **Verification:** **431 passed, 12 skipped, 2 xfailed** — up from 423. `ruff` clean after auto-fix, `mypy` clean. Both xfails confirmed to fail for the right reason via `--runxfail`. Benchmarks confirmed runnable via `--benchmark-enable`. `D-01` magnitude measured directly: worker results are **3.5x the capture size** at 100, 400 and 1600 packets, scaling linearly — at the documented defaults that is the audit's hundreds-of-GB figure.
- **Closed findings:** `R-06`. `P-15` is now **measured** rather than assumed.
- **Follow-ups:** **(1)** `P-15` in `AUDIT.md` should be updated with the measured figures and should be **promoted to `D-##`** — it is no longer an open question, it is a quantified regression (below). **(2)** Re-run the benchmarks after `T0-11`; that is the comparison the suite exists for. **(3)** `--benchmark-disable` makes benchmarks report as *passed* rather than skipped, so `pytest tests/benchmarks` looking green does not mean they ran. Documented in both files, but a stricter marker would be better.
- **Notes:** **`P-15` measured, 4000 packets, Windows, Python 3.13:** single process 113 ms (35 Kpps) — multiprocess x4 527 ms (8 Kpps) — staged 2+4 694 ms (6 Kpps). **The multiprocess path is 4.7x slower than single-process and the staged path 6.2x slower.** The scaling paths are actively counterproductive at this packet count, which vindicates the `--workers 1` default and the design note that the LB tier is queue-decoupling rather than throughput. Micro: `sni_to_app_type` 0.6 us, `extract_sni` 1.4 us, `extract_dns_query` 1.6 us, `extract_http_host` 6.5 us, `parse_packet` 11.3 us — `parse_packet` dominates, and `extract_http_host` being 5x the other extractors is `AUDIT.md`'s O(payload) claim measured rather than asserted (`T0-07` addresses it). Caveats: 4000 tiny 54-byte frames means spawn cost and per-record pickling are both over-weighted, so the direction is trustworthy but the magnitude would shrink on real traffic.
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

- **Status:** done — **Claimed by:** claude-opus-5[1m] — **Session:** ses_t0_05 — **Blocked by:** -
- **Files:** `src/dpi_engine/pcap_io.py`, `tests/test_pcap_io.py`, `tests/test_cli_run.py`
- **Test added:** eight tests. Six are regression tests (fail without the fix): a four-mode failure matrix (missing parent dir, deep missing path, parent-is-a-regular-file, target-is-a-directory) each raising `PcapError` with the path in the message; a Reader/Writer **symmetry** test asserting both classes raise the identical type on each mode; `__cause__` chaining preserved as the original `OSError` with a non-null errno; no file and no parent directory left behind; message content checks that it says what failed and where. Two CLI-level tests: `main()` returns 1 with `error:` on stderr and **no traceback**, and nothing is created on disk. Two guards: the happy path still opens and truncates correctly.
- **How it was tackled:** Reproduced before touching source, by enumerating failure modes rather than testing the one from the audit. That found **four** distinct unwritable paths, leaking **two** different exception types (`FileNotFoundError` x3, `PermissionError` x1), and surfaced the real shape of the bug: it is a pure **asymmetry**. `PcapReader._open` already wraps `open()` in `try/except OSError` and handled all four correctly. `PcapWriter.__init__` did not, so the identical failure produced two different contracts depending on which class you used. Confirmed the user-visible symptom too: `main([...])` raised `FileNotFoundError` out of the function entirely — no exit code, no message, raw traceback. Fix wraps the `open()` in `try/except OSError` raising `PcapError(... Cannot open output pcap file ... ) from exc`, mirroring `PcapReader._open` line for line, with a comment explaining why so the next reader does not remove it as redundant. After the fix all eight matrix cells return `PcapError` and the CLI exits 1.
- **Deviations:** The brief said 15 minutes and one test. Two expansions, both deliberate. **(a)** Replaced the single bad-path test with a four-mode matrix plus symmetry, cause-chaining, filesystem-state and message-quality tests — one test would have passed against a partial fix that only handled `ENOENT`. **(b)** Added two CLI-level tests, because the unit fix alone does not prove the user sees `error: ...` rather than a traceback, and the audit's stated impact was explicitly the CLI behaviour. Also had to import `contextlib` and convert a `try/except/pass` to `contextlib.suppress` for `SIM105`; ruff flagged an unused `noqa` in my own new test which was removed by `--fix`.
- **Verification:** new tests: **6 failed before the fix**, **8 passed after** (the two guards pass either way, by design). Full suite **405 passed, 12 skipped** — up from 397, i.e. +8 new tests and **zero regressions**. `ruff check .` clean. `mypy` clean on 13 files. Failure matrix re-run manually: 8/8 cells now `PcapError`. CLI re-run manually: exit code 1.
- **Closed findings:** `D-04`
- **Follow-ups:** none. Worth noting for `T1-07`: the `_unopenable_paths` helper is a fixture-shaped thing that would benefit from `hypothesis` filesystem strategies, but four hand-picked modes already cover the `OSError` subclasses reachable on Windows and POSIX.
- **Notes:** One extra failure mode found during reproduction was *not* a defect: `PcapWriter("NUL")` succeeds on Windows because `NUL` is a reserved device. That is correct OS behaviour, not a bug, and is excluded from the matrix.
### `T0-06` — Direct pcap record-header read

- **Status:** done — **Claimed by:** claude-opus-5[1m] — **Session:** ses_t0_06 — **Blocked by:** -
- **Files:** `src/dpi_engine/pcap_io.py` (the fix), `src/dpi_engine/worker.py` + `pipeline.py` (byte-counter semantics), `tests/test_pcap_io.py` (14 tests)
- **Test added:** fourteen. Six are D-06/D-07 regression tests: true `orig_len` on a truncated record (60 on the wire, 20 captured); `orig_len` unchanged for untruncated packets; `incl_len` validated *before* any payload read, asserted on a 40-byte file declaring `incl_len=0xFFFFFFF0`; three parametrisations across the bound; the bound is inclusive and matches the original's `incl_len > 65535`; the error names the declared length, not the bytes present. Four are guards: LE **and** BE captures agree; timestamps reproduce dpkt's arithmetic exactly including an out-of-range fraction carrying into seconds; `incl_len` exactly at the bound is accepted; zero-length records are legal. Three pin deliberate decisions: a truncated payload ends iteration cleanly (no phantom packet); a capture cut mid-header does the same; byte counters report captured bytes, not on-wire. One documents a limitation: `PcapWriter` cannot express `incl_len < orig_len` because dpkt packs `n, n`.
- **How it was tackled:** Root cause for both defects was a single design choice. `dpkt.pcap.Reader.__iter__` does `buf = self.__f.read(hdr.caplen)` internally and yields only `(ts, buf)` — discarding `hdr.len`. So delegating record iteration to dpkt both allocated before the size bound could be checked (D-07) and forced `orig_len = len(buf)` (D-06). dpkt still validates the global header, so format checking is untouched; only the per-record loop was replaced with a direct `struct` unpack of the 16-byte header. **Key discovery: neither defect was inherited.** `pcap_reader.cpp:88-93` checks `incl_len > snaplen || incl_len > 65535` *before* `resize()` on line 96, and `main_working.cpp:269-270` shows the original also writes `incl_len = orig_len = data.size()`. Both were regressions introduced by the move to dpkt, which changes how they should be described in `AUDIT.md`. Byte order and timestamp precision are derived from the four spec-defined magic byte sequences rather than by reusing dpkt's own host-endianness-dependent check.
- **Deviations:** three, all material. **(a)** Caught a parity regression I was about to introduce: making `orig_len` truthful meant the byte counters — which read `raw.orig_len` — silently switched from captured length to on-wire length. The C++ original uses `raw.data.size()` (`main_working.cpp:184`) and the CLI label is "Total bytes **read**", so both `worker.py` and `pipeline.py` were reverted to `len(raw.data)` and a test pins it, because it is exactly the kind of change that looks like a fix. **(b)** Two of my own first-draft decisions were wrong and were corrected against the original: a truncated payload and a truncated record header initially raised `PcapFormatError`, when OSC stops cleanly in both cases; and endianness detection initially compared magic bytes against dpkt's *integer* constants, which only worked by coincidence on a little-endian host. **(c)** Scope grew from 2 defects to include the byte-counter audit above, which was not in the brief but was a direct consequence of it.
- **Verification:** new tests: **8 of 14 fail against the previous implementation** (confirmed by `git stash`ing the source and re-running), 14 pass after. Full suite **420 passed, 12 skipped** — up from 405, +15 net, **zero regressions**. `ruff` clean, `mypy` clean on 13 files. **Behavioural equivalence proven by differential snapshot**: full JSON report and output-pcap SHA256 captured across `run_pipeline`, `run_pipeline_multiprocess` and `run_pipeline_staged`, before vs after — **byte-identical in all three**.
- **Closed findings:** `D-06`, `D-07`
- **Follow-ups:** **(1) C++ parity is UNVERIFIED for this change.** `tests/differential` skips 12 of 14 tests because the Docker daemon is absent on this host, so the C++ reference binary cannot be built or run. The before/after Python snapshot is strong evidence but is not the same proof. Re-run `uv run pytest tests/differential` once Docker is available. **(2)** `AUDIT.md` `D-06` should be reframed: its claim that byte counters "under-report" is wrong. Reporting captured bytes is correct and matches C++; the actual defect was that `orig_len`'s docstring described behaviour the code did not implement, with a test locking it in. **(3)** `pcap_io.py's module docstring still says the max_packet_size bound exists so an adversarial caplen "cannot trigger an unbounded read or allocation" — that statement was previously aspirational and is now true; worth re-reading to confirm it matches.
- **Notes:** Two of my own mistakes were caught only because the tests were written before the fix was trusted — the endianness test failed against my own new code, and the BE fixture was malformed because I had confused a magic *value* with magic *bytes*. Neither would have been caught by the existing suite. Cost of this task: roughly 3x the 0.5 day estimate, almost entirely on verification.
### `T0-07` — Bound the HTTP `Host:` scan

- **Status:** done - **Claimed by:** claude-opus-5[1m] - **Session:** ses_t0_07 - **Blocked by:** -
- **Files:** `src/dpi_engine/sni_extractor.py`, `tests/test_sni_extractor.py`, `tests/benchmarks/test_micro_benchmarks.py`
- **Test added:** ten. Six are regression tests (fail without the fix): a `Host:` inside a URL in the request line; a `Host:` only in a POST body; `X-Host:` not matching; a `Host:` mid-header-value not matching; an IPv6 literal with a port not mangled; `CONNECT`/`TRACE` recognised as methods. Four are guards: a body `Host:` cannot override the real header, ordinary `:8080` port stripping still works, the first `Host:` wins over a duplicate, and a bare `[::1]` keeps its brackets.
- **How it was tackled:** Replaced the byte-by-byte scan with a line-oriented one. `_header_block()` truncates the payload at the first CRLFCRLF (or LFLF), then the extractor walks newline-delimited lines and only accepts a line whose pre-colon name equals `host`. Three consequences fall out of that structure rather than needing separate guards: a match must begin a line, so `X-Host:` and `Ghost:` cannot match; a body string can never be reached; and the first `Host:` wins, which is what RFC 9110 says to act on. `D-10` went into a `_strip_port()` helper - a bracketed IPv6 literal only loses a colon appearing *after* the closing bracket. `CONNECT` and `TRACE` added to the method prefixes.
- **Deviations:** two. (a) Also fixed a duplicate-`Host` smuggling vector the brief did not name, because line-walking made it a one-line consequence and leaving it untested would have been an oversight. (b) My first `_strip_port` had an inverted ternary that dropped the closing bracket when a port *was* present - `[2001:db8::1]:8080` became `[2001:db8::1`. Caught by the new test on the first run.
- **Verification:** **441 passed, 12 skipped, 2 xfailed** (up from 431). `ruff` and `mypy --strict` clean. New tests: **6 failed before the fix**, all 10 pass after. Behavioural equivalence on the real fixture proven by differential snapshot - output-pcap SHA256 and full JSON report identical before vs after. **Performance improved ~4x**: `extract_http_host` went from 6.5 us to 1.4 us, so it is no longer 5x the other extractors; this closes `AUDIT.md`'s measured O(payload) claim as a side effect of the correctness fix. `parse_packet` (11.3 us) is now unambiguously the hot spot. Coverage moved 91% -> 89% with the new code, still above the 85 floor.
- **Closed findings:** `D-09`, `D-10`
- **Follow-ups:** **the differential divergence allowlist needs re-checking.** `main_working.cpp` has this same unbounded scan, so any fixture where a `Host:` appears in a body or URL previously diverged - and is now correctly ignored here. The differential suite **could not be run** (no Docker daemon on this host), so the allowlist was updated blind. Re-run `uv run pytest tests/differential` once Docker is available and pin each divergence. That is the second task in a row whose parity is unverified.
- **Notes:** The security framing is what makes this more than a tidy-up. The extracted host feeds **both** `sni_to_app_type` and `RuleManager`'s domain match, so before this fix an attacker who could influence any part of an HTTP payload after the request line could choose which app a flow was attributed to *and* which blocking rule it matched. `GET /?u=http://Host:x HTTP/1.1` was classified as host `x HTTP/1.1`.
### `T0-08` — Per-packet QUIC `undecryptable` accounting

- **Status:** done — **Claimed by:** claude-opus-5[1m] — **Session:** ses_t0_08 — **Blocked by:** -
- **Files:** `src/dpi_engine/quic.py`, `src/dpi_engine/worker.py`, `tests/test_quic.py`
- **Test added:** four, all failing without the fix. Three unit-level on `QuicFlowInspector` (a clean packet after an earlier failure is *not* counted; two failures *are* both counted, so the new flag does not under-count; a clean first packet is not counted) and one end-to-end through the real decision path asserting the pipeline reports exactly `quic_undecryptable == 1` while still extracting the SNI from the following good packet. Built from this file's own Initial builders, so deterministic {EM} not a captured trace.
- **How it was tackled:** `undecryptable_packets` is a *cumulative* counter — incremented once per genuinely failing packet, never reset — and the call site tested it as `if inspector.undecryptable_packets:`, which is true whenever the flow has **ever** failed. One bad packet therefore poisoned the figure permanently: every later Initial on that flow was reported undecryptable even when it decrypted cleanly. `feed()` itself was correct throughout, so the fix is confined to how the caller asks. Added `feed_counted()`, which snapshots the counter, delegates to `feed()`, and returns the per-packet delta as an explicit boolean.
- **Deviations:** the plan called for changing `feed()` to return a per-packet outcome object. Measured first: `feed()` has **16 call sites in tests**, so changing its return type would churn all of them for no behavioural gain. Added `feed_counted()` alongside instead — `feed()` keeps its `str | None` signature, so `extract_quic_sni` and every existing test are untouched. Two errors of mine, both caught by running the tests rather than assuming: my claim script aborted on a missing anchor *before* writing, so the claim silently never persisted (re-asserted here rather than trusted); and the end-to-end test first asserted `processor.stats.quic_packets`, but `quic_packets` is a `FlowProcessor` field, not a `FastPathStats` one.
- **Verification:** **445 passed, 12 skipped, 2 xfailed** (up from 441). `ruff check .` and `mypy` (strict, 13 files) clean. Coverage 89%, above the 85 floor.
- **Closed findings:** `D-08` · **Follow-ups:** none specific.
- **Notes:** this was a *reporting* defect, not a parsing one — the SNI was always extracted correctly and `quic_extractions` was always right. Only `quic_undecryptable` lied, and it lied in the direction that made QUIC support look worse than it is: on a long-lived flow with a single early failure it would report ~100% undecryptable. Worth keeping `feed_counted` as the spelling callers reach for, since the cumulative trap is not obvious from the field name alone.

### `T0-09` — Make `--live-rules` honest
- **Status:** done — **Claimed by:** claude-opus-5[1m] — **Session:** ses_t0_09 — **Blocked by:** -
- **Files:** `src/dpi_engine/pipeline.py`, `src/dpi_engine/cli.py`, `tests/test_staged_pipeline.py`, `tests/test_cli_run.py`
- **Test added:** six, all failing before the fix. Four in `test_staged_pipeline.py` (staged `live_rules=True` still matches single-process; the parameter exists and defaults to off; exactly one control queue per fast path for 3x2 = 6; and `live_rules=True` changes no decision when the rules never change) plus two in `test_cli_run.py` (the flag actually reaches `run_pipeline_staged`, asserted by spying on the call, and `run --help` states the single-process limitation).
- **How it was tackled:** chose the plan's option (a) — thread it through — over option (b) reject the combination, because `RuleBroadcaster.register()` is already generic and the flag works in the single-tier variant, so rejecting it under `--load-balancers` would have removed a working feature for no reason. `run_pipeline_staged` gained a `live_rules` parameter, creates one control queue per **fast path** (not per load balancer — the LB tier never reads a `RuleSnapshot`), registers them all with one broadcaster the parent polls during dispatch, and passes each FP its queue via the existing `control_queue` kwarg. Control queues added to both the `_terminate` and `_close_quietly` lists so the failure path does not leak them. `cli._execute` now passes `live_rules` to staged as well as multiprocess, and the flag's help text is qualified.
- **Deviations:** two of my own mistakes, both caught by running the suite. First, I put `live_rules` into the shared `common` kwargs dict, which broke 8 unrelated CLI tests: `run_pipeline` has no such parameter *by design* (a one-shot single-process run owns its RuleManager, nothing can mutate it mid-run, so the channel would be pure cost), so the value has to be passed explicitly to the two multiprocess variants only. Reverted to explicit per-variant passing, which is also the smaller diff. Second, my earlier edit of the `run_pipeline_staged` signature and docstring used the wrong indentation width and left the file unparseable; caught by compiling before running the suite. Also worth recording: two false alarms where I reported tracker/AUDIT corruption that did not exist — one from a scanner that did not track code fences, one from a cp1252 console rendering em-dashes as `?`.
- **Verification:** **451 passed, 12 skipped, 2 xfailed** (up from 445). `ruff check .` and `mypy` (strict, 13 files) clean. Coverage 91.36%, above the 85 floor. The `test_multiprocess_with_live_rules_still_matches_single_process` twin still passes, so the single-tier path is unregressed.
- **Closed findings:** `D-03` · **Follow-ups:** none specific.
- **Notes:** worth being precise about the severity here, because it is lower than the register's `High`/`High` suggests. Nothing was *wrong* — no packet was misclassified, no counter wrong. The defect was that a documented capability was absent while every observable output looked correct, which is the worst kind: it cannot be detected by running the tool. The register's rating is defensible on the basis that a user relying on `--live-rules` under `--load-balancers` would silently get stale rules, but the fix is small and the honest reading is `Medium`/`Medium`.
### `T0-10` — Teardown in `finally`, stale docstrings, dead code
- **Status:** done — **Claimed by:** claude-opus-5[1m] — **Session:** ses_t0_10 — **Blocked by:** -
- **Files:** `src/dpi_engine/pipeline.py`, `worker.py`, `quic.py`, `load_balancer.py`, `tests/test_safety_constraints.py`
- **Test added:** three. Two `D-12` tests (parametrised over both multiprocess variants) inject a `_collect` failure and assert every queue is closed and every child reaped; one AST check asserting no shipped docstring cites a module-qualified symbol that does not exist.
- **How it was tackled:** `D-12` first: the `_collect` -> `join` -> `_close_quietly` sequence in both variants is now inside `try/finally` calling `_terminate`, so teardown is unconditional. `_terminate` is safe on the happy path — a joined process is not `is_alive()`, so `terminate()` is skipped and the queue closes are the same ones the removed explicit loop performed — so it is now the single teardown path and the two variants cannot drift apart again. Then the four documentation defects. Then the AST check.
- **Deviations:** three substantive ones, all in the plan's favour of correcting it. (1) Plan item 4 is **already satisfied**: it says `types.py:257` cites `DESIGN_DECISIONS.md` item 14, but it already cited item 7, which is exactly the `classifyConnection` terminal-classification bug it describes. There is no item 14, and no item 11 either — that list has only 10 entries. Nothing to change. (2) The plan claims the AST check "would have caught all four" phantom references. Verified against `git show HEAD`: it catches **two** of three — `pipeline.QuicFlowTable` and `pipeline.RuleBroadcaster.SnapshotHolder`, both module-qualified. It cannot catch `with_fast_path_stats=True`, which has no dot to resolve, nor load_balancer's prose claim. I prototyped a second check for bare `name=` references: against the fixed tree it returned 5 false positives for 1 true positive (`i=` and `d=` are C++ loop variables being documented, `confirmed=` and `is_outbound=` are other functions' parameters). Rejected as not worth the false alarms, and the rejected variant's reasoning is recorded in the test's docstring so nobody re-derives it. (3) `D-13` is **not** closed — see Notes.
- **Verification:** **454 passed, 12 skipped, 2 xfailed** (up from 451). `ruff check .` and `mypy` (strict, 13 files) clean. Coverage 91.39%. The `D-12` tests were confirmed to be real regression tests by stashing only `pipeline.py` and re-running: `3 of 3 queues were left open after the failure`.
- **Closed findings:** `D-12` — **Follow-ups:** `D-13` and the dead-code sweep half of `S-03` (tracked as `D-24`) both need a home; see Notes.
- **Notes:** **`D-13` is still open and now has no task.** *(Closed 2026-10-15 — see the `ses_t1_06b` row in §8.)* It is the LB-death orphan: only `_lb_main` sends FP shutdown sentinels, so if an LB dies its fast paths block on `input_queue.get()` until the parent hits the 120 s `_RESULT_TIMEOUT_SECONDS`. Rated `Medium`/`High`. The task title mentions dead code and the pre-seeded record said "`D-13` (proposed)", but the plan's Change list has five items and none of them is LB supervision, so implementing it would have been an undeclared scope increase on a 0.5 d task. Deliberately not claimed closed. It should be its own task, and it is the natural companion to `T0-11` since both concern bounding what happens when a stage dies mid-run. Also note `D-12`'s fix does **not** help here: it guarantees teardown once `_collect` gives up, which is strictly after the 120 s wait the orphan causes.
### `T0-11` — Bound worker memory
- **Status:** done — **Blocked by:** — **Claimed by:** claude-opus-5[1m] — **Session:** ses_t0_11
- **Files:** `src/dpi_engine/worker.py`, `src/dpi_engine/pipeline.py`, `tests/test_resource_bounds.py`, `tests/test_staged_pipeline.py`
- **Test added:** six. Three for `D-01`/`D-22` (the two `T0-03` strict-xfail reproductions, both flipped to passing) plus a fourth that pins the invariant pruning depends on. Three for `D-02`: queues are bounded, the liveness guard raises on a dead consumer, and it waits for a live-but-slow one. Suite now reports **0 xfailed**; `tests/test_resource_bounds.py` is 11 passed.
- **How it was tackled:** `D-01` first. `FlowProcessor.process` now returns a plain `bool` and `WorkerResult` carries `forwarded_bits`, a packed bitmap indexed by `WorkItem.sequence_index` (`set_forwarded` / `is_forwarded`). `ProcessedPacket` is deleted — nothing needed the payload, because the parent still has the input file and every byte it needs is still in there. `_write_forwarded` makes a second sequential pass over the input and writes packet *N* where bit *N* is set. Drop counts come from arithmetic (`total_packets - other_packets - forwarded`) rather than a second bitmap, because `stats` from the dispatch pass already distinguishes decided packets from skipped ones. Then `D-02`: `_QUEUE_MAXSIZE = 1024` on every packet queue via `_bounded_queue_factory`, with dispatch puts going through `_put_bounded`, which bounds each wait and re-checks consumer liveness on expiry.
- **Deviations:** (1) The `D-01` reproduction was **rewritten, not just un-xfailed**. Its assertion was `results < capture // 4`, which conflates two independent structures: `WorkerResult.connections` (used only for `GlobalStats`, already bounded by `max_connections`) dominates as soon as flows outnumber packets, so the ratio measured the wrong thing. Replaced with an invariance assertion — same flow count twice, once with 1000 bytes of payload per packet, asserting the results come back the same size. That tests what `D-01` actually claimed, and is a stronger test than the proxy. (2) The plan said to consider a `bitarray` dependency; used a `bytearray` of packed bits instead, keeping the dependency count at zero as the plan itself allowed. (3) `DEC-01` was **not** required, as recorded in the previous increment.
- **Verification:** **460 passed, 12 skipped, 0 xfailed**. `ruff check .` and `mypy` (strict, 13 files) clean. Coverage 91.07%. **Output verified byte-identical to `HEAD` for all three variants**, twice: unblocked (`888122314b1ea678`) and with `HTTPS`+`UNKNOWN` blocked so the drop path is actually exercised (`65a0feb9646491ac`, 71 dropped / 6 forwarded, `forwarded + dropped == total_packets == 77`). Measured in a `git worktree` at `HEAD` rather than by stashing, so the working tree was never at risk. Result size on 5000 flows x 1000-byte payloads, 4 workers: **6,254,920 -> 551,687 bytes (11.3x smaller)**; per-packet cost 1251 -> 110 bytes, i.e. no longer scaling with packet size.
- **Closed findings:** `D-01`, `D-02`, `D-22` · **Follow-ups:** `D-13` still has no task; `DEC-01` must be recorded before Phase 1.
- **Notes:** **Phase 0 is complete (11/11).** Throughput cost of the bounded queues, measured (20k packets x 200-byte payloads, best of 3, versus `HEAD`): single-process 33.6 -> 32.1 Kpps (~5%, but that path uses no queues at all, so this is noise); multiprocess 11.8 -> 10.2 Kpps (**~16%, the real cost of backpressure**); staged 8.8 -> 8.8 Kpps (unchanged). 16% on the multiprocess path is a fair price for a bound that holds, and `_QUEUE_MAXSIZE` is the knob if a future measurement shows queueing is the bottleneck. Note this does **not** make the engine streaming — it makes the batch engine memory-safe, which the plan calls the prerequisite for streaming. Streaming is `T1-03`. `D-13` (an LB death orphans its fast paths until the parent's 120 s timeout) remains open, and neither `D-12`'s nor `D-02`'s fix helps it.
### `T05-01` — VLAN / 802.1Q and QinQ
- **Status:** done — **Claimed by:** claude-opus-5[1m] — **Session:** ses_t05_01 — **Blocked by:** -
- **Files:** `src/dpi_engine/packet_parser.py`, `tests/test_packet_parser.py`
- **Test added:** eleven. Untagged reports no VLAN; a single tag is peeled and `vlan_id`/`vlan_priority` preserved with the *inner* EtherType reported; all three tag EtherTypes (`0x8100`/`0x88a8`/`0x9100`) peeled (parametrised); double tagging keeps the innermost VID; triple tagging still parses; pathological nesting terminates and degrades to non-IP; a truncated tag degrades safely; tagging does not change the five-tuple; and tagging does not change the extracted SNI. Nine of them fail without the fix.
- **How it was tackled:** `_peel_vlan_tags()` walks the tag chain by hand and rebuilds the frame with the tags spliced out, handing the result to the *existing* dpkt path unchanged. Peeling the raw bytes first — rather than reconstructing a dpkt VLAN object — means the rest of `parse_packet`, including its payload slices, is untouched by tagging. `vlan_id` (`int | None`, so untagged is distinguishable from tagged VID 0) and `vlan_priority` are added to `ParsedPacket` as metadata for Phase 5 fingerprinting. The flow key stays L3, so tagging cannot partition a flow.
- **Deviations:** two of my own errors, both caught by running the tests rather than reasoning about them. (1) I misread `_tag()` as producing outer-first nesting; it wraps *outside*, so the first tag applied is the innermost one, and two of my own assertions were backwards about which VID should win. (2) My ClientHello builder omitted the outer extensions-block length prefix, so `extract_sni` correctly returned None and the test failed for an unrelated reason. Also worth recording: my first end-to-end verification script reported FAIL, and the fault was in the *verifier* — it scanned for tag types from offset 14 instead of 12 — not in the parser. The classification figures matched on the first run; only my own five-tuple extraction was wrong.
- **Verification:** **471 passed, 12 skipped, 0 xfailed**. `ruff check .` and `mypy` (strict, 13 files) clean. **Phase 0.5 exit criterion #1 met**: the sample capture was re-tagged with VID 100 (77 frames, 6994 -> 7302 bytes) and run through all three pipeline variants alongside its untagged twin. Every decision is identical — app counts, detected domains, blocked flows, total/forwarded/dropped, and the per-packet L3 five-tuples of the output pcap. `RESULT: PASS - tagging changes no decision`.
- **Closed findings:** `D-14` · **Follow-ups:** exit criterion #2 (pcapng diagnostic) is `T05-02`, still blocked on `DEC-02`.
- **Notes:** `D-14` was rated product-impact **Blocker**, and it is now gone: before this, 100% of VLAN-tagged traffic was silently discarded as non-IP, and VLAN-tagged captures are the norm in enterprise networks — the tool failed on exactly the traffic it was most likely to be pointed at. The fix inherits from the original C++ (which also ignored tags), so this is a deliberate divergence from parity rather than a bug introduced by the port. The two guard tests — pathological nesting and a truncated tag — passed before the fix as well, since the old behaviour also reported non-IP; they exist to pin the *new* loop's failure modes, and the truncation case in particular would have been a crash if the peel loop had not bounds-checked before slicing.
### `T05-02` — pcapng diagnostic or reader
- **Status:** done — **Blocked by:** — **Claimed by:** claude-opus-5[1m] — **Session:** ses_batch1
- **Files:** `src/dpi_engine/pcap_io.py`, `tests/test_pcap_io.py`
- **Test added:** five. A minimal 28-byte pcapng Section Header Block raises the new error; the message names `editcap` **and** `-F pcap`; the error is catchable as `PcapError` so the CLI's existing handler reports it; the CLI end-to-end exits non-zero with the diagnostic on **stderr** and no traceback; and two negative guards -- a corrupt file and an empty file must still report *invalid pcap*, not pcapng, so the detection cannot over-match.
- **How it was tackled:** `DEC-02` **ratified as Option 2** — detect the `0A0D0D0A` magic in `PcapReader._open` before dpkt sees it, and raise a new `PcapngUnsupportedError` naming the conversion command. A distinct exception type rather than a `PcapFormatError` with nicer wording, because "convert this" and "this file is corrupt" call for different responses. Subclasses `PcapError`, so the three existing `except PcapError` sites in `cli.py` handle it unchanged.
- **Deviations:** the audit framed `D-15` as needing either a ~200-line pcapng reader or this diagnostic, and recommended the diagnostic. Agreed, and recorded rather than re-litigated. Note the finding is only **half** closed by it: precise diagnosis is done, pcapng *reading* is not, so `D-15` stays open as a functional gap and only its misleading-diagnostic half is resolved. Two of my own errors: my CLI test asserted on stdout when the CLI writes errors to stderr, and my gap-verification script had an inverted condition that reported the *absent* hypothesis dependency as FIXED.
- **Verification:** **479 passed, 12 skipped, 0 xfailed**. `ruff check .` and `mypy` (strict, 13 files) clean.
- **Closed findings:** `D-15` (diagnostic half only) · **Follow-ups:** Phase 1 if the golden corpus needs a real reader.
- **Notes:** Phase 0.5 exit criterion #2 — "pcapng input produces a precise, actionable diagnostic" — is met, so **Phase 0.5 is complete (2/2)** alongside criterion #1 (tagged capture classifies identically to its untagged twin).
### `T1-01` — Event bus
- **Status:** done — **Blocked by:** — (DEC-01 decided 2026-10-12) — **Claimed by:** claude-opus-5[1m] — **Session:** ses_t1_01
- **Files:** `src/dpi_engine/events.py` (new), `src/dpi_engine/pipeline.py`, `tests/test_event_bus.py` (new)
- **Test added:** thirteen. The guarantee test (`test_the_fold_reproduces_the_batch_result`) plus the same test with blocking rules, so the drop path is exercised; fidelity tests (one `PacketParsed` per packet with a dense `sequence_index`, skipped frames emitted with `inspected=False` and counted exactly, `FlowCreated` before `FlowClassified`, every flow classified at least once, `FlowBlocked` exactly once per flow, open/close ordered); robustness (a failing subscriber does not stop the run, unsubscribe works); and two fold tests in isolation -- a hand-built synthetic stream pinning the arithmetic, and an empty stream folding to the zero value.
- **How it was tackled:** the spec's own framing — `PipelineResult` becomes a *derived* summary computed by folding the stream — so the batch API is preserved and every existing consumer keeps working. `run_pipeline` takes an optional `bus`, defaulting to `None` so the hot path pays nothing unless someone asks for the stream. `fold_events` reuses `WorkerResult` and `_LoadBalancerResult` rather than re-encoding them, so the fold and the batch path compose from the same objects and cannot drift. `T0-11` is why this is possible: it removed the global `sort` and the per-packet accumulation, so a fold reproduces the batch result exactly. Emission is opt-in at the *bus* level, not the *listener* level, pinned by `test_the_fold_reproduces_the_batch_result_with_a_bus_but_no_subscribers`.
- **Two real bugs in my own emission, both caught by the guarantee test rather than by reading the code:** (1) `FlowCreated` was emitted *before* the decision with an early return, so a brand-new flow never emitted `FlowClassified` at all — `app_counts` under-counted by exactly the number of distinct flows, invisible in the output pcap and in every counter except that one. (2) "is this flow new" was implemented as `get_connection(tuple_) is None`, but `ConnectionTracker.get_connection` also matches the *reverse* five-tuple, so a flow whose reverse direction was already tracked never emitted `FlowCreated`. The exact-tuple containment check (`tuple_ in tracker`) is what 'this flow is new' means. Both are now regression tests.
- **Deviations:** four. (1) The spec lists `FlowEvicted` in the vocabulary; it is defined but **not emitted** — eviction is a `ConnectionTracker` judgement and the tracker has no knowledge of events, which is a layering boundary worth keeping. Documented in its docstring rather than papered over; deferred to `T1-03`. (2) `fold_events` lives in `pipeline.py`, not `events.py`: the fold constructs a `PipelineResult`, and `pipeline` imports the event types in order to emit them, so one direction must be type-only and it cannot be the fold's. `events.py` is a leaf with no runtime pipeline dependency. (3) `TrackerStats.combine` takes a single argument while `FastPathStats.combine` and `LoadBalancerStats.combine` take a sequence — an upstream asymmetry the fold follows rather than unifying. (4) Only the single-process path emits events; the two multiprocess variants return the same `PipelineResult` but do not populate a bus yet.
- **Verification:** **537 passed, 12 skipped, 0 xfailed** (up from 524). `ruff check .` and `mypy` (strict, 14 source files) clean. Coverage 92.02%. **Throughput measured, because this touched the hot loop:** with `bus=None` (the default) the run is *unchanged*, since emission is opt-in. With a bus supplied but zero subscribers the cost is **+7.3%** (3.55 -> 3.81 ms on the sample capture) {EM} pure dataclass construction that nobody reads. That is the number to know before subscribing anything real to this.
- **Closed findings:** `A-01` (streaming analysis: the event bus and the derived summary) · **Follow-ups:** `FlowEvicted` emission, bus wiring for the two multiprocess variants, and a live-consumer contract — all `T1-03`.
- **Notes:** this is the first task that could not be validated by comparing output bytes to `HEAD`, because the point is to change the shape of the data. The guarantee test replaces that check and is stronger: it asserts the two paths agree on every reported figure rather than on the bytes. Worth being explicit that it did its job twice — both emission bugs above were found by it and would have shipped silently without it, since `run_pipeline`'s own return value was unaffected in both cases.
### `T1-02` — `CapSource` abstraction

- **Status:** done · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t1_02 · **Blocked by:** —
- **Files:** `src/dpi_engine/cap_source.py` (new, 264 lines), `tests/test_cap_source.py` (new, 40 tests), `src/dpi_engine/pcap_io.py` (stream support), `src/dpi_engine/pipeline.py` (accept a source)
- **Planned test:** `WatchSource` over a temp directory picks up files as they appear; `StreamSource` round-trips byte-for-byte against `FileSource`
- **How it was tackled:** **the contract is deliberately one line wide: a `CapSource` is an iterable of `RawPacket`.** That is the shape `pipeline._iter_inspectable` already consumed, so no pipeline logic changed — only its parameter type — and `PcapReader` remains the only thing that turns bytes into packets. Three sources: `FileSource` (a capture on disk), `StreamSource` (a pipe or socket), `WatchSource` (a directory, polled, each file read once by identity rather than name so a rotation is not mistaken for a new file and a replacement at the same path is). The whole design rests on delegation: a source that parsed bytes itself would be a second parser, and a second parser carries its own bounds, its own pcapng handling and its own truncation behaviour — three bug surfaces where the rest of the engine has one. `path` is `None` for anything without a single file, so `PcapWriter`'s never-overwrite-the-input guard is *skipped* for a stream rather than fed an invented path, and still enforced for a file source.
- **Deviations:** three, each forced by something the first implementation got wrong.
  - **`PcapReader` needed a stream mode, and it needed a non-rewindable one.** `_open` peeks four bytes of magic and then `seek(0)` to restart. On a pipe there is nothing to seek with, so every stream source would have died on format detection with `io.UnsupportedOperation` — an error naming an implementation detail rather than anything about the capture. Added `_PrefixedStream`, which pushes the four peeked bytes back in front of a non-rewindable stream instead of seeking. Rewind is chosen by `stream.seekable()`, defaulting to *non*-rewindable when a stream will not say: re-prepending four bytes is always correct, whereas seeking a pipe that claims to be seekable and is not fails mid-read.
  - **`close()` had to stop closing streams it does not own — in four places, not one.** `close()` plus three error paths (pcapng, bad magic, wrong linktype) all close the handle. If any closed a caller's stream, the *first* malformed capture on a live pipe would shut the pipe down. Each is guarded and each is tested per rejection reason, because "the error path is careful" is exactly the kind of claim that holds in one branch and not the others.
  - **`WatchSource` records an unreadable file as *attempted*, not as finished.** The first version deliberately left unreadable files unconsumed so a mid-write capture would be retried — which meant a permanently-unreadable file kept `_has_unconsumed()` true and a bounded watch **never terminated**. Caught by a test timing out, not by inspection. Recording the stamp instead satisfies both: a file that keeps growing changes stamp and is retried automatically, and a permanently broken one stops holding the watch open. No `retry_growing` flag was needed, which is why the planned test's version of that parameter does not exist.
- **Verification:** `ruff check .` clean · `mypy` (`--strict`) clean on 17 source files · `pytest -q` → **685 passed, 12 skipped** (was 645; **+40**). Coverage **94%** on `cap_source.py`, overall 92.5% against the 85 floor. **11 of 12 mutations caught, 0 void, and the twelfth is a proven equivalent** rather than a coverage gap — see below.
- **Closed findings:** — (`A-01` is the phase-level finding this belongs to; `A-01` also names `T1-01`, already closed) · **Follow-ups:** no CLI surface — `WatchSource`/`StreamSource` are library-only and nothing in `cli.py` constructs one, so live capture is reachable programmatically but not from the command line yet
- **Notes:** **mutation testing found a hole that green tests could not.** The suite used `BytesIO` and real files — *both seekable* — so the non-rewindable path, which is the entire reason `StreamSource` exists, was never executed. Both mutants on that branch survived. Seven tests now drive a genuinely non-seekable stream, and the live-pipe path is covered end to end. The one remaining survivor was verified **equivalent by simulation**, not waved off: `_PrefixedStream` subclasses `io.RawIOBase`, and `RawIOBase.close()` marks the wrapper closed without touching a handle it never opened — so a non-seekable caller's pipe survives whether or not `close()` checks ownership. Reporting 12/12 there would have been padding. Two tests also found that the main loop and the idle check *disagreed* about a vanished directory (one raised, one silently reported "finished"); the silent one was the dangerous one, since a watch whose directory was unmounted is indistinguishable from one where traffic stopped, so both now raise.
- **How it was tackled:** — · **Deviations:** — · **Verification:** —
- **Closed findings:** — · **Follow-ups:** —
- **Notes:** `PcapReader`/`PcapWriter` stay the only I/O boundary, so the safety invariant holds by construction
- **Status correction (2026-10-13, ses_t1_05):** this block previously read **done**, claimed by `ses_t0_05`. That was **scaffolding, not work**: `src/dpi_engine/cap_source.py` does not exist and no `CapSource`, `WatchSource` or `StreamSource` symbol exists anywhere in `src/`. The summary table already said `pending`, and the table was right. Do not trust this block's status until the evidence line above is rewritten from real code.

### `T1-03` — Streaming output + reorder buffer
- **Status:** done — **Blocked by:** — (DEC-01, DEC-05 decided 2026-10-12) — **Claimed by:** claude-opus-5[1m] — **Session:** ses_t1_03
- **Files:** `src/dpi_engine/{pipeline,worker,connection_tracker,types,load_balancer,cli,events}.py`, `tests/test_reorder_buffer.py`, `tests/test_{event_bus,report,resource_bounds,safety_constraints,staged_pipeline}.py`, `tests/differential/*`
- **Scope (user decision, 2026-10-13):** all three pieces in one commit (A) bounded reorder buffer, (B) `DEC-05` flow folding, (C) the three `T1-01` follow-ups.
- **Done (A):** `worker.PacketDecision` + `worker_main(emit_decisions=)` publish a verdict per packet; `pipeline.ReorderBuffer` holds up to *W* packets keyed on `sequence_index` and emits in input order within the window; `_pump_worker_messages`, `_await_space`, `_collect_streaming`; `DEFAULT_REORDER_WINDOW = 1024`. All **three** variants dispatch, drain and write in one interleaved pass; `reorder_window=None` still selects `T0-11`'s second pass for exact parity. End-to-end verified: streaming and second-pass outputs are **byte-identical** (same SHA-256) on `test_dpi.pcap`.
- **Late-packet policy (documented in the class docstring):** order is preserved by default; out-of-order emission happens only when the window is full *and* the packet at `next_expected` has no verdict. The verdict itself is never guessed, dropped or forwarded early. `out_of_order_emissions` and `late_decisions` report every departure from input order. **Not yet ratified as a numbered decision** - worth raising as `DEC-07` if a consumer ever depends on it (`DEC-06` is taken by the `T1-05` endpoint-matching decision).
- **Done (B):** `canonical_flow_key()` moved to `types.py` (the dependency-free leaf) so `load_balancer` can import it without a cycle with `connection_tracker`. Tracker keys, `blocked_tuples`, `_quic_inspectors` and both hash steps (parent dispatch *and* `LoadBalancer.select_fp`) key canonically. `worker.process` derives `is_outbound` from `tuple_ == conn.tuple`, which is what makes `packets_in`/`bytes_in` real for the first time (`D-25`). `fold_bidirectional` is now exposed on all three variants — including `run_pipeline`, which is the differential baseline and needed it.
- **Done (C):** `FlowEvicted` is emitted via `ConnectionTracker(on_evicted=)`, firing on both the LRU and the stale sweep; the tracker still imports no event vocabulary, the pipeline decides what a departure means.
- **CLI:** `--reorder-window W` (0 = legacy second pass) and `--exact-tuple-flows` (= `DEC-05` off, the C++ reference behaviour).
- **Differential suite:** runs with `fold_bidirectional=False`, pinned by wrappers in `tests/differential/conftest.py` rather than at each call site — so a new differential test cannot silently reintroduce folding. Allowlist entries 6 (folding) and 7 (VLAN peel) added to `tests/differential/README.md`.
- **Three real bugs found and fixed during the work:**
  1. `_ensure_alive` treated any `not p.is_alive()` worker as dead, but a worker that finished and exited cleanly is *done*, not dead — with more workers than a capture has flows that is the common case. It now flags only abnormal exit codes.
  2. The reorder buffer was flushed after the writer's `with` had closed, so it wrote to a closed file. Collection now runs inside the `with`.
  3. `was_blocked` probed `blocked_tuples` with the packet's **own** five-tuple. That container is a plain `set[FiveTuple]`, so its membership test does *not* canonicalise the way `ConnectionTracker.__contains__` does — every reverse-direction packet of an already-blocked flow read as "not blocked", and `conn.state is BLOCKED` then re-fired `FlowBlocked`. On `test_dpi.pcap` that produced **55 events for 23 flows**, which broke the fold's reproduction of `blocked_flows`. The `T1-01` guarantee test caught it; that is exactly what it exists for.
- **Two lines of dead code removed, both proven by a surviving mutation:** `flush_out_of_order`'s `if index == self.next_expected: return False` guard (unreachable — `decide`/`offer_skipped` call `_advance`, which always drains the cursor first), and `offer_skipped`'s `_advance()` (unobservable — the next `decide` or `finish` steps over the entry identically). A mutation that no test can catch is evidence about the *code*, not the tests; both were removed rather than left as untestable lines.
- **Test re-derivations (not weakenings):** `_compare` sorts `blocked_flows` (partitioning decides order, the claim is decision-identity); `test_every_flow_lands_on_exactly_one_fast_path` counts distinct **canonical keys** (43 five-tuples → 27 flows) while still pinning the fixture's 43; three `test_report` expectations moved to a new `unfolded_result` fixture, since a rendering test needs a report that still *contains* NEW states and UNKNOWN apps. `_worker_result_pickle_bytes` now spies on `_collect_streaming` **and** asserts it captured something — its old hook missed and it had been passing vacuously on `0 == 0`.
- **Verification:** `ruff` and `mypy --strict` clean. **554 passed, 12 skipped** (from 538; +16 new). `tests/test_reorder_buffer.py` (15 tests) was mutation-checked: 6 deliberate mutations of `ReorderBuffer`, **all 6 caught**.
- **Left undone, recorded rather than implied:** the two multiprocess variants still do **not** emit events — `T1-01` deviation (4) stands, and it is a separate piece of work, not a loose end of this one. The live-consumer contract doc is also unwritten.
- **Follow-ups:** `D-13` (LB-death orphans its fast paths until the parent's 120 s timeout) is still unowned *(closed 2026-10-15, `ses_t1_06b`)*. The staged wiring did **not** need per-packet verdicts forwarded through the LB tier — each fast path publishes straight to the shared `fp_output_queue` the parent already reads, and the LB only forwards *input* — so `D-13` did not bite here. It will bite whenever an LB death has to be detected promptly rather than by timeout.
### `T1-04` — Rule DSL with provenance

- **Status:** done · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t1_04 · **Blocked by:** —
- **Phase 1 exit criteria verified 2026-10-15, `ses_t1_04` (Appendix B):**
  1. *all existing tests pass unchanged* — **727** at the time of the check, later **732** with the memory suite; no reduction at any point.
  2. *streaming output deterministic under `DEC-01`* — `tests/test_reorder_buffer.py`, 15 passed.
  3. *differential parity with the C++ reference intact* - **14 passed, 0 skipped** (verified 2026-10-15 with Docker running). All 12 previously-skipped tests now execute: total/dropped counts match for no-rules, blocking-IP, the DNS scope improvement, detected domains modulo the documented C++ misclassifications, bare-domain vs wildcard rule behaviour, app-name resolution, three edge-case fixtures (truncated ClientHello, truncated TCP header, oversized declared lengths) and two multiprocess-parity runs. `DEC-05` and `DEC-06` remain **allowlisted divergences** — the suite pins `fold_bidirectional=False` so parity holds for everything else, which *excludes* those two from the parity check rather than verifying them by it. `tests/test_parity_breaks.py` (5 tests) now verifies the **port side** of each claim, so together the two suites say what they intend to.
  4. *`simulate_ruleset` working and exercised* — 22 tests.
  5. *memory bounded under a streaming run with a directory-watch source* — **was not measured by anything.** Flow reaping is covered and the reorder window is covered, but neither ran against a `WatchSource` and neither asserted peak memory. Added `tests/test_streaming_memory_bound.py`, and **it found a real bug** — see Deviations.
- **Files:** `src/dpi_engine/rule_manager.py`, `src/dpi_engine/cap_source.py`, `src/dpi_engine/pipeline.py`, `tests/test_rule_dsl.py` (new, 42), `tests/test_streaming_memory_bound.py` (new, 5), `tests/_mem_probe.py` (new, subprocess probe). **No new module** — the DSL lives beside the rules it describes rather than as a parallel hierarchy.
- **Planned test:** JSON round-trip preserves provenance; a rule without provenance cannot be auto-applied
- **How it was tackled:** **the load-bearing decision is that provenance is a sidecar, not part of the rule set.** `_RuleState` holds `frozenset`s, is read by `should_block` on every inspected packet, and is shared across threads and pickled to workers; a provenance record per rule inside it would put an allocation and a lookup on the hot path to serve a question only the *control* path asks. So matching state is untouched and provenance lives beside it in `RuleManager._provenance`, keyed by the stable keys `D-16` introduced. The consequence is stated plainly in `Provenance`'s docstring and pinned by tests: **a snapshot carries no provenance**, because a worker cannot use it and pickling history to every worker would cost every packet. `Provenance` (source, author, evidence, `created_at`) is frozen and requires a source — provenance with no source is a decoration that answers no question, so that is enforced at construction. Every `block_*` takes `provenance=`, every `unblock_*` clears the record. `is_auto_appliable` is the gate Phase 6 needs, and `audit()` is the review list.
- **Deviations:** four, all forced by something the first version got wrong.
  - **Provenance is recorded *before* the idempotence check.** `block_*` returns early when the rule is already present, so recording after it would silently swallow the legitimate case of re-declaring an existing rule with a new author — which is how an operator updates who vouched for it.
  - **Normalising provenance keys uses `strict=True`, matching `_parse_cidr`.** My first version used `strict=False`, which folded `10.0.0.1/8` — a spelling the parser *rejects* as "host bits set" — into a valid rule's key. Two spellings would then share one audit record while only one of them was a rule at all.
  - **A corrupt provenance record does not fail the file.** `Provenance.from_dict` returns `None` and the rule is kept without an origin. The rules are the load-bearing thing and provenance is the audit trail; failing the whole file would mean a corrupt annotation could stop the operator blocking traffic they asked to block — and then the gate would report "no provenance" for a rule that is in force, the one answer `is_auto_appliable` must never give by accident.
  - **`to_dict` omits the `provenance` key entirely when no rule has any.** Every rules file written before this exists has no such key, so omitting it keeps `save_rules` byte-identical for the common case and keeps the change invisible to anything diffing rules files.
- **The fifth exit criterion found a real defect, which is why it was worth adding.** `WatchSource` reads through one `PcapReader` **per file**, and `max_total_packets` is enforced *inside* `PcapReader` — so every file got a fresh budget and the run-wide bound was silently `files × limit`. Measured: **4 files of 77 packets read 308 packets against `max_total_packets=50`, raising nothing.** A rotating-capture directory is exactly the many-small-files shape that defeats a per-file bound, so `T1-02` had shipped a hole in the engine's main adversarial defence. Fixed by tracking the budget in the source and handing each per-file reader the *remaining* allowance; `run_pipeline` now pushes its bounds down through a shared `_open_source` used by all three variants. Two follow-on bugs surfaced while fixing it: `PcapLimitExceededError` subclasses `PcapError`, so the "skip unreadable files" handler was **swallowing the bound's own error** and truncating silently; and `remaining or 1` collapsed a remaining budget of 0 into 1, stopping the run at 4 packets instead of 50.
  - **The memory criterion measured the wrong thing at first, and that is recorded too.** My first version compared 77 packets against 616 and reported **5.4× peak growth as a possible `D-01` leak**. It was not a leak: with a 1024-slot window, 616 packets all *fit* in the buffer, so it was measuring "more packets fit in the buffer". Re-measured with the input genuinely **exceeding** the window — 1078 → 4312 packets, 4× — peak is **flat at ~1.62 MB**, and a 32-slot window peaks lower than a 1024-slot one, which is what proves `DEC-01` is the cause rather than some unrelated ceiling.
- **Verification:** `ruff check .` clean · `mypy` (`--strict`) clean on 17 source files · `pytest -q` → **732 passed, 12 skipped** (was 685; **+47**). `rule_manager.py` coverage 90%. **14 of 14 mutations caught, 0 void.**
- **Closed findings:** — · **Follow-ups:** no CLI surface — nothing constructs a `Provenance` from a command line, so provenance is currently only settable programmatically; Phase 6's write path will need a way to supply one
- **Notes:** the mutation harness earned its keep twice. **The port-key normaliser survived at first**, and investigating showed why: `str(int(key))` is *identical* to `str(key)` for `443` and `"443"`, so my tests could not tell a normaliser from none. The spellings that differ are the ones `_normalize_port` accepts but `str()` does not collapse — `"0443"` and `" 443 "` — so the test now crosses that boundary, and the mutant is caught. **And `tests/test_rule_dsl.py` had three methods duplicated into two classes** by a scripted refactor of mine; caught because pytest reported `fixture 'self' not found` rather than by reading the diff. Both are the kind of thing that reads as done.
- **Status correction (2026-10-13, ses_t1_05):** previously read **done** under `ses_t0_05` — scaffolding, not work. There is no `rules/` subpackage and `provenance` does not appear in `rule_manager.py`. Note that `T1-05` has since rewritten large parts of `rule_manager.py` (`_RuleState.networks`, `resolve_app_key`, the `dst_ip` parameter), so the rule schema this task planned around has moved on.

### `T1-05` — CIDR + destination-IP rules

- **Status:** done — **Claimed by:** claude-opus-5[1m] — **Session:** ses_t1_05
- **Files:** `src/dpi_engine/{rule_manager,worker,cli}.py`, `tests/test_rule_cidr_and_dst.py` (new), `tests/{test_cli_rules,test_cli_run,test_rule_manager_v2}.py`, `tests/differential/README.md`, `docs/DESIGN_DECISIONS.md`
- **Scope:** three findings in one change, as planned — `D-20` (CIDR/subnet rules), `D-21` (destination-IP blocking), `D-16` (persistence keys; this implements `DEC-04`).
- **Decision — `DEC-06` (user, 2026-10-13):** an IP rule matches **either endpoint**. `block_ip("8.8.8.8")` blocks traffic to *and* from it, rather than source-only as the C++ original did. Deliberate parity break, differential allowlist entry 8. Full rationale and the two rejected options are in `DESIGN_DECISIONS.md`.
- **How it was tackled:** subnets are stored **grouped by prefix length** — `tuple[tuple[int, frozenset[int]], ...]`, not `ipaddress` objects — so matching is one right-shift and one set lookup per *distinct prefix length present*, at most 33, however many networks are registered. That is the whole reason `D-20` was a defect rather than an omission: a per-network `ipaddress` membership test would have made the packet path cost scale with the rule set. `/32` is kept in the subnet table rather than folded into the exact-address set, because a rule written with a prefix is a rule written with a prefix, and conflating the two would make `get_blocked_cidrs()` lie about what was registered. Host bits are **rejected**, not silently masked — `10.1.2.3/8` is almost certainly a mistake, and quietly widening it to `10/8` would apply a rule far broader than the one written.
- **Deviations:** none from scope. One addition: `block_ip`/`unblock_ip` accept a CIDR string and route to `block_cidr`, because `--block-ip 10.0.0.0/8` is the natural spelling and rejecting a valid subnet on a flag named after addresses pushes users back toward enumerating 16,777,216 rules — the defect being fixed.
- **Bugs found while implementing (both caught by the tests, not by review):**
  1. **`RuleManager.should_block` is a second copy of the signature.** `worker.process` holds a `RuleSource` and calls `should_block` through it, which resolves to `RuleSnapshot.should_block` — the method I had edited — but `RuleManager` carries its own wrapper that forwards positionally. Adding the parameter to only one would have left `D-21` open in every real run while unit tests, which go through `RuleManager` directly, reported it fixed. Both now declare it and the wrapper forwards by keyword.
  2. **My own load test was wrong.** It registered `10.{0..255}.0.0/16` and then asserted `10.0.0.1` was *unblocked* — but `i=0` covers exactly that address. Rewritten to `range(1, 256)` with a comment, since the exclusion is the point of the test.
- **A warning nobody sees is not a migration:** `DEC-04` requires a deprecation path, but Python hides `DeprecationWarning` unless raised in `__main__`, so loading a legacy rules file through the CLI printed nothing at all. The alias would then never migrate anything and the decision would be half-implemented in practice while fully implemented in the unit tests. Both CLI load sites now go through `_load_rules_with_notices`, which surfaces the notices on stderr; two tests pin it in both directions, since an unconditional notice is one a user learns to ignore.
- **Test re-derivation (not weakening):** three assertions pinned the format `D-16` calls defective — `blocked_apps == ["YouTube"]` in `test_cli_rules.py` and `test_cli_run.py`, `== ["Zoom"]` in `test_rule_manager_v2.py`. All three moved to the canonical enum name. `test_cli_rules.py` also asserts the *display* output still reads `"Blocked app: YouTube"`, which is the crux: two vocabularies, one persisted and one shown. `test_snapshot_to_dict_is_stable_and_complete` gained a comment tying its name to `D-16` — "stable" is precisely what a display-string key was not.
- **Verification:** `ruff check .` clean · `mypy --strict` clean · `pytest -q` → **581 passed, 12 skipped** (was 554; +27 new). Mutation-checked against a hardened harness: **6 of 6 caught**. The first mutation run was **void** and had to be discarded — a syntax error from a bad edit made every test file fail to *collect*, so pytest exited non-zero for all six and the run read as a clean sweep. The harness now verifies the unmutated baseline is green first and counts only pytest exit code 1 as a catch, treating an exit code 2 as collection-error noise. Re-run clean: baseline 25 passed, and the six mutations fail 4, 9, 1, 1, 1 and 11 tests respectively — specific, not universal.
- **Closed findings:** `D-20` `D-21` `D-16` · **Follow-ups:** —

### `T1-06` — `simulate_ruleset` counterfactual engine

- **Status:** done · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t1_06 · **Blocked by:** —
- **Files:** new `src/dpi_engine/rules/simulator.py`, new `src/dpi_engine/rules/__init__.py`, new `tests/test_simulate_ruleset.py`. **No existing source file was modified.**
- **Planned test:** simulating a ruleset that would block 100% of flows is reported as such; a no-op change yields zero delta
- **How it was tackled:** exactly as the keystone note planned — two runs of the real pipeline, diffed. `simulate_ruleset` calls `run_pipeline` twice (baseline rules, candidate rules) with an `EventBus` attached, recording `PacketParsed.forwarded` per `sequence_index` as the decision bitmap and `PipelineResult.blocked_flows` as the flow set. The constraint that shaped the design: **do not reimplement decision logic.** A simulator that re-derived "would this flow be blocked?" would be a second source of truth free to drift from production, and every number it reported would be a guess wearing the costume of a measurement. Cost is two runs; the difference is exact rather than sampled, which matters because the roadmap wants to make *safety* claims from it ("a ruleset that would block 100% of flows is reported as such") and a sample cannot support one. The package is a separate `dpi_engine.rules` subpackage with an `__init__` that states the enforcement path must never import it — the engine decides about traffic in front of it, a simulator answers "what *would* you do", and keeping them apart stops an analysis tool being one refactor from load-bearing on live traffic.
- **Deviations:** two, both forced by tests rather than chosen up front.
  - **`packets_changed` is not the net drop delta.** The first implementation defined it as `candidate_dropped - baseline_dropped` and cross-checked it against the per-packet diff. A test caught this being *false*: substituting one blocked app for another (Facebook → YouTube) drops **2 packets either way**, so the net is 0, while **4 packets change disposition**. A simulator built on the net would report the most disruptive kind of edit — a policy swap — as "no change at all". Now `packets_changed` is counted from the decision bitmaps and is unsigned; `net_packets_dropped` carries the signed figure, and `test_substitution_moves_packets_without_changing_the_drop_total` pins the distinction.
  - **The consistency guard checks the decision key-sets, not the counters.** The original guard asserted the per-packet diff equalled the net drop delta — the same wrong premise — and fired spuriously on the substitution case above. It now asserts the two runs saw the same *packets*, which is a genuinely universal invariant, and `RuntimeError`s with both directions named if not.
- **Verification:** `ruff check .` clean · `mypy` (`--strict`) clean on 16 source files · `pytest -q` → **623 passed, 12 skipped** (was 601; **+22**). Coverage **100%** on `simulator.py` (87/87 statements), overall **92.16%** against the 85 floor. **Proven to bite: 12 of 12 mutations caught, 0 void**, via a detached worktree with `PYTHONPATH` asserted per run. Five of the first ten survived the initial run and each was a real gap, not a bad anchor: an empty-capture test for `total_loss`'s `dropped > 0` condition, a policy-substitution test for the sign of `net_packets_dropped`, a stricter `unchanged_blocked` assertion, a `baseline_blocked == 0` assertion, and fault injection for the consistency guard.
- **Closed findings:** `A-05` · **Follow-ups:** no CLI surface yet — `simulate_ruleset` is library-only, and `tests/test_simulate_ruleset.py` is not imported by anything in `src`, so there is no read-only command to reach it from
- **Harness note worth keeping:** the mutation harness's first run reported **10 of 10 survived**, which was the harness lying rather than the tests being weak. `dpi_engine` is an editable install resolving to `C:\Project\Packet_analyzer\src`, so pytest inside the worktree imported the *unmutated original* and every mutation "passed". Fixed by putting the worktree's `src` on `PYTHONPATH` and **asserting the resolved module path on every single run**, not once at setup. Same trap as `T1-07`'s first bite run.
- **Notes:** **the keystone component.** Implement by running the engine twice and diffing the decision bitmaps `T0-11` produces — nearly free, and exact rather than approximate. Every safety claim in `AGENTIC_ARCHITECTURE.md` Layers 3/7/8 reduces to this existing
- **Status correction (2026-10-13, ses_t1_05):** previously read **done** under `ses_t0_05` — scaffolding, not work. Neither `rules/simulator.py` nor `src/dpi_engine/pipeline_sim.py` exists, and no `simulate_ruleset` symbol exists anywhere. The "keystone" note above is genuine planning and worth keeping; only the status was false.

### `T1-07` — Property tests + scapy cross-check
- **Status:** done — both increments — **Blocked by:** — **Claimed by:** claude-opus-5[1m] — **Session:** ses_t1_07b
- **Files:** `tests/property/test_extractor_properties.py`, `tests/property/test_scapy_cross_check.py` (both new), `pyproject.toml`, `docs/DESIGN_DECISIONS.md`
- **Test added:** 45. Increment 1 (here): 20 hypothesis property tests. Increment 2 (this pass): 25 scapy cross-check tests — 8 corpus cases in each direction, the no-SNI case in both directions, a truncation sweep asserting ours is never more permissive than the reference, and six `length` values through scapy-built input.
- **How it was tackled:** the decisive design point is that a cross-check is only worth anything if the two sides do not share a builder. So `scapy_builds_a_record` constructs the handshake with scapy's own serialiser and `extract_sni` parses it — agreement there means the extractor reads *the format*, not *our fixture*. The reverse direction (scapy parses our fixture) is kept too, but it is weak evidence since both sides of it were produced by the same author. On truncated input the two deliberately disagree: scapy returns what it managed to read (`'example.co'` from a record cut mid-hostname), ours returns None. Ours is the safer of the two, so the test asserts ours is never *more permissive* rather than asserting equality.
- **Deviations:** one substantial, and it is about the reference rather than the code. `DEC-03`'s own text says to "fall back to deleting the dependency and striking the claim if scapy proves unreliable as a reference". Very nearly taken: the first probe showed scapy finding **no SNI at all** in well-formed input, which would have been that fallback. It was my harness, twice over. (1) `TLSClientHello` expects the handshake body, so the 5-byte TLS record header must be stripped — I stripped 3 (my own framing prefix), misaligning scapy by two bytes. (2) `bytes(TLS() / ch)` does not frame a record: scapy emits content-type `0x00` and a zero length field, so direction B appeared to fail until the handshake was framed explicitly. Also worth recording because it is the same trap as the `R-05` bite test: the first 'it bites' run against mutated code was checked with a sanity command whose own `sys.path.insert` outranked `PYTHONPATH`, so it reported the unmutated module. Re-verified cleanly before believing the 16 failures.
- **Verification:** **524 passed, 12 skipped, 0 xfailed** (up from 499). `ruff check .` and `mypy` (strict, 13 files) clean. Coverage **92.04%**. **Proven to bite:** `_TLS_RECORD_HEADER_LEN` mutated 5 -> 6 in a worktree, with `PYTHONPATH` confirmed to resolve `dpi_engine.sni_extractor` to the mutated tree — **16 of 25 fail**, both directions, including "hand-rolled extractor failed on a ClientHello built by scapy: expected 'example.com', got None". `DESIGN_DECISIONS.md`'s "scapy's stated purpose is unimplemented" stale claim is closed and the dependency note now describes reality.
- **Closed findings:** `R-08`, `R-05` · **Follow-ups:** the `scapy` name is forbidden in `test_safety_constraints.py`'s shipped-source pattern list; tests are out of scope there so no conflict, but the list now has an exception for a dependency it exists partly to police.
- **Notes:** **all five roadmap decisions are now recorded** — `DEC-01` bounded reorder window, `DEC-02` precise pcapng diagnostic, `DEC-03` implement the cross-check, `DEC-04` `AppType.name` + migration, `DEC-05` flow folding default ON — so Phase 1's five blocked tasks are unblocked. `DEC-05` specifically unblocks `D-25`, which I had documented this session as *not cheaply solvable*: `packets_in`/`bytes_in` are permanently 0 because there is no folded flow to attribute the reverse direction to, and folding gives that state an owner. Next is `T1-01` (event bus), whose shape the `DEC-01` decision fixes.
### `T1-08` — Benchmark suite

- **Status:** done · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t1_08 · **Blocked by:** —
- **Files:** `tests/benchmarks/baseline.json` (new, committed), `docs/BENCHMARKS.md` (new), `tests/test_benchmark_baseline.py` (new, 9 tests), plus the docstring corrections in both benchmark files and `D-23`'s row in `AUDIT.md`. **No production source touched.**
- **Planned test:** publish the baseline recorded in `T0-03`
- **How it was tackled:** the benchmark *tests* already existed and were correct, so the work was publishing what they measure — and making the published pair incapable of silently disagreeing. `docs/BENCHMARKS.md` is the human-readable half and `tests/benchmarks/baseline.json` the machine-readable half; the second was deliberately **not** put in `.benchmarks/` (gitignored, and pytest's *comparison* store rather than an artefact). `tests/test_benchmark_baseline.py` recomputes the document's figures from the JSON and fails if they drift, because a hand-edited baseline is the exact rot this task exists to stop, and it is the rot the README and `AUDIT.md` §0 already suffered once. **The `--benchmark-disable` caveat was verified rather than assumed:** a default run finishes in 3.0 s and the real run in 18–19 s, which is now recorded in the document itself.
- **Deviations:** two, both forced by what the measurement actually showed.
  - **`D-23` got worse, so it was corrected rather than closed.** Re-measuring gave **7.26×** (multiprocess) and **8.28×** (staged) against single-process, where the finding recorded 4.7× and 6.2×. The direction held and the magnitude grew by roughly half. Plausible reason: `T0-11` — the change `D-23` was waiting on — replaced shipping packet *bytes* back to the parent with a decision *bitmap*, which removes memory without removing work, and each packet now costs a bit-setting on a path where per-packet pickling already dominated. Recorded as a **hypothesis, not a measurement**, because isolating it needs a benchmark with and without the bitmap. `D-23` stays open with the remaining work narrowed to *establish the crossover point on a realistic capture*.
  - **The magnitude is labelled workload-specific rather than quoted as a property.** 4000 synthetic 54-byte frames over-weight process spawn and per-record pickling, so the direction is trustworthy and the number is not portable. `BENCHMARKS.md` says so explicitly, and the previous docstring overstated this by presenting one machine's ratios without that hedge.
- **Verification:** `uv run pytest tests/benchmarks --benchmark-enable` → 8 benchmarks, 18–19 s. Default run → 3.0 s, proving they do not execute without the flag. `ruff check .` clean · `mypy` (`--strict`) clean on 16 source files · `pytest -q` → **645 passed, 12 skipped** (was 636; +9). **The rot guard proven to bite three ways**, each independently: corrupting `137.5 ms` → *"the baseline records 137.5 ms but BENCHMARKS.md does not contain that figure"*; corrupting `7.26x` → *"recomputed ratio is 7.26x"*; corrupting `29 Kpps` → *"recomputes to 29 Kpps"*. All three fail exactly one test and name the mismatch.
- **Closed findings:** — (`R-06` was closed by `T0-03`, and `P-15` was promoted out of the register into `D-23`; neither is this task's to close) · **Follow-ups:** `D-23` needs a crossover measurement on a realistic capture; `BENCHMARKS.md` should be regenerated whenever the benchmarks change
- **Notes:** first honest measurement of whether the port is fast enough for real captures. **Answer so far: the scaling paths are not, and were not when we looked either.** The one genuinely new finding in the micro-benchmarks is that `parse_packet` (10.73 µs) costs ~7× `extract_sni` (1.57 µs) — most of this engine's per-packet work is header parsing, not payload inspection, which is the opposite of where an intuition about DPI starts.
- **Status correction (2026-10-13, ses_t1_05):** previously read **done**, closing `R-06` and `P-15`. The truth is split, and the block was wrong about both findings even though the code exists:
  - **What genuinely exists:** `tests/benchmarks/test_end_to_end.py` and `test_micro_benchmarks.py`, both real `pytest-benchmark` suites covering all three pipeline variants, tracked in git since `e9b8674`. The benchmark *tests* do not need rebuilding.
  - **What does not exist:** the published baseline. There is no `tests/benchmarks/baseline.json`, no `BENCHMARKS.md`, no baseline anywhere. The task's whole point — publishing what `T0-03` measured — is undone.
  - **Both claimed closures were wrong.** `R-06` was closed by `T0-03`, not by this task (see the `T0-03` row, status `done`). `P-15` is no longer an open finding at all: it was **measured and promoted to `D-23`** (multiprocess 4.7x slower, staged 6.2x). A task cannot close a finding that was already promoted out of the register.
  - **Caveat carried forward:** `--benchmark-disable` is in the project's `addopts`, so `pytest tests/benchmarks` reports these as *passed* without executing them. A green run there does not mean the benchmarks ran — documented in both files, but worth remembering before trusting a green.

### `T1-09` — SNI / DNS parser correctness

- **Status:** done · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t1_05 · **Blocked by:** —
- **Scope reduction (2026-10-13):** `D-19` (IPv6) is **out of scope** and is a follow-up. It belongs to the packet parser, not to SNI/DNS extraction, and the original block claimed to close it with no code path that could have.
- **Files:** `src/dpi_engine/sni_extractor.py`, `tests/test_sni_correctness.py` (new), `tests/property/test_scapy_cross_check.py`
- **Test added:** 19 tests in `tests/test_sni_correctness.py`, built on a new `_sni_extension` helper that can express an arbitrary server_name list — the existing `build_client_hello` fixture could only emit a single `host_name` entry, which is why `D-17` survived: nothing in the suite could construct the shape that triggers it.
- **How it was tackled:** the server_name list is now walked entry by entry via `_hostname_from_sni_extension`, returning the first entry that is both type `host_name` **and** passes policy. A malformed or unfamiliar entry no longer ends the search, and an extension with no usable name falls through to the next extension rather than leaving the loop. `_validated_hostname` applies the policy `D-18` asked for: at most 253 octets, at most 63 per label, no empty labels, and only permitted characters.
- **Deviations:** one, and it needed a decision. The scapy cross-check (`R-08`/`DEC-03`) requires our extractor to agree with scapy, which validates only the *format*. `D-18` requires us to refuse impossible hostnames. They collide, so the divergence is **pinned as a test** (`test_policy_invalid_hostnames_are_refused_while_scapy_still_parses_them`) asserting both halves — scapy returns the value, we return `None`. The corpus entry that triggered the collision was itself wrong: `"very-long-" + "z"*70 + ".example"` put 80 characters in one label while its comment claimed it was within DNS limits, so it was replaced with a genuinely legal 252-octet name. The cross-check compares *format* parsing; illegal names are pinned separately.
- **Dead code removed, both proven by surviving mutations** (the same mechanism `T1-03` used): a `startswith(".")`/`endswith(".")` guard, because `split(".")` already yields an empty first/last element for those cases; and the `len(raw) >= 1` lower bound, because `"".split(".")` is `[""]` and the empty-label check catches it. A third guard — an explicit `decode("ascii")` — was also removed after reverting it to the old `latin-1` fallback changed no result in the suite: any non-ASCII byte decodes to a character above U+0080, which the permitted-character check rejects. One guard per condition, not two.
- **Verification:** `ruff check .` clean · `mypy --strict` clean · `pytest -q` → **601 passed, 12 skipped** (was 581; +20 new). Mutation-checked: **6 of 7 caught**; the seventh targets the length lower bound, which no longer exists. Real-capture path re-verified end to end — 27 active flows, all names still extracted.
- **Closed findings:** `D-17` `D-18` · **Follow-ups:** `D-19` (IPv6) — no task yet
- **History:** this block previously read `done` under `ses_t0_05`, claiming all three findings closed. That was checked rather than trusted, and it was false: `D-17` and `D-18` were both live in the source and none of the planned tests existed. The evidence is preserved in the session log rather than restated here — the point is that the status was corrected *before* the work was done, not after.

### `T2-01` — Golden-capture corpus + scorer

- **Status:** done · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t2_01 · **Blocked by:** —
- **Files:** new `tests/golden/{__init__,corpus,scoring}.py`, new `tests/test_golden_corpus.py` (25 tests). **No production source touched** — the corpus is a test artefact.
- **Planned test:** a labelled capture scores against the engine and reports precision/recall per class
- **How it was tackled:** **33 synthetic captures across Layer 6's five classes**, each a `GoldenCase` — a named set of flows with a declared expected classification — rather than a hand-written pcap. Every label is true *by construction*: the generator knows what it emitted, so "this capture holds two Facebook flows" is a fact about the code that built it rather than a human's assertion that might be wrong. That is what makes a synthetic corpus trustworthy where a real one is not, and it is also reproducible (byte-identical rebuilds, asserted), diffable, small in git and free of licensing weight. `tests/golden/scoring.py` implements Layer 6's "precision/recall per class" and is deliberately strict about one thing: **a detected domain absent from the labels counts against precision.** A recall-only suite would pass while the engine invented classifications nobody asked for, and for a blocking engine a false positive is a false block.
- **Deviations:** three.
  - **Six divergences are allowlisted with reasons rather than fixed or absorbed.** Following the `tests/differential/README.md` precedent (entries 6 and 8), so a reviewer sees what is *accepted* instead of inferring it from a passing number. `Divergence.reason` is mandatory and tested non-empty, because the failure mode of an allowlist is a list of bare hostnames that quietly becomes a list of things nobody fixed.
  - **`Layer 6`'s "30+" floor is asserted, and the corpus is 33.** Starting at 26, six more were added rather than declaring the floor met at 26. Two of the six (`unicode_lookalike`, `null_byte_style`) were then **cut again**: real SNI carries punycode, never raw UTF-8 or NULs, so they were testing a wire format that does not exist. The punycode case already covers IDN honestly.
  - **Two non-ASCII evasion cases became ASCII ones.** Same reasoning: `gооgle.evil.example` cannot appear in a ClientHello. Replaced with typosquats (`micros0ft.evil.example`) and numeric-label hostnames, which are real wire content.
- **Verification:** `ruff check .` clean · `mypy` (`--strict`) clean on 17 source files · `pytest -q` → **774 passed, 0 skipped** (was 749; **+25**). **9 of 11 mutations caught, 0 void, and the two survivors are proven-equivalent by simulation** rather than waved off (see Notes).
- **Closed findings:** — · **Follow-ups:** **`D-27` needs a `DEC-07`-shaped decision** — see Notes. Also `T2-04`'s baseline will be a number in a repository and therefore rot-prone in exactly the way `BENCHMARKS.md` taught us to guard; `tests/test_benchmark_baseline.py` is the precedent.
- **The corpus earned its keep on its first run: it found `D-27`.** Building it surfaced a weakness nothing else had caught: **most apps are classified by bare substring match, so an attacker-controlled hostname containing an app name inherits its classification.** Measured: `cdn.facebook.com.attacker.example` → `FACEBOOK`, `www.facebook.com.evil.example` → `FACEBOOK`, `microsoft-update.evil.example` → `MICROSOFT`, `microsoft.com.attacker.example` → `MICROSOFT`, `cdn.apple.evil.example` → `APPLE`. **The project has already recognised this exact bug class twice** — Twitter's `x.com`/`t.co` were anchored, and Cloudflare's `"cf-"` substring was dropped because "it matches any domain containing that text" — and fixed it for those two rules only. GOOGLE, FACEBOOK, NETFLIX, MICROSOFT and the rest still carry it. It is parity-preserving (the C++ original substring-matches too), so it is an inherited weakness rather than a port bug, and **fixing it is a parity break needing a decision**, which is why it is filed as `D-27` and not quietly fixed. This is the concrete argument for `AGENTIC_ARCHITECTURE.md`'s claim that a golden corpus is worth more than prompt engineering.
- **Mutation testing found a real weakness in my own tests.** The first run caught only 3 of 11. The reason is worth recording: **every gate asserted something that currently passes** — recall is total, nothing is unaccepted, precision clears its floor — so on a corpus with nothing wrong, *a broken gate and a working one produce identical output*. `recall` hard-coded to 1.0 survived, and so did `micro_precision` hard-coded to 1.0. Added `TestGatesCanActuallyFail`, which scores deliberately corrupted input so the scorer is proven able to report failure, and it then caught both. The two remaining survivors are **equivalent**: a constant timestamp offset shifts every build identically, so two builds still compare equal and the determinism property holds; and the stale-allowlist guard is vacuous only because `observed == expected` *currently* holds — which is exactly the coincidence that guard exists to catch the end of.
- **Decomposition and why each piece is here:**
  - **`T2-01` corpus + scorer** — `AGENTIC_ARCHITECTURE.md` Layer 6: *"Golden captures are the highest-leverage single artefact in this entire document. A capture with a known answer is worth more than any prompt engineering."* It is also the phase's stated exit criterion made reachable: "an agent can drive the engine and be scored automatically on every PR" is unimplementable without ground truth, so this is the only `T2` task with nothing upstream of it.
  - **`T2-02` differential extension** — §7 asks to extend the differential suite "from 77 packets to a large generated corpus with an explicit divergence allowlist". Depends on corpus *generation*, not on the corpus, so it can be parallel or second.
  - **`T2-03` agent-tree safety suite** — `A-03`. Chosen to be in Phase 2 rather than Phase 4 because `A-03`'s own wording is that the envelope "quietly stops being true the moment agent code lands in the same repository, and nothing will report it". A guard that must precede code belongs before the code, and no agent tree exists yet, so this is the last cheap moment to write it.
  - **`T2-04` eval history / non-worse gate** — Layer 6's "Change tracking: every eval run recorded; any agent, prompt, model or rule-template change must be non-worse". Naturally last: it needs results to compare.
  - **Not scheduled, deliberately:** OTel tracing, LLM-as-judge, and cost/efficiency regression all need an agent to trace, judge, or cost. They are Phase 4 work wearing a Phase 2 label.
- **Corpus provenance (user decision, 2026-10-15):** **synthetic, generated in-repo.** Every capture's ground truth is then *true by construction* rather than asserted by hand, which is the property that makes a golden corpus worth trusting. It is also reproducible (a byte-identical rebuild), diffable, small in git, and free of the licensing and privacy weight real captures carry. Layer 6's "30+ labelled pcaps" is a floor, not a target, and synthetic is how that floor is met honestly.

### `T2-02` — Differential suite: 77 packets → generated corpus

- **Status:** done · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t2_02 · **Blocked by:** —
- **Files:** new `tests/differential/test_differential_corpus.py` (12 tests), `tests/differential/cpp_reference.py` (new `run_cpp_reference_batch` + `_parse_batch`). **No production source touched.**
- **Planned test:** the existing 14 parity tests run over the generated corpus, not just the 77-packet sample
- **How it was tackled:** `run_cpp_reference_batch` runs the C++ reference over **all 33 captures in one container**, and `test_differential_corpus.py` asserts packet-count parity for each. Batch mode exists because of a measurement, not a preference: **~7.5 s per capture individually versus 0.66 s for all 33 batched**, since essentially all the cost is container startup rather than the binary. Without it, corpus-wide parity is ~4 minutes of CI and nobody runs it; with it, the whole thing takes 6.6 s. Comparison is deliberately on **packet counts**, not classification — the allowlist already documents that app classification diverges, so asserting app equality would either fail on documented behaviour or force the test to restate the allowlist.
- **Deviations:** three.
  - **The batch addresses captures by absolute `/input/...` path, not bare name.** The single-capture path does `cd /tmp && cp /input/<name> .`, so it never encounters this. A batch that looped over bare names ran the binary in `/tmp` where the read-only capture mount does not exist: every capture reported "Could not open file", and the batch returned **33 clean all-zero reports** rather than an error. That is the worst shape this component could fail in — a differential suite that verifies nothing and looks green. Caught by comparing against single mode, and it is now an explicit mutation.
  - **"Materially larger" was corrected to what actually grew.** An early version asserted the corpus was 10x the sample by packet count; it is not. Measured: **33x the captures, 3.3x the distinct domains, 2.7x the flows, but only 1.5x the packets** (118 vs 77). It is scenario *breadth*, not volume, and the limitation is recorded rather than glossed — 33 synthetic captures of 2-8 packets is the right tool for parity across shapes and the wrong tool for anything about throughput, which is why `D-23` still needs real captures.
  - **`TestBatchFailureIsLoud` added because the parity assertions could not fail alone.** Every assertion in the parity class is satisfied by a healthy run, so a broken batch and a working one produce the same output — the same trap `T2-01` hit. Each new case *forces* a failure (a container returning 125, an unparsable segment, a missing capture) and checks it is reported.
- **Verification:** `ruff check .` clean · `mypy` (`--strict`) clean on 17 source files · `pytest -q` → **786 passed, 0 skipped** (was 774; **+12**). Differential suite **22 passed** (14 original + 8 new) in 15.7 s. **7 of 7 mutations caught, 0 void.**
- **Closed findings:** — · **Follow-ups:** the corpus is thin on volume (see Deviations); `D-23`'s throughput work needs real captures, not this
- **Notes:** `AUDIT.md` §7 asked to extend the suite "from 77 packets to a large generated corpus with an explicit divergence allowlist". Why it was capped at 77: **every test in `tests/differential/` was hardcoded to `TEST_DPI_PCAP`**, so the suite's coverage was exactly one capture's worth — which is how `D-27` survived the whole of Phase 1. The mutation harness also caught a **category error in itself**: five mutants removed assertions from the *test* file, and a test that asserts less still passes, so they were un-catchable by construction. Only production mutations are meaningful there.

### `T2-03` — Agent-tree safety suite + envelope statement

- **Status:** pending · **Claimed by:** — · **Session:** — · **Blocked by:** —
- **Files:** new `tests/test_agent_safety_constraints.py`, `docs/DESIGN_DECISIONS.md`
- **Planned test:** the agent tree is AST-scanned on its own terms, and the widened envelope is stated in writing rather than implied
- **How it was tackled:** — · **Deviations:** — · **Verification:** —
- **Closed findings:** `A-03` · **Follow-ups:** —
- **Notes:** closes `A-03`, whose point is that the existing `test_safety_constraints.py` scopes `src/dpi_engine/` only — so the "no network calls, passive and offline" guarantee "quietly stops being true the moment agent code lands in the same repository, and nothing will report it". Two things must land together: a **separate** safety suite for the agent tree, and an explicit written statement that the agent layer *will* need network (threat-intel lookups, ASN resolution, app identification) as a **deliberate, documented widening for that layer only**. Also the natural place to record that "real time" can never mean sniffing a live interface — that would break the envelope at its root.

### `T2-04` — Eval run history / non-worse CI gate

- **Status:** pending · **Claimed by:** — · **Session:** — · **Blocked by:** —
- **Files:** new eval-history storage + a CI comparison step
- **Planned test:** a deliberately worse corpus result fails the gate; an equal or better one passes
- **How it was tackled:** — · **Deviations:** — · **Verification:** —
- **Closed findings:** — · **Follow-ups:** —
- **Notes:** Layer 6's "Change tracking: every eval run recorded; any agent, prompt, model or rule-template change must be non-worse | CI gate". Naturally last — it needs results to compare. Note the tension to resolve when this is built: the baseline it compares against is itself a number in a repository, and therefore rot-prone in exactly the way `BENCHMARKS.md` already taught us to guard. `tests/test_benchmark_baseline.py` is the precedent to follow rather than invent a second mechanism.

### `DOC-01` — root `README.md` corrections

- **Status:** done · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t1_05 · **Blocked by:** —
- **Files:** `../README.md`, `src/dpi_engine/cli.py` (two `--help` strings)
- **Change:** test count unhardcoded; pcapng, VLAN, CIDR and destination-IP documented; flow folding corrected; **an explicit slower-per-packet note added**
- **How it was tackled:** every claim was checked against the source before it was written, and four turned out to be wrong in ways the task did not anticipate. Details below.
- **Deviations:** the task said "test count → the current real count". Not done, deliberately: the figure was **377** when the task was written, the previous session found **581**, and it is **601** now — it drifted by 177 and then 20 across three sessions. Publishing a number guarantees it rots. Line 20 now describes the suite and points at `Testing`, which carries the composition.
- **Verification:** `ruff check .` clean · `mypy --strict` clean · `pytest -q` → 601 passed, 12 skipped. Markdown fence balance checked (12, even). Every new claim smoke-tested: `--block-ip 10.0.0.0/8` writes `blocked_cidrs: ["10.0.0.0/8"]`; `--block-ip 10.1.2.3/8` is rejected with `has host bits set`, exactly as documented; the three variants' failure outputs measured at 458 / 24 / 24 bytes.
- **Closed findings:** `M-01` · **Follow-ups:** — (completed 2026-10-15, see below)
- **Notes:** independent of code work. Most of `M-01`'s "missing limitations" list had been **overtaken by the code fixing them**, which is the better resolution: `D-09`/`D-10` were closed by `T0-07`, so the HTTP-host vectors no longer need a limitation entry at all. `M-01` was written when they were live.
- **Follow-up completed 2026-10-15 (`ses_t1_05b`)** — `AUDIT.md` reconciled in full, which turned out to be considerably more than the single heading recorded here. See the `ses_t1_05b` row in §8.
- **Four things `M-01` did not predict, all found by checking rather than transcribing:**
  1. **The flow-folding bullet described the opposite of current behaviour.** It read "flows are keyed by exact five-tuple… preserved from the original deliberately", but `DEC-05` made bidirectional folding the **default** and added `--exact-tuple-flows` as the opt-out. A reader would have come away with the blocking scope inverted. This was the most material error in the file.
  2. **The VLAN claim was stale in the other direction.** The README said VLAN tags "are not parsed"; `T05-01` added 802.1Q peeling and it is differential allowlist entry 7. `M-01` had asked to make the limitation *louder* ("100% of tagged traffic is discarded") — doing that would have documented a bug that had already been fixed. Now recorded as a deliberate parity break instead.
  3. **The "output left on disk" claim was right for one variant and wrong for two.** `M-02c` had already corrected this in `DESIGN_DECISIONS.md`; the README carried the same stale text. Verified by measurement, not inference: single-process leaves 458 bytes (the packets written before failure), while `--workers` and `--load-balancers` both leave **24 bytes — header only**, because workers are pure compute and results are collected after dispatch.
  4. **The `22 defects` figure in the doc index was faithfully repeating a stale heading in `AUDIT.md`.** Not a README bug: `AUDIT.md:162` still reads "Defect register (`D-01`…`D-22`)" while the file actually contains `D-01`–`D-26`, and its line 171 says "Twenty-one live defects" — three different counts in one document. README corrected to 26; **`AUDIT.md` left alone** because correcting it is outside this task's scope and its §2 is a register others may be citing.
- **Also fixed, in `cli.py`:** `--block-ip` and `--unblock-ip` both read "Block a source IP." That was wrong twice over after `T1-05` — the rule matches **either endpoint** (`DEC-06`) and the flag **accepts a CIDR**. A `--help` string is user-facing documentation, and it was describing a behaviour the code had already left behind. A nonexistent `--block-cidr` flag was briefly written into the README draft and caught by re-reading the argparse definition rather than trusting the prose.

### `DOC-02` — `DESIGN_DECISIONS.md` corrections

- **Status:** done · **Claimed by:** ses_2026-10-03 · **Session:** ses_2026-10-03 · **Blocked by:** -
- **Files:** `docs/DESIGN_DECISIONS.md`, plus two code docstrings in `src/dpi_engine/`
- **Test added:** `n/a` (documentation). Verified by reading against source.
- **How it was tackled:** Six fixes, all verified against source before editing. **(a)** Struck bug-list item 1, which proposed 'guard the loop start, or omit QUIC heuristic support entirely' and so contradicted item 16 where `quic.py` implements the full RFC 9000/9001 path; rewrote it as a record of the original bug with a cross-reference to item 16. **(b)** Rewrote the testing-strategy section from a forward-looking task plan (Tasks 2-12) into a description of the five layers that exist, added `quic.py` and `report.py` to the inventory, and added an explicit **Known gaps in the test strategy** subsection naming the missing property testing, benchmarks, coverage, CI, scapy cross-check and flaky timing tests. **(c)** Corrected the partial-output limitation: it previously claimed all variants leave a partial file, but only `run_pipeline` does - both multiprocess variants write after `_collect` and `join`, so a mid-dispatch failure leaves an **empty** pcap. Added a per-variant table. **(d)** Corrected the efficiency note: it claimed the overwrite check fires after 'dispatched every packet, and been shut down/joined', but the writer is now opened at the top of the dispatch block, so the check fires before the first packet; only the post-spawn cost remains. **(e)** Added a **New open decisions** table cross-referencing `DEC-01`..`DEC-05`. **(f)** Added a **Known issues in the current port** section so the document does not imply the port is defect-free - unbounded memory, no VLAN, the `--live-rules` no-op, the unfulfilled pcap bounds claims, and the unmeasured throughput.
- **Deviations:** Scope extended beyond the audit's six items. Added the new-decisions and known-issues sections because the document would otherwise imply the port is defect-free, and a reader has no other signal.
- **Verification:** `pytest` green (docstring-only source edits). Each corrected claim re-checked against the cited code.
- **Closed findings:** `M-02` (a-f all) · **Follow-ups:** `M-02e`/`M-02f` were code docstrings and were fixed here rather than deferred to `T0-10`: `sni_extractor.py's module docstring claimed QUIC was "intentionally NOT implemented" while citing a resolved section, and `types.py:257` cited DESIGN_DECISIONS item 14 (dead-report cleanup) where items 7 and 11 were meant.
- **Notes:** The document now opens with a status banner pointing at `AUDIT.md`, and states that the audit supersedes it on any disagreement.

- **Status:** done — **Claimed by:** claude-opus-5[1m] — **Session:** ses_2026-10-03 — **Blocked by:** -
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

- **Status:** done — **Claimed by:** claude-opus-5[1m] — **Session:** ses_2026-10-03 — **Blocked by:** -
- **Files:** `AGENTIC_ARCHITECTURE.md`
- **Change:** rewrite §1–§3 from the stale-claim table in `AUDIT.md` §4.2; resequence §8 per `AUDIT.md` §4.6; **keep §4–§7 and §9 essentially verbatim**
- **How it was tackled:** — · **Deviations:** — · **Verification:** manual
- **Closed findings:** `M-04` · **Follow-ups:** — · **Notes:** do it now — the stale content is actively misleading

### `DOC-05` — `OSC/` banners + CMake correction

- **Status:** done — **Claimed by:** claude-opus-5[1m] — **Session:** ses_batch1 — **Blocked by:** -
- **Files:** `OSC/README.md`, `OSC/WINDOWS_SETUP.md`
- **Change:** superseded banner pointing at the root `README.md`; correct the claim that `CMakeLists.txt` builds DPI binaries (it builds only `packet_analyzer` from three files, no `-pthread`)
- **How it was tackled:** — · **Deviations:** — · **Verification:** manual
- **Closed findings:** `M-05` `M-06` · **Follow-ups:** — · **Notes:** these files are the provenance for every `DESIGN_DECISIONS.md` entry — retain, do not delete

### `DOC-06` — Fix `conftest.py` reference

- **Status:** done · **Claimed by:** claude-opus-5[1m] · **Session:** ses_t0_02 · **Blocked by:** `T0-02`
- **Files:** `tests/differential/README.md`
- **Change:** line 83 names a `conftest.py` that does not exist
- **How it was tackled:** resolved by the blocker rather than by editing the README. `T0-02` created `tests/conftest.py` and hoisted the duplicated fixture path into it, so the reference became true. `tests/differential/conftest.py` was added later, independently, to pin `fold_bidirectional=False` for `DEC-05`.
- **Deviations:** — · **Verification:** both files present; `M-07` closed
- **Closed findings:** `M-07` · **Follow-ups:** — · **Notes:** do together with `T0-02`
- **Status correction (2026-10-13, ses_t1_05):** the summary-table row for this task read `done` in the **Findings** column and `pending` in the **Status** column — the same column shift as `DOC-05` and `DOC-08`. The detail block said `pending`, but the append-only session log records `ses_t0_02` completing `T0-02` + `DOC-06` and closing `M-07`, and the filesystem confirms it. The record is now `done`, and the row's columns are realigned.

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

- **Status:** done — **Claimed by:** claude-opus-5[1m] — **Session:** ses_batch1 — **Blocked by:** -
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
| `P-##` port-vs-C++ | 19 | n/a — characterisation (but see `D-23`) | — | — |
| `D-##` defects | 27 | **22** (`D-01`-`D-10`, `D-12`, `D-13`, `D-14`, `D-16`-`D-18`, `D-20`-`D-22`, `D-24`-`D-26`) | 5 (`D-11`, `D-15`, `D-19`, `D-23`, **`D-27`**) | 2 (`D-23`, **`D-27`** — needs a `DEC-07` parity decision) |
| `R-##` rails | 10 | **7** (`R-01`, `R-02`, `R-03`, `R-04`, `R-05`, `R-06`, `R-08`) | 3 | 0 |
| `A-##` agentic | 6 | **1** (`A-05`) | 5 | 0 |
| `M-##` documentation | 7 | **7** (`M-01`, `M-02`, `M-03`, `M-04`, `M-05`, `M-06`, `M-07`) | 0 | 0 |
| `S-##` session | 3 | 0 | 3 | 0 |

**Register corrections (2026-10-13, `ses_t1_05`)** — this table was wrong in both
directions and was recomputed against the code rather than trusted:
- `D-##` read "16 closed / 5 open / 5 unassigned", which cannot add up (26 total),
  and listed `D-24`, `D-25` and `D-26` in **both** the closed and unassigned columns.
  Recomputed: **19 closed, 7 open, 2 unassigned**. `D-16`, `D-20` and `D-21` closed
  under `T1-05` and were absent from the closed list entirely.
- `M-##` read "4 closed / 3 open", listing `M-05` and `M-06` as open. Both are
  closed: `DOC-05` added the superseded banner to `OSC/README.md`, which is present
  at line 1. The task record was right and the register was stale.
- `D-15` is counted **open** because only its diagnostic half landed (`T05-02`);
  the reader half has no task. `D-23` stays open and unowned by design — `T0-11`
  has now landed, so it is finally re-measurable, which is what it was waiting for.
- `M-##` read "6 closed / 1 open" until `DOC-01` landed; now **7 / 0**. Every
  documentation finding is closed. `M-01`'s "missing limitations" list had
  largely been **overtaken by the code fixing them** — `D-09`/`D-10` were closed
  by `T0-07`, so the HTTP-host vectors needed no limitation entry at all.
- **Three `DOC-*` summary rows had their columns shifted**, reading `done` in the
  *Findings* column and `pending` in *Status* (`DOC-05`, `DOC-06`, `DOC-08`). All
  three are genuinely done — verified against `OSC/README.md:1`,
  `tests/differential/conftest.py`, and a transcript-free repo root. `DOC-06`'s
  detail block also said `pending`, but its blocker `T0-02` had landed and made
  its premise true. Rows realigned.
- **§1 was rebuilt.** It still read `phase: 0`, `current_task: R-05`, and a next
  action describing `extract_http_host` work that landed in `T0-07`. Since §1 is
  the only block a cold-starting agent reads, a stale one is the most expensive
  staleness in this file. The header also counted Phase 1 as 4/9, omitting
  `T1-07`; it is **5/9**.
- **Outstanding-work table** listed `D-24`, `D-25` and `D-26`, all closed. Now
  two findings need an owner: `D-13` (whose proposed owner `T0-10` landed
  without taking it) and `D-23` (now unblocked).

**Rules:**
- A finding is `closed` only when its owning task is `done` **and** a regression test exists that fails without the fix.
- **All findings now carry IDs.** `D-23` (throughput, promoted from `P-15` once
  measured), `D-24` (dead code from `S-03`), `D-25` (`packets_in`/`bytes_in`
  permanently zero) and `D-26` (unused `rule_broadcaster` parameter) were allocated
  2026-10-03, closing the gap this section previously flagged. What remains is
  *ownership*: `D-13`, `D-24`, `D-25` and `D-26` have proposed owners in §4 but no
  task yet. `D-23` is deliberately unowned until `T0-11` lands, since re-measuring
  is the entire point of it.
- New findings discovered during implementation get the next free ID in their group. **Never renumber.**

---

## 7. Deviation log

Records where reality differed from `IMPLEMENTATION_PLAN.md`. **Append-only.**
A deviation is not a failure — it is the plan being corrected by evidence.

| Date | Task | Planned | Actual | Reason | Plan updated? |
|---|---|---|---|---|---|
| 2026-10-03 | `T0-03` | add a failing test to demonstrate `D-01` | added two `xfail(strict=True)` tests instead | A red suite breaks CI, so the brief's "expected to FAIL" was not implementable as written. `strict=True` encodes "known broken" honestly and **inverts** on the fix: once `T0-11` lands the test passes and `strict=True` turns that into a failure, forcing the marker to be removed. | no — better mechanism than planned |
| 2026-10-03 | `T0-01` | do `T0-02` next (per tracker order) | did `T0-01` first | Three behavioural changes to the core had landed with only manual verification. An unused CI file is a guess; an executed one is not. Reordering also front-loads the gate every later task is verified by. | no — task order only |
| 2026-10-03 | `T0-01` | 85% coverage floor, estimated achievable | **91% with branch coverage** | Enabling `branch = true` gives a stricter, more honest figure than the line-only 93% measured earlier. Floor of 85 leaves headroom. | no — confirms the plan |
| 2026-10-03 | `T0-06` | parity assumed from the passing differential suite | parity suite could not run: Docker daemon absent | Docker Desktop is not installed on this host and no engine pipe exists, so `tests/differential` skips 12 of 14 tests. Compensated by diffing full JSON report + output-pcap SHA256 across all three pipeline variants, before vs after the change: **byte-identical**. Real parity against the C++ binary remains **unverified** — must be run once Docker is available. | no — follow-up recorded |
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
| 2026-10-15 | `ses_t2_02` | claude-opus-5[1m] | `T2-02` | **`T2-02` done** — differential suite extended from 1 capture to all 33 generated ones. Added `run_cpp_reference_batch` because of a measurement: ~7.5 s per capture individually vs **0.66 s for all 33** in one container, since the cost is startup not compute. Caught a bug that failed in the worst possible shape — addressing captures by bare name produced **33 clean all-zero reports** instead of an error, so the suite verified nothing while looking green. Also corrected my own overclaim: the corpus is 33x the captures but only **1.5x the packets** (breadth, not volume). 7/7 mutations caught | `T2-03` |
| 2026-10-15 | `ses_t2_01` | claude-opus-5[1m] | `T2-01` | **`T2-01` done** - 33 synthetic labelled captures + a per-class precision/recall scorer. **The corpus found `D-27` on its first run**: most apps are matched by bare substring, so `cdn.facebook.com.attacker.example` classifies as `FACEBOOK`. The project already fixed this class twice (Twitter's rule was anchored, Cloudflare's `"cf-"` dropped) and left every other rule carrying it. Parity-preserving, so fixing it is a parity break needing a `DEC-07`. Mutation testing also caught a real weakness in my own tests: every gate asserted something that currently passes, so a broken gate was indistinguishable from a working one | `T2-02`; and a `DEC-07` decision on `D-27` |
| 2026-10-15 | `ses_t2_01` | claude-opus-5[1m] | `T2-01` + Phase 2 decomposition | **Phase 2 had no task IDs** — the rollup said "outline", so a 2–3 week plan spanning `AUDIT.md` §7 and Layer 6 was never decomposed. Created `T2-01`…`T2-04`, deliberately **excluding** the parts of Layer 6 that cannot be built yet (tool-call / trajectory / adversarial evals need the MCP server and agents; OTel tracing, LLM-as-judge and cost tracking need an agent to trace, judge or cost). User chose corpus-first and **synthetic captures**, so ground truth is true by construction rather than asserted by hand | `T2-01` implementation |
| 2026-10-15 | `ses_t1_04b` | claude-opus-5[1m] | Phase 1 exit (criterion 3) | Docker enabled -> **differential suite 2 passed / 12 skipped becomes 14 passed / 0 skipped**, and the project its first **fully-verified 749 passed, 0 skipped** run. Added `tests/test_parity_breaks.py` (5 tests) verifying the port side of `DEC-05` and `DEC-06`, which the differential suite cannot check because it pins folding off to preserve parity. **Phase 1 now exits unconditionally** | Phase 2 (eval harness) |
| 2026-10-15 | `ses_t1_04` | claude-opus-5[1m] | `T1-04` + Phase 1 exit | `T1-04` done - rule DSL with provenance (sidecar, never in `_RuleState`'s hot-path frozensets); 14/14 mutations caught. **Phase 1 COMPLETE 9/9, exited conditionally** *(superseded the same day by `ses_t1_04b`: Docker came up, parity verified, now unconditional).* Verifying Appendix B's five exit criteria found the fifth had never been measured, and measuring it **found a real bug**: a `WatchSource` read 308 packets against `max_total_packets=50` because each file's `PcapReader` got a fresh budget. Also found my own memory test measuring below the reorder window and reporting a leak that was not one | Phase 2 (eval harness); first run `pytest tests/differential` with Docker, since parity was then the one unverifiable criterion |
| 2026-10-15 | `ses_t1_02` | claude-opus-5[1m] | `T1-02` | `T1-02` done - `CapSource` with `FileSource`/`StreamSource`/`WatchSource`. A source is an iterable of `RawPacket`, so no pipeline logic changed and `PcapReader` remains the only parser. Needed real non-rewindable stream support in `PcapReader` (it peeks 4 bytes then `seek(0)`), and `close()` had to stop closing caller-owned streams in **four** places. **11/12 mutations caught; the 12th proven equivalent by simulation, not waved off.** A test also caught `WatchSource` never terminating on a bounded watch, and the main loop and idle check *disagreeing* about a vanished directory | `T1-04` - the last Phase 1 task |
| 2026-10-15 | `ses_t1_08` | claude-opus-5[1m] | `T1-08` | `T1-08` done - benchmark baseline published (`docs/BENCHMARKS.md` + `tests/benchmarks/baseline.json`), with a rot guard that recomputes the document's figures from the JSON. **Re-measuring `D-23` made it worse, not better: 7.26x and 8.28x against the recorded 4.7x/6.2x**, so the finding stays open and narrows to a crossover measurement on realistic traffic. Also verified rather than assumed that a default `pytest tests/benchmarks` reports these as passed WITHOUT EXECUTING THEM (3.0 s vs 18-19 s) | `T1-02` or `T1-04` |
| 2026-10-15 | `ses_t1_06b` | claude-opus-5[1m] | `D-13` | `D-13` closed - the unowned LB-death defect finally got an owner and a fix. `_collect_streaming` now polls the result queue in `_LIVENESS_POLL_SECONDS` slices and re-checks liveness on each empty poll, so a dead LB is named in ~1 s instead of after the 120 s budget. The old message ("only N of M workers reported") described the *fast paths*, which are innocent. 7/7 mutations caught | `T1-08` - publish the benchmark baseline |
| 2026-10-15 | `ses_t1_06` | claude-opus-5[1m] | `T1-06` | `T1-06` done, `A-05` closed - the counterfactual engine. Two runs of the real pipeline diffed, no decision logic reimplemented, no existing source file touched. Found by a test rather than by inspection that a policy **substitution** (Facebook -> YouTube) drops the same 2 packets either way, so the net drop delta is 0 while 4 packets change disposition - so `packets_changed` is counted from the decision bitmaps and the signed figure lives in `net_packets_dropped`. 12/12 mutations caught; 100% coverage on the new module | `T1-08` - publish the benchmark baseline, the missing half of a `partial` task |
| 2026-10-15 | `ses_t1_05b` | claude-opus-5[1m] | `DOC-01` follow-up (`AUDIT.md` reconciliation) | Reconciled `AUDIT.md`. Fixed the trigger — §2's heading said `D-01`…`D-22` while its intro said "twenty-one" and the file held 26 (21 live + 5 inherited in §2.1; the heading was the only error). Then found the same rot the README had, in the two sections that present themselves as **current**: `§0` and `§4.2`. Every numeric row was stale, and five `§0` rows asserted CI, coverage, test timeout, property testing and `conftest.py` as **absent** when all five now exist — `pytest-cov` even carries `fail_under = 85`. Also refreshed the Appendix, whose expected outputs would have made a correct run look like a failure, and marked `ruff format --check` as a characterisation rather than a gate. Descriptions in §2/§5 left untouched per the document's own rule that status lives in the tracker | `T1-08` — the missing half of a `partial` task |
| 2026-10-13 | `ses_t1_05` | claude-opus-5[1m] | `T1-05` `T1-09` `DOC-01` + tracker integrity | `T1-05` done — CIDR (`D-20`), either-endpoint matching (`D-21`/`DEC-06`), stable rule keys (`D-16`/`DEC-04`) — committed `cce25c7`. `T1-09` done — server_name list walked per entry (`D-17`), hostname policy (`D-18`) — committed `e628771`. `DOC-01` done — `M-01` closed, **all `M-##` now closed**. 601 green throughout. Also corrected six task blocks that falsely read `done`, recomputed §6, realigned three malformed `DOC-*` rows, and rebuilt §1, which still said `phase: 0` and named `R-05` as the current task | `T1-02` or `T1-04`; both uncommitted |
| 2026-10-12 | `ses_t1_01` | claude-opus-5[1m] | `T1-01` | event bus done — derived `PipelineResult` — guarantee test caught 2 emission bugs | `T1-03` |
| 2026-10-12 | `ses_t1_07b` | claude-opus-5[1m] | `T1-07` | `R-05` + `R-08` closed — 45 tests, proven to bite | `T1-01` |
| 2026-10-03 | `ses_t1_07` | claude-opus-5[1m] | `T1-07` | increment 1 — `R-05` closed, 20 property tests, proven to catch `D-05` | `T1-07` increment 2 (needs `DEC-03`) |
| 2026-10-03 | `ses_batch1` | claude-opus-5[1m] | `T05-02` `R-10` `D-24` `D-25` `D-26` `DOC-05` `DOC-06` `DOC-08` | 6 items — **Phase 0.5 complete** | `R-05` |
| 2026-10-03 | `ses_t05_01` | claude-opus-5[1m] | `T05-01` | 1 task completed — `D-14` closed — Phase 0.5 exit criterion #1 met | `T05-02` (needs `DEC-02`) |
| 2026-10-03 | `ses_t0_11` | claude-opus-5[1m] | `T0-09` `T0-10` `T0-11` | 3 tasks completed — `D-03`, `D-12`, `D-01`, `D-02`, `D-22` closed — **Phase 0 complete** | Phase 0.5, or `DEC-01` for Phase 1 |
| 2026-10-03 | `ses_t0_10` | claude-opus-5[1m] | `T0-10` | 1 task completed — `D-12` closed | `T0-11` (needs `DEC-01`) |
| 2026-10-03 | `ses_t0_09` | claude-opus-5[1m] | `T0-09` | 1 task completed — `D-03` closed | `T0-10` |
| 2026-10-03 | `ses_t0_08` | claude-opus-5[1m] | `T0-08` | 1 task completed — `D-08` closed | `T0-09` |
| 2026-10-03 | `ses_t0_07` | claude-opus-5[1m] | `T0-07` | 1 task completed - `D-09` + `D-10` closed, `extract_http_host` 4x faster | `T0-08` |
| 2026-10-03 | `ses_t0_03` | claude-opus-5[1m] | `T0-03` | 1 task completed — `R-06` closed, `P-15` now **measured** | `T0-07` |
| 2026-10-03 | `ses_t0_02` | claude-opus-5[1m] | `T0-02` `DOC-06` | 1 task completed — `R-04` + `M-07` closed | `T0-03` |
| 2026-10-03 | `ses_t0_01` | claude-opus-5[1m] | `T0-01` | 1 task completed — `R-01`/`R-02`/`R-03` closed | `T0-02` |
| 2026-10-03 | `ses_t0_06` | claude-opus-5[1m] | `T0-06` | 1 task completed — `D-06` + `D-07` closed (14 tests added) | `T0-02` |
| 2026-10-03 | `ses_t0_05` | claude-opus-5[1m] | `T0-05` | 1 task completed — `D-04` closed | `T0-06` |
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

- **Status:** pending — **Claimed by:** <who> — **Session:** <session id> — **Blocked by:** <DEC-## or ->
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

**Phase 1** - all 404 existing tests pass unchanged · streaming output deterministic
under the chosen `DEC-01` option · differential parity with the C++ reference intact ·
`simulate_ruleset` working and exercised by a test · memory bounded under a streaming
run with a directory-watch source.

*Verified 2026-10-15 (`ses_t1_04`, completed `ses_t1_04b`), all nine tasks `done`.*
**All five criteria are now met and tested.** Criterion 3 was verified in a second
pass once Docker was running: the suite is **14 passed / 0 skipped**, and the whole
project is **749 passed with nothing skipped** — the first fully-verified run it has
had. `DEC-05` and `DEC-06` remain deliberate, allowlisted divergences (entries 6
and 8) rather than open risks; the differential suite excludes them so parity holds
for everything else, and `tests/test_parity_breaks.py` verifies the port side of
each claim. Criterion 5 was unmeasured until this session and the measurement found a
real defect (`WatchSource` gave every file a fresh `max_total_packets` budget, so a
308-packet run sailed past a limit of 50); it is now tested and fixed.

**Caveat on the differential suite:** it needs a running Docker daemon. A machine
without one silently reports 12 skips, and a green run there is *not* evidence of
parity — the same trap as `--benchmark-enable`.

**Per-release** — `ruff format --check` clean · coverage ≥ 85 · differential suite
green · golden-corpus thresholds met · safety suite green · `AUDIT.md` updated with
any new IDs.
