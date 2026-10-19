# Engineering Audit — `dpi-engine`

**Status:** Audit / finding register
**Subject:** `src/dpi_engine/` (Python port) compared against `OSC/src/` (C++ original), plus the repository's documentation set.
**Date:** 2026-10-03
**Scope:** Static reading of every `.h`/`.cpp`/`.py`/`.md`, plus execution of the toolchain to establish the baseline.
**Explicitly out of scope:** No code was changed to produce this document. No file other than this one was modified.

---

## How to read this document

### Finding ID scheme

Every finding has a permanent ID. IDs are the unit of citation — use them in commit messages, PR descriptions, code comments, and the next audit. **IDs survive line-number drift**, which is precisely what made the existing documentation rot (see §6).

| Prefix | Meaning | Home |
|---|---|---|
| `P-##` | Port vs. C++: an axis where the port is better or worse | §1 |
| `D-##` | Live defect in the port | §2 |
| `R-##` | Missing engineering rail | §3 |
| `A-##` | Agentic architecture finding | §4 |
| `M-##` | Documentation defect | §5 |
| `S-##` | Session-transcript reconciliation | §6 |

### One home per fact

A finding is stated **once**, in its home section, at full detail. Every other section that depends on it **links to the ID** rather than restating it. This is a deliberate structural rule, not a stylistic preference: the current documentation set already contains the failure mode this prevents — `AGENTIC_ARCHITECTURE.md` hoists the `x.com`/`t.co` check above the whole classification table while `DESIGN_DECISIONS.md` explicitly warns "do not hoist it again." Two copies of one fact diverged, and now both are wrong.

### The two severity columns

Both are reported because they answer different questions and the current roadmap conflates them.

| Column | Definition | Answers |
|---|---|---|
| **Intrinsic** | Correctness / security / data-loss impact considered in isolation. Would be a bug regardless of roadmap. | "Should I fix this?" |
| **Product blocker** | Whether it blocks the *real-time agentic product* goal. | "Does this stop us shipping?" |

The second column reorders the queue. Unwrapping VLAN/802.1Q (`D-14`) is not a bug — the code behaves exactly as documented — but it silently discards 100% of tagged traffic, so it is a harder blocker than a cosmetic defect. Conversely per-packet throughput (`P-16`) is a design choice, not a bug, but the CLI defaults to `--workers 1`, so the only path that scales is unexercised.

### Severity scale

`Critical` → data loss, hang, or unbounded resource use · `High` → incorrect security outcome or crash · `Medium` → wrong result, or correct result obtained the wrong way · `Low` → dead code, stale comment, or fragility.

---

## §0 — Baseline, verified by execution

Re-derivable at any time via the [Appendix](#appendix--verification-commands). Kept as a table rather than prose because this is the section that goes stale fastest.

> **Re-derived 2026-10-15.** Written on 2026-10-03 and read as a live baseline,
> by 2026-10-15 every row except the runtime deps and the Python pin had moved —
> and five rows asserted rails that **now exist**: CI, coverage, test timeout,
> property testing and `conftest.py`. A baseline that is quoted but not
> refreshed is worse than none, because it looks like evidence. The commands in
> the right-hand column are the source of truth; if your run disagrees with this
> table, trust your run.

| Property | Value | Command |
|---|---|---|
| Modules | 14 + `py.typed`, ~6,800 lines | `src/dpi_engine/*.py` |
| Runtime deps | 1 (`dpkt`) | `pyproject.toml` |
| Optional extra | `cryptography` (QUIC decryption only) | `[project.optional-dependencies].quic` |
| Dev deps | 9: `pytest`, `scapy`, `cryptography`, `ruff`, `mypy`, `pytest-cov`, `pytest-timeout`, `pytest-benchmark`, `hypothesis` | `[dependency-groups].dev` |
| Tests | **613 collected — 601 passed, 12 skipped** (the 12 skips are the Docker-dependent differential tests) | `uv run pytest -q` |
| Lint | `All checks passed!` | `uv run ruff check .` |
| Types | `Success: no issues found in 14 source files` — `strict = true`, `warn_unreachable = true` | `uv run mypy` |
| Format | **31 files would be reformatted**, 33 already — **not enforced**. The project lints with `ruff check` and has not adopted `ruff format`; treat this as a characterisation, not a gate | `uv run ruff format --check .` |
| Commits | 27 | `git log --oneline` |
| CI | **present** — `.github/`, added by `T0-01` | `Test-Path .github` |
| Coverage | **measured** — `branch = true`, `fail_under = 85` | `[tool.coverage]` in `pyproject.toml` |
| Property/fuzz testing | **present** — `hypothesis` properties plus a scapy cross-check under `tests/property/` | `uv run pytest tests/property` |
| Test timeout | **present** — `pytest-timeout`, `timeout = 30` under `[tool.pytest.iniOptions]` | `pyproject.toml` |
| `conftest.py` | **present**, at both `tests/` and `tests/differential/` | `Test-Path tests/conftest.py` |
| Python | 3.13, pinned `<3.14` | `.python-version` |

**Baseline conclusion.** The codebase is in materially better shape than the pre-existing `AGENTIC_ARCHITECTURE.md` claims: type-clean, lint-clean, well-tested, and honestly documented at the module level. The engineering failures that remain are concentrated in **memory behaviour**, **resource-boundedness claims**, and **repository rails** — not in correctness of the decision logic.

**That conclusion has held, and the rails gap it names has since closed.** As of 2026-10-15 the five open defects are `D-11`, `D-13`, `D-15`, `D-19` and `D-23` — none of them a correctness defect in the decision logic. The one regression this audit led with, `D-01` (unbounded accumulation), is closed.

---

## §1 — Verdict: is the Python port better than the OSC C++?

> ### Verdict
>
> **Yes on correctness, safety, and auditability — by a wide margin. No on two specific axes, one of which is a serious architectural regression.**
>
> The port is not "the same engine in a different language." It fixes a material number of real defects in the original, including memory-unsafety, two genuine data races, a shutdown protocol that could corrupt output, and a rule engine that could silently accept blocking rules which never matched anything. It is also, in all likelihood, **slower per packet** than the original — and that is not a cost that has been measured or acknowledged anywhere in the repository.

The comparison below was made by reading all 11 headers and 12 sources in `OSC/` and all 13 modules in `src/dpi_engine/`. `OSC/CMakeLists.txt` builds only `packet_analyzer` from three files (`main.cpp`, `pcap_reader.cpp`, `packet_parser.cpp`) with no `-pthread`; every DPI binary was a hand-written `g++` invocation, and `dpi_engine.cpp` is **never compiled by anything**. The behavioural reference for the port is `OSC/src/main_working.cpp`.

### §1.1 — Axes where the port is strictly better (11 axes, plus 2 corrections)

Do not regress these. They are the reason the port is trustworthy.

The first table is the eleven **axes** — places where the port is better on the
merits. The second is two **behavioural corrections** that were ported
deliberately. Both tables carry `P-##` IDs, so §1.1 holds thirteen IDs in total;
they are split because an axis and a correction are different kinds of claim.

| ID | Axis | OSC C++ | Port | Evidence |
|---|---|---|---|---|
| `P-01` | Memory safety of dissection | `reinterpret_cast` onto unaligned `uint8_t*`; missing post-session-ID bound check in `extract()` | dpkt struct unpacking; **every** offset advance pre-validated | `sni_extractor.cpp:45-127` vs `sni_extractor.py:89-196` |
| `P-02` | QUIC SNI extraction | `QUICSNIExtractor::extract` computes `payload + i - 5` — **literal out-of-bounds read** at `i < 5`, and passes `length - i + 5` which overruns by 5 bytes. Also a functional no-op: `payload[i-5]` is almost never `0x16`, so `isTLSClientHello` always rejects. And it is never called by any engine path. | Real RFC 9001 Initial decryption: HKDF, header protection, packet-number reconstruction, AES-128-GCM, CRYPTO-frame reassembly. Verified against RFC 9001 A.1 vectors. | `sni_extractor.cpp:291-296` vs `quic.py:96-730` |
| `P-03` | Flow-table data race | `GlobalConnectionTable::getGlobalStats()` holds a mutex guarding **only a pointer vector**, then iterates each tracker's live `unordered_map` while the owning FP thread mutates it | No shared mutable state; immutable snapshots merged after the fact | `connection_tracker.cpp:180-202` |
| `P-04` | LB stats data race | `LoadBalancer::getStats()` is `const` but **copies** `per_fp_counts_`, a plain `std::vector` written by the LB thread. Header comment claims "Not shared, so no atomics needed" — it *is* shared. | Per-LB `LoadBalancerStats`, combined by the parent after `join()` | `load_balancer.cpp:83`, `load_balancer.h:86` |
| `P-05` | Pointer stability | `getOrCreateConnection` returns `Connection*` into a map that **rehashes** on growth — structurally unsafe API; any retained pointer dangles | Object identity is stable | `connection_tracker.cpp:36` |
| `P-06` | Shutdown protocol | `running_ = false` in `stop()` makes the output thread exit **while FPs are still pushing**; subsequent pushes hit a shutdown queue and are **silently dropped**. Reader thread may write the output header *after* packet records → corrupt pcap. 700 ms of unconditional `sleep_for`. | Dispatch-then-sentinel ordering; LB drains to exhaustion before fanning out sentinels; 120 s `_collect` timeout converts a lost worker into a diagnosable error; terminate-on-failure path | `dpi_engine.cpp:89,117,153,179` vs `pipeline.py:548-573,615-653` |
| `P-07` | Queue semantics | `ThreadSafeQueue::push` **silently discards** the item when shut down (`if (shutdown_) return;`) — the exact bug the sentinel protocol exists to prevent | Queues are never shut down while pushes are possible; sentinel is a distinct `None` value | `thread_safe_queue.h:26` vs `load_balancer.py:68` |
| `P-08` | Rule pattern correctness | `blockDomain` classifies a rule as a wildcard if it contains `*` **anywhere**, but `domainMatchesPattern` only honours a `*.` prefix. So `example.*`, `foo*bar`, `*`, `a*b.example.com` are stored, counted, echoed, persisted — and **never match anything**. A security control that silently does nothing. | Insertion-time rejection with a clear error | `rule_manager.cpp:105-113,132-150` vs `rule_manager.py:140-215` |
| `P-09` | Rule case sensitivity | Exact-match path compares the raw string; pattern path lower-cases. Two semantics in one function ⇒ `--block-domain FACEBOOK.com` never matches, `*.FACEBOOK.com` does. | Lower-cased everywhere | `rule_manager.cpp:156,161-168` |
| `P-10` | Hot-path cost of rule checks | `shouldBlock` formats the IP to a **string and re-parses it on every packet**, and `isDomainBlocked` allocates two `std::string` copies per wildcard pattern per packet while holding a shared lock | `int in frozenset`; zero string work on the IP path | `rule_manager.cpp:209-217` vs `rule_manager.py:259-296` |
| `P-11` | Classification accuracy | Unanchored substrings. Verified: `'x.com' in 'netflix.com'` is `True` and `'t.co' in 'microsoft.com'` is `True` ⇒ **`www.netflix.com` classifies as Twitter/X**. `'cf-'` matches any domain containing it. | Domain-boundary anchoring; bare substrings dropped | `types.cpp:68-193` vs `types.py:33-41,172-248` |

Two more behavioural corrections, both ported deliberately:

| ID | Correction | Evidence |
|---|---|---|
| `P-12` | Two-tier hash was **degenerate**. Both levels use the same hash with a different modulus; with the default 2 LBs × 2 FPs the moduli are equal, so `lb_index ≡ fp_global_index` — LB0 serves only FP0 and LB1 serves only FP1, forever. **Half the pool is idle.** The port salts each tier separately. | `load_balancer.cpp:75,132`; `dpi_mt.cpp:343,494` vs `load_balancer.py:86-87` |
| `P-13` | LRU eviction is O(1) (`OrderedDict.popitem(last=False)`) vs an **O(n) full scan run on every insert** once the table is full; and the reaper is cadence-triggered inside the hot path rather than only running when the input queue was idle for 100 ms — meaning OSC's `cleanupStale` **never ran under sustained load**. | `connection_tracker.cpp:150-162`, `fast_path.cpp:54-57` vs `connection_tracker.py:183-186,434` |

Also revived: `GlobalConnectionTable::generateReport` was dead code in OSC (built, never printed). It is wired into normal `run` output here.

### §1.2 — Axes where the port is worse (2)

#### `P-14` — Unbounded memory. This is a regression, and it is the most serious finding in the audit.

The original streamed packets: a fast-path produced a decision, invoked an output callback, and the packet was written out. The port instead **materialises every packet in memory for the entire run and ships it back to the parent as one pickled blob**.

The mechanism, end to end:

1. `FlowProcessor.process` appends a `ProcessedPacket` (holding a full `RawPacket`) to a list for **every packet**. Nothing prunes it, and `--max-connections` does not bound it — that flag bounds the *flow table*, not this list.
2. On shutdown the worker pickles that entire list as a single `WorkerResult`.
3. The parent concatenates all workers' lists and performs one `sort(key=sequence_index)` over the union — which is the *only* reason output order is currently deterministic.
4. Every `mp.Queue` in the design is created with no `maxsize`. The parent's dispatch loop therefore **cannot block**, so on a large capture it will fill RAM as fast as the disk can be read, faster than any worker drains.

At the documented defaults (`--max-total-packets 10_000_000` × `--max-packet-size 65535`) a single worker's accumulation is unbounded in practice and can reach hundreds of gigabytes across the process set. **Every other resource bound in the codebase is defeated by this one list**, which is why it is ranked `Critical` intrinsically and blocks the product.

The original's `ThreadSafeQueue` had genuine backpressure (blocking `push` at 10,000). The port has none — memory is the only backpressure, and memory is exactly what runs out. The trade was presumably made to buy deadlock-freedom, which is a legitimate reason; it is not a legitimate reason to ship unbounded.

#### `P-15` — Per-packet throughput.

> **Promoted to `D-23` on 2026-10-03.** This was originally filed here as a
> characterisation ("unmeasured and probably worse"). It has since been
> measured, and the result is a quantified regression rather than an open
> question: **the multiprocess path is 4.7× slower than single-process and the
> staged path 6.2× slower.** See `D-23` for the figures and caveats.

Concrete costs the port added that the original did not have:

| Cost | Original | Port |
|---|---|---|
| Per-packet inter-process transfer | `PacketJob` moved through a queue | `WorkItem` **pickled** through an `mp.Queue` |
| Flow hashing | compile-time `hash_combine` | pure-Python boost-mix, ~10 Python-level ops per packet |
| Dissection | C++ field offsets | dpkt in Python |
| Return path | decisions counted in place | **every packet** pickled back, then sorted |
| Per-packet output | streamed | buffered until every worker has joined |

The repository concedes this indirectly without stating it: `pipeline.py` documents the staged topology as "queue-decoupling and observability, not throughput", and the CLI **defaults to `--workers 1`**. So the code path that exists in order to scale is not the default and has no throughput benchmark. There is no `pytest-benchmark` and no benchmark suite at all (`R-06`).

**Honest position:** this port is better on everything except the two things that matter for running against real traffic at line rate. Whether it is fast enough for a real capture is **currently unknown and untested** — which is itself the finding.

### §1.3 — Deliberately-carried quirks (correct for parity, wrong for product)

These are **not** undiscovered bugs. Each is a conscious decision to preserve C++ behaviour. They are listed so that nobody later "discovers" them and either re-fixes them by accident or wastes time re-reporting them.

| ID | Quirk | Consequence | Ref |
|---|---|---|---|
| `P-16` | Flows keyed by **exact** five-tuple, not direction-folded | Client→server and server→client are independent entries. The direction carrying the ClientHello is classified and potentially blocked; the reverse is **not**. A block does not apply to the other direction. Folding would change blocking scope, so it was left as an option for the product phase. | `pipeline.py:37-46` |
| `P-17` | A recognised-but-unmapped name is labelled `HTTPS`, even on port 80 | Matches the original's documented fallthrough. Preserved rather than "fixed" into a different label. | `types.py:248` |
| `P-18` | HTTP methods matched on their first 4 bytes | `DELETE` matches via `DELE`, `OPTIONS` via `OPTI`. A classification-accuracy nit inherited for parity. | `sni_extractor.py:201` |
| `P-19` | DNS name-compression pointers not followed | Legal but rare in a question section; parsing stops early and may return a truncated name. Cannot loop or read out of bounds. | `sni_extractor.py:303` |

---

## §2 — Defect register (`D-01`…`D-28`)

> **Closure is tracked in [`TASK_TRACKER.md`](TASK_TRACKER.md) §6, not here.** This
> section is the *description* of each finding and is its single home. A row below is
> not updated when a defect is fixed — read the tracker's findings table for whether a
> given `D-##` is still open. If this section and the tracker ever appear to disagree
> about a fact rather than about status, the tracker is describing current state and
> this section describes what was found.

Twenty-eight defects were found, with no gaps in the numbering. **Twenty-three** are
live in the port and appear in the table below: `D-01`…`D-16` plus
`D-22`…`D-28`. The remaining **five** — `D-17`…`D-21` — are inherited C++
behaviour carried forward deliberately and are described in §2.1. So the section
heading, this paragraph and §2.1 all agree: 23 + 5 = 28.

Ordered by intrinsic severity, then product impact. `D-22` is grouped with
`D-01` and `D-23` is promoted from `P-15`, so neither is in numeric order. All
locations were verified against the tree as of 2026-10-03, when this audit was
written. Several have since moved or been fixed — which is expected, and is why
status lives in the tracker rather than here.

| ID | Intrinsic | Product | Location | Issue | Suggested fix |
|---|---|---|---|---|---|
| **`D-01`** | **Critical** | **Blocker** | `worker.py` (`ProcessedPacket` accumulation), `pipeline.py:829-830` | `P-14`. Every packet's full `RawPacket` is retained for the whole run and returned as one pickled `WorkerResult`; all queues unbounded so the parent cannot apply backpressure. Defeats every other resource bound. | Emit forward/drop decisions through a bounded queue as they are made; keep only bounded per-flow state in the worker. Reorder with a bounded window. See `A-05` for the ordering constraint this interacts with. |
| **`D-02`** | High | **Blocker** | all `mp.Queue()` sites in `pipeline.py` | **No backpressure anywhere.** `maxsize` is never set and `put(timeout=)` is never used. Converts every overload into OOM rather than into slowdown. | `maxsize=` on packet queues, or a token semaphore shared across the process set. |
| **`D-23`** | **High** | **Blocker** | `worker.py`, `pipeline.py` (measured) | **The multiprocessing paths are slower than not using them.** Promoted from `P-15` once measured. **Re-measured 2026-10-15** (`T1-08`, published in [`BENCHMARKS.md`](BENCHMARKS.md) and `tests/benchmarks/baseline.json`) — 4000 packets, Windows, Python 3.13, Ryzen 5 5600H: single-process **137.5 ms (29 Kpps)**; `run_pipeline_multiprocess` with 4 workers **998.8 ms (4 Kpps)** — **7.26× slower**; `run_pipeline_staged` with 2 LB + 4 FP **1138.7 ms (4 Kpps)** — **8.28× slower**. The original measurement read 4.7× and 6.2×, so **the ratios have grown by roughly half since `T0-11`** — bounding worker memory removed the per-packet *bytes*, not the per-packet *pickle*, so it made the IPC path slightly heavier without touching the thing that dominates it. Per-packet costs that cause it: a `WorkItem` is pickled per packet in each direction, the five-tuple hash is a pure-Python mix, and every packet now rides back as a bit in a decision bitmap (`D-01`). Micro-benchmarks: `parse_packet` 10.73 µs (the dominant per-packet cost, ~7× SNI extraction), `extract_dns_query` 1.98 µs, `extract_http_host` 1.61 µs, `extract_sni` 1.57 µs, `sni_to_app_type` 0.59 µs. **Caveats that keep this honest:** 4000 synthetic 54-byte frames over-weight both process spawn and per-record pickling, so the *direction* is trustworthy while the magnitude would shrink on real traffic — and the magnitude is workload-specific enough that it should not be quoted as a property of the engine. This does not mean multiprocessing can never pay off — it means the crossover point is unmeasured and is nowhere near a small capture. | Keep `--workers 1` as the default (it already is). Establish the crossover point before offering a worker-count recommendation. Do not present the multiprocess paths as a throughput feature until then. **The `T0-11` re-measurement is now done and the answer was "materially worse", so the next step is the crossover point on a realistic capture, not another round of this benchmark.** |
| **`D-24`** | Low | Low | `packet_parser.py:204`, `rule_manager.py:348`, `load_balancer.py:139,277`, `types.py:292` | **Dead code reached from no production path**, found while auditing the session transcripts (`S-03`): `packet_parser.five_tuple_of` (superseded by `pipeline._make_five_tuple`), `rule_manager.STATIC_RULES` (the documented "no rules" case — the pipelines build a fresh snapshot instead), `load_balancer.queue_for` (the pipelines call `select_fp` directly), `LoadBalancerStats.packets_unroutable` (declared, summed, serialised into JSON, **never incremented anywhere**), and `PacketAction.INSPECT` / `LOG_ONLY` (never produced by any code path). | Delete, or wire up. `packets_unroutable` is the only one that earns its place — either count the condition it describes or remove the field rather than reporting a permanent zero. Note `test_safety_constraints.py` already has the pattern for AST-scanning shipped source; a no-unreachable-symbol check would prevent this recurring. |
| **`D-25`** | Low | Low | `types.py:311,313`, `worker.py:347` | **`Connection.packets_in` / `bytes_in` are permanently 0.** `update_connection` is called exactly once per flow with `is_outbound=True`, so nothing ever writes the inbound counters. `packet_parser` does not determine which side of a capture is the client, so this is a deliberate simplification — but the fields are exported, so any consumer reading them gets a confident zero. | Either document them as reserved and stop exporting them, or derive an inbound/outbound split from the SYN/SYN-ACK handshake the state machine already observes. The second is more useful and is probably cheap. |
| **`D-26`** | Low | Low | `pipeline.py:379` | **`run_pipeline`'s `rule_broadcaster` parameter is never supplied.** The CLI builds its kwargs without it, so the parameter is reachable only from tests. Not a bug, but a public API surface that implies a capability the shipped entry point does not use. | Wire it up in `_cmd_run` if live rules should be reachable from the single-process path too, or drop the parameter. Related: `D-03` (`--live-rules` silently ignored under `--load-balancers`) is the same confusion seen from the other direction. |
| **`D-27`** | Medium | High | `types.py:200-245` (`_SNI_RULES`) | **Most apps are classified by bare substring match, so an attacker-controlled hostname containing an app name is classified as that app.** Measured on the golden corpus (`T2-01`): `cdn.facebook.com.attacker.example` -> `FACEBOOK`, `www.facebook.com.evil.example` -> `FACEBOOK`, `microsoft-update.evil.example` -> `MICROSOFT`, `microsoft.com.attacker.example` -> `MICROSOFT`, `cdn.apple.evil.example` -> `APPLE`, and `notfacebook.com` -> `FACEBOOK`. **The project has already recognised this bug class twice** and fixed it for two rules only: Twitter's `x.com`/`t.co` were anchored (`types.py` docstring: unanchored they false-positive on `netflix.com`, `microsoft.com`), and Cloudflare's `"cf-"` substring was dropped outright because "it matches any domain containing that text". GOOGLE, FACEBOOK, NETFLIX, MICROSOFT, INSTAGRAM and every other rule still carry it. **Parity-preserving** — the C++ original substring-matches too — so this is a deliberate-looking inherited weakness rather than a port-introduced bug, and fixing it is a parity break needing a decision. For a blocking engine a false positive is a false block, so this is user-visible and worth a decision rather than a note. **Found by the golden corpus on its first run**, which is the corpus earning its keep immediately. | **ACCEPTED 2026-10-18 as `DEC-07`; current behaviour kept deliberately.** Both candidate fixes were implemented and measured before deciding: label-boundary anchoring regresses **2 of 17** legitimate hostnames (`d1.awsstatic.com`, `cdn.example-cloudfront.net`) and still misses 4 of 6 attacks; registrable-domain matching regresses **3 of 17** (also `outlook.office365.com`) though it does block all 6. The regressions are instructive - `aws` is a substring of `awsstatic`, `office` of `office365` - so **these rules depend on substring matching to work at all**, and anchoring is a curation project rather than a patch. Keeping parity was preferred over a sixteen-list maintenance commitment taken as a side effect of an audit finding. **Not buried:** carried in `tests/golden/scoring.py`'s `KNOWN_DIVERGENCES` with reasons, reported as per-class precision loss, and a test asserts `FACEBOOK` *stays* weak so the allowlist is told to shrink if this is ever fixed. Operator mitigation exists today: `DomainPattern` anchors, and domain rules are checked *after* app classification, so an exact-match rule overrides it. Full rationale in `DESIGN_DECISIONS.md`. |
| **`D-22`** | High | **Blocker** | `worker.py:151,152,157` | **Unbounded per-worker state that `--max-connections` does not cover.** Three containers grow for the whole run and are **never pruned**: `blocked_tuples` (monotonic set, one entry per blocked flow), `blocked_flows` (append-only report payload), and `_quic_inspectors` (a dict of per-flow QUIC reassembly buffers, each up to `MAX_CRYPTO_BUFFER` = 64 KiB). The tracker's LRU bounds the *flow table*; nothing bounds these. Verified: `worker.py` contains no `pop`/`clear`/`del`/eviction for any of the three. Worst case is `flows × 64 KiB` of QUIC reassembly buffer. Same defect family as `D-01`; grouped here rather than renumbered. | Tie `_quic_inspectors` to the tracker's lifecycle (evict with the flow, or give it a bounded LRU at `max_connections`). Prune `blocked_tuples` when the corresponding flow leaves the tracker — no correctness loss, since a reappearing flow is re-evaluated by the rule check anyway. Cap `blocked_flows` with a documented limit plus an overflow counter. |
| **`D-03`** | High | High | `cli.py:379-387`, `pipeline.py:656-669` | `--live-rules` is **silently ignored** with `--load-balancers`. `run_pipeline_staged` has no `live_rules` parameter and creates no control queues; `cli._execute` builds a `common` dict that omits it. The flag's help text promises a per-worker control channel unconditionally. No warning, no error. | Either thread `live_rules` through `run_pipeline_staged`, or reject the flag combination at parse time with a clear message. |
| **`D-04`** | High | Medium | `pcap_io.py:239` | `PcapWriter.__init__` calls `open(self.path, "wb")` **unguarded** → raw `FileNotFoundError` on a bad directory. `cli.py:353` catches only `(PcapError, ValueError)`, so the user gets an unhandled traceback instead of the `error: ...` the module contract promises. `PcapReader._open` *does* wrap `OSError`; the writer does not. | Wrap in `try/except OSError` → `raise PcapError(f"Cannot open output file ...")`. Mirror `PcapReader._open`. |
| **`D-05`** | High | High | `sni_extractor.py:68,98` | `is_tls_client_hello(payload, length=999)` and `extract_sni(payload, length=999)` on a 5-byte payload raise `IndexError`. `length` is never clamped to `len(payload)`, while both docstrings promise "Never raises on malformed/truncated/adversarial input". | `length = min(length, len(payload))` at both sites. One line each. |
| **`D-06`** | High | Medium | `pcap_io.py:197` | `RawPacket.orig_len` is assigned `len(buf)` and can therefore never differ from `len(data)`. dpkt's `Reader.__iter__` yields `(ts, buf)` and **discards** the pcap record's `origlen` field. The `RawPacket` docstring explicitly claims the on-wire length is preserved on truncated captures — **documented but not implemented**. Every downstream byte counter under-reports on snaplen-truncated captures. `tests/test_pcap_io.py:41` asserts `len(pkt.data) == pkt.orig_len`, **locking the bug in**. | Read the 16-byte per-packet record header directly (which `D-07` requires anyway) and populate `orig_len` from it. Fix the test to assert the truncation case. |
| **`D-07`** | High | Medium | `pcap_io.py:175-181` | `max_packet_size` is checked **after** dpkt has already executed `self.__f.read(hdr.caplen)`. The module docstring states the bound exists "so a corrupted/adversarial `caplen` field cannot trigger an unbounded read or allocation" — the allocation has already happened. A crafted `caplen = 0xFFFFFFF0` triggers a multi-gigabyte read attempt before rejection. | Read the 16-byte record header directly, validate `caplen` against `max_packet_size`, *then* read. This is the same change that fixes `D-06`. |
| **`D-08`** | Medium | Medium | `worker.py:273-274` | `quic_undecryptable` **over-counts**. It increments whenever `inspector.undecryptable_packets` is truthy, but that is a **cumulative** counter. Once any Initial on a flow fails, every subsequent Initial on that flow counts as undecryptable even when it decrypted cleanly and simply had not yet completed the ClientHello. The reported metric is wrong, and it is the metric a reader uses to judge QUIC coverage. | Track the **delta** per `feed()`, or have `feed()` return a per-packet outcome flag. |
| **`D-09`** | Medium | High | `sni_extractor.py:238-261` | `extract_http_host` scans the **entire payload** for a case-insensitive `Host:` with no CRLF header-section boundary and no preceding-boundary check. Verified: `GET /?u=http://Host:x HTTP/1.1` yields `"x HTTP/1.1"`. A POST body, redirect `Location:`, or `User-Agent` can therefore produce a bogus host, which then feeds **both** `sni_to_app_type` and domain-rule matching. Attacker-controllable false classification **and** false blocking. | Bound the scan to the header block (first `\r\n\r\n`), require the match to start at a line start, and drop `CONNECT`/`TRACE` handling gaps. |
| **`D-10`** | Medium | Low | `sni_extractor.py:252-254` | `host.find(":")` strips at the first colon. Verified: `Host: [2001:db8::1]:8080` yields `'[2001'`. Only strip a colon that appears **after** a closing `]`. | Prefer `partition(":")` unless the host starts with `[`, in which case split on `]:`. |
| **`D-11`** | Medium | Medium | `pipeline.py:861` | `_RESULT_TIMEOUT_SECONDS = 120.0` **can fire on a healthy run.** Because `D-01` forces workers to drain their entire backlog before exiting, a multi-GB capture legitimately exceeds 120 s after the parent finishes dispatching. A correct slow run is reported as a `RuntimeError`. | Make the budget scale with outstanding work (e.g. a progress heartbeat from each worker) rather than being a constant. |
| **`D-12`** | Medium | Medium | `pipeline.py:569-573`, `:775-785` | `_collect`, `join`, and `_close_quietly` are **not** wrapped in `try/finally`. A `RuntimeError` from `_collect` leaks live worker processes and unclosed queues — i.e. the failure path re-introduces the leak the shutdown protocol exists to prevent. | Wrap in `try/finally`; terminate and close on any exit path. |
| **`D-13`** | Medium | High | `pipeline.py:650-651` | **Staged pipeline: an LB process death orphans all of its fast-paths forever.** Only `_lb_main` sends FP sentinels, so if an LB dies its FPs block indefinitely on `input_queue.get()` and the parent discovers it only via the 120 s timeout. | Supervise LBs: check `is_alive()` on each LB as results arrive, and terminate + sentinel its FPs on death. |
| **`D-14`** | Medium | **Blocker** | `packet_parser.py:159` | **No VLAN/802.1Q unwrapping.** `dpkt.ethernet.VLANtaggedEthernet` is never handled, so **100% of VLAN-tagged traffic is silently discarded** as non-IP. VLAN-tagged captures are extremely common in enterprise networks. Inherited from the original, but it means the tool currently fails on the traffic it is most likely to be pointed at. | Peel `0x8100`/`0x88a8` (and QinQ `0x9100`) tags in a loop before EtherType dispatch. ~30 lines. |
| **`D-15`** | Low | Medium | `pcap_io.py:126-131`, `packet_parser.py:159` | **No pcapng.** `dpkt.pcap.Reader` rejects the magic, surfacing `PcapFormatError("not a valid pcap file")` for a perfectly valid pcapng file — a misleading diagnostic for the second-most-common capture format. | pcapng reader, or at minimum detect the `0x0A0D0D0A` magic and raise `PcapError("pcapng is not supported; convert with `editcap -F pcap`")`. |
| **`D-16`** | Low | Low | `rule_manager.py:401,323` | Rules-file persistence keys are **human-readable display names** (`"Twitter/X"`, `"GitHub"`). Renaming a display string silently invalidates every previously saved rules file. A case-insensitive lookup was added for *input*, so the input and persistence paths still use two different maps. The obviously stable key (`AppType.name`) is unused. | Persist `AppType.name`; accept display names as an input-only alias with a deprecation path. |
| **`D-28`** | Low | Low | `tests/safety_envelope.py:323` | **The envelope scanner's secondary regex net reports attribute calls as bare ones.** The primary AST pass resolves `re.compile(...)` correctly to `re.compile`, which is not forbidden — but the fallback net then matches the raw text with `\bcompile\s*\(`, and `\b` matches between `.` and `c`, so `re.compile(` is reported as `dynamic_exec` and the shipped file fails its envelope. **Any** `x.compile(`, `x.eval(` or `x.exec(` is affected. Found by `T3-02`, whose `run_store.py` was the first shipped module to call `re.compile` — the scanner has been wrong since `T2-03` and simply never had a trigger. This fails *closed* (a false alarm, not a missed call), so it is not a hole in `A-03`'s guarantee, and the workaround the alarm encourages — spelling the call some other way — is exactly the evasion the scanner exists to catch. That is the cost: a guard whose false positives teach people to work around it stops being a guard. | One character class: `(?<![\w.])` in place of `\b` in the same pattern, so a prefix preceded by `.` (or a word character) is not a bare-name match while ` compile(` still is. **Needs its own task with its own mutation proof** — it is a change to a safety invariant, and the mutation harness already demonstrates how easily a scanner edit becomes a vacuous pass. Do **not** add a regression test that pins the current behaviour: `D-06` records what happens when a test locks a bug in. |

### §2.1 — C++ bugs the port inherited (carried forward, not introduced)

These are *not* port defects — they are inherited behaviour that the port chose to preserve. Listed so they are not re-litigated, and so the roadmap can decide to fix them deliberately.

| ID | Issue | Inherited from |
|---|---|---|
| `D-09`, `D-10` | HTTP `Host:` full-payload scan; IPv6 colon strip | `sni_extractor.cpp:168-197` |
| `D-17` | SNI extension whose first name entry is not `host_name` (`0x00`) uses `break`, aborting the **entire extension loop**, so a valid `server_name` later in the same extension is never found. Every other early-out in the function is correctly scoped. | `sni_extractor.cpp:107,110,115` |
| `D-18` | **No hostname length or character validation.** `extract_sni` can return up to 65535 bytes, which is then `.lower()`-scanned against ~60 patterns, linearly scanned against wildcard rules, stored on `Connection.sni`, and pickled across a process boundary. Real SNI hostnames are ≤253 characters. No DNS 255-byte total-name limit either. | — |
| `D-19` | **No IPv6.** Every IPv6 packet becomes `has_ip=False` and is dropped. | `packet_parser.cpp` |
| `D-20` | **No CIDR/subnet rules.** `ipaddress` is already imported; blocking `10.0.0.0/8` currently requires 16,777,216 individual rules. | `rule_manager.py` |
| `D-21` | **No destination-IP blocking.** `should_block` takes `src_ip` only. | `rule_manager.py:259` |

---

## §3 — Engineering rails gaps (`R-01`…`R-10`)

Not defects in behaviour. These are the reasons a future change can break something without anyone finding out.

| ID | Gap | Evidence | Impact | Fix |
|---|---|---|---|---|
| **`R-01`** | **No CI configuration of any kind** | No `.github/`, `.gitlab-ci.yml`, `.circleci`, `azure-pipelines.yml`, `Jenkinsfile` | Nothing is verified automatically. "Tests pass" is a claim a human makes from memory. | GitHub Actions: `uv sync` → `ruff check` → `mypy` → `pytest`; a second job with Docker for the differential suite. |
| **`R-02`** | **No coverage measurement** | No `pytest-cov`/`coverage.py`, no `.coveragerc` | The coverage percentage is **unknown** and therefore cannot regress without detection. | `pytest-cov` with a floor (85% suggested), uploaded as an artifact. |
| **`R-03`** | **No `pytest-timeout`** | Not installed | A regression into the `D-11`/`D-13` hang path **hangs the suite** rather than failing it — the worst possible failure mode for a test suite. | `pytest-timeout` with a per-test default and a longer bound for the stress tests. |
| **`R-04`** | **`conftest.py` absent but referenced** | `tests/differential/README.md:83` names `build_reference_binary()` in `conftest.py`/`cpp_reference.py`; there is no `conftest.py`. The `cpp_available` fixture is duplicated verbatim across two modules; the `FIXTURES` path is duplicated verbatim across **8** test files. | Fixing a fixture means editing eight files. Documentation is wrong. | Add `tests/conftest.py`; hoist both the fixture and the path constant. |
| **`R-05`** | **No property-based or fuzz testing** | No `hypothesis`, no `atheris`. The only fuzz-like coverage is one deterministic truncation sweep over a single fixed ClientHello. | This codebase *exists* because of byte-level parsing bugs. It is the single worst place to skip property testing. `D-05` and `D-19` are exactly the bugs Hypothesis would have found. | `hypothesis` strategies over `sni_extractor`/`quic`/DNS/HTTP: arbitrary byte strings, truncations, and arbitrary `length` arguments, asserting no exception and bounded output. |
| **`R-06`** | **No benchmark suite** | **Fixed.** `pytest-benchmark` added with `tests/benchmarks/`, opt-in via `--benchmark-disable` in `addopts`. **`P-15` is now measured** and promoted to `D-23`: multiprocess is 4.7x slower than single-process, staged 6.2x. | Re-measure after `D-01`; establish the multiprocess crossover point. |
| **`R-07`** | **Three flaky-by-construction tests** | `test_eviction_cost_does_not_grow_with_table_size` (`< small*10 + 1.0`), `test_no_packet_loss_under_artificially_slowed_worker_processing` (`> 0.03`), `test_many_tiny_flows_completes_within_generous_time_bound` (`< 10.0`) | These will flake on a loaded CI machine and train everyone to ignore red. | Assert on **counters and invariants**, not wall clock. Time budgets become `pytest.mark.timeout`. |
| **`R-08`** | **`scapy`'s stated purpose is unimplemented** | `DESIGN_DECISIONS.md` and `tests/test_environment.py` both state scapy exists to cross-check hand-rolled TLS parsing against an independent implementation. Grep shows it is only *imported* in `test_environment.py` and referenced as a *forbidden string* in `test_safety_constraints.py`. No test cross-checks any parse against scapy. | The largest documentation-vs-implementation divergence in the repository. A dependency is justified by a purpose it does not serve. | Either implement the cross-check (it is genuinely valuable — it is the `R-05` substitute for TLS) or delete the dependency and the claim. |
| **`R-09`** | **Generated artifact tracked in git** | `manual_test_output.pcap` is tracked; `.gitignore` covers only `/output.pcap` and `/*.local.pcap` | Binary noise in history. | Add to `.gitignore`, `git rm --cached`. |
| **`R-10`** | **Test-only hook shipped in production source** | `worker.py:79` `_TEST_DELAY_MS_ENV_VAR` + `_maybe_apply_test_delay()`, called from the hot loop. Justified (Windows `spawn` re-imports the module, so an env var is the only reliable channel) and documented — but it is a latency knob inside the packet path. | A stray environment variable slows production to a crawl. | Move the call behind a module-level `bool` resolved once at import, and have the safety test assert the env var is never set outside tests. |

---

## §4 — Agentic architecture assessment

> ### Verdict
>
> `AGENTIC_ARCHITECTURE.md` is **conceptually the strongest document in this repository** and **roughly 40% factually stale**. Its strategic core — deterministic core / probabilistic periphery, the honest table of where agentic AI *is* and *is not* the right tool, the safety and human-gate layers, and the five failure modes — should be preserved essentially verbatim. Its §1–§3 state assessment and §8 sequencing need rewriting against the current tree, and §8 needs reordering.

It was written at 2026-09-30 23:02. A substantial refactor landed at 2026-10-01 01:15 (see `S-01`). The document was never reconciled, so it now actively misinforms.

### §4.1 — What to keep (do not rewrite)

| Section | Why it is good |
|---|---|
| §4 "The core strategic principle" | The single most important idea in the repository: **the engine stays deterministic; the agent proposes and never decides.** The three hard rules that follow are correct and should be enforced in review. |
| §5 "Where agentic AI is genuinely the right tool" | An unusually honest split, including an explicit list of what must **never** enter the model path. Most "make it agentic" plans lack this section. |
| Layer 7 "Safety & adversarial design" | Treating pcap as an untrusted-input vector — hostnames, cert CNs, and User-Agents are attacker-controlled strings destined for a context window — is the correct and under-appreciated framing. |
| Layer 8 "Human-in-the-loop" | Designed rather than bolted on; the durable checkpointer is the right mechanism. |
| §9 "Five things that will kill this project" | Accurate, and every one of them is still live. |

### §4.2 — Stale claims and their current values

> **This table is a snapshot, re-derived 2026-10-15.** The left column quotes
> claims from `AGENTIC_ARCHITECTURE.md`, which `DOC-04` has since moved into a
> historical banner — the quotes are kept because they record what was asserted.
> The right column is *current* by definition, so it has to be refreshed, and it
> had drifted: every numeric row was stale by the time this note was added.
> Numbers here will rot again; the commands to re-derive them are in the
> Appendix.

| Claim in `AGENTIC_ARCHITECTURE.md` | Current reality |
|---|---|
| "11 modules, ~2,900 lines" | **14 modules, ~6,800 lines** |
| "Tests 168 collected — 159 passed, 9 skipped" | **613 collected — 601 passed, 12 skipped** |
| "Dev dependencies 2 (`pytest`, `scapy`)" | **9**: `pytest`, `scapy`, `cryptography`, `ruff`, `mypy`, `pytest-cov`, `pytest-timeout`, `pytest-benchmark`, `hypothesis` |
| "Commits 3" | **27** |
| "README **0 bytes**" | **15,864 bytes**, and good |
| "**No type checking** … no mypy config and no `py.typed` marker" | `mypy --strict` + `warn_unreachable`, clean on 14 files; `py.typed` shipped |
| "**No linting or formatting** … no ruff config" | `[tool.ruff]` configured and passing |
| Defect #2 — `output_queue.get()` with no timeout, "parent **hangs forever**" | **Fixed.** `_collect` with a 120 s budget → `RuntimeError` |
| Defect #3 — `should_block` raises on empty IP from `src_ip_str` | **Fixed.** `parsed.src_ip` (int) is passed; `is_ip_blocked` is a frozenset lookup |
| Defect #5 — wildcard domain rules silently never match | **Fixed.** `DomainPattern` rejects at insertion |
| Defect #11 — `max_connections=0` degenerates to a 1-entry table | **Fixed.** `ValueError` at `connection_tracker.py:134` |
| Defect #12 — `classify_connection` can un-block a connection | **Fixed.** `is_terminal` is absorbing |
| Defect #14 — genuine circular import | **Fixed.** `pipeline` imports `worker` at module level; `worker` no longer imports `pipeline` |
| Defect #15 — `GlobalStats` / `combine_tracker_reports` are dead code | **Fixed.** Used by all three pipelines and rendered by `report.py` |
| Defect #17 — `DPIStats.combine` docstring contradicts its code | **Fixed.** Docstring now matches |
| "`cleanup_stale()` is never called in any production path" | **Fixed.** Cadence-triggered reaper inside `get_or_create_connection` |
| "Zero tests for `demo_classify.py`" | N/A — module deleted |
> **Status in this column was re-derived 2026-10-15** against `TASK_TRACKER.md`
> §6. At audit time every row below was genuinely open; most are now closed.
> Per-item status belongs to the tracker, so this column names closure and
> points there rather than duplicating the detail.

| Defect #1 — unbounded `processed_packets` | **Closed** → `D-01`. The #1 blocker at audit time; resolved by `T1-01` (event bus replacing accumulation) and `T1-03` (bounded reorder window) |
| Defect #4 — `PcapWriter` `FileNotFoundError` escapes | **Closed** → `D-04` |
| Defect #6 — `extract_sni` `IndexError` on mismatched `length` | **Closed** → `D-05` |
| Defect #7 — `orig_len` is `len(buf)` | **Closed** → `D-06` |
| Defect #8 — `caplen` checked after dpkt read | **Closed** → `D-07` |
| Defects #9, #10 — HTTP host scan, IPv6 colon | **Closed** → `D-09`, `D-10`, by `T0-07`. Note this is the one place where *closing* the finding made a README limitation entry unnecessary: the vectors no longer exist |
| "No CI" | **Closed** → `R-01` (`T0-01`) |
| "No coverage measurement" | **Closed** → `R-02` (`T0-01`) |
| "`conftest.py` referenced but missing" | **Closed** → `R-04` (`T0-02`) |
| "scapy's stated purpose is unimplemented" | **Closed** → `R-08` (`T1-07`) |
| "No property-based testing / no fuzzing" | **Closed** → `R-05` (`T1-07`) |

**Net:** its "Immediate next move #1 — fix defects #1–#4" has been overtaken.
Defects #2 and #3 were already closed when this audit was written, and the two
it went on to recommend — `D-01` and `D-04` — are closed now. As of 2026-10-15
the open defects are `D-11`, `D-13`, `D-15`, `D-19` and `D-23`; closure detail
lives in the tracker.

### §4.3 — `A-01`: "real-time" and the memory fix are the same work

The request is for a real-time product. The good news is that this is not a detour from the blocker in `D-01` — **it is the same piece of work**, and it is the highest-leverage change available.

Today the engine is strictly batch: read a file → accumulate everything → return a dataclass. Three distinct things are being called "real time", and conflating them will cause the wrong architecture:

| Meaning | What it requires | Relation to `D-01` |
|---|---|---|
| **Streaming analysis** — emit events as packets are analyzed, hold bounded state | Event bus; bounded per-flow state; eviction | **This *is* the `D-01` fix.** Same work |
| **Live ingest** — directory watch / file tail / stdin, so the system reacts rather than post-hoc | A `CapSource` abstraction over file / watch / stream | Depends on the above |
| **Near-real-time agent response** — bounded per-node latency | Already implied by the durable checkpointer + human gate | Independent; a Layer 3 concern |

### §4.4 — `A-02`: the hard constraint — streaming is incompatible with the current output ordering

**This must be decided before any Phase 1 work begins**, because it determines the shape of the event bus and it invalidates part of the test suite.

Output order is currently deterministic only because the parent materialises every packet and performs one `sort(key=sequence_index)` over the union. That is the *same* materialisation that causes `D-01`. Streaming therefore forces an explicit choice:

| Option | Guarantee | Cost |
|---|---|---|
| **A.** Per-shard arrival order | Within a shard only; interleaved across shards | Output is non-deterministic across runs → **breaks the differential suite's byte-comparison** |
| **B.** Bounded reorder buffer | Deterministic within a window of size *W*; a late packet beyond *W* is out of order | Needs a bounded window and a defined late-packet policy; *W* becomes a tunable with a memory/latency trade |
| **C.** Drop the byte-order guarantee | Set semantics: compare packet *sets* in tests | Cheapest and honest, but weakens the strongest existing property — byte-identical output is currently asserted for every staged topology |

Option **B** is the IP-defragmentation analogue and is the right answer for a product that wants both. But it is a real engineering item with a real trade-off, and it should be chosen deliberately, documented, and reflected in the tests — not discovered in week three.

### §4.5 — `A-03`: the safety-envelope boundary must be stated, or the guarantee becomes false

`DESIGN_DECISIONS.md`'s safety envelope is **no network calls, passive and offline**, and `tests/test_safety_constraints.py` AST-scans `src/dpi_engine/` for `socket.socket(`, `subprocess.`, `urllib.request`, `eval(`, `exec(`, `os.system(` and more.

Two consequences for the agentic layers:

1. **"Real time" can never mean sniffing a live interface.** That would break the envelope at its root. Real-time means file / directory-watch / stream ingest only.
2. **The agent layer *will* need network** — threat-intel lookups, ASN resolution, web search for app identification. This is a **deliberate, documented widening of the envelope for the agent layer only**; the deterministic core stays offline. Because the existing safety test scopes `src/dpi_engine/` only, the agent tree needs **its own, separate safety suite**. Without that, the "no network" guarantee quietly stops being true the moment agent code lands in the same repository, and nothing will report it.

### §4.6 — `A-04`: roadmap resequencing

The existing roadmap front-loads the hardest, least differentiated work and defers its own stated "killer app" to month four. Layers 1.3–1.5 (IPv6, VLAN, pcapng, JA3/JA4, HTTP/2 fingerprinting, feature store, isolation forest) are 3–6 months of protocol engineering that a `dpkt`-based implementation will get subtly wrong — and none of it is agentic.

| Phase | Content | Rationale for the move |
|---|---|---|
| **0 — Harden** *(~1 week)* | Fix `D-01`…`D-07`; add CI, coverage floor, `pytest-timeout` (`R-01`…`R-03`); add `conftest.py` (`R-04`); correct `M-04` | Small, and it is the actual blocker. Nothing scales while memory is unbounded. The existing plan budgeted 2–3 weeks for a subset. |
| **0.5 — Real captures** *(~1 week)* | **VLAN/802.1Q unwrap** (`D-14`, ~30 lines) + **pcapng** (`D-15`, ~200 lines) | Must precede agent work, or the entire golden corpus is toy untagged IPv4 and every later eval is measuring the wrong distribution. `D-14` alone currently loses 100% of enterprise traffic. |
| **1 — Streaming core** *(3–4 wks)* | Event bus; bounded state; `CapSource` (file / dir-watch / stdin); **the `A-02` ordering decision**; `simulate_ruleset` | Closes `D-01`/`D-02` permanently, delivers real-time ingest, unblocks the dashboard. |
| **2 — Eval harness** *(2–3 wks)* | Golden corpus; tool-call, trajectory, and adversarial evals; OTel tracing; CI gates. **Extend the differential suite from 77 packets to a large generated corpus.** | Must precede agents. The differential corpus is a genuine moat: "provably unchanged behaviour under refactor" is exactly the property needed before an agent starts rewriting rules. |
| **3 — MCP server** *(~1 week)* | The Layer 2 tool surface (~300 lines of glue) | **Pulled forward.** Lowest risk and highest demo value in the whole plan — makes the engine usable from Claude Code / Claude Desktop immediately, with no agent logic at all. |
| **4 — Read-only agents** *(3–4 wks)* | **Explainer + Triage only** | **Changed from the original plan.** Read-only agents have no write path, so they need none of the human-gate machinery. This proves the eval loop with the least new machinery. |
| **5 — ClassifierGap** *(3–4 wks)* | JA3/JA4 + ASN + cited-evidence app identification; signature-table maintenance | The stated "killer app", correctly identified as such. Requires fingerprints, therefore after Phase 1. |
| **6 — Write path** | Policy agent, `RuleStore` with provenance, human approval queue, tiered auto-apply, immutable audit log | **Last.** Nothing is granted write capability until 2–5 are proven. |

### §4.7 — `A-05`: `simulate_ruleset` is the keystone component and it does not exist

Every safety claim in Layers 3, 7, and 8 reduces to a single capability: *can we dry-run a proposed ruleset and show its blast radius?* Without it, "the agent proposes, the human decides" is a policy statement rather than an enforced constraint — and `revert_rule()` without `apply_rule()` in the MCP surface is a convention, not a control.

It should be built in **Phase 1**, ahead of the MCP server, because both the safety argument and the MCP surface depend on it.

### §4.8 — `A-06`: one sharpening of the core principle

Layer 1.5's anomaly model is **also not an LLM** and is deterministic — good. But a *trained* model introduces a training-data and version dependency that the differential suite structurally cannot cover. It therefore needs its own model pinning, its own golden-corpus evaluation, and its own entry in the change-tracking gate. Treat it exactly like the rules: versioned, evaluated, revertible.

---

## §5 — Documentation defect register (`M-01`…`M-08`)

| ID | File | Verdict |
|---|---|---|
| `M-01` | `README.md` (10 KB) | **Good.** Minor corrections needed. |
| `M-02` | `DESIGN_DECISIONS.md` (30 KB) | **Mostly good.** Surgical fixes. |
| `M-03` | `WORKFLOW.md` (23 KB) | **Badly stale — rewrite, do not patch.** |
| `M-04` | `AGENTIC_ARCHITECTURE.md` (50 KB) | **Conceptually strong, ~40% stale** — see §4.2. |
| `M-05` | `OSC/README.md` (36 KB) | Accurate as a C++ record; needs a superseded banner + one factual correction. |
| `M-06` | `OSC/WINDOWS_SETUP.md` (10 KB) | Accurate; needs the same banner. |
| `M-07` | `tests/differential/README.md` (5.4 KB) | One factual error (`R-04`). |
| `M-08` | `TASK_TRACKER.md` | **A structural defect, found 2026-10-20 and fixed in `T3-03`.** Appendix A's template opens a fenced `markdown` code block, and the six `T3-01`…`T3-06` task records were inserted *before the template heading* — so they landed inside the fence and rendered as literal code, while §5 — the section that is supposed to hold them — contained no `T3-*` record at all. Each session appended correctly and none could see the previous one's work. The tracker has no test and the reconciler bounded task records nowhere, so six records were unreachable under a fully green gate. Same class as the clobbered `T3-02` heading: **a markdown structure that no check constrains.** |

### §5.1 — `M-01` `README.md`

**Wrong:**
- "377 unit + 14 differential tests" → actual **390 + 14 = 404** (`M-01a`).

**Missing from Known limitations** (the list is honest but incomplete):
- No pcapng support, with a misleading diagnostic (`D-15`).
- No VLAN/802.1Q — this *is* mentioned under "IPv4/Ethernet only", but the consequence ("100% of tagged traffic is discarded") is not stated, which understates it (`D-14`).
- No CIDR/subnet rules; no destination-IP blocking (`D-20`, `D-21`).
- The `extract_http_host` full-payload scan and IPv6-colon behaviour — both are *false-classification and false-blocking* vectors and belong in a security tool's limitations list (`D-09`, `D-10`).
- **No statement that the port is likely slower per packet than the C++ original** (`P-15`). For a tool whose README currently reads as confident, this omission is the most material one.

> **Outcome, recorded 2026-10-15 — `M-01` is closed, and most of the list above
> was overtaken by the code fixing the underlying defects.** Worth reading
> before re-adding any of these as limitations:
>
> - **pcapng** — still a genuine gap; documented, with `editcap -F pcap` and the
>   rationale for refusing rather than mis-parsing (`DEC-02`).
> - **VLAN** — `T05-01` added 802.1Q/QinQ peeling, so the item inverted. Writing
>   "100% of tagged traffic is discarded" into the README would have documented a
>   bug that had already been fixed. Now listed as a deliberate parity break.
> - **CIDR / destination-IP** — `T1-05` turned both into features (`D-20`,
>   `D-21`). Documented as behaviour rather than as limitations.
> - **`extract_http_host` / IPv6-colon** — `D-09`/`D-10` were closed by `T0-07`,
>   so the vectors no longer exist and no limitation entry was needed at all.
> - **Slower per packet** — documented as asked, carrying `D-23`'s measured
>   figures and an explicit pointer at the preserved C++ original.
>
> Three of the five items resolved by *fixing the defect*, which is the better
> outcome and the reason a "missing limitations" list should be re-checked
> against the code rather than transcribed.

**Correct and should stay:** the three pipeline variants and the explicit statement that the LB tier is queue-decoupling and observability rather than throughput; the domain-rule anchoring table; the "blocking less is the safe direction" note.

### §5.2 — `M-02` `DESIGN_DECISIONS.md`

- `M-02a` **Bug-list item 1 contradicts item 16.** Item 1 is listed under "Bugs fixed during the port" and phrases the QUIC fix as "guarding the loop start, **or omitting QUIC heuristic support entirely (decide during Task 5; default to omitting with a documented TODO)**". Neither happened — `quic.py` implements the full RFC 9000/9001 path. Strike item 1's QUIC clause and cross-reference item 16.
- `M-02b` **"Minor efficiency note" is stale.** It claims the output-path overwrite check "only fires when `PcapWriter` is constructed, which happens **after** all worker processes have been spawned, **dispatched every packet**, and been shut down/joined". `PcapWriter` is now opened at `pipeline.py:535`, at the *top* of the dispatch block — before the first packet is dispatched. Only the "after spawning" part survives.
- `M-02c` **"Known limitation — output file left on disk" is wrong for two of three paths.** It states the file contains "whatever packets were successfully written before the failure". True for `run_pipeline` (streams in-loop). **False** for `run_pipeline_multiprocess` and `run_pipeline_staged`: nothing is written until after every worker has joined (`pipeline.py:587`, `:799`), so a mid-dispatch failure leaves a valid but **empty** 24-byte pcap.
- `M-02d` **§"Testing strategy" is written as a forward plan** ("Tasks 2–12", "to be done") but differential testing and multiprocessing re-validation are **done and pinned**. It also predates nine of the 25 test files and omits `quic.py` and `report.py` entirely.
- `M-02e` **A code docstring contradicts the document.** `sni_extractor.py:29` states "QUIC SNI extraction is intentionally **NOT** implemented (see DESIGN_DECISIONS.md 'Open decisions': default is to omit it)". `quic.py` implements it, and the referenced section is resolved.
- `M-02f` **A wrong cross-reference in code.** `types.py:257` cites `DESIGN_DECISIONS.md` "Bugs fixed during the port" **item 14** for the `ConnectionState` terminal-state invariant. Item 14 is "`GlobalConnectionTable`'s report was dead code". The correct references are **item 7** (classification lock-in) and **item 11** (TCP state machine).

### §5.3 — `M-03` `WORKFLOW.md` — rewrite, do not patch

Dated 2026-09-25, it describes the pre-refactor codebase. Listed by severity of how badly it misleads:

**Documents code that does not exist**
- A module-graph node for **`demo_classify.py`** plus five dependency edges, and **all of §10** walkthroughing its CLI entry point (`python -m dpi_engine.demo_classify`). The module was deleted — `DESIGN_DECISIONS.md` says so explicitly, so this is also a direct **inter-document contradiction** (`M-03a`).

**Documents a bug as if it were the design** — the worst single defect in the repo's documentation
- The §5 `sni_to_app_type` flowchart places the `x.com` / `t.co` domain-boundary check in a node **above the entire pattern table**, i.e. Twitter/X evaluated *first*, with the Twitter substrings repeated below it. `DESIGN_DECISIONS.md` explicitly warns "an earlier revision hoisted it above the whole table … `google.x.com` became Twitter instead of Google. **Do not hoist it again.**" The diagram re-draws the exact bug that was fixed (`M-03b`).

**Wrong line references (5)**

| Cited | Actually |
|---|---|
| `classify_flow_from_packet (pipeline.py:73)` | Symbol no longer exists; now `FlowProcessor.classify` at `worker.py:196` (and it now takes the five-tuple, because QUIC needs per-flow state) |
| `sni_to_app_type (types.py:179)` | `types.py:229` |
| `run_pipeline (pipeline.py:119)` | `pipeline.py:367` |
| `run_pipeline_multiprocess (pipeline.py:219)` | `pipeline.py:462` |
| `worker_main (worker.py:119)` | `worker.py:456` |

**Documents pre-fix behaviour as current**
- §7 rule-evaluation node shows `is_ip_blocked(src_ip)` via validated `ipaddress.IPv4Address` — i.e. the **per-packet string coercion** that the port deliberately removed (`M-03c`).
- §8 diagram shows one rule-check gate; the code has **two independent gates** (`conn.state is not BLOCKED`, then `tuple not in blocked_tuples`).
- §8 shows `classify_flow_from_packet` called unconditionally; the code **skips classification entirely** for `CLOSED` flows, and omits the whole `update_tcp_state` stage.
- §8 shows `stats.tcp_packets += 1` in the read loop, which is then **overwritten** from the result at `pipeline.py:432`.
- §9 claims a local import of `worker` avoids a circular dependency; `pipeline` now imports `worker` at **module top level**.
- §9 shows `worker_id = hash(five_tuple) % num_workers`; the code uses `hash_select()`, an explicit boost-mix, precisely *because* builtin `hash` is forbidden (`PYTHONHASHSEED`).

**Missing**
- Modules: **`quic.py`, `report.py`, `load_balancer.py`** — 3 of 13 absent from the module map.
- The entire **LB tier** and `run_pipeline_staged`; the diagram has 2 branches, the code has 3.
- **QUIC classification branch** — absent; the §5 flow jumps straight from HTTP-Host to DNS.
- **TCP state machine**: `ESTABLISHED` is missing from the §6 state diagram entirely (it is reachable at `connection_tracker.py:281`), as is the `BLOCKED > CLOSED > CLASSIFIED/ESTABLISHED > NEW` precedence rule and the `_guessed` side-set that implements guess-vs-confirmed.
- `reap_if_due` is absent from the `get_or_create_connection` flow.
- **CLI flags** — only 6 of 13 `run` flags appear: missing `--load-balancers`, `--fps-per-lb`, `--live-rules`, `--json`, `--no-quic`, `--top-domains`, `--reap-interval`, `--flow-timeout`.
- The 120 s `_collect` timeout — the anti-hang guard, which is the single most important detail in that section.
- Control queues and the live-rules drain; the worker-loop diagram ends at `input_queue.get()`.
- `DomainPattern` insertion-time rejection (`foo*.com`, `*foo`, bare `*`).
- **Safety envelope omits** `--flow-timeout` (300 s), `--reap-interval` (65536), and QUIC's `MAX_CRYPTO_BUFFER` (64 KiB) / `MAX_QUIC_DATAGRAM`.
- Report sections: 4 of 9 are missing (Pipeline Stages, Inspection Coverage, Flow State, Top N Names).
- `rules --unblock-*` flags; the `Capabilities:` block printed by `inspect`.

**Accurate and worth preserving when rewriting:** §4 (`parse_packet`) and §5's extractor step diagrams were both verified node-for-node against the current code and are correct.

### §5.4 — `M-04` `AGENTIC_ARCHITECTURE.md`

Full stale-claim table at §4.2. Action: rewrite §1–§3 against the current tree, resequence §8 per §4.6, keep §4–§7 and §9 essentially as-is (`A-01`).

### §5.5 — `M-05` / `M-06` — `OSC/README.md`, `OSC/WINDOWS_SETUP.md`

Both are accurate as records of the C++ system and should be retained — they are the provenance for every `DESIGN_DECISIONS.md` entry. Two additions:

1. A **superseded banner** at the top pointing at the root `README.md`, so a reader does not build the C++ and assume it is the product.
2. `OSC/README.md` **documents building DPI binaries that `CMakeLists.txt` never builds.** `CMakeLists.txt` compiles exactly three files into a target named `packet_analyzer`, and includes no `Threads::Threads` / `-pthread`. Adding any DPI source to it would fail to link. Every documented DPI build in both files is a hand-written `g++` line. This is a genuine factual error in `M-05a`.

### §5.6 — `M-07` — `tests/differential/README.md`

States the reference binary is "rebuilt on demand by `build_reference_binary()` in `conftest.py`/`cpp_reference.py`". **There is no `conftest.py`.** The implementation is entirely in `cpp_reference.py`; the `cpp_available` fixture is duplicated verbatim across two test modules. Same root cause as `R-04`.

---

## §6 — Session-transcript reconciliation (`S-01`…`S-03`)

Two transcripts sit in the repository root. Both are **untracked** (`git status` reports `?? session-ses_f0c8.md`, `?? session-ses_f0d1.md`) — they are working-directory noise, not committed artefacts.

### `S-01` — The two sessions contradict each other, and that is the root cause of the doc rot

| | `session-ses_f0d1.md` | `session-ses_f0c8.md` |
|---|---|---|
| Created | 2026-09-30 20:54 | 2026-09-30 23:22 |
| Last updated | 2026-09-30 23:02 | 2026-10-01 01:17 |
| Produced | **`AGENTIC_ARCHITECTURE.md`** | **`DESIGN_DECISIONS.md`** + `README.md` |
| Analysed | the **pre-refactor** tree | the **post-refactor** tree |

**~2 hours and 15 minutes apart.** A substantial refactor landed between them: `classify_flow_from_packet` moved out of `pipeline.py` into `worker.FlowProcessor`; mypy-strict was made clean; PEP 695 generics were introduced; `report.py`, `quic.py`, and `load_balancer.py` were split out; `GlobalStats` was wired into the pipeline.

`AGENTIC_ARCHITECTURE.md` is the artefact of the **older** session and was never reconciled against the newer one. Every stale claim in §4.2 traces back to this single gap. **This is the process finding that matters most in this section**: a document that describes a codebase's state is a snapshot, and it decays the moment the code moves. The ID scheme at the top of this audit exists to make the next audit cheap; the deeper fix is to stop writing state-descriptions into prose and point at executable checks instead (§0 is the only part of this document that should be maintained by hand).

### `S-02` — File edits were done by regex surgery on whole files

`session-ses_f0c8.md` shows most source modifications performed with PowerShell `(Get-Content … -Raw) -replace … | Set-Content … -NoNewline`. This is fragile and it visibly failed: several consecutive edits landed with `F821 Undefined name` / `F401` regressions (a `-replace` matched `from typing import Optional` after the line had already changed), each of which then had to be chased and hand-repaired across multiple follow-up turns.

**Process fix:** edit files with a targeted patch mechanism. Whole-file regex substitution is only safe for mechanical, verifiable substitutions — and even then the output must be re-read and linted immediately, which in this session it eventually was (`ruff` + `mypy` caught everything), but only after several wasted cycles.

### `S-03` — The dead-code sweep never actually completed

The same transcript attempts a dead-code audit and the PowerShell pipeline fails (`Measure-Object : Input object "src/dpi_engine\pipeline.py:3" is not numeric` — `rg -c` emits `file:count`, which `Measure-Object -Sum` cannot consume). The error is printed and the sweep is abandoned. So the "dead code" sweep claimed by that session did not in fact run to completion.

This audit's own dead-code findings are therefore a **first** pass and should be treated as such: `packet_parser.five_tuple_of`, `rule_manager.STATIC_RULES`, `load_balancer.queue_for`, `load_balancer.LoadBalancerStats.packets_unroutable` (declared at `:139`, summed at `:153`, serialised at `:165`, **never incremented anywhere**), and `PacketAction.INSPECT`/`LOG_ONLY` are all unreachable from production paths. Additionally, three **docstring references point at symbols that do not exist**: `quic.py:603` cites `pipeline.QuicFlowTable`, `worker.py:93` cites `pipeline.RuleBroadcaster.SnapshotHolder`, and `pipeline.py:131` documents a `with_fast_path_stats=True` parameter that was never added.

---

## §7 — Prioritized remediation plan

Ordered by dependency, not by severity. Every item traces to an ID above. Effort figures assume one developer.

> **Status of this plan, re-derived 2026-10-15.** The tables below are the
> original remediation ordering, kept as written. **Phase 0, Phase 0.5 and the
> documentation track are complete.** Phase 1 is **5/9** — `T1-01`, `T1-03`,
> `T1-05`, `T1-07` and `T1-09` — leaving `T1-02`, `T1-04`, `T1-06` and the
> missing half of `T1-08`. Phases 2–6 have not started.
>
> This section deliberately carries **no per-item status column**: closure
> belongs to `TASK_TRACKER.md` §6, and a second status table here is exactly the
> duplication that let the tracker's own summary table and its task records
> disagree for several sessions. The exit-criteria text below quotes test counts
> from the time of writing; take live numbers from `pytest` instead.

### Phase 0 — Harden *(~1 week)* — **blocks everything**

| Item | Ref | Effort |
|---|---|---|
| Bound worker packet accumulation; introduce a bounded decision queue | `D-01` | 2–3 d |
| Set `maxsize` / add a shared token semaphore for backpressure | `D-02` | 0.5 d |
| Wrap `PcapWriter` open in `OSError` → `PcapError` | `D-04` | 15 min |
| Clamp `length` to `len(payload)` in both TLS entry points | `D-05` | 15 min |
| Read the pcap record header directly; populate true `orig_len` **and** validate `caplen` before reading | `D-06`, `D-07` | 0.5 d |
| Fix `quic_undecryptable` delta accounting | `D-08` | 0.5 d |
| Bound the header scan and fix the IPv6 colon strip in `extract_http_host` | `D-09`, `D-10` | 0.5 d |
| Thread `live_rules` through `run_pipeline_staged`, or reject the flag combination | `D-03` | 0.5 d |
| Wrap `_collect`/`join`/`close` in `try/finally` | `D-12` | 30 min |
| Add CI: `ruff` + `mypy --strict` + `pytest`; Docker job for differential | `R-01` | 0.5 d |
| Add `pytest-cov` with an 85% floor; add `pytest-timeout` | `R-02`, `R-03` | 0.5 d |
| Add `tests/conftest.py`; hoist the duplicated fixture and `FIXTURES` path | `R-04`, `M-07` | 0.5 d |

**Exit criteria:** no unbounded allocation reachable from any documented flag; no path that can hang without producing a diagnosable error; green CI; a quotable coverage number.

### Phase 0.5 — Real captures *(~1 week)*

| Item | Ref | Effort |
|---|---|---|
| Peel VLAN/802.1Q and QinQ tags before EtherType dispatch | `D-14` | 0.5 d |
| pcapng reader, or a clear "not supported, here's how to convert" diagnostic | `D-15` | 1–2 d |

**Exit criteria:** the tool runs on VLAN-tagged enterprise captures without silently discarding traffic. Rationale for placing this *before* any agent work: otherwise the golden corpus is toy untagged IPv4, and every downstream eval measures the wrong distribution.

### Phase 1 — Streaming core *(3–4 weeks)*

| Item | Ref |
|---|---|
| **Decide and document the `A-02` ordering question** before writing code | `A-02` |
| Event bus replacing `PipelineResult` accumulation | `A-01`, `D-01` |
| `CapSource` abstraction: file / directory watch / stdin | `A-01` |
| Bidirectional flow folding as a default-on option (`P-16`) | `P-16` |
| CIDR and destination-IP rules | `D-20`, `D-21` |
| Streaming `RuleSet` DSL with provenance | roadmap §1.6 |
| **`simulate_ruleset` counterfactual engine** — the keystone (`A-05`) | `A-05` |
| Property-based tests with `hypothesis` for every byte-level extractor | `R-05` |
| `pytest-benchmark`; establish the throughput number `P-15` leaves open | `R-06` |
| Rewrite `WORKFLOW.md` against the new architecture | `M-03` |

**Exit criteria:** the existing suite still passes in full, with no reduction in
the passing count; streaming output is deterministic under the chosen `A-02`
option; differential parity with the C++ reference intact.

### Phase 2 — Eval harness *(2–3 weeks, parallel with Phase 3)*

Golden-capture corpus (30+ labelled pcaps) · tool-call / trajectory / adversarial eval harnesses · OTel tracing · **extend the differential suite from 77 packets to a large generated corpus with an explicit divergence allowlist** · safety suite extended to the agent tree (`A-03`).

**Exit criteria:** an agent can drive the engine and be scored automatically on every PR. This is the phase that makes everything after it safe to build.

### Phase 3 — MCP server *(~1 week)*

Layer 2 tool surface. **Pulled forward** from the original plan: ~300 lines, no agent logic, zero risk, immediate usability from any MCP host.

### Phase 4 — Read-only agents *(3–4 weeks)*

Explainer + Triage only. Episodic and semantic memory. Citation-enforced RAG. **No write path** (`A-06`).

**Exit criteria:** verdict accuracy against the golden corpus, 100% refusal on injection evals, a full replayable trace for every verdict.

### Phase 5 — ClassifierGap *(3–4 weeks)*

Fingerprinting engine (JA3/JA4, TLS version histogram, cipher/extension ordering, ALPN, cert issuer, GREASE, HTTP/2 SETTINGS) · ASN correlation · cited-evidence signature proposals. The product differentiator.

### Phase 6 — Write path

Policy agent · `simulate_ruleset` + blast-radius circuit breaker · durable human-approval queue · versioned `RuleStore` with provenance and immutable audit log · tiered auto-apply.

**Exit criteria:** end-to-end *capture → agent proposes a signed ruleset → human approves → applied → revertible*, with a complete audit trail.

### Parallel documentation track — **complete**

All of `M-01`–`M-07` were corrected and are closed; the documentation findings
register is empty. Two departed from this plan, both deliberately:

- `M-03` (`WORKFLOW.md`) was rewritten **earlier** than recommended here. The
  plan said to wait until after Phase 1 because the architecture would change;
  but a document describing a deleted module (`demo_classify.py`) misleads in
  the present tense, and did so for the whole of Phase 0.
- `M-01` (`README.md`) was resolved partly by the **code overtaking the
  finding**: `D-09`/`D-10` were closed by `T0-07`, so the HTTP-host vectors
  needed no limitation entry, and `T05-01` and `T1-05` turned the VLAN and
  CIDR items from limitations into documented behaviour. Fixing the defect was
  the better outcome in each case.

---

## Appendix — Verification commands

Every claim in this document is re-derivable with the following. Run from the repository root.

> Expected outputs below were re-derived **2026-10-15**. Counts in a verification
> block rot by definition — if one disagrees with what you just ran, trust your
> run and update this block.

```powershell
# §0 baseline
uv run pytest -q                              # 601 passed, 12 skipped
uv run pytest --collect-only -q                # 613 collected
uv run pytest --collect-only -q tests/differential   # 14 collected
uv run ruff check . --output-format concise    # All checks passed!
uv run mypy                                    # Success: no issues found in 14 source files

# NOT part of the gate, and not expected to be clean. The project lints with
# `ruff check` but has not adopted `ruff format`, so this reports reformatting
# and always has — it is here as a characterisation, not a pass condition.
uv run ruff format --check .                   # 31 files would be reformatted, 33 files already formatted

# §0 missing rails
foreach ($p in @('.github','.gitlab-ci.yml','.circleci','azure-pipelines.yml',
                 'Jenkinsfile','.pre-commit-config.yaml','conftest.py',
                 'tests/conftest.py','.coveragerc')) { "$p : $(Test-Path $p)" }

# D-01 / P-14 — unbounded accumulation
rg -n "processed_packets" src/dpi_engine/worker.py src/dpi_engine/pipeline.py
rg -n "mp\.Queue\(\)|Queue\(\)" src/dpi_engine/pipeline.py          # no maxsize anywhere

# D-02 — no backpressure
rg -n "maxsize|put\(.*timeout" src/dpi_engine/                       # no matches

# D-03 — --live-rules silently ignored with --load-balancers
rg -n "live_rules" src/dpi_engine/cli.py src/dpi_engine/pipeline.py

# D-04 — unguarded PcapWriter open (contrast with PcapReader)
rg -n -A3 'open\(self\.path' src/dpi_engine/pcap_io.py
rg -n "except \(PcapError, ValueError\)" src/dpi_engine/cli.py

# D-05 — unclamped length
rg -n "length = len\(payload\)|min\(length" src/dpi_engine/sni_extractor.py

# D-06 / D-07 — orig_len and caplen ordering
rg -n "orig_len|caplen|max_packet_size" src/dpi_engine/pcap_io.py

# D-08 — cumulative quic counter
rg -n -B2 -A2 "undecryptable_packets" src/dpi_engine/worker.py

# D-09 / D-10 — HTTP host extraction
rg -n -A30 "def extract_http_host" src/dpi_engine/sni_extractor.py

# D-11 / D-12 — result collection and teardown
rg -n "_RESULT_TIMEOUT_SECONDS|def _collect|def _terminate|def _close_quietly" src/dpi_engine/pipeline.py

# D-13 — LB is the only sender of FP sentinels
rg -n -A22 "def _lb_main" src/dpi_engine/pipeline.py

# D-14 / D-15 / D-19 — protocol coverage
rg -n "VLAN|0x8100|0x88a8|ETH_TYPE_IP" src/dpi_engine/packet_parser.py
rg -n "pcapng|0x0A0D0D0A" src/dpi_engine/pcap_io.py

# D-16 — persistence keys
rg -n "_APP_NAME_TO_TYPE|_TYPE_TO_APP_NAME" src/dpi_engine/rule_manager.py

# §1.1 — the OSC comparison
Get-Content OSC/src/load_balancer.cpp | Select-Object -Skip 68 -First 10   # P-12: same hash, both tiers
Get-Content OSC/src/sni_extractor.cpp  | Select-Object -Skip 288 -First 9  # P-02: payload + i - 5
Get-Content OSC/src/rule_manager.cpp   | Select-Object -Skip 103 -First 10 # P-08: any '*' is a wildcard
Get-Content OSC/src/fast_path.cpp      | Select-Object -Skip 50 -First 9    # P-13: reap only when idle

# P-11 — the unanchored-substring misclassification, directly
python -c "print('x.com' in 'netflix.com', 't.co' in 'microsoft.com', 'cf-' in 'cf-anything.example.com')"
# -> True True True

# §6 — dead code and dangling docstring references
rg -n "five_tuple_of|STATIC_RULES|packets_unroutable|queue_for" src/dpi_engine/
rg -n "QuicFlowTable|SnapshotHolder|with_fast_path_stats" src/dpi_engine/
rg -n "item 14" src/dpi_engine/types.py

# §6 — transcripts are untracked
git status --short
```
