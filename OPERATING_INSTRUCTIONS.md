# Operating Instructions — `dpi-engine`

**For:** any human or agent working on this repository.
**Read time:** 10 minutes. **Read once per session at minimum.**

This document tells you *how to work here*. For *what to fix*, read
[`AUDIT.md`](AUDIT.md). For *how to build it*, read
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md). For *how to update the
tracker*, read [`TASK_TRACKER_UPDATE_PROTOCOL.md`](TASK_TRACKER_UPDATE_PROTOCOL.md).
For *what state we are in*, read [`TASK_TRACKER.md`](TASK_TRACKER.md) §1.

---

## 1. The one-paragraph version

This is a Python port of a C++ DPI engine, currently mid-refactor. The port is
**better than the original** on correctness, safety, and auditability, and
**worse** on two axes: memory is unbounded, and per-packet throughput is likely
worse than C++. Phase 0 exists to fix the memory problem and add the engineering
rails (CI, coverage, property tests) that make every later change verifiable. After
Phase 0 the project becomes a real-time streaming agentic product. Nothing in the
agentic layers may touch packet-level truth.

---

## 2. Read order

**Every session, in this order. Do not skip.**

| # | Document | Sections | Why |
|---|---|---|---|
| 1 | `TASK_TRACKER.md` | frontmatter, §1 Current state | Tells you what to do. 40 lines. |
| 2 | `IMPLEMENTATION_PLAN.md` | §1 dependency graph, §8 verification gates | Tells you what your task depends on and what "done" means |
| 3 | `AUDIT.md` | §1 verdict, the rows your task traces | Tells you *why* |
| 4 | `TASK_TRACKER_UPDATE_PROTOCOL.md` | §4–§9 | Tells you how to record what you did |
| 5 | `OPERATING_INSTRUCTIONS.md` | this file | How to work here |

**Reading `AUDIT.md` §1 and §2 end-to-end once is strongly recommended** before your
first code change. It explains *why* the safety envelope is the constraint it is,
which is the judgement you will need for every task.

---

## 3. What this codebase is, and what it is not

**It is:** a deterministic, bounded, offline deep packet inspection engine. It reads
pcap files, classifies flows by application from TLS SNI / HTTP `Host` / DNS query
name / decrypted QUIC ClientHello, applies blocking rules, and writes a filtered
capture plus a report. 404 tests, mypy-strict clean, ruff clean, and a differential
suite that builds and runs the actual C++ original under Docker to prove behavioural
parity.

**It is not:** a network agent, a live capture tool, a model, or a product. There is
no API, no service, no UI, no LLM anywhere in the system. `cli.py` is a `print()`
loop. Everything beyond that is roadmap.

**It never will be:** a live interface sniffer. See §5.

---

## 4. The five non-negotiable rules

These are not style preferences. Violating any of them invalidates the project's
only real asset.

### R1 — The engine stays deterministic. The agent proposes; it never decides.

> "The value of this codebase is that `www.netflix.com → NETFLIX, not Twitter/X` is
> *proven* against a compiled C++ reference binary. An LLM guessing is strictly worse
> than a substring table."

No model call may ever enter the per-packet path — classification latency is
microseconds, a network round-trip is milliseconds, and reproducibility is the whole
point. This must be **structurally impossible**, not merely discouraged: the agent
layer must have no tool that returns a per-packet verdict.

### R2 — The safety envelope is inherited, not relaxed.

Binding constraints, enforced by `tests/test_safety_constraints.py`:

- **Passive and offline.** No raw sockets, no live interface capture, no injection or replay, no elevated privileges.
- **No network calls** at runtime, in the tool or its workers.
- **Never overwrite the input**, enforced in `PcapWriter` itself.
- **Bounded resources at every untrusted-input boundary.**
- **Workers are pure compute.** Only the parent process touches the filesystem.

If a task appears to require breaking one of these, **stop.** That is a decision for a
human, recorded as a `DEC-##`, not an engineering judgement.

### R3 — Every change ships with a test that fails without it.

`tests/test_pcap_io.py:41` asserts the `D-06` bug, which locks it in. That is what
failing to do this looks like. A defect is closed only when the test exists.

### R4 — The 404 existing tests are the ground truth.

Any change altering their behaviour is a regression, full stop. The agentic layers are
additive and sit strictly above. A reduced passing count is a failure, not a
trade-off — if a test must be removed, justify it in the deviation log.

### R5 — Never rewrite history or renumber.

In code, in docs, in the tracker: findings are immutable records. A `done` task stays
done; a superseded decision is superseded by a *new* decision, not an edit.

---

## 5. Boundaries you must not cross without a human

| Boundary | Why | What to do instead |
|---|---|---|
| **Adding a network call** | Breaks R2. | Stop. Record a `DEC-##`. |
| **Making the agent layer able to write rules** | Phase 6 only, after 2–5 are proven | Return a proposal and a `simulate_ruleset` counterfactual |
| **Choosing any open decision** | Five need a human: `DEC-01` output-ordering guarantee · `DEC-02` pcapng scope · `DEC-03` scapy implement-or-delete · `DEC-04` rule persistence key · `DEC-05` bidirectional flow folding | Recommend a value with reasoning, record it, wait. **Six of thirty tasks are blocked on these.** |
| **Reopening a `done` task** | Breaks R5 | Open a new task |
| **Committing or pushing** | Not authorised | Ask |
| **Deleting `OSC/`** | It is the provenance for every `DESIGN_DECISIONS.md` entry and the differential reference | Never |
| **Loosening the differential divergence allowlist** | The parity proof is the project's main asset | A new divergence needs a written justification and a pinned test |

---

## 6. How to do a task well

### Before you start

1. Read the tracker's §1 and your task's record in §5.
2. Read the task's `Traces` findings in `AUDIT.md`. **Understand the bug**, do not just
   patch the symptom — several findings here are one mechanism with multiple symptoms.
3. **Verify the tree is green** (§7). Never start work on a red tree.
4. **Claim the task** before editing source. `TASK_TRACKER_UPDATE_PROTOCOL.md` §4.
5. Reproduce the defect first, with a test that fails. Then fix it. Then watch it pass.

### While you work

- **Use targeted patches, never whole-file regex substitution.** PowerShell
  `-replace` + `Set-Content` on source files caused a chain of `F821` import
  regressions in `S-02`. If you must use one, re-read the file and re-lint
  immediately.
- **Re-lint after every few edits**, not just at the end.
- **Note deviations as they happen**, not afterwards. By the end of a session you
  will have forgotten why you did something unusual.
- If you discover a new defect, **allocate the finding ID in `AUDIT.md` first**
  (`UPDATE_PROTOCOL.md` §8), then create the task.

### Before you finish

Walk §10 of the tracker **literally**. Then write the record — *especially*
`How it was tackled`, which is the only field only you can fill and the one that
gets left blank most often.

---

## 7. The verification baseline

Run this before starting and before finishing any task.

```powershell
uv run ruff check .     # All checks passed!
uv run mypy             # Success: no issues found in 13 source files
uv run pytest -q        # 404 passed
```

Also available:

```powershell
uv run pytest --ignore=tests/differential   # 390 tests, no Docker needed
uv run pytest tests/differential            # 14 tests, needs Docker
uv run ruff format --check .                # currently 22 files would be reformatted
```

**If the count is not 404, the tree has drifted.** Find out why before doing anything
else. `UPDATE_PROTOCOL.md` §10 has the internal consistency checks for the tracker
itself.

---

## 8. Environment

| Fact | Value |
|---|---|
| Python | 3.13 (`requires-python = ">=3.13,<3.14"`) |
| Package manager | `uv` — always `uv run <tool>`, never bare `python`/`pytest` |
| Platform | Windows; `multiprocessing` start method is **`spawn`** |
| **`spawn` consequences** | MP entry points must be called from an `if __name__ == "__main__":` guard (the `dpi-engine` console script already is). Child processes **re-import** modules, so anything a test needs to communicate to a worker must go through **picklable arguments or environment variables** — not module-level state. This is why `worker.py` carries a test-delay env-var hook (`R-10`). |
| Optional extra | `uv sync --extra quic` installs `cryptography`, needed for QUIC SNI decryption. Without it, QUIC *detection* still works and the degradation is **reported**. |
| Test suites | 404 total: unit + integration + property + safety + 14 differential (Docker) |
| Dependencies | 1 runtime (`dpkt`); 5 dev (`pytest`, `scapy`, `ruff`, `mypy`, `cryptography`) |

---

## 9. Where things live

```
src/dpi_engine/
  types.py              five-tuples, AppType, Connection, DPIStats, SNI pattern table
  pcap_io.py            pcap read/write + safety bounds        ← T0-05, T0-06, T05-02
  packet_parser.py      Ethernet/IPv4/TCP/UDP dissection       ← T05-01
  sni_extractor.py      TLS SNI, HTTP Host, DNS name            ← T0-04, T0-07, T1-09
  quic.py               QUIC Initial decryption + SNI           ← T0-08
  connection_tracker.py flow table, TCP state machine, LRU, reaper
  rule_manager.py       copy-on-write rules + immutable snapshots ← T1-04, T1-05
  load_balancer.py      two-level hash selection, LB/FP graph    ← T0-10 (docstring)
  worker.py             FlowProcessor: the per-packet decision engine  ← T0-08, T0-11
  pipeline.py           the three pipeline entry points          ← T0-10, T0-11, T1-03
  report.py             text + JSON reporting
  cli.py                argparse front end                       ← T0-09
OSC/                    the original C++ engine — reference only, do not modify
tests/                  unit, integration, property, safety
tests/differential/     parity vs. the compiled C++ binary (Docker)
```

---

## 10. The pipeline variants, and the invariant they share

```
run_pipeline                 single process, no IPC                (default)
run_pipeline_multiprocess    reader parses → N fast-path processes  (--workers N)
run_pipeline_staged          reader → K load balancers → K*F fast paths  (--load-balancers K)
```

**The partitioning invariant all three rely on:** every packet of a given five-tuple
reaches the same fast-path process, so per-flow state — TCP lifecycle, classification,
block decisions — is never split. All three share one decision engine
(`worker.FlowProcessor`) and must produce **byte-identical** output pcaps for the same
input and rules. The test suite asserts this for every staged topology.

**Do not break this.** It is what makes the differential suite meaningful.

Note the staged variant is *not* faster than `--workers`; the LB tier is
queue-decoupling and observability. (And `load_balancer.py`'s module docstring, which
claims the LB stage does the parsing, is **wrong** — fixed by `T0-10`.)

---

## 11. Deliberate quirks — do not "fix" these by accident

Each is a conscious decision to preserve C++ behaviour. Changing one silently breaks
differential parity or blocking scope.

| Quirk | Why |
|---|---|
| Flows keyed by **exact** five-tuple, not direction-folded | A block on client→server does not apply to server→client. Correct for C++ parity, wrong for a product — so `DEC-05` makes it a mode, not a fix |
| A recognised-but-unmapped name is labelled `HTTPS`, even on port 80 | Matches the original's documented fallthrough |
| HTTP methods matched on their first 4 bytes (`DELETE` via `DELE`) | Classification-accuracy nit inherited for parity |
| DNS compression pointers not followed | Legal but rare in a question section; parsing stops early. Cannot loop or read out of bounds |

Full list at `AUDIT.md` §1.3.

---

## 12. What is planned, in one paragraph

Phase 0 (this week): bound memory, add CI/coverage/property tests, fix five
defects. Phase 0.5: VLAN + pcapng so real enterprise captures work. Phase 1: replace
batch accumulation with a streaming event bus and a `CapSource` abstraction, add
`simulate_ruleset` — the component every safety guarantee reduces to. Phase 2: golden
corpus and eval harness, which must exist **before** any agent. Phase 3: MCP server.
Phase 4: read-only agents. Phase 5: fingerprinting and `ClassifierGap`, the actual
differentiator. Phase 6: the write path, with a human gate.

**"Real time" here means file, directory-watch, and stream ingest — never live
interface capture** (R2). And streaming is currently **incompatible with the
byte-identical output ordering**; `DEC-01` resolves that and is on the critical path.

---

## 13. Tone for agents

- **Verdict first, evidence second.** State the conclusion, then the file:line.
- **Never claim something works without running it.** Paste real output.
- **"Unknown" is a valid answer.** "I have not measured this" is far more useful than
  a confident guess — the throughput question (`P-15`) has been open exactly because
  it was assumed rather than measured.
- **Disagreement is expected.** The audit and this plan contain positions a
  reasonable engineer could challenge. If you think one is wrong, say so with evidence
  and open a deviation — do not silently implement around it.