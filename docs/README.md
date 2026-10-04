# Documentation Index

All project documentation lives here. The root [`README.md`](../README.md) stays at
the repository root because it is the project's front door; everything else is here.

> **If you are an agent starting cold:** read [`TASK_TRACKER.md`](TASK_TRACKER.md) §1
> first. It is 40 lines and tells you what to do next.

---

## Read in this order

| Order | Document | What it tells you | Mutable? |
|---|---|---|---|
| 1 | [`OPERATING_INSTRUCTIONS.md`](OPERATING_INSTRUCTIONS.md) | **How to work in this repo.** Read order, the five non-negotiable rules, boundaries you must not cross, verification baseline, deliberate quirks not to "fix" | rarely |
| 2 | [`TASK_TRACKER.md`](TASK_TRACKER.md) | **What is done, decided, and next.** Status of all 30 tasks, decision log, per-task records, session history | **frequently** |
| 3 | [`TASK_TRACKER_UPDATE_PROTOCOL.md`](TASK_TRACKER_UPDATE_PROTOCOL.md) | **How to edit the tracker.** 8 invariants, claim/complete/session-end procedures, status vocabulary, anti-patterns | rarely |
| 4 | [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) | **How to build the fixes.** 30 task specs, dependency graph, 5 human decisions, risk register, verification gates | rarely |
| 5 | [`AUDIT.md`](AUDIT.md) | **What the problems are.** 66 findings — the port-vs-C++ verdict, 22 defects, 10 missing rails, doc defects | rarely — append new IDs only |
| 6 | [`AGENTIC_ARCHITECTURE.md`](AGENTIC_ARCHITECTURE.md) | **Where the project is going.** The 10-layer agentic product vision and roadmap | rarely |
| — | [`DESIGN_DECISIONS.md`](DESIGN_DECISIONS.md) | **Why the port was built this way.** Every bug fixed vs. the C++ original, safety constraints, testing strategy | rarely |
| — | [`WORKFLOW.md`](WORKFLOW.md) | **Architecture diagrams.** ⚠️ badly stale — scheduled for rewrite | rarely |

---

## What each document is for, in one line

- **[`AUDIT.md`](AUDIT.md)** — The findings register. 66 numbered IDs in 6 groups
  (`P-##` port-vs-C++, `D-##` defects, `R-##` missing rails, `A-##` agentic,
  `M-##` documentation, `S-##` session). Every task in the plan traces to these.
  *IDs are permanent — never renumber.*

- **[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md)** — How to fix them. 30 task
  cards with file lists, concrete changes, tests, estimates, and gates. Dependency
  graph and critical path in §1; five human decisions in §2; risk register in §9.

- **[`TASK_TRACKER.md`](TASK_TRACKER.md)** — Mutable state. Task statuses, decision
  log, per-task records (including *how it was tackled* and *deviations*), findings
  closure, deviation log, session log.

- **[`TASK_TRACKER_UPDATE_PROTOCOL.md`](TASK_TRACKER_UPDATE_PROTOCOL.md)** — The
  procedure that keeps the tracker consistent across sessions and agents. Eight
  invariants, six-step claim, nine-step complete, twelve-item validation checklist.

- **[`OPERATING_INSTRUCTIONS.md`](OPERATING_INSTRUCTIONS.md)** — Session workflow for
  any human or agent. The five non-negotiable rules, the boundaries requiring a human
  decision, the `spawn`-start-method consequences on Windows, and what is deliberately
  *not* implemented.

- **[`AGENTIC_ARCHITECTURE.md`](AGENTIC_ARCHITECTURE.md)** — The product vision:
  deterministic core / probabilistic periphery, 10 layers, phased roadmap. §4 (the core
  strategic principle), §5 (where AI is and is not the right tool), Layer 7 (safety),
  Layer 8 (human gate) and §9 (five failure modes) are the strongest material in this
  repository. §1–§3 and §8 are **stale** — see [`AUDIT.md`](AUDIT.md) §4.2 for the
  correction table.

- **[`DESIGN_DECISIONS.md`](DESIGN_DECISIONS.md)** — Provenance for the port itself.
  Which C++ bugs were fixed and why, the binding safety constraints, the differential
  testing strategy. ⚠️ six known defects — see [`AUDIT.md`](AUDIT.md) §5.2.

- **[`WORKFLOW.md`](WORKFLOW.md)** — Diagrams of the pipeline and module flow.
  ⚠️ **Badly stale.** Documents a deleted module, re-draws a bug that was already fixed,
  cites five wrong line numbers, and is missing 3 of 13 modules and 7 CLI flags. Being
  rewritten (`DOC-03`, deferred until after Phase 1). Do not use it as a reference.

---

## Documentation that stays with its directory

These are *not* here, because they describe a specific directory and belong beside it:

| File | Describes |
|---|---|
| [`../README.md`](../README.md) | The project front door — install, usage, CLI reference |
| [`../OSC/README.md`](../OSC/README.md) | The original C++ engine (reference material, unmodified) |
| [`../OSC/WINDOWS_SETUP.md`](../OSC/WINDOWS_SETUP.md) | Build instructions for the C++ reference |
| [`../tests/differential/README.md`](../tests/differential/README.md) | The C++ differential test suite |

---

## Conventions

- **One home per fact.** A finding is described in `AUDIT.md` and nowhere else. A
  task's specification lives in `IMPLEMENTATION_PLAN.md` and nowhere else. The tracker
  stores *status only*. This is what prevents the duplication that produced the current
  documentation drift.
- **Cite symbols, not line numbers.** Line numbers rot. `WORKFLOW.md` is unmaintainable
  largely because of this.
- **Never renumber an ID.** `DEC-##`, `T<n>-<nn>`, `DOC-nn`, and all finding IDs are
  permanent. A retired ID is never reused.
- **State is verified, not asserted.** Where this documentation states a number
  (test count, module count, coverage), that number came from running the command.
  Re-derive it rather than copying it forward.