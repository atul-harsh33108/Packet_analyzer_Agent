# Task Tracker Update Protocol

**Governs:** every edit to [`TASK_TRACKER.md`](TASK_TRACKER.md)
**Audience:** any human or agent working on `dpi-engine`, with or without conversation history.
**Authority:** this document defines *how* to update the tracker. `OPERATING_INSTRUCTIONS.md` defines *what to work on*. `IMPLEMENTATION_PLAN.md` defines *how to build it*. `AUDIT.md` defines *what the problems are*. This file defines only the mechanics of keeping state.

---

## 0. Why this document exists

A tracker that is updated inconsistently is worse than no tracker: it becomes
actively misleading, and the next session trusts it.

The specific failure this prevents has **already happened in this repository**,
twice:

1. `AGENTIC_ARCHITECTURE.md` was written at 2026-09-30 23:02. A large refactor
   landed at 2026-10-01 01:15. The document was never reconciled, so ~40% of its
   factual claims became wrong — test counts, module counts, whether mypy existed,
   and eight "verified defects" that had already been fixed. See `AUDIT.md` §4.2
   and `S-01`.
2. `WORKFLOW.md` cites code by line number throughout. It rotted to the point where
   it documents a deleted module and re-draws a bug that was already fixed.

**The rule that prevents both:** *state is written once, in one place, with an ID
that survives edits — and never restated anywhere it can drift.*

---

## 1. The eight invariants

Non-negotiable. If an edit violates one, the edit is wrong.

| # | Invariant |
|---|---|
| **I1** | **One home per fact.** A finding is described in `AUDIT.md` and nowhere else. A task's *specification* is in `IMPLEMENTATION_PLAN.md` and nowhere else. The tracker stores **status and outcomes only**. Never paste a description into the tracker. |
| **I2** | **Never renumber.** IDs (`DEC-##`, `T<n>-<nn>`, `DOC-nn`, `D-##`, `R-##`, `A-##`, `M-##`, `S-##`, `P-##`) are permanent. A retired ID is never reused and never renumbered. New findings take the next free number. |
| **I3** | **History is append-only.** §2 decisions, §7 deviations and §8 session log are append-only. Never rewrite an existing row to change what was decided or recorded. |
| **I4** | **`done` is terminal.** If a fix is reverted, open a **new** task. Do not move a task from `done` back to `pending`. |
| **I5** | **No claim without an owner.** `in_progress` requires `Claimed by:` and `Session:`. If both are empty, the task is not `in_progress`. |
| **I6** | **Never cite code by line number alone in any new text.** Cite the symbol. Line numbers drift; `quic.py:603` already cites a symbol that does not exist. Use `` `sni_extractor.extract_sni` ``, not `sni_extractor.py:89`. Where a line number genuinely helps, write *both*: "`extract_sni` (`sni_extractor.py`, ~line 89)". |
| **I7** | **Every status change touches all four state locations.** See §2 below. A status change that updates only the task board is incomplete. |
| **I8** | **A defect is closed only when a test fails without its fix.** Code changed with no regression test is not closed. `tests/test_pcap_io.py:41`, which asserts the `D-06` bug, is the standing counter-example. |

---

## 2. The four state locations

Every task status change **must** update all four. This is invariant **I7**.

| # | Location | What changes |
|---|---|---|
| **1** | **Frontmatter** (top of file) | `last_updated`, `last_updated_by`, `session`, and `current_task` / `next_action` if the task moved |
| **2** | **§1 Current state** | `Phase`, `Phase progress`, `Current task`, `Next action`, `Blockers`, `Open decisions`, `Session` |
| **3** | **§4 Task board** | The task's `Status` cell, and `Gate` if it changed |
| **4** | **§5 Task record** | `Status`, `Claimed by`, `Session`, `Blocked by`, and any new content in `How it was tackled` / `Deviations` / `Verification` / `Closed findings` / `Follow-ups` |

Plus, when applicable:

| # | Location | Trigger |
|---|---|---|
| **5** | **§2 Decision log** | A decision is made, reversed, or superseded |
| **6** | **§6 Findings status** | A task moves to `done` and closes findings |
| **7** | **§7 Deviation log** | Reality differed from the plan |
| **8** | **§8 Session log** | At session end |

---

## 3. Procedure — starting a session

Follow in order. Do not skip step 3 even if you think you already know the state.

### Step 1 — Read, in this order

```
AUDIT.md              frontmatter + §1 Current state      (the 40 lines that matter)
IMPLEMENTATION_PLAN.md §1 dependency graph, §8 verification gates
TASK_TRACKER.md        frontmatter, §1, §3, §4
OPERATING_INSTRUCTIONS.md                                      (if this is your first session)
```

### Step 2 — Verify the tree is green before you touch anything

```powershell
uv run ruff check .
uv run mypy
uv run pytest -q
```

Expected: `All checks passed!` · `Success: no issues found in 13 source files` ·
`404 passed`.

**If anything is red, the previous session did not finish cleanly.** Do not start new
work. Either fix the regression, or if it is pre-existing and documented, record it
in §8 and proceed. **Never start new work on a red tree** — you will not be able to
tell your own breakage from inherited breakage.

### Step 3 — Check the tracker's internal consistency

```powershell
# Phase progress counts in §1 and §3 must match the §4 board
# Open decisions in §1 frontmatter/§2 must match
# No task may be in_progress with an empty Claimed by  (invariant I5)
```

### Step 4 — Pick the next task

Selection rules, in priority order:

1. Any task whose `Blocked by` is now resolved (a decision was just made).
2. `T0-01`, `T0-02` — CI and fixtures gate everything else.
3. The highest-value unblocked task on the critical path (§1 of the plan).
4. Any `DOC-*` task, which is independent and can proceed in parallel.

**Never start a task blocked by an open `DEC-##`** unless the tracker records that
decision as resolved in §2.

### Step 5 — Claim it

Apply §4 below. **Do not start editing source before claiming.**

---

## 4. Procedure — claiming a task

Exactly these edits:

1. **§5 task record** — set:
   ```
   - **Status:** in_progress · **Claimed by:** <agent-or-human> · **Session:** <session-id>
   ```
2. **§4 task board** — change that task's `Status` cell from `pending` to `in_progress`.
3. **§1 Current state** — set `Current task` to this task, and rewrite `Next action` as
   a **single concrete sentence**: the first thing to do, with file paths.
4. **Frontmatter** — set `current_task`, `next_action`, `last_updated`,
   `last_updated_by`, `session`.
5. **§3 Phase rollup** — increment that phase's `In progress` count and decrement
   its `Pending` count.

`Next action` must be specific enough that a cold agent could execute it. Compare:

- ✗ `"work on T0-01"` — useless
- ✗ `"add CI"` — still ambiguous
- ✓ `"Create .github/workflows/ci.yml with three jobs (lint, test, differential); add pytest-cov + pytest-timeout to [dependency-groups].dev; add [tool.coverage.*] to pyproject.toml; set global timeout = 60; gitignore + git rm --cached manual_test_output.pcap"` — executable

---

## 5. Procedure — completing a task

### Step 1 — Verify against the definition of done

Walk §10 of `TASK_TRACKER.md` **literally**. Every box, every time. In particular:

```powershell
uv run ruff check .      # clean
uv run mypy              # clean
uv run pytest -q         # green, count NOT reduced
```

**A reduced passing count is a failure, not a trade-off.** If a test was removed,
justify it in `Deviations` with a reason that a reviewer would accept.

### Step 2 — Write the record *while you still remember*

This is the step that gets skipped, and skipping it is why trackers go stale. Fill
in, at minimum:

- **How it was tackled** — what you actually did, in enough detail that a future
  agent could repeat it. Not "implemented the fix". Something like
  *"replaced the dpkt-delegating iteration with a direct struct read of the 16-byte
  record header; endianness logic reused from the global-header path; `orig_len` now
  sourced from record field 12 rather than `len(buf)`; removed the now-redundant
  `PcapLimitExceededError` size check that dpkt performed implicitly."*
- **Deviations** — what differed from the plan and why. Write `none` if genuinely
  none; do not leave it blank.
- **Verification** — the commands **and their actual output summary**.
- **Closed findings** — the IDs this closes.
- **Follow-ups** — anything this spawned, or `none`.

### Step 3 — Apply the four state locations (§2 above)

Set the task record and the board row to `done`. Set `Claimed by` and `Session` to
their real values — do not clear them.

### Step 4 — Update §6 findings status

Recount. If the task closed findings, the `Closed` count rises and `Open` falls by
the same amount. **The three numbers must sum to the group total.**

### Step 5 — Add a §7 deviation row if applicable

Any deviation that changed scope, estimate, or gate. Include the
`Plan updated?` column value — and if `yes`, actually update
`IMPLEMENTATION_PLAN.md` in the same pass. See §7 below.

### Step 6 — Advance the pointer

Set §1 `Current task` and `Next action` to the **next** task, and claim it if you are
continuing in the same session (apply §4). If you are stopping, set `Next action` to
the first action of the next session.

### Step 7 — Update frontmatter

`last_updated`, `last_updated_by`, `session`, and any moved pointers.

### Step 8 — Add the §8 session row

Only when ending the session. See §9 below.

---

## 6. Procedure — recording a decision

Applies when a human resolves a `DEC-##`, or when you discover a decision that was
never captured.

1. **§2 summary table** — set `Status` to `decided`, and fill `Decided value`,
   `Decided by`, `Date`.
2. **§2 detail block** — append a line under that decision:
   ```
   *Decided <date> by <who>:* <value chosen> — <one-line reason>.
   ```
   **Do not delete the options or the recommendation.** A future reader needs to see
   what was rejected and why.
3. **Frontmatter `blockers`** — remove that `DEC-##`.
4. **§4 task board** — any task whose `Gate` named this decision moves `blocked` →
   `pending`.
5. **§1 Current state** — update the `Open decisions` line.
6. **If the decision changed a task's scope**, update `IMPLEMENTATION_PLAN.md` and
   log a §7 deviation row.

**Reversing a decision:** never edit the original row (invariant **I3**). Add a **new**
`DEC-##` row marked `supersedes DEC-0n`, set the old row's status to
`superseded`, and re-gate whatever the new decision blocks.

---

## 7. Procedure — recording a deviation

A deviation is when reality differed from `IMPLEMENTATION_PLAN.md`. It is **not** a
failure and **not** something to hide. It is the plan being corrected by evidence.

Log one when:
- the approach changed materially
- the estimate was wrong by more than ~50%
- a task turned out to depend on something unplanned
- a finding turned out to be wrong or unreproducible

Do **not** log one for: a task taking a different number of hours, or a refactor that
stayed inside the described scope.

1. **§7** — append one row: `Date | Task | Planned | Actual | Reason | Plan updated?`
2. **If `Plan updated?` is `yes`** — edit `IMPLEMENTATION_PLAN.md` in the **same
   pass**, and note in the row which section changed.
3. **If the deviation reveals a new problem** — allocate a finding ID in `AUDIT.md`
   first (see §8), then reference that ID in the deviation row.

**The two documents must never disagree.** A deviation row that says
`Plan updated? = yes` when the plan was not updated is the exact disease that
produced the current documentation state.

---

## 8. Procedure — adding a finding

When implementation reveals a problem the audit did not catch:

1. **Allocate the next free ID** in `AUDIT.md` for the group (`D-##` for defects —
   take the next number after the highest, never fill a gap). **Never renumber**
   (invariant **I2**).
2. **Add the row** to the correct table in `AUDIT.md` with both severity columns.
3. **Add a task row** to `IMPLEMENTATION_PLAN.md` Appendix A, with a `T<n>-<nn>` ID.
4. **Add the task record** stub to `TASK_TRACKER.md` §5 using the Appendix A template.
5. **Add the task board row** to §4.
6. **Add it to the unassigned or assigned count** in §6.
7. **If it blocks the current phase**, add it to §1 `Blockers`.

Do not skip step 2. A finding that exists only in the tracker is not discoverable by
anyone reading `AUDIT.md`.

---

## 9. Procedure — ending a session

### Step 1 — Make the tree green

```powershell
uv run ruff check . && uv run mypy && uv run pytest -q
```

If it cannot be made green, **revert your in-progress source changes** rather than
leaving the tree broken, then record the attempt in the session row. A tracker
pointing at a red tree is a trap for the next session.

### Step 2 — Do not leave a task claimed but unrecorded

Any task you touched must be in one of: `done`, `pending` (with `Notes` explaining
what you tried and why you stopped), or `deferred`. **Never leave something
`in_progress` at the end of a session** — the next agent cannot tell whether it is
still running.

### Step 3 — Fill §1 so the next agent can start cold

A new session may have **no idea what you were doing**. `Next action` must be a
sentence they can execute without asking you anything.

### Step 4 — Append the §8 session row

```
| <date> | <session-id> | <agent> | <tasks touched> | <outcome> | <next action> |
```

`Outcome` is one of: `no change`, `partial — <what completed>`, `<n> tasks completed`,
`blocked on <DEC-id>`.

### Step 5 — Update frontmatter

`last_updated`, `last_updated_by`, `session`, `current_task`, `next_action`.

### Step 6 — Do not commit unless asked

The tracker, plan, audit and session transcripts are currently **untracked**. Do not
`git add` or commit without an explicit instruction.

---

## 10. Validation checklist

Run before declaring a tracker update complete.

- [ ] Frontmatter `last_updated` and `session` changed
- [ ] §1 phase progress counts equal the §4 board's actual status counts
- [ ] §3 rollup counts equal the §4 board's actual status counts
- [ ] §6 group counts sum to each group's total
- [ ] No task is `in_progress` with an empty `Claimed by` (**I5**)
- [ ] No task is `blocked` without a named `DEC-##` in `Blocked by`
- [ ] No task record has a blank `How it was tackled` while `done`
- [ ] No new text cites a code line number without the symbol name (**I6**)
- [ ] Every `done` task has a test that fails without its fix (**I8**)
- [ ] Any deviation with `Plan updated? = yes` is reflected in `IMPLEMENTATION_PLAN.md`
- [ ] No ID was renumbered (**I2**)
- [ ] §7 and §8 rows were appended, never edited (**I3**)

---

## 11. Anti-patterns

Each of these has either already happened in this repository or is a predictable
failure.

| Anti-pattern | Why it is wrong | Do instead |
|---|---|---|
| Leaving a record's `How it was tackled` blank | The one field only the implementer can write. Blank forever means the knowledge is lost. | Fill it in the same session |
| Leaving a task `in_progress` across sessions | The next agent cannot tell if it is running or abandoned | Set `pending` with a `Notes` explaining the stopping point |
| Editing a §8 session row | Destroys the audit trail | Append a new row |
| "Renumbering" to fix a gap | Every cross-reference in 3 documents silently breaks | Take the next free ID |
| Citing `file.py:123` in a task note | Rotts on the next edit — `WORKFLOW.md`'s entire problem | Cite the symbol; line number optional and secondary |
| Bulk-editing source with `sed -i` / PowerShell `-replace` | Caused a chain of `F821` regressions in `S-02` | Targeted patches, then re-lint immediately |
| Marking `done` because the code changed | `D-06` was "fixed" in a docstring while the code still had the bug | Test fails without the fix, passes with it |
| Editing `IMPLEMENTATION_PLAN.md` without a §7 deviation row | The two documents drift and neither can be trusted | Row with `Plan updated? = yes`, plan edited in the same pass |
| Adding a finding to the tracker only | Invisible to anyone reading `AUDIT.md` | ID in `AUDIT.md` first |
| Trusting the tracker's counts without checking | Counts drift silently as tasks complete | Recount from §4 |
| Leaving `session-ses_*.md` in the repo root | 453 KB of untracked noise that looks like project state | `DOC-08` |