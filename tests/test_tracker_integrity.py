"""The tracker's internal consistency, asserted rather than assumed (`M-08`).

`TASK_TRACKER.md` is the authoritative record of what has been done, and until now
**nothing checked it**. Two failures reached a committed tree under a fully green gate:

1. **Six task records were unreachable.** Appendix A's template opens a fenced
   `markdown` block. Every `T3-0x` record from `T3-01` onward was inserted *before the
   template heading* -- which is inside that fence -- so `T3-01`..`T3-06` rendered as
   literal code, and §5, the section that is supposed to hold them, contained no `T3-*`
   record at all. Each session appended correctly and none could see the previous
   session's work.
2. **The `D-##` findings row did not add up.** It read `27` total against
   `22 closed + 4 open`, so `D-27` appeared in no column at all -- and had not since it
   was allocated. Separately, `§3`'s Phase 3 rollup said `2 done` while §4's board said
   `3 done`, for a full session.

All three are the same shape: a number or a structure that no check constrains. The
numbers live in four places (§1, §3, §4, §6) plus `AUDIT.md`, and prose that repeats a
count is prose that drifts. These tests recompute each count from the thing it claims
to describe, so a section can be wrong only if this file is wrong too.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TRACKER = REPO / "docs" / "TASK_TRACKER.md"
AUDIT = REPO / "docs" / "AUDIT.md"

#: Board rows look like ``| `T2-02` | title | traces | status | gate | effort |``.
BOARD_ROW = re.compile(r"^\|\s*`((?:T\d+|DOC)-\d+)`\s*\|")
#: A task record heading is ``### `T3-03` - ...``; the template's ``T<n>-<nn>`` is not.
RECORD_HEADING = re.compile(r"^### `([^`]+)`")
#: §3 rows look like ``| **3** | MCP server | 7 | **3** | 1 | 0 | 3 | 0 | in progress |``.
ROLLUP_ROW = re.compile(r"^\|\s*\*?\*?([0-9.]+|DOC)\*?\*?\s*\|")
FENCE = re.compile(r"^\s*```")
STATUSES = {"done", "pending", "in_progress", "blocked", "partial", "deferred"}
#: §3 names a phase "0.5"; the board names its tasks `T05-`. Nothing derives one
#: from the other, so the mapping is derived here rather than listed: a list of
#: known phases is a list that stops being true when a phase is added, and the
#: phase that stops being checked is the one nobody notices (`M-09`).
def phase_prefix(phase: str) -> str | None:
    """The board's task prefix for a phase, or `None` for a phase it cannot name.

    Phase 0.5 is `T05` and phase 5 is `T5`; `DOC` is the one name that is not
    arithmetic.
    """
    if phase == "DOC":
        return "DOC"
    if not phase or not phase.replace(".", "").isdigit():
        return None
    return "T" + phase.replace(".", "")


@pytest.fixture(scope="module")
def tracker() -> str:
    if not TRACKER.exists():
        pytest.fail(f"{TRACKER} is missing")
    return TRACKER.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def tlines(tracker: str) -> list[str]:
    return tracker.split("\n")


@pytest.fixture(scope="module")
def audit() -> str:
    if not AUDIT.exists():
        pytest.fail(f"{AUDIT} is missing")
    return AUDIT.read_text(encoding="utf-8")


def section_bounds(lines: list[str], prefix: str) -> tuple[int, int]:
    """`[start, stop)` for the ``## `` section whose heading starts with `prefix`."""
    starts = [i for i, ln in enumerate(lines) if ln.startswith(prefix)]
    assert len(starts) == 1, f"expected exactly one {prefix!r} heading, found {len(starts)}"
    start = starts[0]
    stop = next((j for j in range(start + 1, len(lines)) if lines[j].startswith("## ")), len(lines))
    return start, stop


def board_rows(lines: list[str]) -> list[tuple[str, str, str]]:
    """`(task, phase_prefix, status)` for every §4 board row."""
    out: list[tuple[str, str, str]] = []
    for line in lines:
        m = BOARD_ROW.match(line)
        if not m:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 5:
            continue
        status = cells[3].strip("* ")
        if status not in STATUSES:
            continue
        task = m.group(1)
        out.append((task, task.split("-")[0], status))
    return out


def record_ids(lines: list[str]) -> list[str]:
    """Task ids that have a ``### `ID` `` record, excluding the ``<T>`` template."""
    return [
        m.group(1)
        for ln in lines
        if (m := RECORD_HEADING.match(ln)) and "<" not in m.group(1)
    ]


def record_spans(lines: list[str]) -> list[tuple[str, int, int]]:
    headings = [
        (i, m.group(1))
        for i, ln in enumerate(lines)
        if (m := RECORD_HEADING.match(ln)) and "<" not in m.group(1)
    ]
    spans: list[tuple[str, int, int]] = []
    for n, (start, name) in enumerate(headings):
        stop = headings[n + 1][0] if n + 1 < len(headings) else len(lines)
        spans.append((name, start, stop))
    return spans


def ints_in(cell: str) -> list[int]:
    return [int(m) for m in re.findall(r"\d+", cell)]


def _first_int(cell: str) -> int | None:
    found = ints_in(cell)
    return found[0] if found else None


# ---------------------------------------------------------------------------
# M-08: records must be where a reader can find them
# ---------------------------------------------------------------------------


def test_every_task_record_lives_in_section_5(tlines: list[str]) -> None:
    start, stop = section_bounds(tlines, "## 5. ")
    outside = [
        (n + 1, ln[:50])
        for n, ln in enumerate(tlines)
        if (m := RECORD_HEADING.match(ln)) and "<" not in m.group(1)
        and not (start < n < stop)
    ]
    assert not outside, f"task records outside §5 (line, heading): {outside}"


def test_no_task_record_is_inside_a_code_fence(tlines: list[str]) -> None:
    fence_count = 0
    trapped: list[tuple[int, str]] = []
    for n, ln in enumerate(tlines):
        if FENCE.match(ln):
            fence_count += 1
            continue
        if fence_count % 2 == 1 and (m := RECORD_HEADING.match(ln)) and "<" not in m.group(1):
            trapped.append((n + 1, m.group(1)))
    assert fence_count % 2 == 0, (
        f"{fence_count} code fences: unpaired, so everything after one of them renders as code"
    )
    assert not trapped, f"task records trapped inside a code fence: {trapped}"


def test_every_board_row_has_exactly_one_record(tlines: list[str]) -> None:
    board = {task for task, _, _ in board_rows(tlines)}
    records = record_ids(tlines)
    assert len(records) == len(set(records)), "a task has more than one record"
    assert board - set(records) == set(), f"board rows with no record: {sorted(board - set(records))}"
    assert set(records) - board == set(), f"records with no board row: {sorted(set(records) - board)}"


# ---------------------------------------------------------------------------
# §3 rollup vs §4 board -- the `T3-02` miss
# ---------------------------------------------------------------------------


def test_the_phase_rollup_matches_the_board(tlines: list[str]) -> None:
    start, stop = section_bounds(tlines, "## 3. ")
    rows = board_rows(tlines)
    checked = 0
    for ln in tlines[start:stop]:
        m = ROLLUP_ROW.match(ln)
        if not m:
            continue
        phase = m.group(1)
        prefix = phase_prefix(phase)
        if prefix is None:
            continue
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if not cells[2].strip("* ").isdigit():
            continue  # the bare `outline` rows for phases 4-6 have no task count
        stated = [_first_int(c) for c in cells[2:8]]
        assert all(s is not None for s in stated), f"unparsable rollup row: {ln[:80]!r}"
        mine = [st for t, ph, st in rows if ph == prefix]
        actual = {
            "tasks": len(mine),
            "done": mine.count("done"),
            "in_progress": mine.count("in_progress"),
            "blocked": mine.count("blocked"),
            "pending": mine.count("pending"),
            "deferred": mine.count("partial") + mine.count("deferred"),
        }
        assert stated[0] == actual["tasks"], f"phase {phase}: {stated[0]} tasks vs {actual}"
        assert stated[1] == actual["done"], f"phase {phase}: done says {stated[1]}, {actual}"
        # Deferred absorbs `partial`: §3 has no column for it and `DOC-07` is partial.
        assert sum(stated[1:]) == stated[0], f"phase {phase}: rollup columns do not sum"
        assert (stated[2], stated[3], stated[4]) == (
            actual["in_progress"],
            actual["blocked"],
            actual["pending"],
        ), f"phase {phase}: in-progress/blocked/pending disagree with the board: {stated}, {actual}"
        checked += 1
    assert checked >= 6, f"only {checked} rollup rows checked; the parse has gone stale"


def test_section_one_states_the_same_phase_progress_as_the_rollup(tlines: list[str]) -> None:
    """§1 is the only block a cold-starting agent reads, so it is the most
    expensive place for a stale number to live.

    The drift this guards against happened twice in one session: §1's progress
    line was left at 5/8 while §3 moved, because the two are edited at different
    moments and nothing compared them. §3 is checked against the board; §1 was
    checked against nothing.

    It now checks **every** phase rather than one. The check named Phase 3
    because Phase 3 was the newest phase when it was written; Phase 4 was added
    afterwards, its counts were never compared with anything, and they read
    `8/8` for a phase with seven tasks (`M-09`).
    """
    progress = next(
        (ln for ln in tlines if ln.startswith("| **Phase progress** |")), None
    )
    assert progress is not None, "§1 has no Phase progress row"
    cells = [c.strip() for c in progress.strip().strip("|").split("|")]
    stated = {
        phase: (int(done), int(total))
        for phase, done, total in re.findall(
            r"Phase ([\d.]+):\s*(\d+)/(\d+)", cells[1]
        )
    }
    doc = re.search(r"DOC:\s*(\d+)/(\d+)", cells[1])
    if doc is not None:
        stated["DOC"] = (int(doc.group(1)), int(doc.group(2)))
    assert stated, f"§1 states no phase progress at all: {progress!r}"

    start, stop = section_bounds(tlines, "## 3. ")
    checked = 0
    for ln in tlines[start:stop]:
        m = ROLLUP_ROW.match(ln)
        if not m:
            continue
        phase = m.group(1)
        if phase_prefix(phase) is None:
            continue
        row = [c.strip() for c in ln.strip().strip("|").split("|")]
        total = _first_int(row[2])
        done = _first_int(row[3])
        if total is None or done is None:
            continue  # the bare `outline` rows have no counts
        assert phase in stated, f"§3 has a row for phase {phase} and §1 does not name it"
        assert stated[phase] == (done, total), (
            f"§1 says phase {phase} is {stated[phase][0]}/{stated[phase][1]}; "
            f"§3 says {done}/{total}"
        )
        checked += 1
    assert checked >= 8, f"only {checked} phases compared; the parse has gone stale"


def test_the_stated_totals_match_the_board(tlines: list[str]) -> None:
    rows = board_rows(tlines)
    totals = next((ln for ln in tlines if ln.startswith("**Totals:**")), None)
    assert totals is not None, "no `**Totals:**` line in §3"
    numbers = ints_in(totals)
    stated_total, stated_done, stated_progress, stated_blocked, stated_pending, stated_partial = numbers
    actual = {
        "total": len(rows),
        "done": sum(1 for _, _, s in rows if s == "done"),
        "in_progress": sum(1 for _, _, s in rows if s == "in_progress"),
        "blocked": sum(1 for _, _, s in rows if s == "blocked"),
        "pending": sum(1 for _, _, s in rows if s == "pending"),
        "partial": sum(1 for _, _, s in rows if s == "partial"),
    }
    assert (stated_total, stated_done, stated_progress, stated_blocked, stated_pending, stated_partial) == (
        actual["total"],
        actual["done"],
        actual["in_progress"],
        actual["blocked"],
        actual["pending"],
        actual["partial"],
    ), f"totals line {numbers} disagrees with the board: {actual}"


# ---------------------------------------------------------------------------
# §6 findings -- the `D-27` omission
# ---------------------------------------------------------------------------


def test_the_findings_table_sums(tlines: list[str]) -> None:
    start, stop = section_bounds(tlines, "## 6. ")
    checked = 0
    for ln in tlines[start:stop]:
        if not re.match(r"^\|\s*`[DRAMS]-##`", ln):
            continue
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        total, closed, opened, unassigned = (_first_int(c) for c in cells[1:5])
        assert total is not None, f"no total in {ln[:60]!r}"
        assert closed is not None, f"no closed count in {ln[:60]!r}"
        assert opened is not None, f"no open count in {ln[:60]!r}"
        assert closed + opened == total, (
            f"{cells[0]}: {closed} closed + {opened} open != {total} total, "
            "so a finding is counted in no column"
        )
        if unassigned is not None:
            assert unassigned <= opened, f"{cells[0]}: {unassigned} unassigned but only {opened} open"
        # Where the open cell names ids, the count must match them.
        named = re.findall(r"`([DRAMS]-\d+)`", cells[3])
        if named:
            assert len(named) == opened, f"{cells[0]}: {opened} open but names {named}"
        checked += 1
    assert checked >= 5, f"only {checked} findings rows checked; the parse has gone stale"


def test_the_defect_register_and_its_counts_agree(tlines: list[str], audit: str) -> None:
    ids = sorted({int(m) for m in re.findall(r"\bD-(\d{1,2})\b", audit)})
    assert ids == list(range(1, len(ids) + 1)), f"the register has gaps: {ids}"

    tracker_row = next(ln for ln in tlines if ln.startswith("| `D-##` defects"))
    stated_total = ints_in(tracker_row.strip().strip("|").split("|")[1])[0]
    assert stated_total == len(ids), (
        f"tracker §6 says {stated_total} `D-##` findings; `AUDIT.md` holds {len(ids)}"
    )

    heading = next(ln for ln in audit.split("\n") if ln.startswith("## \u00a72 "))
    assert f"`D-{len(ids):02d}`" in heading, (
        f"the §2 heading does not name the highest defect id: {heading!r}"
    )

    # The intro's arithmetic is a sentence, so both its operands and its sum are checked.
    # It wraps across lines, so the paragraph is reassembled before searching it.
    alines = audit.split("\n")
    first = next(i for i, ln in enumerate(alines) if ln.startswith("Twenty-"))
    para = " ".join(alines[first : first + 5])
    m = re.search(r"(\d+) \+ (\d+) = (\d+)", para)
    assert m is not None, f"the §2 intro no longer states its arithmetic: {para!r}"
    live, inherited, summed = (int(g) for g in m.groups())
    assert live + inherited == summed == len(ids), (
        f"§2 intro says {live} + {inherited} = {summed}, but the register holds {len(ids)}"
    )


# ---------------------------------------------------------------------------
# The protocol's own checklist, ported from the ad-hoc reconciler
# ---------------------------------------------------------------------------


def test_every_done_record_accounts_for_its_work(tlines: list[str]) -> None:
    required = ("**Status:**", "**Verification:**", "**Closed findings:**")
    incomplete: list[str] = []
    checked = 0
    for name, start, stop in record_spans(tlines):
        body = "\n".join(tlines[start:stop])
        if "**Status:** done" not in body:
            continue
        checked += 1
        missing = [f for f in required if f not in body]
        if missing:
            incomplete.append(f"{name} is missing {missing}")
    assert checked >= 30, f"only {checked} done records checked; the parse has gone stale"
    assert not incomplete, f"done records missing protocol fields: {incomplete}"
