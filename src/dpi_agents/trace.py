"""The durable trace (`T4-01`).

**A file, not a list.** The design's fifth way to kill this project is *"agent
state in memory instead of a durable checkpointer"*: a long investigation that
dies at step 40 is the normal case, not the exception. The trace is that
checkpointer for the read-only agents, and it is written **as the run happens**,
so the steps that did happen survive the failure that stopped them.

**One line per step, JSON.** Append-only and greppable, so a trace can be read
with `cat` when an agent goes wrong, which is when a human actually wants it.
A trace format that needs the framework to read is a trace format nobody reads.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

__all__ = ["Trace", "TraceStep"]


@dataclasses.dataclass(frozen=True, slots=True)
class TraceStep:
    """One recorded step."""

    index: int
    kind: str
    payload: Mapping[str, Any]


class Trace:
    """An append-only record of a run, written as it happens.

    The file is opened in write mode, so a trace is a *run's* trace and not an
    accumulation of every run that ever happened: two runs' traces cannot be
    confused for one another's, which is the failure a shared append-only file
    invites.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._index = 0
        self._file = self._path.open("w", encoding="utf-8")

    @property
    def path(self) -> Path:
        """Where the trace is written."""
        return self._path

    def record(self, kind: str, payload: Mapping[str, Any]) -> TraceStep:
        """Append one step, and flush it.

        Flushed on every step: a trace that is lost when the process dies is
        exactly the trace you wanted.
        """
        step = TraceStep(index=self._index, kind=kind, payload=dict(payload))
        self._file.write(
            json.dumps(
                {"index": step.index, "kind": step.kind, "payload": step.payload},
                sort_keys=True,
                default=str,
            )
            + "\n"
        )
        self._file.flush()
        self._index += 1
        return step

    def close(self) -> None:
        """Close the file. Safe to call twice."""
        if not self._file.closed:
            self._file.close()

    def __enter__(self) -> Trace:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @staticmethod
    def read(path: str | Path) -> list[TraceStep]:
        """Read a trace back.

        The replay half of "a full replayable trace for every verdict" (Phase 4's
        third exit criterion): the trace has to be readable by something that is
        not the process that wrote it.
        """
        steps: list[TraceStep] = []
        with Path(path).open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                steps.append(
                    TraceStep(index=int(raw["index"]), kind=str(raw["kind"]), payload=raw["payload"])
                )
        return steps
