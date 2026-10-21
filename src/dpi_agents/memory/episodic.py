"""Episodic memory: what happened, and how it turned out (`T4-06`).

**A verdict carries an outcome label** \u2014 what was *actually* found \u2014 because a
memory of what was predicted, with nothing recording how it turned out, teaches
the next agent the same prediction again. The label is the whole point of
keeping the memory: the prediction is cheap, and the outcome is what makes the
next prediction better.

**Durable by construction.** The file is append-only, so the history of what was
believed is part of the history \u2014 a label is a later line, not a rewritten
one. A memory that is only in a process's memory is gone when the process is,
and the phase's own criterion is that every verdict leaves a replayable trace.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from dpi_agents.memory.text import tokens

__all__ = ["Episode", "EpisodicMemory"]


@dataclasses.dataclass(frozen=True, slots=True)
class Episode:
    """One remembered run: what was concluded, and how it turned out."""

    run_id: str
    summary: str
    severity: str
    #: What was actually found. Empty until a human says otherwise.
    outcome: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "summary": self.summary,
            "severity": self.severity,
            "outcome": self.outcome,
        }


class EpisodicMemory:
    """What happened, and how it turned out."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path is not None else None
        self._episodes: dict[str, Episode] = {}

    @property
    def path(self) -> Path | None:
        """Where the memory is written, if it is durable."""
        return self._path

    def remember(self, episode: Episode) -> Episode:
        """Record an episode, and persist it if this memory is durable."""
        self._episodes[episode.run_id] = episode
        self._append(episode)
        return episode

    def label(self, run_id: str, outcome: str) -> Episode:
        """Record what a run **actually** turned out to be."""
        episode = self._episodes.get(run_id)
        if episode is None:
            raise KeyError(f"no episode for the run {run_id!r}")
        labelled = dataclasses.replace(episode, outcome=outcome)
        self._episodes[run_id] = labelled
        self._append(labelled)
        return labelled

    def episodes(self) -> tuple[Episode, ...]:
        """Every episode, in the order they were remembered."""
        return tuple(self._episodes.values())

    def recall(self, run_id: str) -> Episode | None:
        """One episode by its run id."""
        return self._episodes.get(run_id)

    def search(self, query: str, limit: int = 3) -> tuple[Episode, ...]:
        """The episodes that best match `query`, by the store's rule."""
        if limit < 0:
            raise ValueError(f"limit must be >= 0, got {limit}")
        wanted = set(tokens(query))
        if not wanted:
            return ()
        scored: list[tuple[int, str, Episode]] = []
        for episode in self._episodes.values():
            overlap = len(wanted & set(tokens(f"{episode.summary} {episode.outcome}")))
            if overlap:
                scored.append((-overlap, episode.run_id, episode))
        scored.sort(key=lambda item: (item[0], item[1]))
        return tuple(episode for _score, _id, episode in scored[:limit])

    def _append(self, episode: Episode) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(episode.to_json(), sort_keys=True) + "\n")
