"""The agent's memory (`T4-06`).

**Two kinds, not four.** The design names four: episodic, semantic, working and
procedural. This package builds two of them \u2014 **episodic** (what happened) and
**semantic** (what we know) \u2014 because *procedural* memory is the "how we do
this" memory, and there is no procedure yet to remember. Conflating the kinds is
the number one memory-design error in agentic systems, so building two
deliberately is better than building four loosely.
"""

from __future__ import annotations

from dpi_agents.memory.episodic import Episode, EpisodicMemory
from dpi_agents.memory.knowledge import Chunk, Document, KnowledgeStore

__all__ = [
    "Chunk",
    "Document",
    "Episode",
    "EpisodicMemory",
    "KnowledgeStore",
]
