"""Citation enforcement (`T4-06`).

**The checkable half of "the evidence supports the claim".** A citation is a
**quote**, and the quote must appear in the chunk it cites. That is mechanical,
and it catches the failure that matters: a model that cites a document it did
not read, or quotes something that is not in it. A RAG system that retrieves
without checking the retrieved text is a hallucination with extra steps.

**The half that is not checkable here.** Whether the quoted passage *supports*
the claim in the prose is a judgement, and it belongs to a critic \u2014 the
design's Critic agent \u2014 not to this module. So the rule this layer enforces
is stated exactly: **the citation is real**. `T4-04` already guarantees the
other half for a run's flows (the flow it names is in the run); this guarantees
it for the documents.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from dpi_agents.memory.knowledge import KnowledgeStore

__all__ = ["CitationCheck", "verify_citation", "verify_citations"]

_WHITESPACE = re.compile(r"\s+")


def _fold(text: str) -> str:
    """The form a quote is matched against: casefolded, whitespace collapsed."""
    return _WHITESPACE.sub(" ", text.casefold()).strip()


@dataclass(frozen=True, slots=True)
class CitationCheck:
    """What one citation check found."""

    ok: bool
    chunk_id: str
    #: Why it failed, when it did.
    reason: str = ""

    def to_json(self) -> dict[str, Any]:
        return {"ok": self.ok, "chunk_id": self.chunk_id, "reason": self.reason}


def verify_citation(store: KnowledgeStore, chunk_id: str, quote: str) -> CitationCheck:
    """Whether `quote` appears in the chunk `chunk_id`.

    The three ways it can fail, and they are different failures: the chunk does
    not exist (the citation names something the store has never heard of), the
    quote is empty (a citation with no evidence in it), or the quote is not in
    the chunk (the citation is a fabrication, or the text was edited under it).
    """
    if not quote.strip():
        return CitationCheck(
            ok=False, chunk_id=chunk_id, reason="the citation quotes nothing"
        )
    chunk = store.chunk(chunk_id)
    if chunk is None:
        return CitationCheck(
            ok=False,
            chunk_id=chunk_id,
            reason=f"no chunk {chunk_id!r} in the knowledge store",
        )
    if _fold(quote) not in _fold(chunk.text):
        return CitationCheck(
            ok=False,
            chunk_id=chunk_id,
            reason="the quote does not appear in the chunk it cites",
        )
    return CitationCheck(ok=True, chunk_id=chunk_id)


def verify_citations(
    store: KnowledgeStore, citations: tuple[tuple[str, str], ...]
) -> tuple[CitationCheck, ...]:
    """Check every `(chunk id, quote)` pair, in order."""
    return tuple(verify_citation(store, chunk_id, quote) for chunk_id, quote in citations)
