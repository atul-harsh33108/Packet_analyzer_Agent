"""Retrieval-augmented grounding (`T4-06`).

**Citations are checked, not trusted.** A citation is a *quote*, and the quote
must appear in the chunk it cites \u2014 which catches a model that cites a
document it did not read, or quotes something that is not in it. A RAG system
that retrieves without checking the retrieved text is a hallucination with extra
steps.

Whether the quoted passage *supports* the claim in the prose is a judgement, and
it belongs to a critic \u2014 the design's Critic agent \u2014 not to this package.
"""

from __future__ import annotations

from dpi_agents.rag.citations import CitationCheck, verify_citation, verify_citations

__all__ = ["CitationCheck", "verify_citation", "verify_citations"]
