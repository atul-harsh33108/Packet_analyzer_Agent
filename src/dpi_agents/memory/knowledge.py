"""Semantic memory: the knowledge store (`T4-06`).

**Documents, chunked, and retrievable.** The retrieval is **keyword-based and
deterministic** \u2014 not the design's "hybrid". Hybrid means keyword plus
embeddings, and embeddings need a model, which is `T4-07`'s; so the vector half
is deferred rather than faked with something that pretends to be semantic.

**The ordering is part of the contract.** Ties are broken by the chunk id, so
the same query always returns the same chunks in the same order: a retrieval
that reorders itself between runs is a retrieval whose results cannot be
compared between runs, and a corpus whose results cannot be compared is a
corpus that measures nothing.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from dpi_agents.memory.text import paragraphs, tokens

__all__ = ["Chunk", "Document", "KnowledgeStore"]


@dataclasses.dataclass(frozen=True, slots=True)
class Document:
    """One document in the knowledge store."""

    id: str
    title: str
    text: str


@dataclasses.dataclass(frozen=True, slots=True)
class Chunk:
    """One piece of a document, addressable and quotable."""

    id: str
    document_id: str
    index: int
    text: str

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "document_id": self.document_id,
            "index": self.index,
            "text": self.text,
        }


class KnowledgeStore:
    """The semantic memory: documents, chunked, and retrievable by keyword."""

    def __init__(self) -> None:
        self._documents: dict[str, Document] = {}
        self._chunks: dict[str, Chunk] = {}

    def add(self, document: Document) -> None:
        """Add or replace a document, and re-chunk it."""
        self._documents[document.id] = document
        for chunk_id in [
            cid for cid, chunk in self._chunks.items() if chunk.document_id == document.id
        ]:
            del self._chunks[chunk_id]
        for index, text in enumerate(paragraphs(document.text)):
            chunk_id = f"{document.id}#{index}"
            self._chunks[chunk_id] = Chunk(
                id=chunk_id,
                document_id=document.id,
                index=index,
                text=text,
            )

    def documents(self) -> tuple[Document, ...]:
        """Every document, in insertion order."""
        return tuple(self._documents.values())

    def chunk(self, chunk_id: str) -> Chunk | None:
        """One chunk by its id, or `None`."""
        return self._chunks.get(chunk_id)

    def search(self, query: str, limit: int = 3) -> tuple[Chunk, ...]:
        """The chunks that best match `query`.

        Scored by how many of the query's words they contain, ties broken by the
        chunk id.
        """
        if limit < 0:
            raise ValueError(f"limit must be >= 0, got {limit}")
        wanted = set(tokens(query))
        if not wanted:
            return ()
        scored: list[tuple[int, str, Chunk]] = []
        for chunk in self._chunks.values():
            overlap = len(wanted & set(tokens(chunk.text)))
            if overlap:
                scored.append((-overlap, chunk.id, chunk))
        scored.sort(key=lambda item: (item[0], item[1]))
        return tuple(chunk for _score, _id, chunk in scored[:limit])
