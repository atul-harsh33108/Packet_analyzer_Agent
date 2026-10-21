"""The memory and the citation enforcement (`T4-06`).

**Two kinds of memory, and they are not interchangeable.** The semantic store
holds what we know; the episodic memory holds what happened, including how it
turned out \u2014 because a memory of what was predicted, with nothing recording
the outcome, teaches the next agent the same prediction again.

**The citation rule is mechanical.** A citation is a *quote*, and the quote must
appear in the chunk it cites. That is what catches a model citing a document it
did not read. Whether the quote supports the claim in the prose is a judgement,
and it is not this layer's.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from dpi_agents.memory.episodic import Episode, EpisodicMemory
from dpi_agents.memory.knowledge import Document, KnowledgeStore
from dpi_agents.nodes.explainer import explainer_node
from dpi_agents.rag.citations import verify_citation
from dpi_agents.tools import CompositeToolPort, KnowledgeToolPort

AD_DOC = Document(
    id="ad-tracker",
    title="Known advertising and tracking hosts",
    text=(
        "Hosts under metrics.example.net are advertising telemetry.\n"
        "\n"
        "Beaconing to a fixed rare port every sixty seconds is characteristic of "
        "command and control traffic."
    ),
)


class TestTheKnowledgeStore:
    def test_a_document_is_chunked_by_paragraph(self) -> None:
        store = KnowledgeStore()
        store.add(AD_DOC)
        assert len(store.documents()) == 1
        chunk = store.chunk("ad-tracker#0")
        assert chunk is not None
        assert chunk.document_id == "ad-tracker"
        assert "metrics.example.net" in chunk.text
        assert store.chunk("ad-tracker#1") is not None
        assert "Beaconing" in (store.chunk("ad-tracker#1").text)  # type: ignore[union-attr]

    def test_search_ranks_by_the_words_they_share(self) -> None:
        store = KnowledgeStore()
        store.add(AD_DOC)
        store.add(
            Document(
                id="dns",
                title="Name resolution",
                text="A DNS query for a rare top-level domain is worth a look.",
            )
        )
        hits = store.search("rare top-level domain", limit=2)
        assert hits, "the search found nothing"
        assert hits[0].document_id == "dns"

    def test_the_order_is_the_same_every_time(self) -> None:
        """A retrieval that reorders itself between runs cannot be compared."""
        store = KnowledgeStore()
        # Added **out of id order**, so a retrieval that leaves the tie to chance
        # returns a different order than one that breaks it by the id -- and the
        # two documents score the same, so the tie is real.
        store.add(
            Document(
                id="zzz",
                title="Another",
                text="Beaconing to a fixed rare port every sixty seconds.",
            )
        )
        store.add(AD_DOC)
        first = [chunk.id for chunk in store.search("beaconing rare port", limit=5)]
        second = [chunk.id for chunk in store.search("beaconing rare port", limit=5)]
        assert first == second
        assert len(first) == 2, "the tie must be broken by the id, not left to chance"
        assert first == sorted(first), (
            "two chunks with the same score must come back in id order, so the result "
            "does not depend on which one the store happened to hold first"
        )

    def test_an_empty_query_finds_nothing(self) -> None:
        store = KnowledgeStore()
        store.add(AD_DOC)
        assert store.search("   ") == ()
        assert store.search("the") == ()  # a stopword carries no signal

    def test_a_negative_limit_is_refused(self) -> None:
        store = KnowledgeStore()
        with pytest.raises(ValueError):
            store.search("anything", limit=-1)

    def test_replacing_a_document_re_chunks_it(self) -> None:
        store = KnowledgeStore()
        store.add(AD_DOC)
        store.add(Document(id="ad-tracker", title="replaced", text="Only one paragraph."))
        assert store.chunk("ad-tracker#1") is None
        assert store.chunk("ad-tracker#0") is not None


class TestTheEpisodicMemory:
    def test_a_run_is_remembered_and_recalled(self) -> None:
        memory = EpisodicMemory()
        memory.remember(
            Episode(run_id="abc", summary="egress to one host", severity="high")
        )
        episode = memory.recall("abc")
        assert episode is not None
        assert episode.summary == "egress to one host"
        assert episode.outcome == ""

    def test_the_outcome_is_labelled(self) -> None:
        """A memory of what was predicted, with no record of how it turned out,
        teaches the next agent the same prediction again."""
        memory = EpisodicMemory()
        memory.remember(Episode(run_id="abc", summary="egress", severity="high"))
        labelled = memory.label("abc", "a legitimate backup, not exfiltration")
        assert labelled.outcome == "a legitimate backup, not exfiltration"
        assert memory.recall("abc").outcome == "a legitimate backup, not exfiltration"  # type: ignore[union-attr]

    def test_labelling_an_unknown_run_is_refused(self) -> None:
        memory = EpisodicMemory()
        with pytest.raises(KeyError):
            memory.label("nope", "something")

    def test_it_is_durable(self, tmp_path: Path) -> None:
        path = tmp_path / "episodes.jsonl"
        memory = EpisodicMemory(path)
        memory.remember(Episode(run_id="abc", summary="egress", severity="high"))
        memory.label("abc", "benign")
        lines = path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2, "the file is append-only: a label is a later line"
        assert json.loads(lines[0])["outcome"] == ""
        assert json.loads(lines[1])["outcome"] == "benign"

    def test_it_searches_what_it_remembers(self) -> None:
        memory = EpisodicMemory()
        memory.remember(Episode(run_id="a", summary="beaconing to a rare port", severity="high"))
        memory.remember(Episode(run_id="b", summary="ordinary browsing", severity="none"))
        hits = memory.search("rare port")
        assert [episode.run_id for episode in hits] == ["a"]


class TestTheCitationRule:
    def test_a_quote_that_is_in_the_chunk_holds(self) -> None:
        store = KnowledgeStore()
        store.add(AD_DOC)
        check = verify_citation(store, "ad-tracker#0", "advertising telemetry")
        assert check.ok is True

    def test_a_quote_that_is_not_in_the_chunk_does_not(self) -> None:
        """The fabrication the rule exists to catch."""
        store = KnowledgeStore()
        store.add(AD_DOC)
        check = verify_citation(store, "ad-tracker#0", "the host is a known malware host")
        assert check.ok is False
        assert "does not appear" in check.reason

    def test_a_chunk_that_does_not_exist_does_not(self) -> None:
        store = KnowledgeStore()
        store.add(AD_DOC)
        check = verify_citation(store, "never-heard-of#0", "anything")
        assert check.ok is False
        assert "no chunk" in check.reason

    def test_a_citation_that_quotes_nothing_does_not(self) -> None:
        store = KnowledgeStore()
        store.add(AD_DOC)
        check = verify_citation(store, "ad-tracker#0", "   ")
        assert check.ok is False
        assert "quotes nothing" in check.reason

    def test_the_quote_is_matched_through_case_and_whitespace(self) -> None:
        store = KnowledgeStore()
        store.add(AD_DOC)
        check = verify_citation(store, "ad-tracker#0", "  ADVERTISING   TELEMETRY ")
        assert check.ok is True


class TestTheNodeChecksItsCitations:
    def _narrative(self, chunk_id: str, quote: str) -> str:
        return json.dumps(
            {
                "summary": "one host, beaconing",
                "claims": [
                    {
                        "text": "the host beacons every sixty seconds",
                        "flows": [],
                        "apps": [],
                        "citations": [{"chunk_id": chunk_id, "quote": quote}],
                    }
                ],
            }
        )

    def test_a_held_citation_is_accepted(self) -> None:
        store = KnowledgeStore()
        store.add(AD_DOC)
        node = explainer_node((), store=store)
        assert node.parse is not None
        narrative = node.parse(
            self._narrative("ad-tracker#1", "Beaconing to a fixed rare port")
        )
        assert narrative.claims[0].citations[0].chunk_id == "ad-tracker#1"

    def test_a_fabricated_citation_makes_the_verdict_invalid(self) -> None:
        """A quote that is not in the chunk it cites is a fabrication."""
        store = KnowledgeStore()
        store.add(AD_DOC)
        node = explainer_node((), store=store)
        assert node.parse is not None
        with pytest.raises(ValueError, match="does not hold"):
            node.parse(self._narrative("ad-tracker#0", "a sentence the chunk does not contain"))

    def test_a_citation_to_an_unknown_chunk_makes_the_verdict_invalid(self) -> None:
        store = KnowledgeStore()
        store.add(AD_DOC)
        node = explainer_node((), store=store)
        assert node.parse is not None
        with pytest.raises(ValueError, match="does not hold"):
            node.parse(self._narrative("nowhere#0", "anything"))

    def test_without_a_store_the_citation_is_not_checked(self) -> None:
        """A node with no memory has no documents to cite, so there is nothing
        to check against."""
        node = explainer_node(())
        assert node.parse is not None
        narrative = node.parse(self._narrative("ad-tracker#0", "anything at all"))
        assert narrative.claims[0].citations[0].chunk_id == "ad-tracker#0"


class TestTheRetrievalTool:
    async def _call(self, store: KnowledgeStore, name: str, arguments: dict[str, Any]) -> Any:
        from dpi_agents.tools import McpToolPort  # noqa: F401 - the module is the point

        return await KnowledgeToolPort(store).call(name, arguments)

    def test_it_returns_framed_passages(self) -> None:
        import asyncio

        store = KnowledgeStore()
        store.add(AD_DOC)
        result = asyncio.run(self._call(store, "search_knowledge", {"query": "telemetry"}))
        assert result.is_error is False
        assert result.content.startswith("<untrusted_capture_data>")
        assert "metrics.example.net" in result.content

    def test_an_unknown_tool_is_an_error(self) -> None:
        import asyncio

        store = KnowledgeStore()
        result = asyncio.run(self._call(store, "something_else", {}))
        assert result.is_error is True

    def test_a_bad_limit_is_an_error_and_not_a_crash(self) -> None:
        import asyncio

        store = KnowledgeStore()
        result = asyncio.run(self._call(store, "search_knowledge", {"query": "x", "limit": "many"}))
        assert result.is_error is True


class TestTheCompositePort:
    def test_an_unknown_tool_is_an_error(self) -> None:
        import asyncio

        port = CompositeToolPort({})
        result = asyncio.run(port.call("whatever", {}))
        assert result.is_error is True
        assert "no tool named" in result.content

    def test_the_routes_are_explicit(self) -> None:
        """A port that answers "no such tool" is indistinguishable from a port
        that ran the tool and failed."""

        class Recording:
            def __init__(self) -> None:
                self.calls: list[str] = []

            async def call(self, name: str, arguments: Any) -> Any:
                from dpi_agents.runtime import ToolResult

                self.calls.append(name)
                return ToolResult(content="ok")

        import asyncio

        recording = Recording()
        port = CompositeToolPort({"one": recording})
        asyncio.run(port.call("one", {}))
        assert recording.calls == ["one"]
