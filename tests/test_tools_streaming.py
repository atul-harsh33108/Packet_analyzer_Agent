"""The live event stream (`T3-07`).

The planned test, from the task record: *a consumer that abandons the iterator
must neither deadlock the run nor let the producer buffer without bound* -- the
first is a hang, the second is `D-01`/`D-02` again.

Both halves are here, and they are separate tests because they are separate
properties: a stream can be deadlock-free and still buffer without bound, and
the other way round. Neither is proved by the other.

The async tests use `asyncio.run` rather than an async plugin: the project has
no `pytest-asyncio`, and adding a dependency for ergonomics is not worth it when
the alternative is one line.
"""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path

from conftest import TEST_DPI_PCAP
from dpi_engine.events import CaptureClosed, CaptureOpened, Event, PacketParsed
from dpi_engine.pipeline import run_pipeline, run_pipeline_multiprocess, run_pipeline_staged
from dpi_mcp.run_store import RunStore
from dpi_mcp.tools.streaming import EventStream, stream_dpi_events

#: How long a run may take before the test calls it a hang. Generous, because
#: the point is to catch a deadlock, not to measure the engine.
_HANG_TIMEOUT = 60.0


def _stream(tmp_path: Path, **kwargs: object) -> EventStream:
    """A stream over the fixture, writing into the test's directory."""
    return stream_dpi_events(
        TEST_DPI_PCAP,
        tmp_path / "forwarded.pcap",
        store_root=tmp_path / "store",
        **kwargs,  # type: ignore[arg-type]
    )


class TestTheStream:
    def test_it_yields_the_engines_own_events(self, tmp_path: Path) -> None:
        """The events are the engine's, not copies of them.

        A copy would be a second home for the event vocabulary, and the copy
        would be the one an agent reads.
        """

        async def scenario() -> tuple[list[Event], object]:
            stream = _stream(tmp_path)
            stream.start()
            events = [event async for event in stream.events()]
            outcome = await stream.finish()
            return events, outcome

        events, outcome = asyncio.run(scenario())
        assert events, "the stream produced no events at all"
        assert all(isinstance(event, Event) for event in events)
        assert any(isinstance(event, CaptureOpened) for event in events)
        assert any(isinstance(event, PacketParsed) for event in events)
        assert any(isinstance(event, CaptureClosed) for event in events)
        assert outcome.events_produced == len(events)  # type: ignore[attr-defined]
        assert not outcome.events_dropped  # type: ignore[attr-defined]

    def test_the_run_is_stored_and_can_be_queried(self, tmp_path: Path) -> None:
        """A stream that does not store its run would leave the other tools empty."""

        async def scenario() -> object:
            stream = _stream(tmp_path)
            stream.start()
            _ = [event async for event in stream.events()]
            return await stream.finish()

        outcome = asyncio.run(scenario())
        run_id = outcome.run_id  # type: ignore[attr-defined]
        summaries = RunStore(tmp_path / "store").list_runs()
        assert [summary.run_id for summary in summaries] == [run_id]

    def test_a_failed_run_raises_rather_than_ending_the_stream_silently(
        self, tmp_path: Path
    ) -> None:
        """A truncated stream must not look like a short capture."""

        async def scenario() -> None:
            stream = stream_dpi_events(
                tmp_path / "does-not-exist.pcap",
                tmp_path / "out.pcap",
                store_root=tmp_path / "store",
            )
            stream.start()
            _ = [event async for event in stream.events()]
            await stream.finish()

        try:
            asyncio.run(scenario())
        except Exception as exc:
            assert "does-not-exist.pcap" in str(exc), exc
        else:  # pragma: no cover - the run must fail
            raise AssertionError("a missing capture must not finish quietly")


class TestAConsumerThatStopsConsuming:
    """The planned test: neither a hang nor an unbounded buffer."""

    def test_it_does_not_deadlock_the_run(self, tmp_path: Path) -> None:
        """A consumer that walks away must not leave the run stuck.

        The engine's pipeline cannot be cancelled, so the run goes on. What it
        must not do is *hang*, and it must not keep the process alive: the
        pipeline runs in a daemon thread for exactly that reason.
        """

        async def scenario() -> object:
            stream = _stream(tmp_path)
            stream.start()
            iterator = stream.events()
            await iterator.__anext__()
            await iterator.aclose()
            # The run is still going. Waiting for it is the whole test: if the
            # producer were blocked on a full queue nobody was draining, this
            # would never return.
            return await asyncio.wait_for(stream.finish(), timeout=_HANG_TIMEOUT)

        outcome = asyncio.run(scenario())
        assert outcome.run_id  # type: ignore[attr-defined]

    def test_it_does_not_let_the_producer_buffer_without_bound(
        self, tmp_path: Path
    ) -> None:
        """A queue nobody drains must not become a heap.

        The queue is bounded, so the producer's only options are to drop or to
        block. It drops (`DEC-10`), and the drops are counted -- so this test
        can see the difference between a bounded buffer and an unbounded one:
        with an unbounded buffer there would be nothing to drop.
        """

        async def scenario() -> object:
            # A tiny queue, and a consumer that never reads.
            stream = _stream(tmp_path, queue_size=4)
            stream.start()
            return await asyncio.wait_for(stream.finish(), timeout=_HANG_TIMEOUT)

        outcome = asyncio.run(scenario())
        dropped = dict(outcome.events_dropped)  # type: ignore[attr-defined]
        assert dropped, "a four-slot queue and no consumer should have dropped events"
        assert "PacketParsed" in dropped, (
            f"the dropped events are counted by type, and the per-packet ones are the "
            f"bulk of them: {dropped}"
        )
        assert outcome.events_produced > sum(dropped.values())  # type: ignore[attr-defined]

    def test_the_drops_are_reported_and_not_silent(self, tmp_path: Path) -> None:
        """A partial view that cannot be shown to be partial is a wrong answer."""

        async def scenario() -> object:
            stream = _stream(tmp_path, queue_size=2)
            stream.start()
            return await asyncio.wait_for(stream.finish(), timeout=_HANG_TIMEOUT)

        outcome = asyncio.run(scenario())
        payload = outcome.to_json()  # type: ignore[attr-defined]
        assert payload["events_dropped"], "the drops must be in the answer"
        assert isinstance(payload["events_dropped"], list)
        assert all(len(pair) == 2 for pair in payload["events_dropped"])


class TestWhyItIsSingleProcess:
    """The constraint is the engine's, and this pins it where it is written down.

    `run_pipeline_multiprocess` and `run_pipeline_staged` have no `bus`: the
    fine-grained events are emitted inside the child processes and only one
    aggregated result per worker crosses the boundary. If that ever changes, the
    streaming tool's contract should change with it -- and this test is what
    says so.
    """

    def test_the_single_process_path_has_a_bus(self) -> None:
        assert "bus" in inspect.signature(run_pipeline).parameters

    def test_the_other_two_do_not(self) -> None:
        for entry_point in (run_pipeline_multiprocess, run_pipeline_staged):
            assert "bus" not in inspect.signature(entry_point).parameters, (
                f"{entry_point.__name__} now takes a bus. The streaming tool's "
                "contract is single-process because the other two modes have "
                "nothing to stream; if that has changed, the tool should offer "
                "the mode rather than quietly not stream."
            )
