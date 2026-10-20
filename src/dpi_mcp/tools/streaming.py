"""The engine's live event stream, as an async iterator (`T3-07`).

**Why this module exists, given that the engine has no streaming consumer
contract.** The engine publishes typed events on an `EventBus` -- a fan-out with
no queue, no threading and no backpressure, because the buffering belongs to the
consumer. This module is that consumer: it runs the blocking pipeline in a
thread, moves the events across a **bounded** queue, and hands them to an async
consumer one at a time.

**One decision shapes it (`DEC-10`): drop-and-count.** When the consumer is
slower than the producer, the queue is full, and the event is *dropped and
counted* rather than waited for. The reasons, in order of weight:

- **The live channel is a view, not the answer.** The authoritative summary
  comes back in the tool's result, complete, whatever happened to the stream. A
  consumer that missed an event has missed a diagnostic, not a fact.
- **The engine's bus must not block on an agent.** The bus is a library
  interface called from the pipeline's hot path; making it wait on a remote
  consumer's pace couples the engine to a client it knows nothing about.
- **The bounded structures this codebase already has agree.** The reorder window
  (`DEC-01`) drops rather than blocks, and the run store's event log keeps what
  it can represent and *counts the rest* in `events_omitted`.

What is dropped is never silent: the counts are in the result, by event type.

**Single-process only, and that is a property of the engine rather than a
restriction of this tool.** `run_pipeline_multiprocess` and `run_pipeline_staged`
have no `bus` parameter at all: the fine-grained events are emitted inside the
child processes and only one aggregated `WorkerFinished` per worker crosses the
boundary. There is nothing to stream in those modes, so this tool does not offer
a `mode` it would have to refuse two values of.

**The run cannot be cancelled.** The engine's pipeline is a straight-line
function with no cancellation contract, so a consumer that walks away leaves the
run to finish. That is why the pipeline runs in a **daemon** thread: the process
can still exit, and the run's own footprint stays the engine's.
"""

from __future__ import annotations

import asyncio
import queue
import threading
from collections import Counter
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dpi_engine.events import Event, EventBus
from dpi_engine.pcap_io import DEFAULT_MAX_PACKET_SIZE, DEFAULT_MAX_TOTAL_PACKETS
from dpi_engine.pipeline import run_pipeline
from dpi_mcp.run_store import RunRecord, RunStore, record_from_result
from dpi_mcp.tools.ruleset import build_rule_manager
from dpi_mcp.tools.runs import ruleset_fingerprint, run_outcome

__all__ = [
    "DEFAULT_QUEUE_SIZE",
    "EventStream",
    "StreamOutcome",
    "stream_dpi_events",
]

#: How many events may wait for a consumer before the producer starts dropping.
#:
#: Big enough that a local client never trips it -- it is a safety valve against
#: a consumer that has stopped, not a throttle -- and small enough that the
#: stream's own memory is a number rather than a function of the capture.
DEFAULT_QUEUE_SIZE = 1024

#: How often the consumer checks the queue. The queue is polled rather than
#: waited on, because a blocking wait would occupy a thread of the default
#: executor for every event, and the alternative -- waking the loop from the
#: producer thread -- queues a callback per event and is unbounded in exactly
#: the way this module exists to avoid.
_POLL_SECONDS = 0.01


@dataclass(frozen=True)
class StreamOutcome:
    """What a finished stream produced.

    `events_produced` is what the engine emitted, and `events_dropped` is what
    never made it into the queue -- by type, because a consumer that was told
    "0 delivered" needs to know whether it saw nothing or saw a hole.

    There is no "delivered" count here: the consumer knows what it consumed.
    The *server* reports what the **client** received, which is a different
    number when the client asked for no progress notifications.
    """

    run_id: str
    run: dict[str, Any]
    events_produced: int
    events_dropped: tuple[tuple[str, int], ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "run": self.run,
            "events_produced": self.events_produced,
            "events_dropped": [list(pair) for pair in self.events_dropped],
        }


class EventStream:
    """A running analysis whose events can be consumed as they happen.

    The pipeline is blocking, so it runs in a thread; the events cross a bounded
    queue; the consumer is async. Three consequences, all deliberate:

    - **The producer never waits for the consumer** (`DEC-10`). A full queue
      drops the event and counts it, by type.
    - **The queue is bounded**, so an abandoned consumer cannot make the
      producer's memory grow: the stream's footprint is `queue_size` events,
      whatever the capture's size.
    - **The run cannot be cancelled.** A consumer that stops consuming leaves
      the run to finish on its own; the thread is a daemon so the process can
      still exit.
    """

    def __init__(
        self,
        *,
        capture: str | Path,
        output: str | Path,
        store_root: str | Path,
        ruleset: object = None,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        enable_quic: bool = True,
        fold_bidirectional: bool = True,
        max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
        max_total_packets: int = DEFAULT_MAX_TOTAL_PACKETS,
    ) -> None:
        if queue_size < 1:
            raise ValueError(f"queue_size must be at least 1, got {queue_size}")
        self._capture = capture
        self._output = output
        self._store_root = store_root
        self._ruleset = ruleset
        self._enable_quic = enable_quic
        self._fold_bidirectional = fold_bidirectional
        self._max_packet_size = max_packet_size
        self._max_total_packets = max_total_packets
        self._queue: queue.Queue[Event] = queue.Queue(maxsize=queue_size)
        self._dropped: Counter[str] = Counter()
        self._produced = 0
        self._finished = threading.Event()
        self._error: BaseException | None = None
        self._record: RunRecord | None = None
        self._thread: threading.Thread | None = None

    # -- running -----------------------------------------------------------

    def start(self) -> None:
        """Start the analysis.

        Separate from the constructor so that a caller can hold the stream
        before anything runs, and so that starting twice is an error rather
        than two runs writing the same output file.
        """
        if self._thread is not None:
            raise RuntimeError("this stream has already been started")
        self._thread = threading.Thread(
            target=self._run,
            name="dpi-stream",
            daemon=True,
        )
        self._thread.start()

    def _run(self) -> None:
        """The analysis, in the pipeline's thread."""
        bus = EventBus()
        bus.subscribe(self._on_event)
        try:
            result = run_pipeline(
                self._capture,
                self._output,
                build_rule_manager(self._ruleset, source="<stream ruleset>"),
                bus=bus,
                # The store refuses a run with no flow table, and a run with no
                # flow table is indistinguishable from a capture with no flows.
                with_flow_table=True,
                enable_quic=self._enable_quic,
                fold_bidirectional=self._fold_bidirectional,
                max_packet_size=self._max_packet_size,
                max_total_packets=self._max_total_packets,
            )
            record = record_from_result(
                result,
                capture_path=self._capture,
                ruleset=ruleset_fingerprint(self._ruleset),
            )
            RunStore(self._store_root).save(record)
            self._record = record
        except BaseException as exc:
            self._error = exc
        finally:
            self._finished.set()

    def _on_event(self, event: Event) -> None:
        """The bus handler, called in the pipeline's thread.

        Drop-and-count (`DEC-10`): a full queue means the consumer is not
        keeping up, and the event is dropped rather than waited for. The count
        is by type, so a consumer can tell a run that saw no blocks from a run
        whose block events were dropped.
        """
        self._produced += 1
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self._dropped[type(event).__name__] += 1

    # -- consuming ---------------------------------------------------------

    async def events(self) -> AsyncIterator[Event]:
        """The engine's events, as they happen.

        The iterator ends when the run ends. It does **not** raise: a failed run
        raises from `finish`, so the error is reported once, in one place,
        rather than as a truncated stream that looks like a short capture.
        """
        while True:
            event = await self._next_event()
            if event is None:
                return
            yield event

    async def _next_event(self) -> Event | None:
        """The next event, or `None` when the run is over and the queue is empty."""
        while True:
            try:
                return self._queue.get_nowait()
            except queue.Empty:
                pass
            if self._finished.is_set() and self._queue.empty():
                return None
            await asyncio.sleep(_POLL_SECONDS)

    async def finish(self) -> StreamOutcome:
        """Wait for the run to end, and report what it produced.

        The wait is in an executor because the run is a thread and a blocking
        join on the event loop would stop the server answering anything else --
        including the cancellation that would have ended the wait.
        """
        if self._thread is None:
            raise RuntimeError("this stream has not been started")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._thread.join)
        if self._error is not None:
            raise self._error
        record = self._record
        if record is None:  # pragma: no cover - the run sets one or raises
            raise RuntimeError("the run finished without producing a record")
        return StreamOutcome(
            run_id=record.run_id,
            run=run_outcome(record, output=self._output),
            events_produced=self._produced,
            events_dropped=tuple(sorted(self._dropped.items())),
        )


def stream_dpi_events(
    capture: str | Path,
    output: str | Path,
    ruleset: object = None,
    *,
    store_root: str | Path,
    queue_size: int = DEFAULT_QUEUE_SIZE,
    enable_quic: bool = True,
    fold_bidirectional: bool = True,
    max_packet_size: int = DEFAULT_MAX_PACKET_SIZE,
    max_total_packets: int = DEFAULT_MAX_TOTAL_PACKETS,
) -> EventStream:
    """A live run: its events as they happen, and its results at the end.

    The stream is returned unstarted, so a caller can decide when the analysis
    begins; `start`, then `events`, then `finish`.

    **Single-process only.** The engine's multiprocess variants publish one
    aggregated result per worker rather than a live event stream, so there is
    nothing to stream in them and no `mode` is offered here.
    """
    return EventStream(
        capture=capture,
        output=output,
        store_root=store_root,
        ruleset=ruleset,
        queue_size=queue_size,
        enable_quic=enable_quic,
        fold_bidirectional=fold_bidirectional,
        max_packet_size=max_packet_size,
        max_total_packets=max_total_packets,
    )
