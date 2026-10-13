"""Typed event stream, and the bus it is published on.

`A-01` in `docs/AUDIT.md` identifies streaming analysis -- emit events as packets
are analysed, hold bounded state -- as *the same work* as fixing the unbounded
memory defect, which `T0-11` did. This module is the mechanism that makes the
distinction real: the engine publishes events, and `PipelineResult` stops being
an accumulator and becomes a **derived** summary.

**Why that direction rather than the reverse.** The batch API is what every
existing consumer -- the CLI, the report writer, the test suite, the OSC
differential comparison -- is written against. Deriving the summary from events
means `run_pipeline` and friends keep their exact signatures and return values,
the event stream is an *additional* output rather than a replacement, and there
is a testable invariant that makes the refactor safe: folding a recorded stream
must reproduce the batch result exactly, for the same capture.

That invariant is `tests/test_event_bus.py`, and it is the reason the fold exists
as a derivation rather than as a second implementation of reporting logic.

**The fold lives in `pipeline.fold_events`, not here.** It has to *construct* a
`PipelineResult`, which lives in `pipeline`, and `pipeline` imports these types in
order to emit them. One of those two directions has to be type-only and it cannot
be the fold's, so this module stays a leaf: vocabulary and bus only, with no
runtime dependency on the pipeline, importable from anywhere.
"""

from __future__ import annotations

import contextlib
import dataclasses
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

from dpi_engine.types import AppType, FiveTuple

if TYPE_CHECKING:
    from dpi_engine.pipeline import _LoadBalancerResult
    from dpi_engine.worker import WorkerResult

__all__ = [
    "CaptureClosed",
    "CaptureOpened",
    "Event",
    "EventBus",
    "FlowBlocked",
    "FlowClassified",
    "FlowCreated",
    "FlowEvicted",
    "Handler",
    "LimitExceeded",
    "LoadBalancerFinished",
    "PacketParsed",
    "Recorder",
    "WorkerFinished",
]


# ---------------------------------------------------------------------------
# The event vocabulary
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class Event:
    """Base class for every event. Empty by design, so `isinstance` is the only
    thing a consumer needs in order to dispatch on one."""


@dataclasses.dataclass(frozen=True, slots=True)
class CaptureOpened(Event):
    """A capture was opened successfully and its global header validated."""

    path: str
    linktype: int


@dataclasses.dataclass(frozen=True, slots=True)
class CaptureClosed(Event):
    """The reader reached the end of the capture.

    Carries nothing on purpose: the totals are already on the events that
    preceded it, and a close event carrying a total would invite double-counting
    in any consumer that folds both.
    """


@dataclasses.dataclass(frozen=True, slots=True)
class PacketParsed(Event):
    """One packet was read and its headers parsed.

    `inspected` is the distinction the reader makes internally -- `False` for
    non-IPv4 frames and non-TCP/UDP protocols, which are counted as
    `other_packets` and never reach a flow. It is a field rather than being
    inferred from `flow is None` because the reader knows it before the engine
    does, and inferring it would make the fold depend on packet order.

    `forwarded` is the rule decision; a packet that was never considered (skipped
    by the reader) reports `True` since nothing was dropped.
    """

    sequence_index: int
    byte_len: int
    inspected: bool
    is_tcp: bool
    is_udp: bool
    forwarded: bool


@dataclasses.dataclass(frozen=True, slots=True)
class FlowCreated(Event):
    """A flow the flow table had never seen was first observed."""

    five_tuple: FiveTuple


@dataclasses.dataclass(frozen=True, slots=True)
class FlowClassified(Event):
    """A packet's flow had a classification applied.

    Emitted **once per inspected packet**, not once per flow, because that is
    what the batch accumulator tallies: `_record_stats` increments
    `app_counts[conn.app_type]` for every packet, so `app_counts` is a per-packet
    count and not a count of distinct flows. A future per-flow "classification
    changed" event would be a different thing and would be additive.
    """

    five_tuple: FiveTuple
    app_type: AppType
    sni: str


@dataclasses.dataclass(frozen=True, slots=True)
class FlowBlocked(Event):
    """A flow was newly matched by a blocking rule."""

    five_tuple: FiveTuple
    app_type: AppType
    sni: str


@dataclasses.dataclass(frozen=True, slots=True)
class FlowEvicted(Event):
    """A flow left the flow table, by LRU pressure or staleness.

    **Defined but not emitted.** Eviction is a `ConnectionTracker` judgement, and
    the tracker deliberately knows nothing about events -- adding the dependency
    would make the innermost hot loop depend on the reporting layer. It is in the
    vocabulary because a live view will need it, and emitting it is a
    `T1-03` concern; the fold does not read it, so its absence costs nothing
    here.
    """

    five_tuple: FiveTuple


@dataclasses.dataclass(frozen=True, slots=True)
class LimitExceeded(Event):
    """A configured resource bound was hit, ending the run mid-capture."""

    kind: str
    detail: str


@dataclasses.dataclass(frozen=True, slots=True)
class WorkerFinished(Event):
    """A fast-path's aggregate crossed the process boundary.

    In the single-process variant there is exactly one of these, carrying the one
    engine's finalized result. Carrying the existing `WorkerResult` rather than
    re-encoding it is deliberate: the fold then composes from the same object the
    batch path composes from, so the two cannot drift.

    Also the only home of `quic_packets`/`quic_undecryptable`, which are per-flow
    aggregates. They deliberately do *not* appear on `PacketParsed`, where
    carrying them would make any consumer count them twice.
    """

    worker_id: int
    result: WorkerResult


@dataclasses.dataclass(frozen=True, slots=True)
class LoadBalancerFinished(Event):
    """A load balancer's aggregate crossed the process boundary (staged only)."""

    lb_id: int
    result: _LoadBalancerResult


# ---------------------------------------------------------------------------
# The bus
# ---------------------------------------------------------------------------

Handler = Callable[[Event], None]


class EventBus:
    """Fan-out to subscribers, in subscription order.

    Deliberately minimal. No queue, no threading, no backpressure: this is the
    *interface* a live consumer subscribes to, and adding buffering here would
    duplicate the bounded-reorder-window work that belongs in `T1-03` (`DEC-01`
    decided a bounded reorder window; the window belongs there, one layer down,
    rather than being implicit in a bus).

    A subscriber that raises does not stop the others -- a dashboard losing
    interest must not stop the run -- which is the same reasoning that makes
    `_close_quietly` swallow errors.
    """

    def __init__(self) -> None:
        self._handlers: list[Handler] = []

    def subscribe(self, handler: Handler) -> Callable[[], None]:
        """Registers `handler`, returning an unsubscribe callable."""
        self._handlers.append(handler)

        def unsubscribe() -> None:
            # Unsubscribing twice is not an error.
            with contextlib.suppress(ValueError):
                self._handlers.remove(handler)

        return unsubscribe

    def emit(self, event: Event) -> None:
        for handler in list(self._handlers):
            try:
                handler(event)
            except Exception:
                # Intentionally silent, for the same reason as `_close_quietly`:
                # raising here would mask the run's own progress. A real
                # deployment would want this counted and exported.
                continue

    def __len__(self) -> int:
        return len(self._handlers)


class Recorder:
    """A bus subscriber that collects events into a list.

    Exists so the fold can be exercised on a *recorded* stream, which is the
    shape of the safety guarantee, and so a streaming consumer can be written
    against a plain list in tests rather than against the pipeline.
    """

    def __init__(self) -> None:
        self.events: list[Event] = []

    def __call__(self, event: Event) -> None:
        self.events.append(event)

    def __iter__(self) -> Iterator[Event]:
        return iter(self.events)

    def of(self, kind: type[Event]) -> list[Event]:
        """Every recorded event that is an instance of `kind`."""
        return [e for e in self.events if isinstance(e, kind)]
