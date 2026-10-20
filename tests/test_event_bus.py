"""`T1-01` — the event bus, and the guarantee that makes it safe.

The spec's own words: *fold a synthetic event stream and assert the derived
`PipelineResult` equals the current batch result for the same capture. **This is
the guarantee that makes the refactor safe.***

It is worth being precise about why. The whole point of `T1-01` is to change how
data leaves the engine, so the usual safety net -- "the output pcap is
byte-identical to `HEAD`" -- cannot apply: that net checks the *bytes*, and this
change is about the *shape of the data*. What can apply, and is strictly
stronger, is a check that the two paths agree on every reported figure. If
folding the stream reproduces the batch result, then:

  * the event stream is *faithful* -- it is not a second, subtly different
    program that happens to share a fixture;
  * and every existing consumer of `PipelineResult` can be moved onto the stream
    one at a time, because there is something to compare against.

`T0-11` is what makes this possible: it removed the global `sort` and the
per-packet accumulation, so a fold over events reproduces exactly what the batch
path computes without having to re-sort anything.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from conftest import TEST_DPI_PCAP
from dpi_engine import pipeline
from dpi_engine.events import (
    CaptureClosed,
    CaptureOpened,
    Event,
    EventBus,
    FlowBlocked,
    FlowClassified,
    FlowCreated,
    FlowEvicted,
    LimitExceeded,
    PacketParsed,
    Recorder,
    WorkerFinished,
    event_to_dict,
)
from dpi_engine.rule_manager import RuleManager
from dpi_engine.types import AppType, FiveTuple, canonical_flow_key


def _summary(result: pipeline.PipelineResult) -> dict:
    """Everything a consumer of `PipelineResult` would actually read.

    Compared as a dict of plain values rather than by `==` on the dataclass,
    because `GlobalStats` and `FastPathStats` are nested dataclasses and
    `PipelineResult` has no `__eq__` that is useful here. Comparing a *summary*
    rather than the objects also means the failure message says which field
    diverged, which is the entire value of the assertion.
    """
    return {
        "total_packets": result.stats.total_packets,
        "total_bytes": result.stats.total_bytes,
        "forwarded": result.stats.forwarded_packets,
        "dropped": result.stats.dropped_packets,
        "tcp": result.stats.tcp_packets,
        "udp": result.stats.udp_packets,
        "other": result.stats.other_packets,
        "active": result.stats.active_connections,
        "app_counts": {str(k): v for k, v in sorted(result.app_counts.items(), key=str)},
        "domains": dict(sorted(result.detected_domains.items())),
        "blocked_flows": [(tuple(t), str(a), s) for t, a, s in result.blocked_flows],
        "per_worker": result.per_worker_packet_counts,
        "quic_packets": result.quic_packets,
        "quic_undecryptable": result.quic_undecryptable,
        "drop_rate": round(result.drop_rate_percent, 9),
        "n_global_states": len(result.global_stats.state_counts)
        if result.global_stats is not None
        else -1,
    }


# ---------------------------------------------------------------------------
# The guarantee
# ---------------------------------------------------------------------------


def test_the_fold_reproduces_the_batch_result(tmp_path: Path) -> None:
    """THE guarantee. Folding a recorded stream must equal the batch result.

    Everything else in this file is a supporting test for this one.
    """
    bus = EventBus()
    recording = Recorder()
    bus.subscribe(recording)

    out = pipeline.run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", rule_manager=None, bus=bus)
    folded = pipeline.fold_events(recording)

    assert _summary(folded) == _summary(out), (
        "folding the event stream produced a different PipelineResult from the "
        "batch path. That means the events are not faithful, so any consumer "
        "moved onto the stream would be a different program."
    )


def test_the_fold_reproduces_the_batch_result_with_blocking_rules(tmp_path: Path) -> None:
    """Same guarantee, but with rules that actually drop packets.

    The unblocked capture drops nothing, so the previous test exercises one
    branch of every counter. Blocking `UNKNOWN` covers the drop path, the
    `FlowBlocked` event, and the drop-rate arithmetic.
    """
    rules = RuleManager()
    rules.block_app(AppType.HTTPS)
    rules.block_app(AppType.UNKNOWN)

    bus = EventBus()
    recording = Recorder()
    bus.subscribe(recording)
    out = pipeline.run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", rule_manager=rules, bus=bus)
    folded = pipeline.fold_events(recording)

    assert out.stats.dropped_packets > 0, (
        "fixture did not drop anything, so the blocking path was not exercised"
    )
    assert out.blocked_flows, "fixture blocked no flows, so FlowBlocked was not emitted"
    assert recording.of(FlowBlocked), "no FlowBlocked events were emitted"
    assert _summary(folded) == _summary(out)


def test_the_fold_reproduces_the_batch_result_with_a_bus_but_no_subscribers(
    tmp_path: Path,
) -> None:
    """A bus with no subscribers must still produce the same run.

    Emission is opt-in at the *bus* level, not at the *listener* level, so this
    pins that passing a bus changes nothing about the result -- the failure mode
    being guarded against is a fold that only works when someone is listening.
    """
    out_with = pipeline.run_pipeline(
        TEST_DPI_PCAP, tmp_path / "with.pcap", bus=EventBus()
    )
    out_without = pipeline.run_pipeline(TEST_DPI_PCAP, tmp_path / "without.pcap")
    assert _summary(out_with) == _summary(out_without)


# ---------------------------------------------------------------------------
# Supporting properties of the stream itself
# ---------------------------------------------------------------------------


def test_the_stream_reports_every_packet_exactly_once(tmp_path: Path) -> None:
    """One `PacketParsed` per packet in the capture, `sequence_index` dense.

    A gap or a duplicate here would be invisible in the fold (the totals would
    still balance) but fatal to any streaming consumer that wants to reassemble.
    """
    bus = EventBus()
    recording = Recorder()
    bus.subscribe(recording)
    pipeline.run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", bus=bus)

    indices = [e.sequence_index for e in recording.of(PacketParsed)]
    assert indices, "no PacketParsed events were recorded"
    assert indices == list(range(len(indices))), (
        f"sequence_index is not a dense 0..N-1 range: {len(indices)} events"
    )


def test_skipped_packets_are_emitted_with_inspected_false(tmp_path: Path) -> None:
    """Reader-skipped frames must appear, or the fold could not reproduce the totals.

    `stats.total_packets` counts them, so an event stream that omitted them
    would silently under-report -- and the fold's arithmetic would then need a
    fudge factor to match, which is exactly the kind of thing that turns into a
    wrong dashboard three months later.
    """
    bus = EventBus()
    recording = Recorder()
    bus.subscribe(recording)
    out = pipeline.run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", bus=bus)

    skipped = [e for e in recording.of(PacketParsed) if not e.inspected]
    inspected = [e for e in recording.of(PacketParsed) if e.inspected]

    assert len(inspected) == out.stats.tcp_packets + out.stats.udp_packets
    assert len(skipped) == out.stats.other_packets
    assert all(e.is_tcp is False and e.is_udp is False for e in skipped)


def test_flow_created_precedes_flow_classified(tmp_path: Path) -> None:
    """A flow's lifecycle events must be ordered.

    A consumer reconstructing state from the stream must never see a
    classification for a flow it has not been told exists. This is the
    invariant the earlier emission bug broke: a new flow emitted `FlowCreated`
    and *returned*, so its `FlowClassified` never came.

    Keyed on `DEC-05`'s canonical flow identity, not on the packet's own tuple.
    With folding, a flow and its reverse direction are one flow: the first
    packet emits `FlowCreated` carrying *its* tuple, and every later packet --
    in either direction -- emits `FlowClassified` carrying its own. Requiring an
    exact-tuple match would demand a second `FlowCreated` for the reverse
    direction, which is precisely the duplication folding exists to remove.

    It still bites for the bug it was written against: the first packet of a new
    flow is in the flow's canonical direction, so a missing `FlowClassified`
    after that `FlowCreated` fails here.
    """
    bus = EventBus()
    recording = Recorder()
    bus.subscribe(recording)
    pipeline.run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", bus=bus)

    created: set[FiveTuple] = set()
    for event in recording.events:
        if isinstance(event, FlowCreated):
            key = canonical_flow_key(event.five_tuple)
            assert key not in created, f"flow {event.five_tuple} was created twice"
            created.add(key)
        elif isinstance(event, FlowClassified):
            assert canonical_flow_key(event.five_tuple) in created, (
                f"flow {event.five_tuple} was classified before it was created"
            )

    assert created, "no FlowCreated events at all"
    assert len(created) <= len(recording.of(FlowClassified))


def test_flow_evicted_is_emitted_when_the_table_evicts(tmp_path: Path) -> None:
    """`FlowEvicted` must actually fire.

    It was defined in the `T1-01` vocabulary but never emitted, because eviction
    happens inside `ConnectionTracker` and the tracker deliberately knows nothing
    about events. The `on_evicted` hook is what closes that gap without
    reversing the dependency: the tracker calls a callback, the pipeline decides
    what a departure means.

    Driven by shrinking `max_connections` well below the capture's flow count, so
    LRU eviction is guaranteed rather than incidental.
    """
    bus = EventBus()
    recording = Recorder()
    bus.subscribe(recording)

    pipeline.run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", bus=bus, max_connections=4)

    evicted = recording.of(FlowEvicted)
    assert evicted, "flows were evicted but no FlowEvicted event was emitted"

    created = {canonical_flow_key(e.five_tuple) for e in recording.of(FlowCreated)}
    seen = []
    for event in evicted:
        key = canonical_flow_key(event.five_tuple)
        assert key in created, f"flow {event.five_tuple} was evicted without ever being created"
        seen.append(key)
    assert len(seen) == len(set(seen)), "the same flow was evicted twice"

    # The table really is bounded, which is what made them evict in the first
    # place -- without this the test would pass on a capture that never evicted.
    assert len(seen) > 0


def test_every_flow_is_classified_at_least_once(tmp_path: Path) -> None:
    """The exact regression the guarantee test caught.

    `_emit_lifecycle_events` used to emit `FlowCreated` for a new flow and
    return, so the first packet of every flow contributed no `FlowClassified`
    and `app_counts` under-counted by the number of distinct flows -- a bug
    invisible in the output pcap and in every counter except that one.
    """
    bus = EventBus()
    recording = Recorder()
    bus.subscribe(recording)
    out = pipeline.run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", bus=bus)

    created = {e.five_tuple for e in recording.of(FlowCreated)}
    classified = {e.five_tuple for e in recording.of(FlowClassified)}

    assert created, "no flows were created"
    assert created <= classified, (
        f"{len(created - classified)} flow(s) were created but never classified, "
        "so the fold's app_counts would under-count"
    )
    # app_counts counts packets, so it must be >= the number of distinct flows.
    assert sum(out.app_counts.values()) >= len(created)


def test_flow_blocked_fires_once_per_flow(tmp_path: Path) -> None:
    """Not once per packet, and not zero times.

    The transition detection compares state before and after the decision; a
    "read the blocked flag" version would emit once per packet of a blocked flow,
    which no consumer wants and which the fold would still survive.
    """
    rules = RuleManager()
    rules.block_app(AppType.HTTPS)
    rules.block_app(AppType.UNKNOWN)

    bus = EventBus()
    recording = Recorder()
    bus.subscribe(recording)
    out = pipeline.run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", rule_manager=rules, bus=bus)

    blocked = [e.five_tuple for e in recording.of(FlowBlocked)]
    assert blocked, "no FlowBlocked events at all"
    assert len(blocked) == len(set(blocked)), (
        "a flow emitted FlowBlocked more than once; the transition check is wrong"
    )
    assert len(blocked) == len(out.blocked_flows), (
        f"emitted {len(blocked)} FlowBlocked events for {len(out.blocked_flows)} "
        "blocked flows"
    )


def test_the_worker_aggregate_is_emitted_once(tmp_path: Path) -> None:
    """Exactly one `WorkerFinished`, and it is what the fold composes from.

    The single-process variant has one fast path, so there is one aggregate. If
    this were ever emitted zero times the fold would silently report
    `fast_path_stats=None`, `per_worker_packet_counts=[]` and no
    `global_stats` -- all of which *look* like legitimate empty values rather
    than like a missing event. That failure mode is quiet, which is why it gets
    its own test instead of relying on the guarantee test to notice.
    """
    bus = EventBus()
    recording = Recorder()
    bus.subscribe(recording)
    out = pipeline.run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", bus=bus)

    finished = recording.of(WorkerFinished)
    assert len(finished) == 1, f"expected one WorkerFinished, got {len(finished)}"
    assert finished[0].worker_id == 0

    folded = pipeline.fold_events(recording)
    assert folded.fast_path_stats is not None, (
        "the fold found no WorkerFinished, so the fast-path stats are missing"
    )
    assert folded.per_worker_packet_counts == [finished[0].result.fp_stats.packets_processed]
    assert folded.fast_path_stats.packets_processed == out.fast_path_stats.packets_processed
    assert folded.quic_packets == out.quic_packets
    assert folded.quic_undecryptable == out.quic_undecryptable


def test_capture_open_and_close_are_emitted_in_order(tmp_path: Path) -> None:
    bus = EventBus()
    recording = Recorder()
    bus.subscribe(recording)
    pipeline.run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", bus=bus)

    kinds = [type(e).__name__ for e in recording.events]
    assert kinds[0] == "CaptureOpened", kinds[:3]
    assert kinds[-1] == "CaptureClosed", kinds[-3:]
    assert recording.of(CaptureOpened)[0].linktype == 1


def test_a_failing_subscriber_does_not_stop_the_run(tmp_path: Path) -> None:
    """A dashboard losing interest must not stop the engine.

    Same reasoning as `_close_quietly`: raising out of `emit` would mask the
    run's own progress, and a subscriber is by definition not the engine.
    """
    def boom(_event: object) -> None:
        raise RuntimeError("subscriber exploded")

    bus = EventBus()
    bus.subscribe(boom)
    recording = Recorder()
    bus.subscribe(recording)

    out = pipeline.run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", bus=bus)
    plain = pipeline.run_pipeline(TEST_DPI_PCAP, tmp_path / "plain.pcap")

    assert _summary(out) == _summary(plain)
    assert recording.events, "the surviving subscriber recorded nothing"


def test_unsubscribing_stops_delivery(tmp_path: Path) -> None:
    bus = EventBus()
    recording = Recorder()
    unsubscribe = bus.subscribe(recording)
    assert len(bus) == 1
    unsubscribe()
    assert len(bus) == 0
    pipeline.run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", bus=bus)
    assert not recording.events


# ---------------------------------------------------------------------------
# The fold in isolation
# ---------------------------------------------------------------------------


def test_a_synthetic_stream_folds_to_the_expected_summary() -> None:
    """The fold, driven by hand-built events, with the pipeline out of the way.

    This is the part of the spec's wording -- "fold a *synthetic* event stream"
    -- that the end-to-end tests cannot cover: it pins the arithmetic itself, so
    a regression in the fold is attributable to the fold.
    """
    def parsed(
        seq: int,
        *,
        inspected: bool,
        tcp: bool,
        udp: bool,
        fwd: bool,
        size: int = 100,
    ) -> PacketParsed:
        return PacketParsed(
            sequence_index=seq,
            byte_len=size,
            inspected=inspected,
            is_tcp=tcp,
            is_udp=udp,
            forwarded=fwd,
        )

    t = FiveTuple(0x0A000001, 0x08080808, 5000, 443, 6)
    events = [
        CaptureOpened(path="synthetic", linktype=1),
        parsed(0, inspected=False, tcp=False, udp=False, fwd=True, size=60),
        parsed(1, inspected=True, tcp=True, udp=False, fwd=True),
        parsed(2, inspected=True, tcp=True, udp=False, fwd=True),
        parsed(3, inspected=True, tcp=True, udp=False, fwd=False),
        parsed(4, inspected=True, tcp=True, udp=False, fwd=False),
        FlowCreated(five_tuple=t),
        FlowClassified(five_tuple=t, app_type=AppType.HTTPS, sni="a.example"),
        FlowBlocked(five_tuple=t, app_type=AppType.HTTPS, sni="a.example"),
        LimitExceeded(kind="Synthetic", detail="not reached"),
        CaptureClosed(),
    ]
    result = pipeline.fold_events(events)

    assert result.stats.total_packets == 5
    assert result.stats.total_bytes == 460  # 60 + 4 x 100
    assert result.stats.forwarded_packets == 3  # 1 skipped + 2 forwarded
    assert result.stats.dropped_packets == 2
    assert result.stats.tcp_packets == 4
    assert result.stats.udp_packets == 0
    assert result.stats.other_packets == 1
    assert result.app_counts[AppType.HTTPS] == 1
    assert result.detected_domains == {"a.example": AppType.HTTPS}
    assert len(result.blocked_flows) == 1
    assert result.drop_rate_percent == pytest.approx(50.0)
    assert result.quic_packets == 0
    # Events with no figure the fold reads are simply ignored.
    assert result.per_worker_packet_counts == []
    assert result.fast_path_stats is None
    assert result.load_balancer_stats is None


def test_an_empty_stream_folds_to_an_empty_result() -> None:
    """A fold over nothing is the zero value, not an error.

    A consumer that subscribes before the capture exists must get something
    sensible rather than an AttributeError.
    """
    result = pipeline.fold_events([])
    assert result.stats.total_packets == 0
    assert result.app_counts == {}
    assert result.fast_path_stats is None
    assert result.drop_rate_percent == 0.0


# ---------------------------------------------------------------------------
# The wire form (`T3-07`)
# ---------------------------------------------------------------------------
#
# The engine owns the events' wire form, for the same reason it owns
# `CaptureProfile`'s: a boundary that kept its own copy of these fields would be
# a second home for them, and the two would drift apart silently.


def test_an_event_names_its_kind() -> None:
    assert event_to_dict(CaptureOpened(path="a.pcap", linktype=1))["kind"] == "CaptureOpened"
    assert event_to_dict(CaptureClosed())["kind"] == "CaptureClosed"
    assert event_to_dict(
        PacketParsed(
            sequence_index=0, byte_len=10, inspected=True, is_tcp=True, is_udp=False, forwarded=True
        )
    )["kind"] == "PacketParsed"


def test_a_five_tuple_is_named_and_not_a_bare_array() -> None:
    """Five numbers in a row do not say which is the port."""
    five_tuple = FiveTuple(src_ip=1, dst_ip=2, src_port=3, dst_port=4, protocol=6)
    payload = event_to_dict(FlowCreated(five_tuple=five_tuple))
    assert payload["five_tuple"] == {
        "src_ip": 1,
        "dst_ip": 2,
        "src_port": 3,
        "dst_port": 4,
        "protocol": 6,
    }


def test_an_app_is_named_by_its_stable_key() -> None:
    """`AppType.name`, not its display name: `DEC-04` made that the persisted key."""
    five_tuple = FiveTuple(src_ip=1, dst_ip=2, src_port=3, dst_port=4, protocol=6)
    payload = event_to_dict(
        FlowClassified(five_tuple=five_tuple, app_type=AppType.TWITTER, sni="api.twitter.com")
    )
    assert payload["app"] == "TWITTER"
    assert payload["sni"] == "api.twitter.com"
    assert payload["kind"] == "FlowClassified"


def test_a_limit_event_says_which_limit() -> None:
    """The event's own `kind` is the limit's kind, so the discriminator is named."""
    payload = event_to_dict(LimitExceeded(kind="max_packets", detail="100"))
    assert payload["kind"] == "LimitExceeded"
    assert payload["limit_kind"] == "max_packets"
    assert payload["detail"] == "100"


def test_an_opened_capture_carries_its_identity() -> None:
    """The path and the link type are what the event is *for*."""
    payload = event_to_dict(CaptureOpened(path="a.pcap", linktype=1))
    assert payload == {"kind": "CaptureOpened", "path": "a.pcap", "linktype": 1}


def test_a_parsed_packet_carries_its_decision() -> None:
    """`forwarded` is the rule decision, and `inspected` is the reader's own
    distinction -- a frame that never reached a flow has to say so."""
    payload = event_to_dict(
        PacketParsed(
            sequence_index=7,
            byte_len=100,
            inspected=True,
            is_tcp=True,
            is_udp=False,
            forwarded=False,
        )
    )
    assert payload == {
        "kind": "PacketParsed",
        "sequence_index": 7,
        "byte_len": 100,
        "inspected": True,
        "is_tcp": True,
        "is_udp": False,
        "forwarded": False,
    }


def test_the_worker_aggregate_is_not_carried_to_the_wire() -> None:
    """`WorkerFinished` holds the fast path's whole result.

    Every connection it saw, and a bitmap of per-packet decisions: not a thing
    to hand to a client. The event says the fast path finished; the run's
    result is what the caller asked for.
    """
    payload = event_to_dict(WorkerFinished(worker_id=0, result=object()))  # type: ignore[arg-type]
    assert payload == {"kind": "WorkerFinished", "worker_id": 0}


def test_an_unknown_event_type_is_named_rather_than_dropped() -> None:
    """A future event type is still delivered: the consumer sees that something
    happened, which is the safe direction."""

    class SomethingNew(Event):
        pass

    assert event_to_dict(SomethingNew()) == {"kind": "SomethingNew"}


def test_every_event_is_json_ready() -> None:
    """The wire form has to survive `json.dumps`, or the boundary finds out late."""
    import json

    events = [
        CaptureOpened(path="a.pcap", linktype=1),
        CaptureClosed(),
        PacketParsed(
            sequence_index=0, byte_len=10, inspected=True, is_tcp=True, is_udp=False, forwarded=True
        ),
        FlowCreated(five_tuple=FiveTuple(1, 2, 3, 4, 6)),
        FlowClassified(
            five_tuple=FiveTuple(1, 2, 3, 4, 6), app_type=AppType.TWITTER, sni="x.example"
        ),
        FlowBlocked(
            five_tuple=FiveTuple(1, 2, 3, 4, 6), app_type=AppType.TWITTER, sni="x.example"
        ),
        FlowEvicted(five_tuple=FiveTuple(1, 2, 3, 4, 6)),
        LimitExceeded(kind="max_packets", detail="100"),
    ]
    for event in events:
        payload = event_to_dict(event)
        assert json.loads(json.dumps(payload)) == payload
        assert payload["kind"] == type(event).__name__
