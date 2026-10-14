"""The bounded reorder window (DEC-01): `pipeline.ReorderBuffer`.

Two things have to be pinned, and they pull in opposite directions:

* **Within the window**, output must be byte-identical to the second-pass path
  `T0-11` left behind, in input order. That is what makes the buffer a
  replacement for it rather than a different product.
* **Beyond the window**, the documented late-packet policy applies: order may be
  given up, but the *decision* never is. A packet is written only from a
  worker's actual verdict -- never guessed, never dropped to make room.

The unit tests below drive the buffer directly so both sides of the window
boundary are reachable in microseconds. The integration tests then check that
the real multiprocess pipeline agrees with them.
"""

from __future__ import annotations

import pathlib
from pathlib import Path

import pytest

from conftest import TEST_DPI_PCAP
from dpi_engine.pcap_io import RawPacket
from dpi_engine.pipeline import (
    ReorderBuffer,
    run_pipeline,
    run_pipeline_multiprocess,
    run_pipeline_staged,
)


class RecordingWriter:
    """Stands in for `PcapWriter`, recording what the buffer emits and in what
    order. Real file I/O would make the ordering assertions indistinguishable
    from a flaky filesystem."""

    def __init__(self) -> None:
        self.written: list[int] = []

    def write(self, raw: RawPacket) -> None:
        self.written.append(raw.orig_len)


def _packet(index: int) -> RawPacket:
    """A distinguishable packet: `orig_len` carries the index so the emission
    order can be read straight off the recorded writer."""
    payload = bytes([index % 256])
    return RawPacket(
        ts_sec=1_700_000_000 + index, ts_usec=0, data=payload, orig_len=index
    )


def _buffer(window: int) -> tuple[ReorderBuffer, RecordingWriter]:
    writer = RecordingWriter()
    return ReorderBuffer(writer, window), writer


# ---------------------------------------------------------------------------
# Within the window: order is preserved
# ---------------------------------------------------------------------------


def test_in_order_decisions_emit_in_order() -> None:
    buf, writer = _buffer(4)
    for i in range(4):
        buf.offer(i, _packet(i))
    for i in range(4):
        buf.decide(i, forwarded=True)

    assert writer.written == [0, 1, 2, 3]
    assert (buf.forwarded_packets, buf.dropped_packets) == (4, 0)
    assert buf.out_of_order_emissions == 0


def test_out_of_order_decisions_still_emit_in_input_order() -> None:
    """The whole point of the window: verdicts may arrive in any order, output
    may not."""
    buf, writer = _buffer(4)
    for i in range(4):
        buf.offer(i, _packet(i))

    for i in (3, 1, 0, 2):
        buf.decide(i, forwarded=True)

    assert writer.written == [0, 1, 2, 3]
    assert buf.out_of_order_emissions == 0
    assert buf.late_decisions == 0


def test_dropped_packets_are_not_written_but_are_counted() -> None:
    buf, writer = _buffer(3)
    for i in range(3):
        buf.offer(i, _packet(i))
    buf.decide(0, forwarded=True)
    buf.decide(1, forwarded=False)
    buf.decide(2, forwarded=True)

    assert writer.written == [0, 2]
    assert (buf.forwarded_packets, buf.dropped_packets) == (2, 1)


def test_skipped_packets_are_neither_written_nor_counted_as_drops() -> None:
    """A frame the reader declined to inspect was never offered to a worker, so
    writing it or counting it as a drop would both be wrong -- the drop total is
    derived from `total - other`, and counting it here would subtract twice."""
    buf, writer = _buffer(3)
    buf.offer(0, _packet(0))
    buf.offer_skipped(1)
    buf.offer(2, _packet(2))
    buf.decide(0, forwarded=True)
    buf.decide(2, forwarded=True)

    assert writer.written == [0, 2]
    assert (buf.forwarded_packets, buf.dropped_packets) == (2, 0)


def test_a_skipped_packet_does_not_stall_the_window() -> None:
    """Skipped frames get no verdict, so if they did not resolve immediately
    `next_expected` would wait forever on a hole no worker will ever fill."""
    buf, writer = _buffer(8)
    buf.offer_skipped(0)
    buf.offer(1, _packet(1))
    buf.decide(1, forwarded=True)

    assert writer.written == [1]
    assert buf.next_expected == 2


def test_a_later_verdict_cannot_emit_before_an_earlier_undecided_one() -> None:
    buf, writer = _buffer(4)
    for i in range(3):
        buf.offer(i, _packet(i))
    buf.decide(2, forwarded=True)

    assert writer.written == [], "nothing may be emitted while packet 0 is undecided"


def test_window_must_be_positive() -> None:
    with pytest.raises(ValueError, match="window must be >= 1"):
        ReorderBuffer(RecordingWriter(), 0)


# ---------------------------------------------------------------------------
# Beyond the window: the late-packet policy
# ---------------------------------------------------------------------------


def test_a_full_window_with_a_stalled_head_emits_out_of_order() -> None:
    """The one circumstance in which order is given up.

    Packets are dispatched hash-partitioned, so the packet at `next_expected` is
    routinely the one still in flight while later packets have been decided.
    Blocking on it would serialise the run on whichever worker got the slowest
    flow; the policy is to emit what is ready and let the straggler land late.
    """
    buf, writer = _buffer(2)
    buf.offer(0, _packet(0))
    buf.offer(1, _packet(1))

    buf.decide(1, forwarded=True)  # packet 0 is still undecided
    assert writer.written == [], "the window is not yet full, so nothing may jump the queue"

    # Filling the window is what arms the policy.
    assert buf.full() is True
    assert buf.flush_out_of_order() is True
    assert writer.written == [1]
    assert buf.out_of_order_emissions == 1

    # The straggler still gets its real verdict, late.
    buf.decide(0, forwarded=True)
    assert writer.written == [1, 0]
    assert buf.next_expected == 2
    # The counters must survive the tombstone, which is the subtle part: the
    # already-emitted entry is still in the store when `_advance` steps over it,
    # and re-emitting it would file the straggler as a *drop* rather than a
    # second write -- corrupting the totals without ever touching the file.
    assert (buf.forwarded_packets, buf.dropped_packets) == (2, 0)
    assert buf.pending() == 0


def test_out_of_order_emission_never_guesses_a_verdict() -> None:
    """Order may be sacrificed. The decision may not be: nothing is written
    until a worker has actually decided it."""
    buf, writer = _buffer(1)
    buf.offer(0, _packet(0))

    assert buf.full() is True
    assert buf.flush_out_of_order() is False, "an undecided packet cannot be emitted at all"
    assert writer.written == []

    buf.decide(0, forwarded=False)
    assert writer.written == [], "a packet decided as dropped must never be written"


def test_flush_emits_the_lowest_ready_index_so_output_stays_near_ordered() -> None:
    buf, writer = _buffer(3)
    for i in range(3):
        buf.offer(i, _packet(i))
    for i in (2, 1):
        buf.decide(i, forwarded=True)

    assert buf.flush_out_of_order() is True
    assert writer.written == [1], "packet 1 is earlier than 2, so it goes first"


def test_a_verdict_arriving_after_emission_is_counted_not_written_twice() -> None:
    buf, writer = _buffer(1)
    buf.offer(0, _packet(0))
    buf.decide(0, forwarded=True)
    assert writer.written == [0]

    buf.decide(0, forwarded=True)  # a duplicate / already-emitted verdict
    assert writer.written == [0]
    assert buf.late_decisions == 1


def test_finish_flushes_everything_resolvable() -> None:
    buf, writer = _buffer(4)
    for i in range(3):
        buf.offer(i, _packet(i))
    buf.offer_skipped(3)
    for i in range(3):
        buf.decide(i, forwarded=True)

    buf.finish()
    assert writer.written == [0, 1, 2]
    assert buf.pending() == 0


# ---------------------------------------------------------------------------
# Integration: the real pipeline, both sides of the boundary
# ---------------------------------------------------------------------------


def _payloads(path: pathlib.Path) -> list[bytes]:
    from dpi_engine.pcap_io import PcapReader

    with PcapReader(path) as reader:
        return [bytes(raw.data) for raw in reader]


def test_streaming_output_is_byte_identical_to_the_second_pass(tmp_path: Path) -> None:
    """The replacement claim, asserted on real files: with a window large enough
    for the capture, streaming writes exactly what `T0-11`'s second pass wrote."""
    second_pass = run_pipeline_multiprocess(
        TEST_DPI_PCAP, tmp_path / "second.pcap", num_workers=3, reorder_window=None
    )
    streaming = run_pipeline_multiprocess(
        TEST_DPI_PCAP, tmp_path / "stream.pcap", num_workers=3
    )

    assert _payloads(tmp_path / "second.pcap") == _payloads(tmp_path / "stream.pcap")
    assert second_pass.stats == streaming.stats
    assert second_pass.app_counts == streaming.app_counts
    assert second_pass.blocked_flows == streaming.blocked_flows


def test_a_one_packet_window_still_forwards_exactly_the_same_packets(
    tmp_path: Path,
) -> None:
    """Beyond the window, order may differ but *which* packets are forwarded may
    not -- a reordered capture that drops or invents a packet is a different
    product, not a late one."""
    reference = run_pipeline(TEST_DPI_PCAP, tmp_path / "ref.pcap")
    squeezed = run_pipeline_multiprocess(
        TEST_DPI_PCAP, tmp_path / "tiny.pcap", num_workers=3, reorder_window=1
    )

    assert _payloads(tmp_path / "tiny.pcap") == _payloads(tmp_path / "ref.pcap")
    assert squeezed.stats.forwarded_packets == reference.stats.forwarded_packets
    assert squeezed.stats.dropped_packets == reference.stats.dropped_packets


def test_all_three_variants_agree_on_a_squeezed_window(tmp_path: Path) -> None:
    single = run_pipeline(TEST_DPI_PCAP, tmp_path / "single.pcap")
    mp = run_pipeline_multiprocess(
        TEST_DPI_PCAP, tmp_path / "mp.pcap", num_workers=2, reorder_window=1
    )
    staged = run_pipeline_staged(
        TEST_DPI_PCAP, tmp_path / "staged.pcap", num_load_balancers=2, reorder_window=1
    )

    expected = _payloads(tmp_path / "single.pcap")
    assert _payloads(tmp_path / "mp.pcap") == expected
    assert _payloads(tmp_path / "staged.pcap") == expected
    for variant in (mp, staged):
        assert variant.stats.forwarded_packets == single.stats.forwarded_packets
        assert variant.stats.dropped_packets == single.stats.dropped_packets
