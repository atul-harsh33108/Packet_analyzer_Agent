"""Verify the two documented parity breaks actually behave as documented.

`DEC-05` and `DEC-06` are deliberate divergences from the C++ original. The
differential suite runs with `fold_bidirectional=False` so parity holds for
everything else, which means those two are *excluded* from the parity check rather
than *verified* by it. They are documented in `tests/differential/README.md`
allowlist entries 6 and 8.

This checks the port side of each claim. It cannot check the C++ side -- that needs
Docker -- but it can confirm that the port really does what the allowlist says it
does, so the divergence is a measured property rather than an aspiration. With the
Docker suite green, the two halves together say what they intend to.
"""

from __future__ import annotations

from pathlib import Path

from conftest import TEST_DPI_PCAP
from dpi_engine.pipeline import run_pipeline
from dpi_engine.rule_manager import RuleManager
from dpi_engine.types import AppType


class TestDec05BidirectionalFolding:
    """Allowlist entry 6: folding is ON by default and changes per-flow counts."""

    def test_folding_is_the_default(self, tmp_path: Path) -> None:
        """If folding were off by default the product default would be the parity
        behaviour, and the allowlist entry would be describing an unreachable mode.
        """
        on = run_pipeline(TEST_DPI_PCAP, tmp_path / "on.pcap")
        off = run_pipeline(
            TEST_DPI_PCAP, tmp_path / "off.pcap", fold_bidirectional=False
        )

        assert on.global_stats is not None
        assert off.global_stats is not None
        # Folding merges the two directions of a conversation into one flow, so
        # the default must report strictly fewer distinct flows.
        assert on.global_stats.total_connections_seen < off.global_stats.total_connections_seen, (
            "bidirectional folding must reduce the distinct-flow count; if it does "
            "not, DEC-05 is not doing what the allowlist says"
        )

    def test_folding_gives_inbound_counters_an_owner(self) -> None:
        """`D-25`: `packets_in`/`bytes_in` were permanently 0 without folding.

        With folding off there is no shared `Connection` to attribute the reverse
        direction to, so both counters stay zero -- exactly as the C++ original
        leaves them. With it on, they are populated. That is the divergence
        allowlist entry 6 rests on, and `D-25` could not be fixed by a counter
        alone for precisely this reason.

        Asserted at the tracker rather than through `PipelineResult`, because that
        is where the counters live: neither `GlobalStats` nor `TrackerStats`
        aggregates them, so a pipeline-level assertion would be asserting on a field
        that does not exist rather than on the behaviour.
        """
        from dpi_engine.connection_tracker import ConnectionTracker
        from dpi_engine.packet_parser import parse_packet
        from dpi_engine.pcap_io import PcapReader
        from dpi_engine.types import FiveTuple

        with PcapReader(TEST_DPI_PCAP) as reader:
            # Keep only the packets this engine can parse, so the loop below does
            # not have to re-derive the same filter.
            raws = [raw for raw in reader if parse_packet(raw) is not None]

        def inbound_total(fold: bool) -> int:
            tracker = ConnectionTracker(fold_bidirectional=fold)
            for raw in raws:
                parsed = parse_packet(raw)
                assert parsed is not None
                conn = tracker.get_or_create_connection(
                    FiveTuple(
                        src_ip=parsed.src_ip,
                        dst_ip=parsed.dst_ip,
                        src_port=parsed.src_port,
                        dst_port=parsed.dst_port,
                        protocol=parsed.protocol,
                    )
                )
                tracker.update_connection(
                    conn, len(raw.data), is_outbound=parsed.src_ip == conn.tuple.src_ip
                )
            return sum(c.packets_in for c in tracker.get_all_connections())

        assert inbound_total(fold=True) > 0, (
            "folding must give the inbound counters an owner"
        )
        assert inbound_total(fold=False) == 0, (
            "without folding there is no shared flow to attribute the reverse "
            "direction to, so both counters stay zero"
        )

    def test_folding_does_not_change_what_gets_blocked(self, tmp_path: Path) -> None:
        """Folding is a bookkeeping change, not a policy change.

        Worth pinning because it is the reason `DEC-05` was acceptable: it changes
        how flows are *counted*, not which packets are dropped.
        """
        rules = RuleManager()
        rules.block_app(AppType.FACEBOOK)

        on = run_pipeline(TEST_DPI_PCAP, tmp_path / "on.pcap", rules, fold_bidirectional=True)
        off = run_pipeline(
            TEST_DPI_PCAP, tmp_path / "off.pcap", rules, fold_bidirectional=False
        )

        assert on.stats.dropped_packets == off.stats.dropped_packets
        assert on.stats.forwarded_packets == off.stats.forwarded_packets


class TestDec06EitherEndpointIpMatching:
    """Allowlist entry 8: an IP rule matches source *or* destination."""

    def test_a_destination_ip_rule_fires(self, tmp_path: Path) -> None:
        """The divergence itself.

        The original checks the source address only, so a rule written to block an
        IP was inert whenever that IP was the destination (`D-21`). The port has no
        opt-out for this, deliberately: source-only is not a behaviour anyone would
        select.
        """
        rules = RuleManager()
        # 8.8.8.8 appears as a destination in ordinary traffic, so blocking it
        # must drop something here.
        rules.block_ip("8.8.8.8")

        result = run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", rules)

        assert result.stats.dropped_packets > 0, (
            "blocking a destination IP must drop traffic; if it does not, DEC-06 "
            "is not implemented and the finding D-21 is still live"
        )

    def test_a_source_ip_rule_still_fires(self, tmp_path: Path) -> None:
        """Either endpoint includes the source, obviously -- but it is the case the
        original handled, so a regression here would be invisible to the test above.
        """
        rules = RuleManager()
        rules.block_ip("192.168.1.50")

        result = run_pipeline(TEST_DPI_PCAP, tmp_path / "out.pcap", rules)

        assert result.stats.dropped_packets > 0
