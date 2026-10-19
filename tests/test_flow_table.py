"""`T3-06` — `with_flow_table` surfaces per-flow rows from a run.

**Why this task exists.** Phase 3's `query_flows`, `get_flow_detail` and `diff_runs`
all need a queryable flow table. `PipelineResult` had none: `global_stats` is
deliberately *aggregate only* (totals, distributions, top domains), and
`blocked_flows` carries only blocked flows. The per-flow rows existed transiently --
`WorkerResult.connections` reached the parent and was aggregated away -- but nothing
could ask about a specific flow afterwards.

**The flag is off by default on purpose.** Retaining one row per live flow is only
useful to a caller that will ask questions about the run later; a CLI report does not
need it, and `D-01`/`D-02` established that this engine's memory behaviour is a
designed property rather than an accident. The strongest test in this file is
therefore `test_the_flag_changes_nothing_else`.

The cross-variant test is the load-bearing one: all three pipeline entry points must
produce **the same rows**, because the MCP surface will present them as one table and a
difference between variants would be indistinguishable from a real change in the
capture.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import TEST_DPI_PCAP
from dpi_engine.connection_tracker import to_flow_records
from dpi_engine.pipeline import (
    run_pipeline,
    run_pipeline_multiprocess,
    run_pipeline_staged,
)
from dpi_engine.rule_manager import RuleManager
from dpi_engine.types import (
    AppType,
    Connection,
    ConnectionState,
    DPIStats,
    FiveTuple,
    FlowRecord,
    PacketAction,
)


@pytest.fixture(scope="module")
def capture() -> Path:
    return Path(TEST_DPI_PCAP)


@pytest.fixture(scope="module")
def without(tmp_path_factory: pytest.TempPathFactory, capture: Path) -> object:
    out = tmp_path_factory.mktemp("off")
    return run_pipeline(str(capture), out / "o.pcap", RuleManager())


@pytest.fixture(scope="module")
def with_table(tmp_path_factory: pytest.TempPathFactory, capture: Path) -> object:
    out = tmp_path_factory.mktemp("on")
    return run_pipeline(str(capture), out / "o.pcap", RuleManager(), with_flow_table=True)


class TestTheFlagIsOptIn:
    def test_absent_by_default(self, without: object) -> None:
        """`None`, not `[]`.

        A caller must be able to tell "I did not ask" from "this capture had no flows",
        exactly as `global_stats=None` already allows. An empty list would make those
        indistinguishable, and the distinction is the difference between a flag that
        works and one that is silently ignored.
        """
        assert without.flow_table is None

    def test_the_declared_field_default_is_also_none(self) -> None:
        """Pins the *declared* default, not just the value a run happens to produce.

        Every production construction site passes `flow_table=` explicitly, so changing
        the dataclass default is invisible through `run_pipeline` -- a mutation
        harness reported it as a survivor, and it is a true equivalent mutant *for the
        pipeline*. It is not equivalent for anyone constructing `PipelineResult`
        directly, where the default is the whole contract, so the default is asserted
        rather than left to chance.
        """
        from dpi_engine.pipeline import PipelineResult

        assert PipelineResult(stats=DPIStats()).flow_table is None, (
            "the declared default must be None; a caller building a PipelineResult "
            "without a run must not see an empty list, which would read as "
            "'this capture had no flows'"
        )

    def test_requested_gives_rows(self, with_table: object) -> None:
        assert with_table.flow_table, "with_flow_table=True produced no rows"

    def test_the_flag_changes_nothing_else(
        self, without: object, with_table: object
    ) -> None:
        """**The most important assertion in this file.**

        The flag must add rows and nothing but rows. If it perturbed any count, the
        differential parity suite and the golden corpus would both be measuring a
        different engine, and neither would say so -- they would just quietly compare
        against their own recorded baselines.
        """
        assert with_table.stats == without.stats
        assert with_table.app_counts == without.app_counts
        assert with_table.detected_domains == without.detected_domains
        assert with_table.blocked_flows == without.blocked_flows
        assert with_table.global_stats == without.global_stats
        assert with_table.fast_path_stats == without.fast_path_stats


class TestAllThreeVariantsAgree:
    """One table, three pipelines.

    The MCP surface presents `query_flows` as a single view. A row that differed
    between the single-process and multiprocess paths would be indistinguishable from
    a genuine change in the capture, so the equivalence is the property, not a
    convenience.
    """

    def test_single_multiprocess_and_staged_produce_identical_rows(
        self, tmp_path: Path, capture: Path
    ) -> None:
        single = run_pipeline(
            str(capture), tmp_path / "s.pcap", RuleManager(), with_flow_table=True
        )
        multi = run_pipeline_multiprocess(
            str(capture), tmp_path / "m.pcap", RuleManager(),
            num_workers=2, with_flow_table=True,
        )
        staged = run_pipeline_staged(
            str(capture), tmp_path / "g.pcap", RuleManager(),
            num_load_balancers=1, fps_per_lb=1, with_flow_table=True,
        )

        assert single.flow_table == multi.flow_table, (
            "the single-process and multiprocess flow tables differ; a caller cannot "
            "tell which pipeline produced a row"
        )
        assert single.flow_table == staged.flow_table, (
            "the single-process and staged flow tables differ"
        )

    def test_every_variant_off_gives_none(
        self, tmp_path: Path, capture: Path
    ) -> None:
        assert run_pipeline_multiprocess(
            str(capture), tmp_path / "m.pcap", RuleManager(), num_workers=2
        ).flow_table is None
        assert run_pipeline_staged(
            str(capture), tmp_path / "g.pcap", RuleManager(),
            num_load_balancers=1, fps_per_lb=1,
        ).flow_table is None

    def test_the_ordering_is_deterministic(self, tmp_path: Path, capture: Path) -> None:
        """Two runs of the same capture must order rows identically.

        Without the sort in `to_flow_records`, ordering would follow the tracker's LRU
        (i.e. packet arrival) and, across workers, completion order -- so `diff_runs`
        would report churn that is really just scheduling.
        """
        first = run_pipeline(
            str(capture), tmp_path / "a.pcap", RuleManager(), with_flow_table=True
        )
        second = run_pipeline(
            str(capture), tmp_path / "b.pcap", RuleManager(), with_flow_table=True
        )
        assert first.flow_table == second.flow_table


class TestRecordShape:
    def test_rows_are_immutable(self, with_table: object) -> None:
        """A retained row must not change under the caller.

        `Connection` is live tracker state; `FlowRecord` exists precisely so a stored
        answer cannot be mutated afterwards by the thing that produced it.
        """
        row = with_table.flow_table[0]
        with pytest.raises(Exception):  # noqa: B017 - FrozenInstanceError
            row.app = "TAMPERED"  # type: ignore[misc]

    def test_enum_fields_are_names_not_enums(self, with_table: object) -> None:
        """`DEC-04`'s persistence rule: what gets stored is `.name`.

        A stored row that held enum members could not be written as JSON without a
        codec, and would break the day a member was renamed.
        """
        for row in with_table.flow_table:
            assert isinstance(row.app, str), f"{row.app!r} is not a str"
            assert isinstance(row.state, str), f"{row.state!r} is not a str"
            assert row.app in {a.name for a in AppType}
            assert row.state in {s.name for s in ConnectionState}

    def test_rows_are_json_serialisable(self, with_table: object) -> None:
        """The whole point: an MCP tool returns JSON, so the row must already be one.

        Serialised through `dataclasses.asdict` because `FlowRecord.five_tuple` is a
        property, not a field, and would otherwise drag a `FiveTuple` into the payload.
        """
        from dataclasses import asdict

        payload = [asdict(r) for r in with_table.flow_table]
        text = json.dumps(payload)
        assert json.loads(text) == payload

    def test_five_tuple_round_trips(self, with_table: object) -> None:
        """`get_flow_detail` is addressed by five-tuple, so it must be reconstructible."""
        for row in with_table.flow_table:
            t = row.five_tuple
            assert isinstance(t, FiveTuple)
            assert (t.src_ip, t.dst_ip, t.src_port, t.dst_port, t.protocol) == (
                row.src_ip, row.dst_ip, row.src_port, row.dst_port, row.protocol
            )

    def test_hostname_is_present_where_the_flow_was_classified(
        self, with_table: object
    ) -> None:
        """A classified row without its hostname would be far less useful.

        The SNI is the human-meaningful half of a row: without it a caller has an IP
        and an app name but nothing to show a person.
        """
        classified = [r for r in with_table.flow_table if r.app != AppType.UNKNOWN.name]
        assert classified, "no classified rows in the fixture"
        assert any(r.hostname for r in classified), (
            "no classified row carries its SNI; the hostname is being dropped"
        )


class TestToFlowRecords:
    """The converter in isolation, including the ordering guarantee."""

    @staticmethod
    def _conn(**kw: object) -> Connection:
        base = {
            "tuple": FiveTuple(1, 2, 3, 4, 6),
            "state": ConnectionState.CLASSIFIED,
            "app_type": AppType.GOOGLE,
            "sni": "www.google.com",
        }
        base.update(kw)
        return Connection(**base)  # type: ignore[arg-type]

    def test_it_sorts_regardless_of_input_order(self) -> None:
        """The guarantee `diff_runs` depends on."""
        a = self._conn(tuple=FiveTuple(10, 20, 30, 40, 6))
        b = self._conn(tuple=FiveTuple(1, 2, 3, 4, 6))
        c = self._conn(tuple=FiveTuple(5, 6, 7, 8, 6))

        forward = to_flow_records([a, b, c])
        backward = to_flow_records([c, b, a])
        assert forward == backward
        assert [r.src_ip for r in forward] == [1, 5, 10]

    def test_it_maps_every_field(self) -> None:
        conn = self._conn(
            packets_out=7,
            bytes_out=900,
            action=PacketAction.DROP,
        )
        row = to_flow_records([conn])[0]
        assert row.app == "GOOGLE"
        assert row.state == "CLASSIFIED"
        assert row.hostname == "www.google.com"
        assert row.packets == 7
        assert row.bytes == 900
        assert row.action == "DROP"

    def test_it_preserves_a_golden_path(self) -> None:
        """A golden path in the sorted order must come first, so ordering is total."""
        conns = [
            self._conn(tuple=FiveTuple(9, 9, 9, 9, 6)),
            self._conn(tuple=FiveTuple(1, 9, 9, 9, 17)),
        ]
        rows = to_flow_records(conns)
        assert rows[0].protocol == 17, "protocol was not part of the sort key"
        assert rows[1].protocol == 6

    def test_an_empty_input_gives_an_empty_list(self) -> None:
        assert to_flow_records([]) == []

    def test_it_does_not_alias_the_input(self) -> None:
        """The rows must be independent copies, not views onto live state."""
        conn = self._conn(app_type=AppType.GOOGLE)
        row = to_flow_records([conn])[0]
        conn.app_type = AppType.NETFLIX
        conn.sni = "changed.example"
        assert row.app == "GOOGLE", "the record aliased live tracker state"
        assert row.hostname == "www.google.com"


class TestRecordsStayBounded:
    def test_row_count_is_capped_by_max_connections(
        self, tmp_path: Path, capture: Path
    ) -> None:
        """Retaining rows must not become a new unbounded retention path.

        `D-01`/`D-02` bounded this engine's memory on purpose. The flow table is
        bounded by the same `max_connections` the tracker's LRU enforces, so it cannot
        hold more rows than the tracker could hold connections -- and lowering the cap
        must lower the row count, or something is retaining flows independently of the
        tracker.
        """
        generous = run_pipeline(
            str(capture), tmp_path / "a.pcap", RuleManager(),
            with_flow_table=True, max_connections=100_000,
        )
        tight = run_pipeline(
            str(capture), tmp_path / "b.pcap", RuleManager(),
            with_flow_table=True, max_connections=4,
        )
        assert tight.flow_table is not None and generous.flow_table is not None
        assert len(tight.flow_table) < len(generous.flow_table), (
            f"a cap of 4 produced {len(tight.flow_table)} rows against "
            f"{len(generous.flow_table)} uncapped; the flow table is not bounded by "
            "the tracker"
        )


class TestFlowRecordType:
    def test_it_is_a_frozen_slotted_dataclass(self) -> None:
        import dataclasses

        assert dataclasses.is_dataclass(FlowRecord)
        params = FlowRecord.__dataclass_params__
        assert params.frozen is True, "FlowRecord must be frozen"
        assert hasattr(FlowRecord, "__slots__"), "FlowRecord should use slots"

    def test_it_is_hashable_and_comparable_by_value(
        self, with_table: object
    ) -> None:
        """Rows must be comparable, or two runs cannot be diffed row by row.

        `diff_runs` compares a row in run A against the same row in run B; that is
        equality on values, which a mutable record cannot support once either side has
        been touched.
        """
        first = with_table.flow_table[0]
        clone = FlowRecord(**{f: getattr(first, f) for f in first.__slots__})
        assert clone == first, "an identical row did not compare equal"
        assert hash(clone) == hash(first)

    def test_a_changed_field_changes_equality(self, with_table: object) -> None:
        """The other half: equality must actually discriminate."""
        first = with_table.flow_table[0]
        fields = {f: getattr(first, f) for f in first.__slots__}
        fields["app"] = "SOMETHING_ELSE"
        assert FlowRecord(**fields) != first
