"""`T3-02` â€” the run store: persist and query a finished run's flows, stats and events.

**What this file is protecting.** `query_flows`, `get_flow_detail` and `diff_runs` all
read from the store, and two of them answer *"what did this run see?"*. So the two
failure shapes that matter most here are:

1. **A stored run that quietly loses data.** `record_from_result` refuses a result with
   no flow table rather than storing an empty one, because `query_flows` returning `[]`
   for a run that had 27 flows is a wrong answer that looks like a fact about the capture.
2. **A read that quietly rescues a damaged file.** Truncated JSON, a wrong schema, and a
   payload edited after it was written all raise. A store that skipped bad files would
   report a tidier history than the one on disk.

The identity tests are the other half. `run_id` is content-addressed, so *which* fields
feed the hash is a behavioural decision rather than an implementation detail: the
per-field test below fails if any of them stops contributing, and the second test fails
if `created_at` or the event log starts contributing. That pair is what keeps `diff_runs`
comparing the pair of runs the caller asked about.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from conftest import TEST_DPI_PCAP
from dpi_engine.events import (
    CaptureClosed,
    Event,
    EventBus,
    FlowBlocked,
    FlowClassified,
    LimitExceeded,
    PacketParsed,
    Recorder,
)
from dpi_engine.pipeline import PipelineResult, run_pipeline
from dpi_engine.rule_manager import RuleManager
from dpi_engine.types import AppType, ConnectionState, FiveTuple, FlowRecord
from dpi_mcp.run_store import (
    SCHEMA,
    BlockedFlow,
    CounterDelta,
    FlowFilter,
    RunRecord,
    RunStats,
    RunStore,
    _event_to_record,
    capture_digest,
    diff_records,
    record_from_result,
)

_COMMIT = "testcommit"

#: Every counter a diff must expose. Named rather than derived from `RunStats`, because
#: the point is that dropping one is a deliberate act with a failing test attached.
EXPECTED_COUNTERS = {
    "total_packets",
    "total_bytes",
    "forwarded_packets",
    "dropped_packets",
    "tcp_packets",
    "udp_packets",
    "other_packets",
    "active_connections",
}


# ---------------------------------------------------------------------------
# Fixtures: two real runs over the shared capture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def workdir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("runstore")


@pytest.fixture(scope="module")
def incumbent(workdir: Path) -> PipelineResult:
    """The capture under the default (permissive) ruleset."""
    return run_pipeline(
        str(TEST_DPI_PCAP), workdir / "incumbent.pcap", RuleManager(), with_flow_table=True
    )


@pytest.fixture(scope="module")
def candidate(workdir: Path) -> PipelineResult:
    """The same capture with NETFLIX blocked -- a real, visible policy difference."""
    rules = RuleManager()
    rules.block_app(AppType.NETFLIX)
    return run_pipeline(
        str(TEST_DPI_PCAP), workdir / "candidate.pcap", rules, with_flow_table=True
    )


@pytest.fixture(scope="module")
def untabled(workdir: Path) -> PipelineResult:
    """A run that never asked for a flow table -- the shape `record_from_result` refuses."""
    return run_pipeline(str(TEST_DPI_PCAP), workdir / "untabled.pcap", RuleManager())


@pytest.fixture(scope="module")
def no_globals(workdir: Path) -> PipelineResult:
    """A run that did not compute `global_stats`, so its connection totals are unknown."""
    return run_pipeline(
        str(TEST_DPI_PCAP),
        workdir / "noglobals.pcap",
        RuleManager(),
        with_global_stats=False,
        with_flow_table=True,
    )


@pytest.fixture(scope="module")
def rec_a(incumbent: PipelineResult) -> RunRecord:
    return record_from_result(incumbent, capture_path=TEST_DPI_PCAP, commit=_COMMIT)


@pytest.fixture(scope="module")
def rec_b(candidate: PipelineResult) -> RunRecord:
    return record_from_result(candidate, capture_path=TEST_DPI_PCAP, commit=_COMMIT)


@pytest.fixture
def store(tmp_path: Path) -> RunStore:
    return RunStore(tmp_path / "runs")


@pytest.fixture
def populated(store: RunStore, rec_a: RunRecord, rec_b: RunRecord) -> RunStore:
    store.save(rec_a)
    store.save(rec_b)
    return store


# ---------------------------------------------------------------------------
# Building a record from a live result
# ---------------------------------------------------------------------------


class TestRecordFromResult:
    def test_it_refuses_a_result_with_no_flow_table(self, untabled: PipelineResult) -> None:
        """**The silent-empty trap.** Storing no rows would make `query_flows` answer.

        A run whose flow table was never requested has not *observed* zero flows; it has
        not recorded them. Those are different, and only one of them may be reported to
        an agent as an empty result.
        """
        assert untabled.flow_table is None, "fixture is not exercising the refusal"
        with pytest.raises(ValueError, match="with_flow_table=True"):
            record_from_result(untabled, capture_path=TEST_DPI_PCAP)

    def test_it_carries_the_flows(self, rec_a: RunRecord, incumbent: PipelineResult) -> None:
        assert len(rec_a.flows) == len(incumbent.flow_table or [])
        assert len(rec_a.flows) > 0

    def test_flows_are_ordered_by_five_tuple(self, rec_a: RunRecord) -> None:
        keys = [
            (f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol) for f in rec_a.flows
        ]
        assert keys == sorted(keys), (
            "stored flows are not in five-tuple order; diff_runs and query_flows would "
            "report an order that depends on how the run happened to be scheduled"
        )

    def test_app_counts_are_name_keyed_and_sorted(self, rec_a: RunRecord) -> None:
        """`DEC-04`: what gets persisted is `AppType.name`, never the enum or its repr."""
        assert rec_a.app_counts, "no app counts captured"
        names = [name for name, _ in rec_a.app_counts]
        assert names == sorted(names)
        assert all(name in {app.name for app in AppType} for name in names)
        assert all(isinstance(count, int) for _, count in rec_a.app_counts)

    def test_detected_domains_are_sorted_pairs(self, rec_a: RunRecord) -> None:
        hosts = [host for host, _ in rec_a.detected_domains]
        assert hosts == sorted(hosts)
        assert all(app in {a.name for a in AppType} for _, app in rec_a.detected_domains)

    def test_it_captures_the_capture_digest_and_size(self, rec_a: RunRecord) -> None:
        digest, size = capture_digest(TEST_DPI_PCAP)
        assert rec_a.capture_sha256 == digest
        assert rec_a.capture_bytes == size
        assert rec_a.capture_bytes == Path(TEST_DPI_PCAP).stat().st_size

    def test_stats_mirror_the_result(self, rec_a: RunRecord, incumbent: PipelineResult) -> None:
        assert rec_a.stats.total_packets == incumbent.stats.total_packets
        assert rec_a.stats.dropped_packets == incumbent.stats.dropped_packets
        assert rec_a.stats.tcp_packets == incumbent.stats.tcp_packets
        assert rec_a.stats.udp_packets == incumbent.stats.udp_packets

    def test_global_counters_are_none_when_not_measured(self, no_globals: PipelineResult) -> None:
        """`None` is not `0`: a run that did not compute `global_stats` has no total.

        Reporting zero would be a claim about the capture rather than a statement about
        what the run measured.
        """
        assert no_globals.global_stats is None
        stats = RunStats.from_result(no_globals)
        assert stats.total_connections_seen is None
        assert stats.classified_connections is None
        assert stats.blocked_connections is None
        assert no_globals.flow_table is not None, "the flow table is independent of this"

    def test_global_counters_are_present_when_measured(self, incumbent: PipelineResult) -> None:
        assert incumbent.global_stats is not None
        stats = RunStats.from_result(incumbent)
        assert stats.total_connections_seen is not None
        assert stats.total_connections_seen > 0

    def test_a_record_survives_the_missing_globals(
        self, no_globals: PipelineResult, tmp_path: Path
    ) -> None:
        """`None` must round-trip as `null`, not collapse to `0` on the way through JSON."""
        record = record_from_result(no_globals, capture_path=TEST_DPI_PCAP, commit=_COMMIT)
        store = RunStore(tmp_path / "runs")
        store.save(record)
        restored = store.load(record.run_id)
        assert restored.stats.total_connections_seen is None
        assert restored.to_json()["stats"]["total_connections_seen"] is None

    def test_recorded_at_defaults_to_now_but_can_be_pinned(
        self, incumbent: PipelineResult
    ) -> None:
        default = record_from_result(incumbent, capture_path=TEST_DPI_PCAP)
        pinned = record_from_result(
            incumbent, capture_path=TEST_DPI_PCAP, created_at="2020-01-01T00:00:00+00:00"
        )
        assert default.created_at != ""
        assert pinned.created_at == "2020-01-01T00:00:00+00:00"

    def test_the_schema_is_stamped(self, rec_a: RunRecord) -> None:
        assert rec_a.schema == SCHEMA
        assert rec_a.to_json()["schema"] == SCHEMA


class TestDropRateUsesInspectedPackets:
    def test_the_denominator_excludes_frames_no_rule_could_match(self) -> None:
        """Same denominator as `PipelineResult.drop_rate_percent`, and the same reason.

        With 60 of 100 packets being non-TCP/UDP, dividing by `total_packets` would
        understate the rate by more than half -- and it would look like a smaller problem
        than it is.
        """
        stats = RunStats(
            total_packets=100,
            tcp_packets=10,
            udp_packets=30,
            other_packets=60,
            dropped_packets=4,
        )
        assert stats.drop_rate_percent == pytest.approx(10.0)
        assert stats.drop_rate_percent != pytest.approx(4.0)

    def test_no_inspected_packets_is_zero_not_a_division_error(self) -> None:
        assert RunStats(total_packets=5, other_packets=5).drop_rate_percent == 0.0


# ---------------------------------------------------------------------------
# Identity: the run id is content-addressed
# ---------------------------------------------------------------------------


class TestRunIdentity:
    def test_the_id_is_the_content_hash(self, rec_a: RunRecord) -> None:
        assert rec_a.run_id == rec_a.computed_run_id()

    def test_the_same_observation_gets_the_same_id(self, incumbent: PipelineResult) -> None:
        first = record_from_result(incumbent, capture_path=TEST_DPI_PCAP, commit=_COMMIT)
        second = record_from_result(incumbent, capture_path=TEST_DPI_PCAP, commit=_COMMIT)
        assert first.run_id == second.run_id

    def test_a_different_observation_gets_a_different_id(self, rec_a: RunRecord, rec_b: RunRecord) -> None:
        assert rec_a.run_id != rec_b.run_id

    @pytest.mark.parametrize(
        "mutate",
        [
            pytest.param(lambda r: replace(r, capture_sha256="0" * 32), id="capture"),
            pytest.param(lambda r: replace(r, commit="other"), id="commit"),
            pytest.param(lambda r: replace(r, ruleset="ruleset-2"), id="ruleset"),
            pytest.param(
                lambda r: replace(
                    r, stats=replace(r.stats, dropped_packets=r.stats.dropped_packets + 1)
                ),
                id="stats",
            ),
            pytest.param(
                lambda r: replace(
                    r, app_counts=tuple(sorted((*r.app_counts, ("ZOOM", 1))))
                ),
                id="app_counts",
            ),
            pytest.param(
                lambda r: replace(
                    r,
                    detected_domains=tuple(
                        sorted((*r.detected_domains, ("added.example", "GOOGLE")))
                    ),
                ),
                id="detected_domains",
            ),
            pytest.param(
                lambda r: replace(
                    r,
                    blocked_flows=(
                        *r.blocked_flows,
                        BlockedFlow(FiveTuple(9, 8, 7, 6, 17), "ZOOM", "z.example"),
                    ),
                ),
                id="blocked_flows",
            ),
            pytest.param(lambda r: replace(r, flows=r.flows[:-1]), id="flows"),
        ],
    )
    def test_every_fingerprinted_field_changes_the_id(
        self, rec_a: RunRecord, mutate: Callable[[RunRecord], RunRecord]
    ) -> None:
        """Each field in the fingerprint must genuinely contribute to it.

        Written as a sweep rather than one assertion per field so that *adding* a field
        to the fingerprint without adding it here is visible in the diff of this file.
        A field that silently stops contributing is how `diff_runs` ends up comparing the
        wrong pair of runs while reporting success.
        """
        changed = mutate(rec_a)
        assert changed.computed_run_id() != rec_a.computed_run_id()

    @pytest.mark.parametrize(
        "mutate",
        [
            pytest.param(lambda r: replace(r, created_at="1999-01-01T00:00:00+00:00"), id="created_at"),
            pytest.param(lambda r: replace(r, capture_path="elsewhere.pcap"), id="capture_path"),
            pytest.param(lambda r: replace(r, event_log=()), id="event_log"),
            pytest.param(lambda r: replace(r, events_omitted=(("PacketParsed", 9),)), id="events_omitted"),
        ],
    )
    def test_the_excluded_fields_do_not_change_the_id(
        self, rec_a: RunRecord, mutate: Callable[[RunRecord], RunRecord]
    ) -> None:
        """When a run was stored, and where its bytes happened to live, are not identity.

        `created_at` is storage metadata; `capture_path` is where the file sat, and the
        same bytes under two paths are the same observation; the event log is derived
        from the run and is bounded differently depending on whether a caller offered it.
        Including any of them would make re-storing an identical run look like a new one.
        """
        assert mutate(rec_a).computed_run_id() == rec_a.computed_run_id()

    def test_the_same_bytes_at_a_different_path_are_the_same_run(
        self, tmp_path: Path, incumbent: PipelineResult
    ) -> None:
        """Deliberate: identity follows the capture's content, not its location."""
        copy = tmp_path / "copy.pcap"
        copy.write_bytes(Path(TEST_DPI_PCAP).read_bytes())
        assert capture_digest(copy) == capture_digest(TEST_DPI_PCAP)

        here = record_from_result(incumbent, capture_path=TEST_DPI_PCAP, commit=_COMMIT)
        there = record_from_result(incumbent, capture_path=copy, commit=_COMMIT)
        assert here.run_id == there.run_id

    def test_different_bytes_are_a_different_run(
        self, tmp_path: Path, incumbent: PipelineResult
    ) -> None:
        other = tmp_path / "other.pcap"
        other.write_bytes(b"not the same capture at all")
        here = record_from_result(incumbent, capture_path=TEST_DPI_PCAP, commit=_COMMIT)
        there = record_from_result(incumbent, capture_path=other, commit=_COMMIT)
        assert here.run_id != there.run_id

    def test_declaring_a_ruleset_separates_two_otherwise_identical_runs(
        self, incumbent: PipelineResult
    ) -> None:
        """The documented caveat, made concrete.

        The id identifies an *observation*. Two rulesets producing identical output
        collapse onto one id unless the caller says which ruleset it used -- which is why
        `ruleset` exists as an explicit parameter rather than being inferred.
        """
        undeclared = record_from_result(incumbent, capture_path=TEST_DPI_PCAP, commit=_COMMIT)
        declared = record_from_result(
            incumbent, capture_path=TEST_DPI_PCAP, commit=_COMMIT, ruleset="incumbent-v3"
        )
        assert undeclared.run_id != declared.run_id


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_save_then_load_is_the_same_record(self, store: RunStore, rec_a: RunRecord) -> None:
        store.save(rec_a)
        assert store.load(rec_a.run_id) == rec_a

    def test_json_survives_a_real_encode_and_decode(self, rec_a: RunRecord) -> None:
        """`json.loads(json.dumps(x)) == x` is the property that matters.

        A `to_json` emitting tuples would pass a naive comparison and still not be JSON;
        this asserts the payload is its own re-encoding.
        """
        payload = rec_a.to_json()
        assert json.loads(json.dumps(payload)) == payload

    def test_from_json_reconstructs_an_equal_record(self, rec_a: RunRecord) -> None:
        assert RunRecord.from_json(rec_a.to_json()) == rec_a

    def test_a_record_with_events_round_trips(
        self, workdir: Path, incumbent: PipelineResult
    ) -> None:
        bus = EventBus()
        recorder = Recorder()
        bus.subscribe(recorder)
        run_pipeline(
            str(TEST_DPI_PCAP), workdir / "events.pcap", RuleManager(), bus=bus,
            with_flow_table=True,
        )
        record = record_from_result(
            incumbent, capture_path=TEST_DPI_PCAP, events=recorder.events, commit=_COMMIT
        )
        assert record.event_log
        restored = RunRecord.from_json(record.to_json())
        assert restored == record
        assert restored.event_log == record.event_log

    def test_every_stored_field_survives(self, rec_a: RunRecord) -> None:
        restored = RunRecord.from_json(rec_a.to_json())
        for field in (
            "run_id",
            "capture_path",
            "capture_sha256",
            "capture_bytes",
            "created_at",
            "commit",
            "ruleset",
            "stats",
            "app_counts",
            "detected_domains",
            "blocked_flows",
            "flows",
            "event_log",
            "events_omitted",
        ):
            assert getattr(restored, field) == getattr(rec_a, field), f"{field} did not survive"

    def test_the_stored_file_is_human_readable_json(
        self, store: RunStore, rec_a: RunRecord
    ) -> None:
        path = store.save(rec_a)
        raw = json.loads(path.read_text(encoding="utf-8"))
        assert raw["run_id"] == rec_a.run_id
        assert raw["schema"] == SCHEMA
        assert isinstance(raw["flows"], list) and raw["flows"]


# ---------------------------------------------------------------------------
# save()
# ---------------------------------------------------------------------------


class TestSave:
    def test_it_creates_its_directory(self, tmp_path: Path, rec_a: RunRecord) -> None:
        nested = RunStore(tmp_path / "a" / "b" / "runs")
        assert not nested.root.exists()
        path = nested.save(rec_a)
        assert path.exists()

    def test_resaving_the_same_run_is_idempotent_and_keeps_the_first_timestamp(
        self, store: RunStore, rec_a: RunRecord
    ) -> None:
        """Re-storing an identical observation must not rewrite when it was seen.

        `created_at` is when the run was *first* recorded; letting a re-save move it
        forward would quietly reorder the history.
        """
        first_path = store.save(rec_a)
        first_time = store.load(rec_a.run_id).created_at
        second_path = store.save(rec_a)
        assert second_path == first_path
        assert store.load(rec_a.run_id).created_at == first_time

    def test_a_different_payload_under_the_same_id_raises(
        self, store: RunStore, rec_a: RunRecord
    ) -> None:
        """Only a hash collision or a nondeterministic engine can cause this.

        Overwriting would hide either, and the caller would find out later by reading a
        record that does not match the run they thought they stored.
        """
        store.save(rec_a)
        forged = replace(rec_a, stats=replace(rec_a.stats, dropped_packets=999))
        with pytest.raises(ValueError, match="different payload"):
            store.save(forged)

    def test_it_leaves_no_temporary_file_behind(self, store: RunStore, rec_a: RunRecord) -> None:
        """Atomic publish is the point: no half-written file is ever visible as a run."""
        store.save(rec_a)
        assert list(store.root.glob("*.tmp")) == []
        assert [p.name for p in store.root.glob("*.json")] == [f"{rec_a.run_id}.json"]

    def test_saving_two_runs_yields_two_files(
        self, populated: RunStore, rec_a: RunRecord, rec_b: RunRecord
    ) -> None:
        assert len(list(populated.root.glob("*.json"))) == 2
        assert rec_a.run_id != rec_b.run_id


class TestListRuns:
    def test_an_absent_root_lists_nothing(self, store: RunStore) -> None:
        assert store.list_runs() == ()

    def test_summaries_carry_no_flows(self, populated: RunStore) -> None:
        for summary in populated.list_runs():
            assert not hasattr(summary, "flows"), (
                "a summary that looked like a record would invite indexing into flows "
                "that are not there"
            )
        assert {s.run_id for s in populated.list_runs()} == {
            p.stem for p in populated.root.glob("*.json")
        }

    def test_summaries_report_the_flow_count(self, populated: RunStore, rec_a: RunRecord) -> None:
        summary = next(s for s in populated.list_runs() if s.run_id == rec_a.run_id)
        assert summary.flow_count == len(rec_a.flows)

    def test_a_summary_serialises_to_clean_json(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        """`T3-04` hands these to an agent, so the header must survive a JSON hop.

        And the numbers must agree with the run it summarises -- a summary that reported
        a different flow count from the record it points at would send the caller to a
        `query_flows` that returns a different number of rows.
        """
        summary = next(s for s in populated.list_runs() if s.run_id == rec_a.run_id)
        payload = summary.to_json()
        assert json.loads(json.dumps(payload)) == payload
        assert payload["run_id"] == rec_a.run_id
        assert payload["flow_count"] == len(rec_a.flows)
        assert payload["total_packets"] == rec_a.stats.total_packets
        assert payload["dropped_packets"] == rec_a.stats.dropped_packets
        assert "flows" not in payload

    def test_it_raises_on_a_corrupt_file_rather_than_skipping_it(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        """A skipped file makes the store's history look tidier than it is."""
        (populated.root / f"{rec_a.run_id}.json").write_text("{ not json", encoding="utf-8")
        with pytest.raises(ValueError, match="not valid JSON"):
            populated.list_runs()


# ---------------------------------------------------------------------------
# load() guards
# ---------------------------------------------------------------------------


class TestLoadGuards:
    def test_a_missing_run_says_so(self, store: RunStore) -> None:
        store.root.mkdir(parents=True, exist_ok=True)
        with pytest.raises(FileNotFoundError, match="no run"):
            store.load("0123456789abcdef")

    @pytest.mark.parametrize(
        "bad",
        [
            pytest.param("../../etc/passwd", id="unix-traversal"),
            pytest.param("..\\..\\windows\\system32", id="windows-traversal"),
            pytest.param("..%2f..%2fetc", id="encoded-traversal"),
            pytest.param("", id="empty"),
            pytest.param("nothex", id="not-hex"),
            pytest.param("ABCDEF0123456789", id="uppercase"),
            pytest.param("0123456789abcde", id="too-short"),
            pytest.param("0123456789abcdef0", id="too-long"),
        ],
    )
    def test_a_non_id_never_reaches_the_filesystem(self, store: RunStore, bad: str) -> None:
        """The id arrives from an agent in a later tool call, so it is data, not a path.

        Without validation `load("../../etc/passwd")` reads outside the store, and
        `path_for` is reachable from every read method.
        """
        with pytest.raises(ValueError, match="not a run id"):
            store.load(bad)
        with pytest.raises(ValueError, match="not a run id"):
            store.path_for(bad)

    def test_truncated_json_raises(self, populated: RunStore, rec_a: RunRecord) -> None:
        path = populated.root / f"{rec_a.run_id}.json"
        text = path.read_text(encoding="utf-8")
        path.write_text(text[: len(text) // 2], encoding="utf-8")
        with pytest.raises(ValueError, match="not valid JSON"):
            populated.load(rec_a.run_id)

    def test_a_json_array_raises(self, populated: RunStore, rec_a: RunRecord) -> None:
        (populated.root / f"{rec_a.run_id}.json").write_text("[1, 2]", encoding="utf-8")
        with pytest.raises(ValueError, match="does not contain a JSON object"):
            populated.load(rec_a.run_id)

    def test_a_wrong_schema_raises_rather_than_guessing(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        """Old data must not be read through new field meanings."""
        path = populated.root / f"{rec_a.run_id}.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["schema"] = "dpi-run/v0"
        path.write_text(json.dumps(raw), encoding="utf-8")
        with pytest.raises(ValueError, match="dpi-run/v0"):
            populated.load(rec_a.run_id)

    def test_an_edited_payload_is_detected(self, populated: RunStore, rec_a: RunRecord) -> None:
        """The id is a content hash, so a stored id and its contents must agree.

        Editing a counter in place leaves a file that parses perfectly and reports a
        run that never happened. Trusting it would make `diff_runs` compare the wrong
        pair of runs while reporting success.
        """
        path = populated.root / f"{rec_a.run_id}.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["stats"]["dropped_packets"] = 999
        path.write_text(json.dumps(raw), encoding="utf-8")
        with pytest.raises(ValueError, match="hash to"):
            populated.load(rec_a.run_id)

    def test_a_missing_key_raises(self, populated: RunStore, rec_a: RunRecord) -> None:
        path = populated.root / f"{rec_a.run_id}.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        del raw["stats"]
        path.write_text(json.dumps(raw), encoding="utf-8")
        with pytest.raises(ValueError, match="stats"):
            populated.load(rec_a.run_id)

    def test_a_wrongly_typed_field_raises(self, populated: RunStore, rec_a: RunRecord) -> None:
        path = populated.root / f"{rec_a.run_id}.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["stats"]["dropped_packets"] = "four"
        path.write_text(json.dumps(raw), encoding="utf-8")
        with pytest.raises(ValueError, match="dropped_packets"):
            populated.load(rec_a.run_id)

    def test_a_modified_flow_row_raises(self, populated: RunStore, rec_a: RunRecord) -> None:
        path = populated.root / f"{rec_a.run_id}.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["flows"][0]["app"] = "MADE_UP"
        path.write_text(json.dumps(raw), encoding="utf-8")
        with pytest.raises(ValueError, match="hash to"):
            populated.load(rec_a.run_id)


# ---------------------------------------------------------------------------
# query() and filters
# ---------------------------------------------------------------------------


class TestQuery:
    def test_no_filter_returns_every_flow(self, populated: RunStore, rec_a: RunRecord) -> None:
        assert populated.query(rec_a.run_id) == rec_a.flows

    def test_limit_zero_means_no_limit(self, populated: RunStore, rec_a: RunRecord) -> None:
        """Following `report.render_detected_domains`'s convention rather than
        inventing a second meaning for zero."""
        assert len(populated.query(rec_a.run_id, limit=0)) == len(rec_a.flows)

    def test_limit_caps_the_result(self, populated: RunStore, rec_a: RunRecord) -> None:
        result = populated.query(rec_a.run_id, limit=3)
        assert len(result) == 3
        assert result == rec_a.flows[:3]

    def test_a_negative_limit_is_rejected(self, populated: RunStore, rec_a: RunRecord) -> None:
        with pytest.raises(ValueError, match="limit"):
            populated.query(rec_a.run_id, limit=-1)

    def test_a_filter_that_matches_nothing_is_a_legitimate_empty(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        """Distinct from an error: this is an answer about the capture."""
        assert populated.query(rec_a.run_id, filter=FlowFilter(min_bytes=10**9)) == ()

    def test_querying_does_not_change_what_is_stored(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        before = populated.load(rec_a.run_id)
        populated.query(rec_a.run_id, filter=FlowFilter(app="NETFLIX"), limit=1)
        assert populated.load(rec_a.run_id) == before


class TestFlowFilterValidation:
    @pytest.mark.parametrize("bad", ["NETFLIXX", "netfli", "GOOGLE.COM", ""])
    def test_an_unknown_app_raises_rather_than_matching_nothing(self, bad: str) -> None:
        """A typo reported as "no flows matched" reads as a fact about the capture."""
        with pytest.raises(ValueError, match="unknown app"):
            FlowFilter(app=bad)

    def test_a_known_app_is_normalised_to_upper_case(self) -> None:
        assert FlowFilter(app="Netflix").app == "NETFLIX"
        assert FlowFilter(app="netflix").app == "NETFLIX"

    @pytest.mark.parametrize("bad", ["CLASSIFED", "classified ", "nope"])
    def test_an_unknown_state_raises(self, bad: str) -> None:
        with pytest.raises(ValueError, match="unknown state"):
            FlowFilter(state=bad)

    def test_a_known_state_is_normalised(self) -> None:
        assert FlowFilter(state="classified").state == ConnectionState.CLASSIFIED.name

    @pytest.mark.parametrize("bad", ["999.1.1.1", "not-an-ip", "1.2.3", "::1"])
    def test_a_malformed_ip_raises_at_construction(self, bad: str) -> None:
        """Eagerly, so a bad address cannot be mistaken for a filter that found nothing."""
        with pytest.raises(ValueError, match="not a valid IPv4"):
            FlowFilter(ip=bad)

    def test_a_valid_ip_is_accepted(self) -> None:
        assert FlowFilter(ip="8.8.8.8").ip == "8.8.8.8"


class TestFiltering:
    def test_the_app_filter_selects_only_that_app(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        selected = populated.query(rec_a.run_id, filter=FlowFilter(app="NETFLIX"))
        assert selected
        assert all(flow.app == "NETFLIX" for flow in selected)
        assert len(selected) == sum(1 for flow in rec_a.flows if flow.app == "NETFLIX")

    def test_the_hostname_filter_is_exact_not_a_substring(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        """Pins the `D-27` decision for the query surface.

        Bare-substring matching produced confident wrong answers for classification;
        a filter an agent uses to narrow a result set is the last place to reintroduce
        it. Here a correct exact match is found, and a prefix of it is not.
        """
        host = next(flow.hostname for flow in rec_a.flows if flow.hostname)
        exact = populated.query(rec_a.run_id, filter=FlowFilter(hostname=host))
        assert len(exact) == 1 and exact[0].hostname == host

        prefix = populated.query(rec_a.run_id, filter=FlowFilter(hostname=host[:4]))
        assert prefix == (), "a partial hostname matched; the filter is not exact"

    def test_the_hostname_filter_ignores_case(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        host = next(flow.hostname for flow in rec_a.flows if flow.hostname)
        assert populated.query(
            rec_a.run_id, filter=FlowFilter(hostname=host.upper())
        ) == populated.query(rec_a.run_id, filter=FlowFilter(hostname=host.lower()))

    def test_the_ip_filter_matches_either_endpoint(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        """Matching only the source would silently hide every reply flow.

        Asserted as `flow in result` for its own source address *and* its own destination
        address: a filter that matched one side would drop the flow from the other query,
        and "fewer results" is not something a caller can notice on their own.
        """
        flow = rec_a.flows[0]
        src = ".".join(str((flow.src_ip >> s) & 0xFF) for s in (24, 16, 8, 0))
        dst = ".".join(str((flow.dst_ip >> s) & 0xFF) for s in (24, 16, 8, 0))

        by_src = populated.query(rec_a.run_id, filter=FlowFilter(ip=src))
        by_dst = populated.query(rec_a.run_id, filter=FlowFilter(ip=dst))
        assert flow in by_src, "a flow was not found by its own source address"
        assert flow in by_dst, (
            "a flow was not found by its own destination address; the filter is only "
            "looking at one endpoint"
        )

    def test_the_protocol_filter_selects_one_transport(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        for protocol in (6, 17):
            selected = populated.query(rec_a.run_id, filter=FlowFilter(protocol=protocol))
            assert all(flow.protocol == protocol for flow in selected)

    def test_the_min_bytes_filter_is_inclusive_at_the_boundary(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        flow = max(rec_a.flows, key=lambda f: f.bytes)
        assert any(
            f.bytes == flow.bytes
            for f in populated.query(rec_a.run_id, filter=FlowFilter(min_bytes=flow.bytes))
        )
        assert all(
            f.bytes >= flow.bytes
            for f in populated.query(rec_a.run_id, filter=FlowFilter(min_bytes=flow.bytes))
        )

    def test_filters_conjoin(self, populated: RunStore, rec_a: RunRecord) -> None:
        """Two constraints narrow; neither replaces the other."""
        flow = next(
            f for f in rec_a.flows if f.protocol == 6 and f.app != AppType.UNKNOWN.name
        )
        selected = populated.query(
            rec_a.run_id, filter=FlowFilter(protocol=6, app=flow.app)
        )
        assert selected
        assert all(f.protocol == 6 and f.app == flow.app for f in selected)
        assert len(selected) <= len(
            populated.query(rec_a.run_id, filter=FlowFilter(protocol=6))
        )

    def test_an_empty_filter_matches_everything(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        assert populated.query(rec_a.run_id, filter=FlowFilter()) == rec_a.flows


# ---------------------------------------------------------------------------
# get_flow_detail
# ---------------------------------------------------------------------------


class TestFlowDetail:
    def test_a_stored_five_tuple_is_found(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        flow = rec_a.flows[0]
        assert populated.flow(rec_a.run_id, flow.five_tuple) == flow

    def test_an_absent_flow_is_none_not_an_empty_row(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        assert populated.flow(rec_a.run_id, FiveTuple(1, 2, 3, 4, 6)) is None

    @pytest.mark.parametrize("index", [0, 1, 2, 3, 4])
    def test_every_component_of_the_tuple_is_part_of_the_key(
        self, populated: RunStore, rec_a: RunRecord, index: int
    ) -> None:
        """A lookup that keyed on fewer fields would return the wrong flow's data."""
        flow = rec_a.flows[0]
        parts = [flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol]
        parts[index] = parts[index] + 1
        assert populated.flow(rec_a.run_id, FiveTuple(*parts)) is None


# ---------------------------------------------------------------------------
# diff_runs
# ---------------------------------------------------------------------------


class TestDiff:
    def test_blocking_an_app_is_visible_as_a_worse_drop_rate(
        self, populated: RunStore, rec_a: RunRecord, rec_b: RunRecord
    ) -> None:
        """`T3-04`'s planned test, at the store level.

        Blocking NETFLIX must show up as more dropped packets and a higher drop rate.
        A diff that reported "no change" here would read as an improvement.
        """
        delta = populated.diff(rec_a.run_id, rec_b.run_id)
        assert delta.counter("dropped_packets").after > delta.counter("dropped_packets").before
        assert delta.drop_rate_change_percent > 0
        assert rec_b.stats.dropped_packets > rec_a.stats.dropped_packets

    def test_the_blocked_flow_is_reported_as_changed_with_its_fields(
        self, populated: RunStore, rec_a: RunRecord, rec_b: RunRecord
    ) -> None:
        delta = populated.diff(rec_a.run_id, rec_b.run_id)
        assert delta.changed, "the blocked flow did not appear in the diff"
        fields = {name for change in delta.changed for name in change.changed_fields}
        assert "action" in fields
        assert "state" in fields

    def test_a_run_diffed_against_itself_is_empty(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        delta = populated.diff(rec_a.run_id, rec_a.run_id)
        assert delta.flows_changed == 0
        assert all(counter.change == 0 for counter in delta.counters)
        assert delta.drop_rate_change_percent == pytest.approx(0.0)

    def test_the_diff_is_directional(
        self, populated: RunStore, rec_a: RunRecord, rec_b: RunRecord
    ) -> None:
        forward = populated.diff(rec_a.run_id, rec_b.run_id)
        backward = populated.diff(rec_b.run_id, rec_a.run_id)
        assert forward.counter("dropped_packets").change == -backward.counter(
            "dropped_packets"
        ).change
        assert forward.run_a == backward.run_b

    def test_every_counter_is_present(self, populated: RunStore, rec_a: RunRecord, rec_b: RunRecord) -> None:
        delta = populated.diff(rec_a.run_id, rec_b.run_id)
        assert {counter.name for counter in delta.counters} == EXPECTED_COUNTERS
        for name in EXPECTED_COUNTERS:
            assert delta.counter(name).name == name

    def test_asking_for_an_unknown_counter_names_the_ones_that_exist(
        self, populated: RunStore, rec_a: RunRecord, rec_b: RunRecord
    ) -> None:
        delta = populated.diff(rec_a.run_id, rec_b.run_id)
        with pytest.raises(KeyError, match="no counter named"):
            delta.counter("packets_seen")

    def test_it_serialises(self, populated: RunStore, rec_a: RunRecord, rec_b: RunRecord) -> None:
        payload = populated.diff(rec_a.run_id, rec_b.run_id).to_json()
        assert json.loads(json.dumps(payload)) == payload
        assert payload["flows_changed"] == len(payload["added"]) + len(payload["removed"]) + len(payload["changed"])


class TestDiffPrimitive:
    """`diff_records` directly, so added/removed can be exercised without a second capture."""

    def test_an_added_flow_appears_only_in_added(self, rec_a: RunRecord) -> None:
        extra = FlowRecord(
            src_ip=11, dst_ip=22, src_port=33, dst_port=44, protocol=6,
            app="ZOOM", state="NEW", hostname="z.example",
        )
        delta = diff_records(rec_a, replace(rec_a, flows=tuple(sorted((*rec_a.flows, extra), key=lambda f: (f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol)))))
        assert delta.added == (extra,)
        assert delta.removed == ()
        assert delta.changed == ()

    def test_a_removed_flow_appears_only_in_removed(self, rec_a: RunRecord) -> None:
        delta = diff_records(rec_a, replace(rec_a, flows=rec_a.flows[1:]))
        assert delta.removed == (rec_a.flows[0],)
        assert delta.added == ()
        assert delta.changed == ()

    def test_the_key_is_the_whole_five_tuple_not_just_the_source(
        self, rec_a: RunRecord
    ) -> None:
        """Same source address, different destination port -- two flows, not one change.

        This is the mutant catcher for a diff keyed on `src_ip` alone, which would report
        a single "changed" flow instead of one addition and one removal.
        """
        head = rec_a.flows[0]
        unused_port = max(flow.dst_port for flow in rec_a.flows) + 1
        moved = replace(head, dst_port=unused_port)
        delta = diff_records(rec_a, replace(rec_a, flows=(moved, *rec_a.flows[1:])))

        assert delta.removed == (head,)
        assert delta.added == (moved,)
        assert delta.changed == ()

    def test_a_field_change_is_reported_with_the_field_name(self, rec_a: RunRecord) -> None:
        head = rec_a.flows[0]
        edited = replace(head, bytes=head.bytes + 1234)
        delta = diff_records(rec_a, replace(rec_a, flows=(edited, *rec_a.flows[1:])))
        assert len(delta.changed) == 1
        assert delta.changed[0].changed_fields == ("bytes",)
        assert delta.changed[0].before == head
        assert delta.changed[0].after == edited

    def test_changed_fields_is_derived_and_complete(self, rec_a: RunRecord) -> None:
        head = rec_a.flows[0]
        edited = replace(head, bytes=head.bytes + 1, app="ZOOM", hostname="z.example")
        delta = diff_records(rec_a, replace(rec_a, flows=(edited, *rec_a.flows[1:])))
        assert delta.changed[0].changed_fields == ("app", "bytes", "hostname")


# ---------------------------------------------------------------------------
# The event policy
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def recorded(
    workdir: Path, incumbent: PipelineResult
) -> tuple[RunRecord, list[Event]]:
    """One run with a live event bus attached, plus the events it emitted.

    Module-scoped rather than class-scoped: pytest deprecated class-scoped fixtures
    defined as instance methods, and the run is only worth doing once.
    """
    bus = EventBus()
    recorder = Recorder()
    bus.subscribe(recorder)
    run_pipeline(
        str(TEST_DPI_PCAP), workdir / "recorded.pcap", RuleManager(), bus=bus,
        with_flow_table=True,
    )
    record = record_from_result(
        incumbent, capture_path=TEST_DPI_PCAP, events=recorder.events, commit=_COMMIT
    )
    return record, list(recorder.events)


class TestEventPolicy:
    def test_no_events_offered_means_none_not_empty(self, rec_a: RunRecord) -> None:
        """`None` distinguishes "not collected" from "the run emitted nothing"."""
        assert rec_a.event_log is None

    def test_events_offered_means_a_log_even_if_empty(
        self, incumbent: PipelineResult
    ) -> None:
        record = record_from_result(
            incumbent, capture_path=TEST_DPI_PCAP, events=[], commit=_COMMIT
        )
        assert record.event_log == ()

    def test_kept_plus_omitted_equals_offered(
        self, recorded: tuple[RunRecord, list[Event]]
    ) -> None:
        """**The documented identity.** A reader can prove the log is partial.

        Without this, `events_omitted` is a claim nothing checks, and a log that had
        quietly started dropping whole classes of event would look complete.
        """
        record, events = recorded
        assert record.event_log is not None
        kept = len(record.event_log)
        omitted = sum(count for _, count in record.events_omitted)
        assert kept + omitted == len(events)

    def test_per_packet_events_are_counted_not_stored(
        self, recorded: tuple[RunRecord, list[Event]]
    ) -> None:
        """`FlowClassified` fires once per inspected packet, so storing it is O(packets).

        Retaining it would reintroduce exactly the unbounded retention `D-01`/`D-02`
        removed, and the aggregate it contributes to is already on the record.
        """
        record, events = recorded
        omitted = dict(record.events_omitted)
        assert "PacketParsed" in omitted
        assert "FlowClassified" in omitted
        kept_kinds = {event.kind for event in record.event_log or ()}
        assert "PacketParsed" not in kept_kinds
        assert "FlowClassified" not in kept_kinds

        per_packet = sum(1 for event in events if isinstance(event, PacketParsed))
        assert omitted["PacketParsed"] == per_packet

    def test_flow_scale_events_are_kept(self, recorded: tuple[RunRecord, list[Event]]) -> None:
        record, _ = recorded
        kinds = {e.kind for e in record.event_log or ()}
        assert "FlowCreated" in kinds
        assert "CaptureOpened" in kinds
        assert "CaptureClosed" in kinds

    def test_the_sequence_numbers_keep_the_original_positions(
        self, recorded: tuple[RunRecord, list[Event]]
    ) -> None:
        """Gaps are visible rather than closed up by renumbering.

        Renumbering would make a sampled log look like a contiguous one, which is the
        same failure as reporting a partial log as complete.
        """
        record, _ = recorded
        assert record.event_log is not None
        sequences = [event.sequence for event in record.event_log]
        assert sequences == sorted(sequences)
        assert len(set(sequences)) == len(sequences)
        assert set(sequences) != set(range(len(sequences))), (
            "expected gaps: this log samples a longer stream"
        )

    def test_a_blocked_flow_event_carries_its_app_and_hostname(
        self, workdir: Path, candidate: PipelineResult
    ) -> None:
        bus = EventBus()
        recorder = Recorder()
        bus.subscribe(recorder)
        rules = RuleManager()
        rules.block_app(AppType.NETFLIX)
        run_pipeline(
            str(TEST_DPI_PCAP), workdir / "blockedevent.pcap", rules, bus=bus,
            with_flow_table=True,
        )
        record = record_from_result(
            candidate, capture_path=TEST_DPI_PCAP, events=recorder.events, commit=_COMMIT
        )
        blocked = [e for e in record.event_log or () if e.kind == "FlowBlocked"]
        assert blocked, "the blocking run emitted no FlowBlocked event to store"
        assert blocked[0].app == AppType.NETFLIX.name
        assert blocked[0].hostname

    def test_capture_opened_carries_the_linktype(
        self, recorded: tuple[RunRecord, list[Event]]
    ) -> None:
        record, _ = recorded
        opened = next(e for e in record.event_log or () if e.kind == "CaptureOpened")
        assert opened.detail.startswith("linktype=")

    def test_it_tracks_a_limit_exceeded(self) -> None:
        """The one event whose absence would hide a truncated run."""
        stored = _event_to_record(7, LimitExceeded(kind="packets", detail="hit the cap"))
        assert stored is not None
        assert stored.sequence == 7
        assert stored.kind == "LimitExceeded"
        assert stored.detail == "packets: hit the cap"

    def test_a_capture_closed_event_is_stored(self) -> None:
        stored = _event_to_record(3, CaptureClosed())
        assert stored is not None and stored.kind == "CaptureClosed"

    def test_an_unrepresentable_event_returns_none_rather_than_raising(self) -> None:
        """The safe direction: a new event type lands in `events_omitted`, not nowhere."""
        assert (
            _event_to_record(
                0, FlowClassified(FiveTuple(1, 2, 3, 4, 6), AppType.ZOOM, "z.example")
            )
            is None
        )

    def test_a_flow_blocked_event_converts_with_its_flow(self) -> None:
        stored = _event_to_record(
            5, FlowBlocked(FiveTuple(1, 2, 3, 4, 6), AppType.NETFLIX, "n.example")
        )
        assert stored is not None
        assert stored.five_tuple == FiveTuple(1, 2, 3, 4, 6)
        assert stored.app == "NETFLIX"
        assert stored.hostname == "n.example"


# ---------------------------------------------------------------------------
# capture_digest
# ---------------------------------------------------------------------------


class TestCaptureDigest:
    def test_it_reports_the_size_and_a_stable_hash(self, tmp_path: Path) -> None:
        blob = tmp_path / "blob.bin"
        blob.write_bytes(b"x" * 5000)
        digest, size = capture_digest(blob)
        assert size == 5000
        assert digest == capture_digest(blob)[0]
        assert len(digest) == 32

    def test_different_content_gives_a_different_digest(self, tmp_path: Path) -> None:
        first, second = tmp_path / "a.bin", tmp_path / "b.bin"
        first.write_bytes(b"a" * 100)
        second.write_bytes(b"b" * 100)
        assert capture_digest(first)[0] != capture_digest(second)[0]

    def test_it_reads_across_chunk_boundaries(self, tmp_path: Path) -> None:
        """Content is hashed in 1 MiB chunks, so the joins must not lose bytes."""
        blob = tmp_path / "big.bin"
        payload = bytes(range(256)) * (4096 * 3 + 17)  # > 3 MiB, ragged tail
        blob.write_bytes(payload)
        digest, size = capture_digest(blob)
        assert size == len(payload)
        assert digest == hashlib.sha256(payload).hexdigest()[:32]

    def test_an_empty_file_is_hashable(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.bin"
        empty.write_bytes(b"")
        digest, size = capture_digest(empty)
        assert size == 0 and len(digest) == 32


# ---------------------------------------------------------------------------
# Type-level properties the store relies on
# ---------------------------------------------------------------------------


class TestStoredTypesAreImmutable:
    @pytest.mark.parametrize(
        "record_type", [RunStats, RunRecord, BlockedFlow, FlowFilter]
    )
    def test_records_are_frozen(self, record_type: type) -> None:
        """A stored answer must not be mutable after the fact."""
        assert dataclasses.is_dataclass(record_type)
        assert record_type.__dataclass_params__.frozen is True

    def test_two_identical_records_are_equal(self, rec_a: RunRecord) -> None:
        assert replace(rec_a) == rec_a
        assert replace(rec_a).computed_run_id() == rec_a.computed_run_id()

    def test_a_differing_record_is_not_equal(self, rec_a: RunRecord) -> None:
        assert replace(rec_a, commit="other") != rec_a


class TestFilterEdgeCases:
    """The `matches` branches the happy-path selections never reach.

    Grouped here rather than folded into `TestFiltering`: each one is a filter returning
    `False` (`state`, `action`) or the `action` filter's normalisation, and a filter that
    silently stopped rejecting is indistinguishable from a filter that found nothing.
    """

    def test_the_state_filter_selects_only_that_state(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        state = rec_a.flows[0].state
        selected = populated.query(rec_a.run_id, filter=FlowFilter(state=state))
        assert selected
        assert len(selected) == sum(1 for flow in rec_a.flows if flow.state == state)
        assert all(flow.state == state for flow in selected)

    def test_a_known_state_that_no_flow_has_is_a_legitimate_empty(
        self, populated: RunStore, rec_a: RunRecord, rec_b: RunRecord
    ) -> None:
        """A validated name is not a promise of a match, so an empty answer is correct.

        The state is taken from the run that *did* block, so the test proves the two runs
        really differ in this field rather than assuming it.
        """
        blocked_state = next(flow.state for flow in rec_b.flows if flow.action == "DROP")
        assert all(flow.state != blocked_state for flow in rec_a.flows)
        assert populated.query(rec_a.run_id, filter=FlowFilter(state=blocked_state)) == ()

    def test_the_action_filter_normalises_case(self) -> None:
        assert FlowFilter(action="forward").action == "FORWARD"
        assert FlowFilter(action="DrOp").action == "DROP"

    def test_the_action_filter_selects_the_blocked_flow(
        self, populated: RunStore, rec_b: RunRecord
    ) -> None:
        """`action` is how a caller separates a policy block from ordinary traffic."""
        dropped = populated.query(rec_b.run_id, filter=FlowFilter(action="drop"))
        assert dropped
        assert all(flow.action == "DROP" for flow in dropped)

    def test_the_action_filter_matches_nothing_in_a_permissive_run(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        assert populated.query(rec_a.run_id, filter=FlowFilter(action="DROP")) == ()


class TestCounterDirection:
    """`increased`/`decreased` are what a caller reads to decide which run was worse."""

    @pytest.mark.parametrize(
        ("before", "after", "increased", "decreased"),
        [
            pytest.param(3, 5, True, False, id="up"),
            pytest.param(5, 3, False, True, id="down"),
            pytest.param(4, 4, False, False, id="flat"),
        ],
    )
    def test_direction(
        self, before: int, after: int, increased: bool, decreased: bool
    ) -> None:
        delta = CounterDelta("dropped_packets", before, after)
        assert delta.increased is increased
        assert delta.decreased is decreased
        assert delta.change == after - before

    def test_the_blocked_run_reads_as_an_increase_in_drops(
        self, populated: RunStore, rec_a: RunRecord, rec_b: RunRecord
    ) -> None:
        delta = populated.diff(rec_a.run_id, rec_b.run_id).counter("dropped_packets")
        assert delta.increased and not delta.decreased


class TestMalformedShapeGuards:
    """A record that *parses* but has the wrong shape must still fail, and say where.

    `json.loads` accepts every input below, so the decoders are the only thing between an
    agent and a `query_flows` that answered out of a field it misread. Each case asserts
    the message names the offending field: "invalid record" with no field is a debugging
    session, not a diagnosis, and an agent cannot act on it.

    Lists are replaced rather than appended to, so the index in the expected message is
    the index in the file rather than one that depends on how many entries the run had.
    """

    @staticmethod
    def _mutate(store: RunStore, run_id: str, mutate: Callable[[dict[str, Any]], None]) -> None:
        path = store.root / f"{run_id}.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        mutate(raw)
        path.write_text(json.dumps(raw), encoding="utf-8")

    @pytest.mark.parametrize(
        ("mutate", "expected"),
        [
            pytest.param(
                lambda r: r.__setitem__("stats", []),
                "stats must be an object",
                id="stats-not-an-object",
            ),
            pytest.param(
                lambda r: r.__setitem__("run_id", 5),
                "run_id must be a string",
                id="string-field-is-an-int",
            ),
            pytest.param(
                lambda r: r["stats"].__setitem__("total_connections_seen", "many"),
                "total_connections_seen must be an integer or null",
                id="nullable-int-is-a-string",
            ),
            pytest.param(
                lambda r: r.__setitem__("blocked_flows", "none"),
                "blocked_flows must be a list",
                id="list-field-is-a-string",
            ),
            pytest.param(
                lambda r: r.__setitem__("blocked_flows", ["not an object"]),
                "blocked_flows[0] must be an object",
                id="list-entry-is-not-an-object",
            ),
            pytest.param(
                lambda r: r.__setitem__("event_log", "not a list"),
                "event_log must be a list",
                id="event-log-is-not-a-list",
            ),
            # Caught a real hole: `_list_from` checked the container but not its
            # elements, so this fell through to `RunEvent.from_json` and raised
            # `AttributeError` on `.get` -- an exception type `load` does not translate.
            pytest.param(
                lambda r: r.__setitem__("event_log", ["not an object"]),
                "event_log[0] must be an object",
                id="event-log-entry-is-not-an-object",
            ),
            pytest.param(
                lambda r: r.__setitem__(
                    "event_log",
                    [
                        {
                            "sequence": 0,
                            "kind": "FlowCreated",
                            "five_tuple": [1, 2, 3],
                            "app": "",
                            "hostname": "",
                            "detail": "",
                        }
                    ],
                ),
                "five_tuple must be a 5-element list",
                id="five-tuple-too-short",
            ),
            pytest.param(
                lambda r: r.__setitem__("app_counts", "GOOGLE"),
                "app_counts must be a list",
                id="pairs-not-a-list",
            ),
            pytest.param(
                lambda r: r.__setitem__("app_counts", [["GOOGLE", 1, 2]]),
                "app_counts[0] must be a 2-element list",
                id="app-count-pair-too-long",
            ),
            pytest.param(
                lambda r: r.__setitem__("app_counts", [[7, 1]]),
                "app_counts[0] must be [str, int]",
                id="app-count-name-not-a-string",
            ),
            pytest.param(
                lambda r: r.__setitem__("detected_domains", [["example.com"]]),
                "detected_domains[0] must be a 2-element list",
                id="domain-pair-too-short",
            ),
            pytest.param(
                lambda r: r.__setitem__("detected_domains", [[1, 2]]),
                "detected_domains[0] must be [str, str]",
                id="domain-pair-not-strings",
            ),
        ],
    )
    def test_a_wrong_shape_names_the_field(
        self,
        populated: RunStore,
        rec_a: RunRecord,
        mutate: Callable[[dict[str, Any]], None],
        expected: str,
    ) -> None:
        self._mutate(populated, rec_a.run_id, mutate)
        with pytest.raises(ValueError, match=re.escape(expected)):
            populated.load(rec_a.run_id)

    def test_a_well_formed_event_log_still_loads(
        self, populated: RunStore, rec_a: RunRecord
    ) -> None:
        """The shape check must not have narrowed the format it is there to protect."""
        entry = {
            "sequence": 4,
            "kind": "FlowBlocked",
            "five_tuple": [1, 2, 3, 4, 6],
            "app": "NETFLIX",
            "hostname": "n.example",
            "detail": "",
        }
        self._mutate(populated, rec_a.run_id, lambda r: r.__setitem__("event_log", [entry]))
        stored = populated.load(rec_a.run_id).event_log
        assert stored is not None and len(stored) == 1
        assert stored[0].five_tuple == FiveTuple(1, 2, 3, 4, 6)
        assert stored[0].app == "NETFLIX"

    @pytest.mark.parametrize(
        "field",
        ["run_id", "capture_path", "created_at", "commit", "ruleset"],
    )
    def test_every_string_field_is_checked(
        self, populated: RunStore, rec_a: RunRecord, field: str
    ) -> None:
        """A field that skipped its decode would be read as whatever JSON happened to hold."""
        self._mutate(populated, rec_a.run_id, lambda r: r.__setitem__(field, 5))
        with pytest.raises(ValueError, match=re.escape(f"{field} must be a string")):
            populated.load(rec_a.run_id)
