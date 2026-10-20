"""`T3-04` -- the three run-store tools (`query_flows`, `get_flow_detail`, `diff_runs`).

**What this file is protecting.** These tools are the only way an agent can read a
stored run, and every one of them can answer a *wrong* question convincingly. Four
failure shapes, one class of test each:

1. **A filter that quietly matches nothing.** `app="NETFLX"` must not come back as
   "no flows matched": that reads as a fact about the capture when it is a typo in the
   query. `FlowFilter` already raises (`T3-02`), and the tool layer must not swallow
   it on the way to the agent.
2. **A capped result that looks complete.** `limit=2` against a 27-flow run must say
   so. `matched` and `returned` are the two numbers that make truncation checkable --
   the same argument `T3-02` made for `events_omitted`, one layer up.
3. **A negative answer and a broken question arriving the same way.**
   `{"found": False}` is what a *well-formed* five-tuple the run never saw gets.
   `ToolInputError` is what a five-tuple that is not one gets. If both were `None`, an
   agent could not tell "I asked for the wrong thing" from "the answer is no", so it
   would retry the query instead of fixing it.
4. **A diff that hides a regression.** `T2-04`'s lesson was that a gate which hides a
   failure reads as an improvement. The last class compares a permissive run with one
   that blocks NETFLIX and insists on the *sign*, not merely that some diff exists.

The filter tests are behavioural rather than structural: each is a question the tool
is supposed to answer, so ignoring a filter argument, or matching a hostname by
substring (`D-27`, the reason `FlowFilter` is exact), fails a test that reads like the
question it broke.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from conftest import TEST_DPI_PCAP
from dpi_engine.pipeline import PipelineResult, run_pipeline
from dpi_engine.rule_manager import RuleManager
from dpi_engine.types import AppType, FiveTuple
from dpi_mcp.run_store import RunRecord, RunStore, record_from_result
from dpi_mcp.tools import diff_runs, get_flow_detail, query_flows
from dpi_mcp.tools.errors import ToolInputError

_COMMIT = "testcommit"

#: The top-level keys each tool promises. Pinned rather than derived, so that adding
#: or dropping one is a deliberate act with a failing test attached -- the same
#: treatment `CaptureProfile`'s key set got in `T3-03`.
QUERY_KEYS = {"run_id", "matched", "returned", "flows"}
DETAIL_KEYS = {"run_id", "found", "flow"}

#: The fields of a flow row, which is what an agent actually reads and what
#: `get_flow_detail` accepts. The five-tuple fields come first (`flow_to_json`'s order),
#: because they are the ones a caller passes back in. Pinned for the same reason: the
#: codec is public now, and a renamed field would otherwise only be noticed by a client.
FLOW_KEYS = {
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "app",
    "state",
    "hostname",
    "packets",
    "bytes",
    "action",
}


# ---------------------------------------------------------------------------
# Fixtures: a store built from two real runs over the shared capture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def workdir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("runstore_tools")


@pytest.fixture(scope="module")
def permissive(workdir: Path) -> PipelineResult:
    """The capture under the default ruleset -- nothing dropped."""
    return run_pipeline(
        str(TEST_DPI_PCAP), workdir / "permissive.pcap", RuleManager(), with_flow_table=True
    )


@pytest.fixture(scope="module")
def stricter(workdir: Path) -> PipelineResult:
    """The same capture with NETFLIX blocked -- one packet fewer forwarded."""
    rules = RuleManager()
    rules.block_app(AppType.NETFLIX)
    return run_pipeline(
        str(TEST_DPI_PCAP), workdir / "stricter.pcap", rules, with_flow_table=True
    )


@pytest.fixture(scope="module")
def rec_a(permissive: PipelineResult) -> RunRecord:
    return record_from_result(permissive, capture_path=TEST_DPI_PCAP, commit=_COMMIT)


@pytest.fixture(scope="module")
def rec_b(stricter: PipelineResult) -> RunRecord:
    return record_from_result(stricter, capture_path=TEST_DPI_PCAP, commit=_COMMIT)


@pytest.fixture
def root(tmp_path: Path, rec_a: RunRecord, rec_b: RunRecord) -> Path:
    """A populated store root -- the path an operator would configure once."""
    store = RunStore(tmp_path / "runs")
    store.save(rec_a)
    store.save(rec_b)
    return store.root


@pytest.fixture
def row(rec_a: RunRecord) -> dict[str, Any]:
    """One stored row's five fields: the input `get_flow_detail` accepts."""
    flow = rec_a.flows[0]
    return {
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
    }


# ---------------------------------------------------------------------------
# query_flows: the filter is the question
# ---------------------------------------------------------------------------


class TestQueryFlowsSelects:
    def test_no_filter_returns_every_stored_flow(
        self, root: Path, rec_a: RunRecord
    ) -> None:
        result = query_flows(rec_a.run_id, store_root=root)
        assert set(result) == QUERY_KEYS
        assert result["matched"] == len(rec_a.flows)
        assert result["returned"] == len(rec_a.flows)
        assert len(result["flows"]) == len(rec_a.flows)
        assert result["flows"], "the fixture stored no flows; nothing below is exercised"
        assert all(set(row) == FLOW_KEYS for row in result["flows"])
        assert list(result["flows"][0])[:5] == [
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
        ], "a five-tuple is no longer the first five fields of a row"

    def test_app_filter_selects_only_that_app(self, root: Path, rec_a: RunRecord) -> None:
        expected = [flow for flow in rec_a.flows if flow.app == "TWITTER"]
        assert len(expected) == 2, "fixture no longer has two TWITTER flows"

        result = query_flows(rec_a.run_id, store_root=root, app="TWITTER")

        assert result["matched"] == len(expected)
        assert [row["hostname"] for row in result["flows"]] == [
            flow.hostname for flow in expected
        ]

    def test_app_filter_is_case_insensitive(self, root: Path, rec_a: RunRecord) -> None:
        """`FlowFilter` normalises to upper case. A tool that re-implemented the
        comparison with `==` would answer "no flows" for a lower-case app name."""
        lower = query_flows(rec_a.run_id, store_root=root, app="twitter")
        upper = query_flows(rec_a.run_id, store_root=root, app="TWITTER")
        assert lower["matched"] == upper["matched"] > 0

    def test_state_filter_selects_and_normalises_case(
        self, root: Path, rec_a: RunRecord
    ) -> None:
        """Every stored flow is CLASSIFIED, so a matching count alone cannot show the
        argument arrived. `BLOCKED` is a valid state no stored flow has: a tool that
        dropped the argument would answer 27 to both queries."""
        stored = query_flows(rec_a.run_id, store_root=root, state="classified")
        assert stored["matched"] == len(rec_a.flows)

        absent = query_flows(rec_a.run_id, store_root=root, state="BLOCKED")
        assert absent == {
            "run_id": rec_a.run_id,
            "matched": 0,
            "returned": 0,
            "flows": [],
        }

    def test_action_filter_selects(self, root: Path, rec_a: RunRecord) -> None:
        """`action` is how an agent asks "what was denied?". The fixture forwards
        everything, so the negative query is what shows it is applied rather than
        accepted and dropped. Lower case also exercises the filter's normalisation."""
        forwarded = query_flows(rec_a.run_id, store_root=root, action="forward")
        assert forwarded["matched"] == len(rec_a.flows)

        denied = query_flows(rec_a.run_id, store_root=root, action="BLOCK")
        assert denied["matched"] == 0

    def test_hostname_is_exact_not_a_substring(
        self, root: Path, rec_a: RunRecord
    ) -> None:
        """**The `D-27` trap, one layer up.** `api.twitter.com` and `twitter.com` are
        both stored. A substring filter answers `twitter.com` with two rows; the exact
        filter answers with the one flow that reported that hostname."""
        hosts = {flow.hostname for flow in rec_a.flows}
        assert {"api.twitter.com", "twitter.com"} <= hosts, "fixture lost the pair"

        exact = query_flows(rec_a.run_id, store_root=root, hostname="twitter.com")
        assert [row["hostname"] for row in exact["flows"]] == ["twitter.com"]

        prefix = query_flows(rec_a.run_id, store_root=root, hostname="twitter")
        assert prefix["matched"] == 0, (
            "a partial hostname matched; the filter is substring-based and would report "
            "a confident wrong answer for any prefix an agent guessed"
        )

    def test_ip_filter_matches_either_endpoint(
        self, root: Path, rec_a: RunRecord
    ) -> None:
        """`DEC-06`: an IP rule matches either endpoint, so the filter must too.

        Both addresses of one stored flow are used, as `T3-02`'s store test does. The
        fixture's rows are folded, so 8.8.8.8 only ever appears as `src_ip`; a
        source-only tool would answer the destination query with nothing and a
        count-only assertion on 8.8.8.8 would never notice.
        """
        flow = rec_a.flows[0]
        src = ".".join(str((flow.src_ip >> shift) & 0xFF) for shift in (24, 16, 8, 0))
        dst = ".".join(str((flow.dst_ip >> shift) & 0xFF) for shift in (24, 16, 8, 0))
        assert src != dst

        first_row = dataclasses.asdict(flow)

        by_src = query_flows(rec_a.run_id, store_root=root, ip=src)
        by_dst = query_flows(rec_a.run_id, store_root=root, ip=dst)

        assert first_row in by_src["flows"], "a flow was not found by its own source address"
        assert first_row in by_dst["flows"], (
            "a flow was not found by its own destination address; the tool is looking at "
            "one endpoint"
        )
        assert by_src["matched"] < by_dst["matched"], (
            "both queries selected everything, so this proves nothing about the filter"
        )

    def test_protocol_filter(self, root: Path, rec_a: RunRecord) -> None:
        expected = [flow for flow in rec_a.flows if flow.protocol == 17]
        assert len(expected) == 4, "fixture no longer has four UDP flows"

        result = query_flows(rec_a.run_id, store_root=root, protocol=17)

        assert result["matched"] == len(expected)
        assert {row["protocol"] for row in result["flows"]} == {17}

    def test_min_bytes_threshold(self, root: Path, rec_a: RunRecord) -> None:
        """A threshold selects on stored bytes, and a threshold nothing clears is a
        legitimate empty answer rather than an error."""
        nonzero = [flow for flow in rec_a.flows if flow.bytes > 0]
        assert 0 < len(nonzero) < len(rec_a.flows), (
            "fixture needs both zero-byte and non-zero rows for this to discriminate"
        )

        some = query_flows(rec_a.run_id, store_root=root, min_bytes=1)
        assert some["matched"] == len(nonzero)

        none = query_flows(rec_a.run_id, store_root=root, min_bytes=100)
        assert none == {
            "run_id": rec_a.run_id,
            "matched": 0,
            "returned": 0,
            "flows": [],
        }

    def test_filters_conjoin(self, root: Path, rec_a: RunRecord) -> None:
        """Each half alone matches two or sixteen rows; together they must match the
        intersection. A tool that used the last argument to win would pass every test
        above and fail this one."""
        assert query_flows(rec_a.run_id, store_root=root, app="TWITTER")["matched"] == 2
        assert query_flows(rec_a.run_id, store_root=root, min_bytes=1)["matched"] == 16

        both = query_flows(rec_a.run_id, store_root=root, app="TWITTER", min_bytes=1)
        assert both["matched"] == 1
        assert both["flows"][0]["app"] == "TWITTER"
        assert both["flows"][0]["bytes"] >= 1


class TestQueryFlowsErrors:
    def test_unknown_app_is_an_error_not_an_empty_result(
        self, root: Path, rec_a: RunRecord
    ) -> None:
        """The most important test in this class: a typo must not read as a fact about
        the capture. `FlowFilter` raises; the tool must let it through unchanged."""
        with pytest.raises(ValueError, match="NETFLX"):
            query_flows(rec_a.run_id, store_root=root, app="NETFLX")

    def test_malformed_ip_is_an_error(self, root: Path, rec_a: RunRecord) -> None:
        with pytest.raises(ValueError, match="not a valid IPv4"):
            query_flows(rec_a.run_id, store_root=root, ip="8.8.8")

    def test_unknown_state_is_an_error(self, root: Path, rec_a: RunRecord) -> None:
        with pytest.raises(ValueError, match="CLASSIFED"):
            query_flows(rec_a.run_id, store_root=root, state="CLASSIFED")

    def test_negative_limit_is_an_error(self, root: Path, rec_a: RunRecord) -> None:
        with pytest.raises(ValueError, match="limit must be >= 0"):
            query_flows(rec_a.run_id, store_root=root, limit=-1)

    def test_missing_run_is_an_error_not_an_empty_result(self, root: Path) -> None:
        """A run id that is not in the store is a broken reference. Answering it with
        zero flows would report a run that never ran as a run that saw nothing."""
        with pytest.raises(FileNotFoundError, match="list_runs"):
            query_flows("0" * 16, store_root=root)

    def test_a_path_is_not_a_run_id(self, root: Path) -> None:
        """Run ids arrive from an agent, so they are data, not path components."""
        with pytest.raises(ValueError, match="not a run id"):
            query_flows("../../etc/passwd", store_root=root)


class TestQueryFlowsTruncation:
    def test_limit_caps_the_rows_and_reports_the_total(
        self, root: Path, rec_a: RunRecord
    ) -> None:
        """**The silent-truncation trap.** Two rows out of 27 is a partial answer; the
        caller must be able to see that it is partial without asking again."""
        result = query_flows(rec_a.run_id, store_root=root, limit=2)
        assert result["returned"] == 2
        assert len(result["flows"]) == 2
        assert result["matched"] == len(rec_a.flows)
        assert result["matched"] > result["returned"]

    def test_zero_means_no_cap(self, root: Path, rec_a: RunRecord) -> None:
        result = query_flows(rec_a.run_id, store_root=root, limit=0)
        assert result["returned"] == result["matched"] == len(rec_a.flows)

    def test_a_limit_above_the_total_is_not_a_truncation(
        self, root: Path, rec_a: RunRecord
    ) -> None:
        result = query_flows(rec_a.run_id, store_root=root, limit=10_000)
        assert result["returned"] == result["matched"] == len(rec_a.flows)

    def test_matched_counts_the_filtered_set_not_the_run(
        self, root: Path, rec_a: RunRecord
    ) -> None:
        result = query_flows(rec_a.run_id, store_root=root, app="TWITTER", limit=1)
        assert result["matched"] == 2
        assert result["returned"] == 1


# ---------------------------------------------------------------------------
# get_flow_detail: an answer, or a refusal to accept the question
# ---------------------------------------------------------------------------


class TestGetFlowDetail:
    def test_a_row_from_query_flows_round_trips(
        self, root: Path, rec_a: RunRecord
    ) -> None:
        """The tool must accept its own output. An agent reads a row with
        `query_flows` and asks about it with `get_flow_detail`; if the row carries keys
        the second tool rejects, every agent has to learn the projection by trial."""
        listed = query_flows(rec_a.run_id, store_root=root, limit=1)
        detail = get_flow_detail(rec_a.run_id, listed["flows"][0], store_root=root)

        assert set(detail) == DETAIL_KEYS
        assert detail["found"] is True
        assert detail["flow"] == listed["flows"][0]

    def test_extra_keys_are_ignored(self, root: Path, rec_a: RunRecord, row: dict[str, Any]) -> None:
        """A minimal five-tuple and a full stored row must answer the same question.
        The row from `query_flows` carries `app`, `hostname` and the rest; refusing the
        superset would make the round trip above fail for the wrong reason."""
        bare = get_flow_detail(rec_a.run_id, row, store_root=root)
        noisy = get_flow_detail(
            rec_a.run_id,
            {**dataclasses.asdict(rec_a.flows[0]), "unexpected": "ignored"},
            store_root=root,
        )
        assert noisy["found"] is True
        assert noisy["flow"] == bare["flow"]

    def test_an_absent_flow_is_a_result_with_found_false(
        self, root: Path, rec_a: RunRecord, row: dict[str, Any]
    ) -> None:
        """A well-formed question the run answers "no" to is a **result**. It must be
        distinguishable from a malformed question, which raises."""
        unseen = FiveTuple(
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
            protocol=row["protocol"],
        ).reverse()
        assert all(
            (flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, flow.protocol)
            != tuple(unseen)
            for flow in rec_a.flows
        ), "the reversed tuple is stored; this fixture exercises the wrong path"

        detail = get_flow_detail(rec_a.run_id, unseen._asdict(), store_root=root)

        assert detail == {"run_id": rec_a.run_id, "found": False, "flow": None}

    def test_a_missing_run_is_an_error(self, root: Path, row: dict[str, Any]) -> None:
        with pytest.raises(FileNotFoundError, match="list_runs"):
            get_flow_detail("0" * 16, row, store_root=root)

    @pytest.mark.parametrize(
        ("change", "match"),
        [
            ({"src_ip": "134744072"}, "src_ip"),
            ({"src_port": True}, "src_port"),
            ({"src_ip": -1}, "src_ip"),
            ({"src_ip": 2**32}, "src_ip"),
            ({"dst_port": 70_000}, "dst_port"),
            ({"protocol": 300}, "protocol"),
            ({"dst_ip": 1.5}, "dst_ip"),
        ],
    )
    def test_a_malformed_field_is_an_error(
        self, root: Path, rec_a: RunRecord, row: dict[str, Any], change: dict[str, Any], match: str
    ) -> None:
        """A typo must not become `found: False`. `True` is in this list because
        `isinstance(True, int)` is `True`, so a naive integer check accepts a boolean
        as a port number and reports the flow as absent."""
        with pytest.raises(ToolInputError, match=match):
            get_flow_detail(rec_a.run_id, {**row, **change}, store_root=root)

    @pytest.mark.parametrize("missing", ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"])
    def test_a_missing_field_is_an_error(
        self, root: Path, rec_a: RunRecord, row: dict[str, Any], missing: str
    ) -> None:
        incomplete = {key: value for key, value in row.items() if key != missing}
        with pytest.raises(ToolInputError, match=missing):
            get_flow_detail(rec_a.run_id, incomplete, store_root=root)

    @pytest.mark.parametrize(
        "value",
        [
            None,
            [1, 2, 3, 4, 6],
            "8.8.8.8:53",
            tuple(FiveTuple(1, 2, 3, 4, 6)),
        ],
        ids=["none", "list", "str", "five_tuple_sequence"],
    )
    def test_a_non_mapping_is_an_error(
        self, root: Path, rec_a: RunRecord, value: Any
    ) -> None:
        """Five-tuples travel as JSON objects. A bare sequence is refused rather than
        guessed at, because the field order is not something an agent should recall."""
        with pytest.raises(ToolInputError, match="object"):
            get_flow_detail(rec_a.run_id, value, store_root=root)


# ---------------------------------------------------------------------------
# diff_runs: a worse run must read as worse
# ---------------------------------------------------------------------------


class TestDiffRuns:
    def test_a_worse_run_shows_as_worse(
        self, root: Path, rec_a: RunRecord, rec_b: RunRecord
    ) -> None:
        """**The regression gate.** The stricter run drops a packet the permissive one
        forwarded. `T2-04`'s lesson was that a gate which hides a failure reads as an
        improvement, so the assertion is on direction and magnitude, not existence."""
        diff = diff_runs(rec_a.run_id, rec_b.run_id, store_root=root)

        assert diff["run_a"] == rec_a.run_id
        assert diff["run_b"] == rec_b.run_id
        assert diff["drop_rate_change_percent"] > 0, (
            "blocking an app increased drops but the diff does not show it"
        )

        counters = {entry["name"]: entry for entry in diff["counters"]}
        assert counters["dropped_packets"]["change"] == 1
        assert counters["forwarded_packets"]["change"] == -1
        assert diff["flows_changed"] == 1

    def test_the_direction_of_a_diff_is_the_argument_order(
        self, root: Path, rec_a: RunRecord, rec_b: RunRecord
    ) -> None:
        """The same pair reversed must report the opposite sign. A diff that took the
        magnitude, or sorted its arguments, would call a regression a recovery."""
        forwards = diff_runs(rec_a.run_id, rec_b.run_id, store_root=root)
        backwards = diff_runs(rec_b.run_id, rec_a.run_id, store_root=root)

        assert forwards["drop_rate_change_percent"] == -backwards["drop_rate_change_percent"]
        assert forwards["drop_rate_change_percent"] > 0 > backwards["drop_rate_change_percent"]

    def test_a_run_against_itself_shows_no_movement(
        self, root: Path, rec_a: RunRecord
    ) -> None:
        diff = diff_runs(rec_a.run_id, rec_a.run_id, store_root=root)
        assert diff["flows_changed"] == 0
        assert diff["drop_rate_change_percent"] == 0.0
        assert {entry["change"] for entry in diff["counters"]} == {0}

    def test_a_missing_run_is_an_error(self, root: Path, rec_a: RunRecord) -> None:
        with pytest.raises(FileNotFoundError, match="list_runs"):
            diff_runs(rec_a.run_id, "0" * 16, store_root=root)

    def test_flow_rows_are_the_same_shape_query_flows_emits(
        self, root: Path, rec_a: RunRecord, rec_b: RunRecord
    ) -> None:
        """`diff["added"]`, `["removed"]` and `["changed"][*]["before"]` must be rows an
        agent can feed straight back into `get_flow_detail` -- one wire format, one
        codec, not a second projection that drifts."""
        listed = set(query_flows(rec_a.run_id, store_root=root)["flows"][0])
        diff = diff_runs(rec_b.run_id, rec_a.run_id, store_root=root)

        for row in diff["added"]:
            assert set(row) == listed
        for change in diff["changed"]:
            assert set(change["before"]) == listed
            assert set(change["after"]) == listed


# ---------------------------------------------------------------------------
# The surface itself
# ---------------------------------------------------------------------------


class TestSurface:
    def test_every_result_survives_json_serialisation(
        self, root: Path, rec_a: RunRecord, rec_b: RunRecord, row: dict[str, Any]
    ) -> None:
        """The MCP transport serialises these, not the tests. A result holding a
        dataclass or a `FiveTuple` would fail at protocol time on a live server and
        nowhere else, so the round trip is asserted here."""
        results = [
            query_flows(rec_a.run_id, store_root=root),
            get_flow_detail(rec_a.run_id, row, store_root=root),
            diff_runs(rec_a.run_id, rec_b.run_id, store_root=root),
        ]
        for result in results:
            assert json.loads(json.dumps(result)) == result

    def test_the_tools_are_exported(self) -> None:
        import dpi_mcp.tools as tools

        assert {"query_flows", "get_flow_detail", "diff_runs"} <= set(tools.__all__)

    def test_reading_a_run_does_not_write_to_the_store(
        self, root: Path, rec_a: RunRecord, rec_b: RunRecord, row: dict[str, Any]
    ) -> None:
        """A query tool that cached, or re-saved a record, would change the directory an
        operator is inspecting. Reading is reading."""
        before = sorted((path.name, path.stat().st_mtime_ns) for path in root.iterdir())
        query_flows(rec_a.run_id, store_root=root)
        get_flow_detail(rec_a.run_id, row, store_root=root)
        diff_runs(rec_a.run_id, rec_b.run_id, store_root=root)
        after = sorted((path.name, path.stat().st_mtime_ns) for path in root.iterdir())
        assert after == before
