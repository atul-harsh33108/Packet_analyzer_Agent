"""The verdict evaluation (`T4-05`).

**The expectation is derived**, so the tests are about the *scorer*, not about a
number that was written down once. And the criterion has two sides: a verdict
that matches, **and** a case that must not be flagged not being flagged.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from agent_harness import connected, store_a_run, tool_schemas
from dpi_agents.model import ModelReply, ScriptedModel, ToolCall
from dpi_agents.nodes.triage import TRIAGE_TOOL_NAMES, triage_node
from dpi_agents.runtime import Agent
from dpi_agents.schemas import TriageVerdict
from dpi_agents.tools import McpToolPort
from dpi_agents.trace import Trace
from dpi_engine.types import FiveTuple
from dpi_mcp.run_store import RunStore
from eval.verdicts import (
    SEVERITY_BY_CLASS,
    expected_verdict,
    score_verdict,
    trace_covers_verdict,
)
from golden.corpus import ALL_CLASSES, GoldenCase, GoldenClass, iter_cases, materialise


def _case(golden_class: str, hostname: str = "host.example.com") -> GoldenCase:
    """A case of one class, with one host."""
    from golden.corpus import ExpectedFlow

    return GoldenCase(
        name=f"{golden_class}_case",
        golden_class=golden_class,
        description="a case for the evaluation",
        expected=(ExpectedFlow(hostname=hostname, app=_app_for(golden_class)),),
    )


def _app_for(golden_class: str) -> Any:
    from dpi_engine.types import AppType

    if golden_class == GoldenClass.LEGITIMATE_ENTERPRISE:
        return AppType.GOOGLE
    if golden_class == GoldenClass.AD_TRAFFIC:
        return AppType.ADS
    return AppType.UNKNOWN


def _rows(hostname: str) -> list[Any]:
    """One flow row, as the store's own type.

    Built through the store's decoder, so the row is the store's row and not a
    copy of one.
    """
    from dpi_mcp.run_store import flow_from_json

    return [
        flow_from_json(
            {
                "src_ip": 1,
                "dst_ip": 2,
                "src_port": 3,
                "dst_port": 4,
                "protocol": 6,
                "app": "UNKNOWN",
                "state": "ESTABLISHED",
                "hostname": hostname,
                "packets": 4,
                "bytes": 400,
                "action": "FORWARD",
            }
        )
    ]


def _verdict(
    severity: str = "high",
    categories: tuple[str, ...] = (GoldenClass.C2_BEACONING,),
    flows: tuple[FiveTuple, ...] = (FiveTuple(1, 2, 3, 4, 6),),
) -> TriageVerdict:
    return TriageVerdict(
        severity=severity,
        categories=categories,
        flows=flows,
        needs_deep=False,
    )


class TestTheExpectation:
    def test_every_class_has_a_stated_severity(self) -> None:
        """A class with no stated severity has no expected verdict."""
        assert set(SEVERITY_BY_CLASS) == set(ALL_CLASSES)
        for severity in SEVERITY_BY_CLASS.values():
            assert severity in ("none", "low", "medium", "high", "critical")

    def test_the_legitimate_traffic_is_the_quiet_control(self) -> None:
        """The corpus's control for the false-positive side."""
        case = _case(GoldenClass.LEGITIMATE_ENTERPRISE)
        expected = expected_verdict(case)
        assert expected.quiet is True
        assert expected.severity == "none"

    def test_the_expectation_comes_from_the_case(self) -> None:
        case = _case(GoldenClass.EXFILTRATION, hostname="exfil.example.com")
        expected = expected_verdict(case)
        assert expected.severity == "high"
        assert expected.categories == (GoldenClass.EXFILTRATION,)
        assert expected.hostnames == ("exfil.example.com",)
        assert expected.quiet is False

    def test_every_corpus_case_has_an_expectation(self) -> None:
        """Every case in the corpus, not a sample of them."""
        for case in iter_cases():
            expected = expected_verdict(case)
            assert expected.severity in SEVERITY_BY_CLASS.values()
            assert expected.hostnames, f"{case.name} has no expected hosts"


class TestTheScorer:
    def test_a_matching_verdict_scores_correct(self) -> None:
        case = _case(GoldenClass.C2_BEACONING, hostname="beacon.example.com")
        score = score_verdict(case, _verdict(), _rows("beacon.example.com"))
        assert score.correct is True
        assert score.severity_ok and score.category_ok and score.flows_ok
        assert score.false_positive is False

    def test_the_wrong_severity_is_caught(self) -> None:
        case = _case(GoldenClass.C2_BEACONING, hostname="beacon.example.com")
        score = score_verdict(case, _verdict(severity="low"), _rows("beacon.example.com"))
        assert score.severity_ok is False
        assert score.correct is False

    def test_the_wrong_category_is_caught(self) -> None:
        case = _case(GoldenClass.C2_BEACONING, hostname="beacon.example.com")
        score = score_verdict(
            case, _verdict(categories=("something_else",)), _rows("beacon.example.com")
        )
        assert score.category_ok is False
        assert score.correct is False

    def test_a_citation_of_a_flow_the_run_does_not_have_is_caught(self) -> None:
        """A flow that is not in the run cites nothing, however confident the prose."""
        case = _case(GoldenClass.C2_BEACONING, hostname="beacon.example.com")
        score = score_verdict(
            case,
            _verdict(flows=(FiveTuple(9, 9, 9, 9, 6),)),
            _rows("beacon.example.com"),
        )
        assert score.flows_ok is False
        assert score.correct is False

    def test_a_quiet_case_that_is_flagged_is_a_false_positive(self) -> None:
        """The second side of the criterion.

        An agent that says "high" about legitimate enterprise traffic is the
        failure the corpus's control class exists to catch \u2014 and an accuracy
        number alone would not see it.
        """
        case = _case(GoldenClass.LEGITIMATE_ENTERPRISE, hostname="www.google.com")
        flagged = score_verdict(
            case,
            _verdict(
                severity="high",
                categories=(GoldenClass.LEGITIMATE_ENTERPRISE,),
                flows=(FiveTuple(1, 2, 3, 4, 6),),
            ),
            _rows("www.google.com"),
        )
        assert flagged.false_positive is True
        assert flagged.correct is False

        quiet = score_verdict(
            case,
            _verdict(
                severity="none",
                categories=(GoldenClass.LEGITIMATE_ENTERPRISE,),
                flows=(),
            ),
            _rows("www.google.com"),
        )
        assert quiet.false_positive is False
        assert quiet.correct is True


class TestTheTrace:
    def test_a_complete_trace_covers_the_verdict(self, tmp_path: Path) -> None:
        steps = [
            _step("model", {"system": "prompt", "prompt_version": "untrusted-data/1"}),
            _step("tool", {"name": "query_flows"}),
            _step("model", {"system": "prompt", "prompt_version": "untrusted-data/1"}),
            _step("verdict", {"parsed": True}),
        ]
        assert trace_covers_verdict(steps) is True

    def test_a_trace_without_the_verdict_does_not_cover_it(self) -> None:
        steps = [_step("model", {"system": "prompt", "prompt_version": "v"})]
        assert trace_covers_verdict(steps) is False

    def test_a_trace_without_the_prompt_cannot_be_replayed(self) -> None:
        """Replaying a node means running it again with the same prompt."""
        steps = [
            _step("model", {"system": "", "prompt_version": "v"}),
            _step("verdict", {"parsed": True}),
        ]
        assert trace_covers_verdict(steps) is False

    def test_a_trace_without_a_prompt_version_cannot_be_replayed(self) -> None:
        """Which prompt produced a verdict has to be answerable afterwards."""
        steps = [
            _step("model", {"system": "prompt"}),
            _step("verdict", {"parsed": True}),
        ]
        assert trace_covers_verdict(steps) is False


def _step(kind: str, payload: dict[str, Any]) -> Any:
    from dpi_agents.trace import TraceStep

    return TraceStep(index=0, kind=kind, payload=payload)


class TestTheRunner:
    def test_a_run_over_a_real_case_is_scored_and_traced(self, tmp_path: Path) -> None:
        """The plumbing, end to end: a corpus case, a run, a verdict, a score, a trace.

        The scripted model makes the *accuracy* here meaningless \u2014 it is the
        script's verdict, not the model's judgement \u2014 so what this proves is
        that the apparatus works: the right run is reached, the citation is
        checkable, and the trace is replayable.
        """
        materialised = materialise(tmp_path / "corpus")
        capture = materialised["c2_dns_tunnel"]
        case = next(c for c in iter_cases() if c.name == "c2_dns_tunnel")

        async def scenario() -> tuple[Any, list[dict[str, Any]], list[Any]]:
            store_root = tmp_path / "store"
            run_id = store_a_run(capture, store_root)
            rows = RunStore(store_root).query(run_id)
            flow = rows[0]
            async with connected(store_root) as session:
                schemas = await tool_schemas(session, TRIAGE_TOOL_NAMES)
                model = ScriptedModel(
                    [
                        ModelReply(
                            text="looking",
                            tool_calls=(
                                ToolCall(name="query_flows", arguments={"run_id": run_id}),
                            ),
                        ),
                        ModelReply(
                            text=json.dumps(
                                {
                                    "severity": "high",
                                    "categories": [GoldenClass.C2_BEACONING],
                                    "flows": [
                                        {
                                            "src_ip": flow.src_ip,
                                            "dst_ip": flow.dst_ip,
                                            "src_port": flow.src_port,
                                            "dst_port": flow.dst_port,
                                            "protocol": flow.protocol,
                                        }
                                    ],
                                    "needs_deep": True,
                                }
                            )
                        ),
                    ]
                )
                path = tmp_path / "trace.jsonl"
                with Trace(path) as trace:
                    outcome = await Agent(model=model, trace=trace).run(
                        triage_node(schemas), tools=McpToolPort(session)
                    )
            return outcome, list(rows), Trace.read(path)

        outcome, rows, steps = asyncio.run(scenario())
        assert outcome.reason == "verdict", outcome.error
        assert trace_covers_verdict(steps) is True

        score = score_verdict(case, outcome.verdict, rows)
        assert score.severity_ok is True
        assert score.category_ok is True
        assert score.flows_ok is True, "the verdict cited a flow the case does not have"
        assert score.false_positive is False
