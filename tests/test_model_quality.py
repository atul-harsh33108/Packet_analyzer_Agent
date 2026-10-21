"""The opt-in quality run (`T4-07`).

**This is the phase's first exit criterion measured against a real model.**
`T4-05` built the scorer and the derived expectations; `T4-01`'s deterministic
fake can only measure the **plumbing** \u2014 did the agent reach the right run and
cite the right flows \u2014 because a scripted model says what the script says.
This run is what measures whether a model is any good.

**It is opt-in, and the skip says what it means.** No key, no run \u2014 exactly as
the differential suite skips without Docker. A skip that reads as a pass is not a
measurement, so the reason says so: the quality figure is **not measured** here,
and nothing downstream may treat this file's green as evidence about a model.

**There is no threshold, on purpose.** A number set before the first real
measurement is a number with nothing behind it. The thresholds are a follow-up,
to be set from the first run that has a model behind it \u2014 and the measurement
below is what that decision will be made from.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import pytest

from agent_harness import connected, store_a_run, tool_schemas
from dpi_agents.nodes.triage import TRIAGE_TOOL_NAMES, triage_node
from dpi_agents.runtime import Agent
from dpi_agents.tools import McpToolPort
from dpi_agents.trace import Trace
from dpi_mcp.run_store import RunStore
from eval.verdicts import score_verdict, trace_covers_verdict
from golden.corpus import iter_cases, materialise

pytestmark = pytest.mark.skipif(
    not os.environ.get("DPI_MODEL_API_KEY"),
    reason=(
        "no DPI_MODEL_API_KEY, so there is no model to measure. The quality figure is "
        "OPT-IN: this skip means the quality is NOT measured, and a green run here is "
        "not evidence about any model."
    ),
)

#: The run is many model calls, and the suite's 30s ceiling is per test.
_TIMEOUT = 1800


def _client() -> Any:
    from dpi_model_client import OpenAiCompatibleModel, settings_from_environment

    return OpenAiCompatibleModel(settings_from_environment())


def test_a_real_model_is_measured_against_the_golden_corpus(tmp_path: Path) -> None:
    """Every corpus case, run, judged and scored \u2014 with the two-sided rule.

    The false positives are counted separately and deliberately: an agent that
    flags the legitimate-enterprise cases is the failure the corpus's control
    class exists to catch, and an accuracy number alone would not see it.
    """
    client = _client()
    materialised = materialise(tmp_path / "corpus")
    scores: list[Any] = []
    traces: list[tuple[str, bool]] = []

    async def scenario() -> None:
        for case in iter_cases():
            capture = materialised[case.name]
            store_root = tmp_path / "store" / case.name
            run_id = store_a_run(capture, store_root)
            rows = list(RunStore(store_root).query(run_id))
            async with connected(store_root) as session:
                schemas = await tool_schemas(session, TRIAGE_TOOL_NAMES)
                path = tmp_path / "traces" / f"{case.name}.jsonl"
                with Trace(path) as trace:
                    outcome = await Agent(model=client, trace=trace).run(
                        triage_node(schemas),
                        tools=McpToolPort(session),
                        state=f"The run to triage is {run_id}.",
                    )
                traces.append((case.name, trace_covers_verdict(Trace.read(path))))
            if outcome.reason != "verdict":
                # A model that refused, or ran out of budget, is a *result* \u2014 and
                # it is recorded as one, not as a crash.
                scores.append(None)
                continue
            scores.append(score_verdict(case, outcome.verdict, rows))

    asyncio.run(scenario())

    judged = [score for score in scores if score is not None]
    assert judged, "no case produced a verdict at all"
    assert all(covered for _case, covered in traces), (
        "a verdict without a replayable trace is not a verdict we can check"
    )

    correct = sum(1 for score in judged if score.correct)
    false_positives = sum(1 for score in judged if score.false_positive)
    report = {
        "cases": len(scores),
        "judged": len(judged),
        "correct": correct,
        "accuracy": round(correct / len(judged), 3),
        "false_positives": false_positives,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
