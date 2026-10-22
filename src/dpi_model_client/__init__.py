"""The real model client (`T4-07`).

**Safety envelope: `NETWORKED_AGENT`** \u2014 and that is the *shape* of the project
rather than a limitation of it. The agent runtime in `src/dpi_agents/` stays
`OFFLINE_CORE`, so the code that reads a capture cannot reach the network, and
the safety suite proves it by checking imports as well as calls.

**What lives in this package and nowhere else:** the one thing that talks to a
model provider. A package per concern, not per convenience: the boundary is
where the *capability* is, and the capability is a network call.
"""

from __future__ import annotations

from dpi_model_client.client import (
    ModelClientError,
    ModelSettings,
    OpenAiCompatibleModel,
    settings_from_environment,
)
from dpi_model_client.quality import (
    MAX_FALSE_POSITIVES,
    QUALITY_THRESHOLDS,
    QualityJudgement,
    judge_quality,
    threshold_for,
)

__all__ = [
    "MAX_FALSE_POSITIVES",
    "QUALITY_THRESHOLDS",
    "ModelClientError",
    "ModelSettings",
    "OpenAiCompatibleModel",
    "QualityJudgement",
    "judge_quality",
    "settings_from_environment",
    "threshold_for",
]
