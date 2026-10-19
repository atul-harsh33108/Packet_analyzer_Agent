"""The Layer 2 tool surface (`AGENTIC_ARCHITECTURE.md`, `T3-03`, `T3-04`, `T3-07`).

Tools are grouped by **what they are for**, not by which task happened to build them:
`single_run` holds the three that take a capture and answer immediately;
`ruleset` holds the one adapter every rule-taking tool shares. `T3-04`'s three run-store
tools and `T3-07`'s streaming tool will land in their own modules beside these.

**Nothing here imports the `mcp` SDK.** That import belongs to the wiring boundary
(`server.py`, `T3-05`). The SDK is not installed in this environment at all, which is
convenient for development and dangerous for testing: "the tools work without the SDK"
is *vacuously true* while the SDK is absent, so it is asserted structurally (no shipped
tool module imports `mcp`) and behaviourally (the tools run with `import mcp` forced to
fail) rather than by an import that cannot fail. A guard that cannot fail is worse than
no guard, because it reads as coverage.
"""

from __future__ import annotations

from dpi_mcp.tools.errors import ToolInputError
from dpi_mcp.tools.ruleset import build_rule_manager
from dpi_mcp.tools.single_run import (
    RunMode,
    inspect_capture,
    run_dpi,
    simulate_ruleset,
)

__all__ = [
    "RunMode",
    "ToolInputError",
    "build_rule_manager",
    "inspect_capture",
    "run_dpi",
    "simulate_ruleset",
]
