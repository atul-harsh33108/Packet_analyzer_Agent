"""The DPI engine's MCP tool surface (`AGENTIC_ARCHITECTURE.md` Layer 2).

**Safety envelope: `OFFLINE_CORE`** — declared in `tests/safety_envelope.py`.

That is not an oversight for a package whose job is to be driven by an agent. This
one serves **stdio**, which is how Claude Desktop, Claude Code, Cursor and Zed launch
a local server: the client is already running on the host, and the server's entire
I/O surface is those inherited pipes. It never opens a socket, so it stays inside the
same envelope as `dpi_engine` and Phase 3 needs no envelope widening at all.

**Streamable HTTP is deliberately not served here** (`DEC-08`). It is a different
transport, not a flag: it would require widening this package to `NETWORKED_AGENT`,
and it would put an unauthenticated network endpoint in front of a policy engine
before any agent exists to use it. The SDK already installs the HTTP/ASGI stack
(`uvicorn`, `starlette`, `sse-starlette`), so enabling it later is code and auth
rather than new dependencies -- there was no cost advantage to taking it now.

**This module imports nothing from the `mcp` SDK.** That import belongs at the
wiring boundary (`server.py`, `T3-05`), so the tool implementations stay plain typed
Python that can be tested, read and used without a protocol library installed. The
discipline `AGENTIC_ARCHITECTURE.md` says MCP forces -- explicit, typed, documented
tool contracts -- is only real if the contracts do not depend on the protocol to be
testable.

## Scope, and what is deliberately absent

Phase 3 ships **7** of the 11 tools in the Layer 2 design (`DEC-08`):

| tool | needs |
|---|---|
| `inspect_capture` | `cap_source.py` |
| `run_dpi` | pipeline + `report.py` |
| `stream_dpi_events` | `events.py` |
| `simulate_ruleset` | `rules/simulator.py` (`T1-06`) |
| `query_flows` | run store (`T3-02`) |
| `get_flow_detail` | run store (`T3-02`) |
| `diff_runs` | run store (`T3-02`) |

Four are **not** here, and their absence is the point rather than an omission:

- `get_fingerprints` -- JA3/JA4 are Phase 5 (`ClassifierGap`); zero references in the
  engine today.
- `query_anomalies` -- needs anomaly scoring that does not exist.
- `list_rule_versions` / `revert_rule` -- need a `RuleStore`, which is Phase 6.

A tool that returns "not implemented" is worse than an absent tool: an agent can
believe it asked a question and received an answer. These are absent so that their
absence is visible.
"""

from __future__ import annotations

__all__: list[str] = []
