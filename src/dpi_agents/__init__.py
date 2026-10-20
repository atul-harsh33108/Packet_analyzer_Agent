"""The agent layer: Layers 3-5 of `AGENTIC_ARCHITECTURE.md` (`T4-01` onward).

**Safety envelope: `OFFLINE_CORE`** -- and that is the point of the package's
shape, not a limitation of it. The runtime talks to a *model port*, and the
model port has two implementations: a deterministic fake in this package, and
the real client in `src/dpi_model_client/` at `NETWORKED_AGENT` (`T4-07`,
`DEC-11`). So the code that touches a capture **cannot reach the network**, and
the envelope scanner can prove it rather than a reviewer having to believe it.

That is the mirror image of the rule the project already enforces for the
core -- *a core that transitively loads an HTTP client is offline in name
only* -- and it is the same failure with the arrows reversed. Here the danger
is not that the engine phones home; it is that an agent reading a capture can be
*told* what to do by whatever the capture contained. An agent that cannot reach
the network cannot be redirected by a hostname in a DNS query.

**Nothing here imports a provider, and nothing here imports the `mcp` SDK.**
The agent drives the MCP tool surface, so the tool wrappers will speak MCP --
but from the *agent* side, through a port, exactly as the tools themselves stay
plain typed Python on the other side of it.
"""

from __future__ import annotations

__all__: list[str] = []
