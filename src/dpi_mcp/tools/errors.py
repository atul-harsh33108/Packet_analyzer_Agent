"""The one exception the tool layer raises for input it cannot use (`T3-03`).

Deliberately **not** a wrapper around the engine's exceptions. `PcapError` and
`RuleManagerError` already carry meaning an agent needs -- "your capture is unreadable"
and "your rules did not parse" call for different next moves -- and the wiring
(`T3-05`) translates this type while letting those pass through. A single
`ToolError(Exception)` swallowing both would make "you sent nonsense" and "the engine
could not read your file" indistinguishable, which is the *user's* problem to
disambiguate at 3 a.m. rather than the protocol's.
"""

from __future__ import annotations

__all__ = ["ToolInputError"]


class ToolInputError(ValueError):
    """An argument was not usable as a tool input.

    A `ValueError` because it is an input error, not a runtime one, and because
    `ValueError` is what a caller would already catch around a hand-written function.
    """
