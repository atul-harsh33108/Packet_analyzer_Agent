"""Turning an agent-supplied ruleset into a `RuleManager` (`T3-03`).

Every rule-taking tool faces the same question: what *is* a ruleset at this boundary?
The answer has to be **data**, never an engine object. An MCP client can send JSON and
nothing else, so a contract that accepted a `RuleManager` would be unimplementable over
the protocol it exists to serve -- and untestable without the engine in process.

`RuleManager.from_dict` is already the loader for the rules-file shape, and it already
raises `RuleManagerError` for anything malformed. So this module adds **no second
dialect** and does not re-implement validation: it decides only what "absent" means, and
everything else is delegated. That matters because a second validator would drift from
the first, and the two would disagree exactly when a rule matters -- the failure `D-16`
records for the rule maps.

`None` means "no rules", which is what the engine's own `rule_manager=None` default
means. That is the common case for `simulate_ruleset`'s baseline: "what would this
candidate change about the capture, against the policy that is currently in force?"
"""

from __future__ import annotations

from dpi_engine.rule_manager import RuleManager

__all__ = ["build_rule_manager"]


def build_rule_manager(ruleset: object, *, source: str = "<tool ruleset>") -> RuleManager:
    """Builds a `RuleManager` from a rules document, or an empty one for `None`.

    `source` only names the offending input in error messages, following
    `RuleManager.from_dict`. Everything the document itself must satisfy is checked in
    exactly one place, there.
    """
    if ruleset is None:
        return RuleManager()
    return RuleManager.from_dict(ruleset, source=source)
