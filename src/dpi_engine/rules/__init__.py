"""Counterfactual analysis over captures: simulation, not enforcement.

Kept separate from `dpi_engine` proper because nothing in the enforcement path may
import it. The engine's job is to decide what to do with traffic in front of it; a
module that answers "what *would* you do" is a different contract, and letting the
simulator import into the enforcement path would put an analysis tool one refactor
away from being load-bearing on live traffic.
"""

from __future__ import annotations

__all__ = ["simulator"]
