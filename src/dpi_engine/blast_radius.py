"""The blast-radius circuit breaker (`T6-04`).

A number on a counterfactual is not a decision. This module is the step that
turns a real `SimulationReport` into one of four answers:

- **auto-apply** -- a signature-table entry with no escalation. It identifies
  traffic rather than dropping it and is reversible in one click, which is what
  makes it safe to apply without a human in the loop.
- **one-click** -- a ruleset at or below **both** the configured flow cap and
  the percentage cap. It is queued with its counterfactual attached.
- **explicit-confirm** -- anything above either cap, anything that newly blocks
  a configured protected app, or anything the Critic objected to. The human sees
  the counterfactual and the objection before anything changes.
- **refused** -- a candidate that would forward nothing at all. `total_loss` is
  not a threshold to tune; a policy that blocks everything is never approvable.

**The figures are read, never re-derived.** `flows_newly_blocked` is the length
of the report's own `newly_blocked` tuple, and the percentage is its
`drop_rate_change_percent`. Recomputing either from the rule document would make
this a second source of truth, free to drift from the simulator that production
also trusts. The flow cap therefore counts **newly blocked flows**; the
percentage is the report's packet-level drop-rate change, because that is the
percentage `SimulationReport` measures and it exposes no flow denominator. The
distinction is named in the field rather than blurred.

**Nothing here can apply a change.** The output is a frozen `BreakerDecision`
with a tier, the reasons for it and the figures it rested on. There is no store,
no rule manager and no write call in this module; `T6-05` persists the decision
and `T6-06` is the only door that moves an active version.

**Thresholds are configuration, not constants.** The defaults come from Layer 8
of the design: 0.1% for one-click and 5% as the critical line. Layer 8 names a
flow cap `N` without a value, so this module ships 10 as an operator-replaceable
default rather than pretending the document supplied a number. A configuration
is validated at construction: a `NaN` cap would make every comparison false and
silently turn every candidate into a one-click, which is exactly the kind of
safe-looking default that is not safe.
"""

from __future__ import annotations

import dataclasses
import enum
import math

from dpi_engine.proposal import Proposal
from dpi_engine.rule_store import PolicyKind
from dpi_engine.rules.simulator import SimulationReport
from dpi_engine.types import AppType

__all__ = [
    "DEFAULT_CRITICAL_PERCENT",
    "DEFAULT_MAX_FLOWS",
    "DEFAULT_ONE_CLICK_PERCENT",
    "BreakerConfig",
    "BreakerDecision",
    "Reason",
    "Tier",
    "classify",
]

#: Layer 8's one-click line, in percentage points of the report's drop rate.
DEFAULT_ONE_CLICK_PERCENT = 0.1

#: Layer 8's critical line. Crossing it is still an explicit confirmation; the
#: separate reason exists so the record says *which* line was crossed.
DEFAULT_CRITICAL_PERCENT = 5.0

#: Layer 8 says "more than N flows" without choosing N. Ten is a product
#: default, not a number from the document, and is configuration for that reason.
DEFAULT_MAX_FLOWS = 10


class Tier(enum.StrEnum):
    """The four answers the breaker may give."""

    AUTO_APPLY = "auto-apply"
    ONE_CLICK = "one-click"
    EXPLICIT_CONFIRM = "explicit-confirm"
    REFUSED = "refused"


class Reason(enum.StrEnum):
    """Why a tier was chosen, recorded rather than paraphrased in prose."""

    SIGNATURE_TABLE = "signature-table"
    WITHIN_CAPS = "within-caps"
    ABOVE_FLOW_CAP = "above-flow-cap"
    ABOVE_PERCENT_CAP = "above-percent-cap"
    ABOVE_CRITICAL_RATE = "above-critical-rate"
    PROTECTED_APP = "protected-app"
    CRITIC_OBJECTION = "critic-objection"
    TOTAL_LOSS = "total-loss"


@dataclasses.dataclass(frozen=True, slots=True)
class BreakerConfig:
    """The thresholds a deployment chooses. Validated, because a wrong one is silent.

    `max_flows` is an absolute count of **newly blocked flows**.
    `one_click_percent` and `critical_percent` are percentage points of the
    report's drop-rate change (its own packet-level figure). `protected_apps`
    are engine `AppType`s: a change that newly blocks one of them always needs a
    human, whatever the numbers say.
    """

    max_flows: int = DEFAULT_MAX_FLOWS
    one_click_percent: float = DEFAULT_ONE_CLICK_PERCENT
    critical_percent: float = DEFAULT_CRITICAL_PERCENT
    protected_apps: frozenset[AppType] = frozenset()

    def __post_init__(self) -> None:
        if isinstance(self.max_flows, bool) or not isinstance(self.max_flows, int):
            raise ValueError(
                "max_flows must be a non-negative integer, got "
                f"{type(self.max_flows).__name__}"
            )
        if self.max_flows < 0:
            raise ValueError(f"max_flows must be non-negative, got {self.max_flows}")

        for name in ("one_click_percent", "critical_percent"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(
                    f"{name} must be a finite non-negative number, got "
                    f"{type(value).__name__}"
                )
            if not math.isfinite(value) or value < 0:
                raise ValueError(
                    f"{name} must be a finite non-negative number, got {value!r}"
                )

        if self.critical_percent < self.one_click_percent:
            raise ValueError(
                "critical_percent must not sit below one_click_percent: "
                f"{self.critical_percent!r} < {self.one_click_percent!r}"
            )

        if not isinstance(self.protected_apps, frozenset):
            raise ValueError(
                "protected_apps must be a frozenset of AppType, got "
                f"{type(self.protected_apps).__name__}"
            )
        for app in self.protected_apps:
            if not isinstance(app, AppType):
                raise ValueError(
                    f"protected_apps contains {app!r}, which is not an AppType"
                )


@dataclasses.dataclass(frozen=True, slots=True)
class BreakerDecision:
    """A tier and the facts it rests on. Immutable, and unable to disagree with itself.

    The tier's marker reason is checked here as well as produced by `classify`:
    an auto-apply decision that also carries a cap breach, or a refusal that
    carries an approval reason, would be a record whose first field contradicts
    its last. The record is the audit trail's input, so it is refused at
    construction rather than explained away later.
    """

    tier: Tier
    reasons: tuple[Reason, ...]
    flows_newly_blocked: int
    #: Percentage points of the report's own drop-rate change, not a flow share.
    drop_rate_change_percent: float
    #: Newly blocked protected apps, deduplicated and sorted by engine name.
    protected_apps: tuple[AppType, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.tier, Tier):
            raise ValueError(
                f"a breaker decision needs a Tier, got {type(self.tier).__name__}"
            )
        if not isinstance(self.reasons, tuple) or not self.reasons:
            raise ValueError("a breaker decision needs at least one reason")
        if any(not isinstance(reason, Reason) for reason in self.reasons):
            raise ValueError(
                "a breaker decision's reasons must be Reasons, got "
                f"{[type(reason).__name__ for reason in self.reasons]}"
            )

        if isinstance(self.flows_newly_blocked, bool) or not isinstance(
            self.flows_newly_blocked, int
        ):
            raise ValueError(
                "flows_newly_blocked must be a non-negative integer, got "
                f"{type(self.flows_newly_blocked).__name__}"
            )
        if self.flows_newly_blocked < 0:
            raise ValueError(
                f"flows_newly_blocked must be non-negative, got "
                f"{self.flows_newly_blocked}"
            )

        if isinstance(self.drop_rate_change_percent, bool) or not isinstance(
            self.drop_rate_change_percent, (int, float)
        ):
            raise ValueError(
                "drop_rate_change_percent must be a finite number, got "
                f"{type(self.drop_rate_change_percent).__name__}"
            )
        if not math.isfinite(self.drop_rate_change_percent):
            raise ValueError(
                "drop_rate_change_percent must be finite, got "
                f"{self.drop_rate_change_percent!r}"
            )

        if not isinstance(self.protected_apps, tuple) or any(
            not isinstance(app, AppType) for app in self.protected_apps
        ):
            raise ValueError(
                "protected_apps must be a sorted tuple of unique AppTypes, got "
                f"{self.protected_apps!r}"
            )
        names = [app.name for app in self.protected_apps]
        if names != sorted(names) or len(set(names)) != len(names):
            raise ValueError(
                "protected_apps must be a sorted tuple of unique AppTypes, got "
                f"{self.protected_apps!r}"
            )

        approval = {
            Reason.SIGNATURE_TABLE,
            Reason.WITHIN_CAPS,
            Reason.TOTAL_LOSS,
        }
        if self.tier is Tier.AUTO_APPLY and self.reasons != (Reason.SIGNATURE_TABLE,):
            raise ValueError(
                "an auto-apply decision must carry exactly the signature-table reason"
            )
        if self.tier is Tier.ONE_CLICK and self.reasons != (Reason.WITHIN_CAPS,):
            raise ValueError(
                "a one-click decision must carry exactly the within-caps reason"
            )
        if self.tier is Tier.REFUSED and self.reasons != (Reason.TOTAL_LOSS,):
            raise ValueError(
                "a refused decision must carry exactly the total-loss reason"
            )
        if self.tier is Tier.EXPLICIT_CONFIRM and any(
            reason in approval for reason in self.reasons
        ):
            raise ValueError(
                "an explicit-confirm decision must not carry an approval reason"
            )


def classify(
    proposal: Proposal,
    report: SimulationReport,
    *,
    config: BreakerConfig | None = None,
    critic_objection: bool = False,
) -> BreakerDecision:
    """Classify one proposal from the counterfactual that was actually run.

    The order is the precedence: a total loss is refused before any threshold is
    consulted, then every escalator is collected, and only a clean record can be
    auto-applied or queued for one click. `critic_objection` is an input because
    the breaker does not have a Critic and must not guess one; the caller that
    ran the review supplies it.
    """
    settings = BreakerConfig() if config is None else config

    newly_blocked = len(report.newly_blocked)
    touched = tuple(
        sorted(
            {
                delta.app_type
                for delta in report.newly_blocked
                if delta.app_type in settings.protected_apps
            },
            key=lambda app: app.name,
        )
    )

    if report.total_loss:
        return BreakerDecision(
            tier=Tier.REFUSED,
            reasons=(Reason.TOTAL_LOSS,),
            flows_newly_blocked=newly_blocked,
            drop_rate_change_percent=report.drop_rate_change_percent,
            protected_apps=touched,
        )

    reasons: list[Reason] = []
    if newly_blocked > settings.max_flows:
        reasons.append(Reason.ABOVE_FLOW_CAP)
    if report.drop_rate_change_percent > settings.one_click_percent:
        reasons.append(Reason.ABOVE_PERCENT_CAP)
    if report.drop_rate_change_percent > settings.critical_percent:
        reasons.append(Reason.ABOVE_CRITICAL_RATE)
    if touched:
        reasons.append(Reason.PROTECTED_APP)
    if critic_objection:
        reasons.append(Reason.CRITIC_OBJECTION)

    if reasons:
        tier = Tier.EXPLICIT_CONFIRM
    elif proposal.kind is PolicyKind.SIGNATURES:
        tier = Tier.AUTO_APPLY
        reasons.append(Reason.SIGNATURE_TABLE)
    else:
        tier = Tier.ONE_CLICK
        reasons.append(Reason.WITHIN_CAPS)

    return BreakerDecision(
        tier=tier,
        reasons=tuple(reasons),
        flows_newly_blocked=newly_blocked,
        drop_rate_change_percent=report.drop_rate_change_percent,
        protected_apps=touched,
    )
