"""The blast-radius circuit breaker (`T6-04`).

The breaker is the first thing in the write path that can say **no**, so these
tests are written around the four answers it is allowed to give and the exact
lines between them:

- a signature-table entry is auto-applied, because it identifies traffic rather
  than dropping it and is reversible;
- a ruleset within **both** the configured flow cap and the percentage cap is
  one-click;
- anything above either, anything touching a protected app, and anything the
  Critic flagged is an explicit confirmation;
- a candidate that would forward nothing is **refused**, never made approvable.

The other half is what the breaker must *not* do: it reads `SimulationReport`'s
own figures rather than re-deriving a decision, and it has no path to a store.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import math
from pathlib import Path
from typing import Any

import pytest

from conftest import TEST_DPI_PCAP
from dpi_engine import blast_radius as breaker_module
from dpi_engine.blast_radius import (
    BreakerConfig,
    BreakerDecision,
    Reason,
    Tier,
    classify,
)
from dpi_engine.proposal import Citation, Proposal
from dpi_engine.rule_manager import Provenance, RuleManager
from dpi_engine.rule_store import PolicyKind
from dpi_engine.rules.simulator import FlowDelta, SimulationReport, simulate_ruleset
from dpi_engine.types import AppType, FiveTuple, FlowRecord

RUN_ID = "0123456789abcdef"
_FLOW = FiveTuple(
    src_ip=0x0A000001,
    dst_ip=0x0A000002,
    src_port=49152,
    dst_port=443,
    protocol=6,
)
_RECORD = FlowRecord(
    src_ip=_FLOW.src_ip,
    dst_ip=_FLOW.dst_ip,
    src_port=_FLOW.src_port,
    dst_port=_FLOW.dst_port,
    protocol=_FLOW.protocol,
    app="TIKTOK",
    state="ESTABLISHED",
    packets=3,
    bytes=120,
)
_RULESET = {"blocked_apps": ["TIKTOK"]}
_SIGNATURES = {
    "version": 1,
    "signatures": [
        {
            "id": "tiktok-client",
            "app": "TIKTOK",
            "all_of": [{"field": "sni_present", "value": True}],
        }
    ],
}


class _Resolver:
    """The `CitationResolver` port, holding exactly the one flow that is cited."""

    def resolve(self, cited: Citation) -> FlowRecord | None:
        if cited.run_id == RUN_ID and cited.five_tuple == _FLOW:
            return _RECORD
        return None


def _proposal(kind: PolicyKind = PolicyKind.RULESET) -> Proposal:
    return Proposal.build(
        kind=kind,
        document=_RULESET if kind is PolicyKind.RULESET else _SIGNATURES,
        provenance=Provenance(
            source="agent:policy",
            author="policy-agent/1",
            evidence=f"run {RUN_ID}",
        ),
        note="blocked after review",
        citations=(Citation(run_id=RUN_ID, five_tuple=_FLOW),),
        resolver=_Resolver(),
        agent_version="policy-agent/1",
        prompt_version="policy/1",
        model_version="model-x/2026-10-30",
    )


def _delta(app: AppType, index: int = 0) -> FlowDelta:
    return FlowDelta(
        flow_key=FiveTuple(
            src_ip=0x0A000000 + index,
            dst_ip=0x0A000100 + index,
            src_port=49152 + index,
            dst_port=443,
            protocol=6,
        ),
        app_type=app,
        sni=f"{app.name.lower()}.example",
    )


def _report(
    *,
    newly_blocked: tuple[FlowDelta, ...] = (),
    newly_allowed: tuple[FlowDelta, ...] = (),
    unchanged_blocked: tuple[FlowDelta, ...] = (),
    drop_rate_change_percent: float = 0.0,
    total_loss: bool = False,
    forwarded: int = 77,
    total_packets: int = 77,
) -> SimulationReport:
    return SimulationReport(
        newly_blocked=newly_blocked,
        newly_allowed=newly_allowed,
        unchanged_blocked=unchanged_blocked,
        baseline_blocked=len(unchanged_blocked),
        candidate_blocked=len(unchanged_blocked) + len(newly_blocked),
        baseline_dropped=0,
        candidate_dropped=total_packets - forwarded,
        baseline_forwarded=total_packets,
        candidate_forwarded=forwarded,
        baseline_total_packets=total_packets,
        candidate_total_packets=total_packets,
        drop_rate_change_percent=drop_rate_change_percent,
        total_loss=total_loss,
        baseline_output=Path("baseline_sim.pcap"),
        candidate_output=Path("candidate_sim.pcap"),
    )


# ---------------------------------------------------------------------------
# The configuration: thresholds are policy, and a policy can be wrong
# ---------------------------------------------------------------------------


class TestTheConfiguration:
    def test_the_defaults_are_layer_8s_lines(self) -> None:
        config = BreakerConfig()

        assert config.max_flows == 10
        assert config.one_click_percent == 0.1
        assert config.critical_percent == 5.0
        assert config.protected_apps == frozenset()

    @pytest.mark.parametrize("value", [-1, 1.5, True, "10", None])
    def test_the_flow_cap_must_be_a_non_negative_integer(self, value: Any) -> None:
        with pytest.raises(ValueError, match="max_flows"):
            BreakerConfig(max_flows=value)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("one_click_percent", -0.1),
            ("one_click_percent", math.nan),
            ("one_click_percent", math.inf),
            ("one_click_percent", True),
            ("one_click_percent", "0.1"),
            ("critical_percent", -0.1),
            ("critical_percent", math.nan),
            ("critical_percent", -math.inf),
            ("critical_percent", False),
        ],
    )
    def test_a_percent_must_be_a_finite_non_negative_number(
        self, field: str, value: Any
    ) -> None:
        with pytest.raises(ValueError, match=field):
            BreakerConfig(**{field: value})

    def test_the_critical_line_cannot_sit_below_the_one_click_line(self) -> None:
        with pytest.raises(ValueError, match="critical_percent"):
            BreakerConfig(one_click_percent=1.0, critical_percent=0.5)

    @pytest.mark.parametrize(
        "value",
        [set(), {"TIKTOK"}, frozenset({"TIKTOK"}), ("TIKTOK",)],
    )
    def test_protected_apps_must_be_a_frozenset_of_app_types(self, value: Any) -> None:
        with pytest.raises(ValueError, match="protected_apps"):
            BreakerConfig(protected_apps=value)

    def test_a_protected_app_is_the_engines_own_enum(self) -> None:
        config = BreakerConfig(protected_apps=frozenset({AppType.TIKTOK}))

        assert config.protected_apps == {AppType.TIKTOK}

    def test_the_configuration_is_frozen(self) -> None:
        config = BreakerConfig()

        with pytest.raises(dataclasses.FrozenInstanceError):
            config.max_flows = 1  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Refused: the one answer no threshold can improve
# ---------------------------------------------------------------------------


class TestRefusal:
    def test_total_loss_is_refused(self) -> None:
        decision = classify(_proposal(), _report(total_loss=True))

        assert decision.tier is Tier.REFUSED
        assert decision.reasons == (Reason.TOTAL_LOSS,)

    def test_total_loss_is_refused_even_for_a_signature_table(self) -> None:
        """A signature table is only auto-appliable while it is near-zero blast radius."""
        decision = classify(
            _proposal(PolicyKind.SIGNATURES), _report(total_loss=True, forwarded=0)
        )

        assert decision.tier is Tier.REFUSED

    def test_total_loss_is_refused_even_when_a_critic_objected(self) -> None:
        """Refusal dominates: there is no approval to qualify."""
        decision = classify(
            _proposal(), _report(total_loss=True), critic_objection=True
        )

        assert decision.tier is Tier.REFUSED
        assert decision.reasons == (Reason.TOTAL_LOSS,)

    def test_the_refusal_still_records_the_blast_radius(self) -> None:
        report = _report(
            newly_blocked=(_delta(AppType.TIKTOK), _delta(AppType.YOUTUBE, 1)),
            drop_rate_change_percent=100.0,
            total_loss=True,
            forwarded=0,
        )

        decision = classify(_proposal(), report)

        assert decision.flows_newly_blocked == 2
        assert decision.drop_rate_change_percent == 100.0

    def test_a_refused_candidate_never_becomes_an_explicit_confirmation(self) -> None:
        decision = classify(
            _proposal(),
            _report(total_loss=True, drop_rate_change_percent=100.0),
            config=BreakerConfig(max_flows=0, one_click_percent=0.0),
            critic_objection=True,
        )

        assert decision.tier is not Tier.EXPLICIT_CONFIRM
        assert decision.tier is Tier.REFUSED


# ---------------------------------------------------------------------------
# Auto-apply: signature-table entries, and only while they are reversible
# ---------------------------------------------------------------------------


class TestAutoApply:
    def test_a_signature_table_is_auto_applied(self) -> None:
        decision = classify(_proposal(PolicyKind.SIGNATURES), _report())

        assert decision.tier is Tier.AUTO_APPLY
        assert decision.reasons == (Reason.SIGNATURE_TABLE,)
        assert decision.flows_newly_blocked == 0

    def test_a_ruleset_is_never_auto_applied(self) -> None:
        decision = classify(_proposal(PolicyKind.RULESET), _report())

        assert decision.tier is Tier.ONE_CLICK

    def test_a_signature_table_that_would_block_traffic_is_not_auto_applied(self) -> None:
        """Auto-apply requires a near-zero blast radius, not merely a kind."""
        report = _report(newly_blocked=(_delta(AppType.TIKTOK),))

        decision = classify(
            _proposal(PolicyKind.SIGNATURES),
            report,
            config=BreakerConfig(max_flows=0),
        )

        assert decision.tier is Tier.EXPLICIT_CONFIRM
        assert decision.reasons == (Reason.ABOVE_FLOW_CAP,)

    def test_a_signature_table_a_critic_flagged_needs_a_human(self) -> None:
        decision = classify(
            _proposal(PolicyKind.SIGNATURES), _report(), critic_objection=True
        )

        assert decision.tier is Tier.EXPLICIT_CONFIRM
        assert decision.reasons == (Reason.CRITIC_OBJECTION,)

    def test_an_empty_report_is_still_read_as_zero_not_missing(self) -> None:
        decision = classify(_proposal(PolicyKind.SIGNATURES), _report())

        assert decision.flows_newly_blocked == 0
        assert decision.drop_rate_change_percent == 0.0


# ---------------------------------------------------------------------------
# One-click: at or below both caps, with an exact boundary
# ---------------------------------------------------------------------------


class TestOneClick:
    def test_a_no_op_ruleset_is_one_click(self) -> None:
        decision = classify(_proposal(), _report())

        assert decision.tier is Tier.ONE_CLICK
        assert decision.reasons == (Reason.WITHIN_CAPS,)

    def test_exactly_the_flow_cap_is_allowed(self) -> None:
        report = _report(
            newly_blocked=(_delta(AppType.TIKTOK, 1), _delta(AppType.YOUTUBE, 2))
        )

        decision = classify(_proposal(), report, config=BreakerConfig(max_flows=2))

        assert decision.tier is Tier.ONE_CLICK

    def test_one_flow_above_the_cap_is_confirmed(self) -> None:
        report = _report(
            newly_blocked=(
                _delta(AppType.TIKTOK, 1),
                _delta(AppType.YOUTUBE, 2),
                _delta(AppType.GOOGLE, 3),
            )
        )

        decision = classify(_proposal(), report, config=BreakerConfig(max_flows=2))

        assert decision.tier is Tier.EXPLICIT_CONFIRM
        assert decision.reasons == (Reason.ABOVE_FLOW_CAP,)

    def test_exactly_the_percent_cap_is_allowed(self) -> None:
        report = _report(drop_rate_change_percent=1.0)

        decision = classify(
            _proposal(), report, config=BreakerConfig(one_click_percent=1.0)
        )

        assert decision.tier is Tier.ONE_CLICK

    def test_above_the_percent_cap_is_confirmed(self) -> None:
        report = _report(drop_rate_change_percent=1.0000001)

        decision = classify(
            _proposal(), report, config=BreakerConfig(one_click_percent=1.0)
        )

        assert decision.tier is Tier.EXPLICIT_CONFIRM
        assert decision.reasons == (Reason.ABOVE_PERCENT_CAP,)

    def test_the_percent_cap_uses_the_reports_own_figure(self) -> None:
        decision = classify(_proposal(), _report(drop_rate_change_percent=0.1))

        assert decision.drop_rate_change_percent == 0.1
        assert decision.tier is Tier.ONE_CLICK

    def test_a_change_that_blocks_less_does_not_escalate(self) -> None:
        report = _report(
            newly_allowed=(_delta(AppType.TIKTOK),),
            drop_rate_change_percent=-5.0,
        )

        decision = classify(_proposal(), report)

        assert decision.tier is Tier.ONE_CLICK
        assert decision.flows_newly_blocked == 0

    def test_between_the_caps_is_confirmed_but_not_critical(self) -> None:
        decision = classify(_proposal(), _report(drop_rate_change_percent=1.0))

        assert decision.tier is Tier.EXPLICIT_CONFIRM
        assert decision.reasons == (Reason.ABOVE_PERCENT_CAP,)

    def test_above_the_critical_line_says_so(self) -> None:
        decision = classify(_proposal(), _report(drop_rate_change_percent=6.0))

        assert decision.reasons == (
            Reason.ABOVE_PERCENT_CAP,
            Reason.ABOVE_CRITICAL_RATE,
        )

    def test_exactly_the_critical_line_is_not_critical(self) -> None:
        decision = classify(_proposal(), _report(drop_rate_change_percent=5.0))

        assert decision.reasons == (Reason.ABOVE_PERCENT_CAP,)

    def test_the_critical_line_may_equal_the_one_click_line(self) -> None:
        config = BreakerConfig(one_click_percent=1.0, critical_percent=1.0)

        at_line = classify(_proposal(), _report(drop_rate_change_percent=1.0), config=config)
        above = classify(_proposal(), _report(drop_rate_change_percent=2.0), config=config)

        assert at_line.tier is Tier.ONE_CLICK
        assert above.reasons == (
            Reason.ABOVE_PERCENT_CAP,
            Reason.ABOVE_CRITICAL_RATE,
        )


# ---------------------------------------------------------------------------
# Protected apps: "touched" means newly blocked, not present in the capture
# ---------------------------------------------------------------------------


class TestProtectedApps:
    def test_newly_blocking_a_protected_app_needs_a_human(self) -> None:
        config = BreakerConfig(
            max_flows=10,
            one_click_percent=5.0,
            protected_apps=frozenset({AppType.TIKTOK}),
        )
        report = _report(newly_blocked=(_delta(AppType.TIKTOK),))

        decision = classify(_proposal(), report, config=config)

        assert decision.tier is Tier.EXPLICIT_CONFIRM
        assert decision.reasons == (Reason.PROTECTED_APP,)
        assert decision.protected_apps == (AppType.TIKTOK,)

    def test_a_protected_app_already_blocked_is_not_touched(self) -> None:
        config = BreakerConfig(protected_apps=frozenset({AppType.TIKTOK}))
        report = _report(unchanged_blocked=(_delta(AppType.TIKTOK),))

        decision = classify(_proposal(), report, config=config)

        assert decision.tier is Tier.ONE_CLICK
        assert decision.protected_apps == ()

    def test_a_protected_app_that_is_only_unblocked_is_not_touched(self) -> None:
        config = BreakerConfig(protected_apps=frozenset({AppType.TIKTOK}))
        report = _report(
            newly_allowed=(_delta(AppType.TIKTOK),),
            drop_rate_change_percent=-1.0,
        )

        decision = classify(_proposal(), report, config=config)

        assert decision.tier is Tier.ONE_CLICK
        assert decision.protected_apps == ()

    def test_each_protected_app_is_named_once_in_a_stable_order(self) -> None:
        config = BreakerConfig(
            one_click_percent=100.0,
            critical_percent=100.0,
            protected_apps=frozenset({AppType.TIKTOK, AppType.YOUTUBE}),
        )
        report = _report(
            newly_blocked=(
                _delta(AppType.YOUTUBE, 1),
                _delta(AppType.TIKTOK, 2),
                _delta(AppType.YOUTUBE, 3),
            )
        )

        decision = classify(_proposal(), report, config=config)

        assert decision.protected_apps == (AppType.TIKTOK, AppType.YOUTUBE)

    def test_no_configured_protected_apps_means_none_are_touched(self) -> None:
        report = _report(newly_blocked=(_delta(AppType.TIKTOK),))

        decision = classify(_proposal(), report, config=BreakerConfig(max_flows=1))

        assert decision.tier is Tier.ONE_CLICK
        assert decision.protected_apps == ()

    def test_protected_apps_are_named_even_when_the_candidate_is_refused(self) -> None:
        config = BreakerConfig(protected_apps=frozenset({AppType.TIKTOK}))
        report = _report(
            newly_blocked=(_delta(AppType.TIKTOK),),
            drop_rate_change_percent=100.0,
            total_loss=True,
            forwarded=0,
        )

        decision = classify(_proposal(), report, config=config)

        assert decision.tier is Tier.REFUSED
        assert decision.protected_apps == (AppType.TIKTOK,)


# ---------------------------------------------------------------------------
# The Critic's objection is an input, not a re-derivation
# ---------------------------------------------------------------------------


class TestCriticObjection:
    def test_an_objection_escalates_an_otherwise_clean_ruleset(self) -> None:
        decision = classify(_proposal(), _report(), critic_objection=True)

        assert decision.tier is Tier.EXPLICIT_CONFIRM
        assert decision.reasons == (Reason.CRITIC_OBJECTION,)

    def test_an_objection_is_recorded_alongside_the_caps(self) -> None:
        decision = classify(
            _proposal(), _report(drop_rate_change_percent=6.0), critic_objection=True
        )

        assert decision.reasons == (
            Reason.ABOVE_PERCENT_CAP,
            Reason.ABOVE_CRITICAL_RATE,
            Reason.CRITIC_OBJECTION,
        )

    def test_no_objection_adds_no_reason(self) -> None:
        decision = classify(_proposal(), _report())

        assert Reason.CRITIC_OBJECTION not in decision.reasons


# ---------------------------------------------------------------------------
# The decision value: a tier that cannot disagree with its reasons
# ---------------------------------------------------------------------------


class TestTheDecision:
    def test_a_combined_case_orders_the_reasons_deterministically(self) -> None:
        config = BreakerConfig(
            max_flows=0,
            one_click_percent=0.5,
            critical_percent=5.0,
            protected_apps=frozenset({AppType.TIKTOK}),
        )
        report = _report(
            newly_blocked=(_delta(AppType.TIKTOK),),
            drop_rate_change_percent=6.0,
        )

        decision = classify(
            _proposal(), report, config=config, critic_objection=True
        )

        assert decision.reasons == (
            Reason.ABOVE_FLOW_CAP,
            Reason.ABOVE_PERCENT_CAP,
            Reason.ABOVE_CRITICAL_RATE,
            Reason.PROTECTED_APP,
            Reason.CRITIC_OBJECTION,
        )

    def test_the_decision_is_frozen(self) -> None:
        decision = classify(_proposal(), _report())

        with pytest.raises(dataclasses.FrozenInstanceError):
            decision.tier = Tier.REFUSED  # type: ignore[misc]

    def test_a_decision_needs_a_tier(self) -> None:
        with pytest.raises(ValueError, match="Tier"):
            BreakerDecision(
                tier="one-click",  # type: ignore[arg-type]
                reasons=(Reason.WITHIN_CAPS,),
                flows_newly_blocked=0,
                drop_rate_change_percent=0.0,
                protected_apps=(),
            )

    def test_a_decision_needs_at_least_one_reason(self) -> None:
        """Explicit-confirm is the one tier no marker check would catch."""
        with pytest.raises(ValueError, match="reason"):
            BreakerDecision(
                tier=Tier.EXPLICIT_CONFIRM,
                reasons=(),
                flows_newly_blocked=0,
                drop_rate_change_percent=0.0,
                protected_apps=(),
            )

    def test_a_decision_needs_reason_values(self) -> None:
        with pytest.raises(ValueError, match="Reason"):
            BreakerDecision(
                tier=Tier.ONE_CLICK,
                reasons=("within-caps",),  # type: ignore[arg-type]
                flows_newly_blocked=0,
                drop_rate_change_percent=0.0,
                protected_apps=(),
            )

    def test_a_decision_rejects_a_negative_flow_count(self) -> None:
        with pytest.raises(ValueError, match="flows_newly_blocked"):
            BreakerDecision(
                tier=Tier.ONE_CLICK,
                reasons=(Reason.WITHIN_CAPS,),
                flows_newly_blocked=-1,
                drop_rate_change_percent=0.0,
                protected_apps=(),
            )

    @pytest.mark.parametrize("value", [1.5, True, "1", None])
    def test_a_decision_rejects_a_non_integer_flow_count(self, value: Any) -> None:
        with pytest.raises(ValueError, match="flows_newly_blocked"):
            BreakerDecision(
                tier=Tier.ONE_CLICK,
                reasons=(Reason.WITHIN_CAPS,),
                flows_newly_blocked=value,
                drop_rate_change_percent=0.0,
                protected_apps=(),
            )

    @pytest.mark.parametrize("value", [math.nan, math.inf, True, "0.1"])
    def test_a_decision_rejects_an_unusable_percent(self, value: Any) -> None:
        with pytest.raises(ValueError, match="drop_rate_change_percent"):
            BreakerDecision(
                tier=Tier.ONE_CLICK,
                reasons=(Reason.WITHIN_CAPS,),
                flows_newly_blocked=0,
                drop_rate_change_percent=value,
                protected_apps=(),
            )

    @pytest.mark.parametrize(
        "apps",
        [
            (AppType.TIKTOK, AppType.TIKTOK),
            (AppType.YOUTUBE, AppType.TIKTOK),
            ("TIKTOK",),
        ],
    )
    def test_a_decision_requires_protected_apps_sorted_and_unique(
        self, apps: tuple[Any, ...]
    ) -> None:
        with pytest.raises(ValueError, match="protected_apps"):
            BreakerDecision(
                tier=Tier.EXPLICIT_CONFIRM,
                reasons=(Reason.PROTECTED_APP,),
                flows_newly_blocked=0,
                drop_rate_change_percent=0.0,
                protected_apps=apps,
            )

    def test_an_auto_apply_decision_cannot_carry_a_cap_reason(self) -> None:
        with pytest.raises(ValueError, match="auto-apply"):
            BreakerDecision(
                tier=Tier.AUTO_APPLY,
                reasons=(Reason.SIGNATURE_TABLE, Reason.ABOVE_FLOW_CAP),
                flows_newly_blocked=1,
                drop_rate_change_percent=0.0,
                protected_apps=(),
            )

    def test_an_explicit_decision_cannot_carry_an_approval_reason(self) -> None:
        with pytest.raises(ValueError, match="explicit-confirm"):
            BreakerDecision(
                tier=Tier.EXPLICIT_CONFIRM,
                reasons=(Reason.WITHIN_CAPS,),
                flows_newly_blocked=0,
                drop_rate_change_percent=0.0,
                protected_apps=(),
            )

    def test_a_one_click_decision_cannot_carry_an_escalation(self) -> None:
        with pytest.raises(ValueError, match="one-click"):
            BreakerDecision(
                tier=Tier.ONE_CLICK,
                reasons=(Reason.WITHIN_CAPS, Reason.ABOVE_FLOW_CAP),
                flows_newly_blocked=1,
                drop_rate_change_percent=0.0,
                protected_apps=(),
            )

    def test_a_refusal_is_exactly_the_total_loss_reason(self) -> None:
        with pytest.raises(ValueError, match="refused"):
            BreakerDecision(
                tier=Tier.REFUSED,
                reasons=(Reason.TOTAL_LOSS, Reason.PROTECTED_APP),
                flows_newly_blocked=0,
                drop_rate_change_percent=100.0,
                protected_apps=(),
            )


# ---------------------------------------------------------------------------
# Over a real counterfactual, not a hand-written number
# ---------------------------------------------------------------------------


def _app_blocking(app: AppType) -> RuleManager:
    rules = RuleManager()
    rules.block_app(app)
    return rules


class TestOverARealCounterfactual:
    def test_a_real_rule_is_classified_from_the_real_report(
        self, tmp_path: Path
    ) -> None:
        report = simulate_ruleset(
            RuleManager(),
            _app_blocking(AppType.TIKTOK),
            TEST_DPI_PCAP,
            output_dir=tmp_path / "tiktok",
        )

        decision = classify(_proposal(), report)

        # The sample capture is 77 packets, so one newly blocked flow is already
        # 1.3 points: above Layer 8's 0.1% one-click line on this capture.
        assert decision.tier is Tier.EXPLICIT_CONFIRM
        assert decision.reasons == (Reason.ABOVE_PERCENT_CAP,)
        assert decision.flows_newly_blocked == len(report.newly_blocked)
        assert decision.drop_rate_change_percent == report.drop_rate_change_percent

    def test_the_same_real_report_is_one_click_at_its_exact_boundary(
        self, tmp_path: Path
    ) -> None:
        report = simulate_ruleset(
            RuleManager(),
            _app_blocking(AppType.TIKTOK),
            TEST_DPI_PCAP,
            output_dir=tmp_path / "boundary",
        )

        decision = classify(
            _proposal(),
            report,
            config=BreakerConfig(
                max_flows=len(report.newly_blocked),
                one_click_percent=report.drop_rate_change_percent,
            ),
        )

        assert decision.tier is Tier.ONE_CLICK
        assert decision.reasons == (Reason.WITHIN_CAPS,)

    def test_a_real_total_loss_is_refused(self, tmp_path: Path) -> None:
        candidate = RuleManager()
        candidate.block_cidr("0.0.0.0/0")
        report = simulate_ruleset(
            RuleManager(),
            candidate,
            TEST_DPI_PCAP,
            output_dir=tmp_path / "total-loss",
        )

        assert report.total_loss, "the fixture must actually forward nothing"
        decision = classify(_proposal(), report)

        assert decision.tier is Tier.REFUSED
        assert decision.reasons == (Reason.TOTAL_LOSS,)
        assert decision.drop_rate_change_percent == 100.0

    def test_a_real_no_op_is_auto_appliable_for_a_signature_table(
        self, tmp_path: Path
    ) -> None:
        report = simulate_ruleset(
            RuleManager(), RuleManager(), TEST_DPI_PCAP, output_dir=tmp_path / "no-op"
        )

        decision = classify(_proposal(PolicyKind.SIGNATURES), report)

        assert decision.tier is Tier.AUTO_APPLY
        assert decision.reasons == (Reason.SIGNATURE_TABLE,)


# ---------------------------------------------------------------------------
# No path from a tier to an installed rule
# ---------------------------------------------------------------------------


class TestNoPathToApplication:
    def test_the_breaker_cannot_publish_or_activate_a_version(self) -> None:
        tree = ast.parse(inspect.getsource(breaker_module))
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }

        assert not calls & {"commit", "publish", "activate", "apply", "block_app"}

    def test_the_breaker_does_not_import_a_store_or_a_rule_manager(self) -> None:
        """`PolicyKind` lives in `rule_store`; the store class and writer do not."""
        tree = ast.parse(inspect.getsource(breaker_module))
        imported = {
            (alias.name or "").split(".")[-1]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        imported_modules = {
            node.module.split(".")[-1]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }

        assert "RuleStore" not in imported
        assert "RuleManager" not in imported
        assert "rule_manager" not in imported_modules
