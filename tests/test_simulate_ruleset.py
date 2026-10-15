"""Counterfactual ruleset simulation (`T1-06`, closes `A-05`).

`simulate_ruleset` answers the question an operator actually has before shipping a
policy change: *what would this ruleset do to my capture?* It does that by running
the **real pipeline twice** — once with the ruleset in force, once with the
candidate — and diffing the two per-packet decision streams.

The two properties that make this worth having, and that these tests exist to pin:

1. **Exact, not sampled or estimated.** Every safety claim we want to make later
   ("a ruleset that would block 100% of flows is reported as such") has to fall out
   of the same decision path production uses, not a re-implementation of it. So the
   simulator drives `run_pipeline` and reads `PacketParsed.forwarded` — the very bit
   that decides whether a packet reaches the output file. A simulator that
   re-derived decisions would be a second source of truth, and would drift.

2. **The baseline is a real measurement, not an assumption.** Simulation is
   reported relative to what the *current* ruleset does, because "blocks 40% of
   flows" means something different when the incumbent already blocks 35%.

These run against the real 771-packet sample capture, because the point is to
exercise the production path, and a synthetic fixture would only prove the
fixture works.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from conftest import TEST_DPI_PCAP
from dpi_engine.pcap_io import PcapWriter
from dpi_engine.pipeline import run_pipeline
from dpi_engine.rule_manager import RuleManager
from dpi_engine.rules import simulator
from dpi_engine.rules.simulator import (
    FlowDelta,
    SimulationReport,
    simulate_ruleset,
)
from dpi_engine.types import AppType


def _app_blocking(*apps: AppType) -> RuleManager:
    rules = RuleManager()
    for app in apps:
        rules.block_app(app)
    return rules


class TestNoOpSimulation:
    """The identity case. If a no-op is not exactly zero everywhere, the diff is
    broken and every other number in this module is untrustworthy."""

    def test_identical_rulesets_report_no_change(self, tmp_path: Path) -> None:
        report = simulate_ruleset(
            _app_blocking(AppType.FACEBOOK),
            _app_blocking(AppType.FACEBOOK),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )

        assert isinstance(report, SimulationReport)
        # Tuples, not lists: `SimulationReport` is frozen, so its collections must
        # be too, or the report would only be *apparently* immutable.
        assert report.newly_blocked == ()
        assert report.newly_allowed == ()
        assert report.packets_changed == 0
        assert report.baseline_dropped == report.candidate_dropped
        # `unchanged_blocked` is the detail, `baseline_blocked`/`candidate_blocked`
        # the counts; they must agree, which is only meaningful if you take a
        # length rather than comparing a tuple to an int.
        assert len(report.unchanged_blocked) == report.baseline_blocked
        assert report.baseline_blocked == report.candidate_blocked

    def test_two_empty_rulesets_agree_with_the_bare_pipeline(self, tmp_path: Path) -> None:
        """A simulation with no rules must reproduce the no-rules run exactly.

        This is the load-bearing check that the simulator is not quietly doing
        something of its own: if the empty case ever diverged from
        `run_pipeline`, every "what would this do" answer would be suspect.
        """
        report = simulate_ruleset(
            RuleManager(), RuleManager(), TEST_DPI_PCAP, output_dir=tmp_path
        )
        reference = run_pipeline(TEST_DPI_PCAP, tmp_path / "reference.pcap", RuleManager())

        assert report.candidate_total_packets == reference.stats.total_packets
        assert report.candidate_dropped == reference.stats.dropped_packets
        assert report.candidate_forwarded == reference.stats.forwarded_packets
        assert report.packets_changed == 0

    def test_repeated_simulation_of_the_same_ruleset_is_deterministic(
        self, tmp_path: Path
    ) -> None:
        candidate = _app_blocking(AppType.YOUTUBE)
        first = simulate_ruleset(
            RuleManager(), candidate, TEST_DPI_PCAP, output_dir=tmp_path
        )
        second = simulate_ruleset(
            RuleManager(), candidate, TEST_DPI_PCAP, output_dir=tmp_path
        )

        assert first == second


class TestNewlyBlocked:
    def test_blocking_an_app_appears_as_newly_blocked_flows(self, tmp_path: Path) -> None:
        report = simulate_ruleset(
            RuleManager(),
            _app_blocking(AppType.YOUTUBE),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )

        assert report.newly_blocked, "blocking YouTube should newly block some flows"
        assert report.newly_allowed == ()
        assert all(
            delta.app_type is AppType.YOUTUBE for delta in report.newly_blocked
        ), "only YouTube flows should be reported as newly blocked"
        assert report.candidate_dropped > report.baseline_dropped
        # The two blocked-flow counts must differ here. Asserting only the packet
        # counters is not enough: a simulator that reported the *candidate's* flow
        # count in both slots would satisfy every other assertion in this test.
        assert report.baseline_blocked == 0
        assert report.candidate_blocked == len(report.newly_blocked)

    def test_newly_blocked_flows_were_forwarded_by_the_baseline(self, tmp_path: Path) -> None:
        """The delta must be a *change*, not a restatement.

        Guards against a simulator that reports the candidate's whole blocked set
        as "newly blocked" — which would look plausible and overstate every blast
        radius, since a ruleset that was already blocking would appear to add
        flows it never touched.
        """
        report = simulate_ruleset(
            _app_blocking(AppType.FACEBOOK),
            _app_blocking(AppType.FACEBOOK, AppType.YOUTUBE),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )

        baseline_blocked = {d.flow_key for d in report.unchanged_blocked_deltas}
        for delta in report.newly_blocked:
            assert delta.flow_key not in baseline_blocked

        # Tightening Facebook to Facebook+YouTube leaves every Facebook flow
        # blocked in both runs, so `unchanged_blocked` legitimately equals the
        # baseline's whole blocked set here. That makes this test blind to a bug
        # where `unchanged_blocked` is just a copy of the baseline -- which is why
        # the substitution case below carries that assertion instead.
        assert len(report.unchanged_blocked) == report.baseline_blocked
        assert {d.app_type for d in report.unchanged_blocked} == {AppType.FACEBOOK}

    def test_substituting_one_rule_for_another_does_not_call_it_unchanged(
        self, tmp_path: Path
    ) -> None:
        """Baseline blocks Facebook; candidate blocks YouTube instead.

        Nothing is blocked by both, so `unchanged_blocked` must be empty even
        though the baseline blocked plenty. A simulator that reported the whole
        baseline as "unchanged" would claim a policy swap had no effect on
        Facebook traffic -- the most misleading possible answer here.
        """
        report = simulate_ruleset(
            _app_blocking(AppType.FACEBOOK),
            _app_blocking(AppType.YOUTUBE),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )

        assert report.baseline_blocked > 0
        assert report.candidate_blocked > 0
        assert report.unchanged_blocked == ()
        assert len(report.newly_blocked) == report.candidate_blocked
        assert len(report.newly_allowed) == report.baseline_blocked
        assert report.flows_changed == report.baseline_blocked + report.candidate_blocked

    def test_every_delta_is_typed_as_a_flow_delta(self, tmp_path: Path) -> None:
        report = simulate_ruleset(
            RuleManager(),
            _app_blocking(AppType.YOUTUBE),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )
        assert all(isinstance(d, FlowDelta) for d in report.newly_blocked)


class TestNewlyAllowed:
    def test_relaxing_a_rule_reports_the_flows_it_frees(self, tmp_path: Path) -> None:
        report = simulate_ruleset(
            _app_blocking(AppType.YOUTUBE),
            RuleManager(),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )

        assert report.newly_allowed, "unblocking YouTube should free some flows"
        assert report.newly_blocked == ()
        assert report.candidate_dropped < report.baseline_dropped
        assert report.candidate_forwarded > report.baseline_forwarded
        # Both halves of `flows_changed` must be counted, not just the blocking
        # one. Pinned by asserting the exact total: `newly_allowed` is non-empty
        # here, so a `flows_changed` that ignored it would be short by exactly
        # `len(report.newly_allowed)` and still pass a bare "it changed" check.
        assert report.flows_changed == len(report.newly_allowed)
        assert report.baseline_blocked == len(report.newly_allowed)
        assert report.candidate_blocked == 0

    def test_the_two_directions_are_mirror_images(self, tmp_path: Path) -> None:
        """Blocking then unblocking must return the engine to the empty-ruleset state.

        This is the strongest available check that the diff is complete and
        order-independent: if any state leaked between the two runs, the round
        trip would not land back on zero.
        """
        tighten = simulate_ruleset(
            RuleManager(),
            _app_blocking(AppType.YOUTUBE),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )
        loosen = simulate_ruleset(
            _app_blocking(AppType.YOUTUBE),
            RuleManager(),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )
        round_trip = simulate_ruleset(
            _app_blocking(AppType.YOUTUBE),
            _app_blocking(AppType.YOUTUBE),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )

        blocked = {d.flow_key for d in tighten.newly_blocked}
        freed = {d.flow_key for d in loosen.newly_allowed}
        assert blocked == freed, (
            "the flows blocked by tightening must be exactly the flows freed by "
            "loosening it; a mismatch means the diff is losing or inventing flows"
        )
        assert round_trip.packets_changed == 0


class TestBlastRadiusReporting:
    """The safety claim the roadmap wants to make about this component."""

    def test_blocking_every_application_is_reported_as_total_loss(
        self, tmp_path: Path
    ) -> None:
        """The stated success criterion for `T1-06`.

        A ruleset that would block 100% of flows must be reported as such. If the
        simulator cannot say "this change would block everything", it cannot warn
        anyone before they ship it, and the whole point of a write path is that
        warning.
        """
        everything = tuple(AppType)
        report = simulate_ruleset(
            RuleManager(), _app_blocking(*everything), TEST_DPI_PCAP, output_dir=tmp_path
        )

        assert report.candidate_forwarded == 0
        assert report.total_loss, "blocking every app must be flagged as total loss"
        # Nothing may reach the wire, and nothing may be presented as safe.
        assert report.candidate_dropped == report.candidate_total_packets
        assert report.drop_rate_change_percent > 0.0

    def test_the_summary_reports_the_same_numbers_as_the_report(self, tmp_path: Path) -> None:
        """`summary()` is what a CLI or a log line will show an operator.

        It is a second presentation of the report's own figures, so it can drift
        from them the way any duplicated view can. Asserted against the fields
        rather than against a literal string, so the wording is free to change
        without the test becoming noise, but the numbers are not.
        """
        report = simulate_ruleset(
            RuleManager(),
            _app_blocking(AppType.YOUTUBE),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )
        summary = report.summary()

        assert str(report.flows_changed) in summary
        assert str(len(report.newly_blocked)) in summary
        assert f"{report.candidate_dropped}/{report.candidate_total_packets}" in summary

    def test_a_no_op_summary_does_not_claim_a_change(self, tmp_path: Path) -> None:
        """A summary reading "0 flows change" must not be worded as though it did.

        The alternative — omitting the counts entirely and leaving the operator to
        infer from silence — is the failure this prevents: a simulation that
        changed nothing has to say so plainly, because "nothing reported" and
        "nothing found" look identical otherwise.
        """
        report = simulate_ruleset(
            RuleManager(), RuleManager(), TEST_DPI_PCAP, output_dir=tmp_path
        )
        assert report.summary().startswith("0 flows change")

    def test_an_empty_capture_is_not_total_loss(self, tmp_path: Path) -> None:
        """Total loss means traffic was stopped, not that there was none.

        A capture with no packets forwards nothing and drops nothing. Calling that
        "total loss" would make the flag fire on empty input — so a simulation
        over a quiet capture would demand confirmation before applying a rule that
        in fact does nothing. This pins why `total_loss` requires `dropped > 0` and
        not merely `forwarded == 0`.
        """
        empty = tmp_path / "empty.pcap"
        PcapWriter(empty).close()

        report = simulate_ruleset(
            RuleManager(), _app_blocking(AppType.YOUTUBE), empty, output_dir=tmp_path
        )

        assert report.candidate_total_packets == 0
        assert report.candidate_dropped == 0
        assert not report.total_loss
        assert report.newly_blocked == ()

    def test_a_narrowing_change_is_not_flagged_as_total_loss(self, tmp_path: Path) -> None:
        report = simulate_ruleset(
            RuleManager(),
            _app_blocking(AppType.YOUTUBE),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )
        assert not report.total_loss

    def test_drop_rate_change_is_signed_and_nonzero_for_a_real_change(
        self, tmp_path: Path
    ) -> None:
        tighten = simulate_ruleset(
            RuleManager(),
            _app_blocking(AppType.YOUTUBE),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )
        loosen = simulate_ruleset(
            _app_blocking(AppType.YOUTUBE),
            RuleManager(),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )

        assert tighten.drop_rate_change_percent > 0
        assert loosen.drop_rate_change_percent < 0
        # The signed net must keep its direction too, or a caller computing a
        # budget from it would add headroom when the change actually removes it.
        assert tighten.net_packets_dropped > 0
        assert loosen.net_packets_dropped < 0

    def test_packet_deltas_and_flow_deltas_are_two_views_of_one_measurement(
        self, tmp_path: Path
    ) -> None:
        """The per-flow and per-packet views must agree.

        Without this the report could show internally inconsistent numbers — a
        plausible-looking blast radius beside a contradictory packet count — and
        nothing else in the suite would catch it.
        """
        report = simulate_ruleset(
            RuleManager(),
            _app_blocking(AppType.YOUTUBE),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )

        assert len(report.newly_blocked) + len(report.newly_allowed) == report.flows_changed
        # Adding a rule can only drop more, so here the net and the per-packet
        # diff coincide. They do *not* coincide for a substitution — see
        # `test_substitution_moves_packets_without_changing_the_drop_total`.
        assert report.packets_changed == report.net_packets_dropped
        assert report.packets_changed > 0

    def test_substitution_moves_packets_without_changing_the_drop_total(
        self, tmp_path: Path
    ) -> None:
        """Replacing one blocked app with another is a net-zero change in drops.

        Both rulesets drop the same number of packets, so a report built from the
        drop counters alone would say "nothing changed" while in fact every one of
        those packets changed disposition — and told the wrong people about it.
        This is the case that forced `packets_changed` to be counted from the
        decision bitmaps rather than derived from the counters.
        """
        report = simulate_ruleset(
            _app_blocking(AppType.FACEBOOK),
            _app_blocking(AppType.YOUTUBE),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )

        assert report.net_packets_dropped == 0, "the two rulesets drop the same count"
        assert report.packets_changed > 0, "yet the packets changed disposition"
        assert report.drop_rate_change_percent == 0.0
        assert report.flows_changed > 0, "and flows genuinely differ"


class TestDomainRules:
    def test_blocking_a_detected_domain_appears_in_the_delta(self, tmp_path: Path) -> None:
        report = simulate_ruleset(
            RuleManager(),
            _app_blocking(AppType.FACEBOOK),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )
        assert report.newly_blocked

    def test_a_domain_rule_nobody_matches_changes_nothing(self, tmp_path: Path) -> None:
        """Rules are commonly written before the traffic exists to match them.

        A simulator that reported activity for a non-matching rule would train
        operators to ignore it, which is worse than not having one.
        """
        rules = RuleManager()
        rules.block_domain("nothing.in.this.capture.example")

        report = simulate_ruleset(RuleManager(), rules, TEST_DPI_PCAP, output_dir=tmp_path)

        assert report.newly_blocked == ()
        assert report.packets_changed == 0


class TestSimulationIsSideEffectFree:
    """A simulator must not leave artefacts a later run could trip over — most
    importantly it must not overwrite the capture it was asked about."""

    def test_the_input_capture_is_not_modified(self, tmp_path: Path) -> None:
        import shutil

        copy = tmp_path / "input.pcap"
        shutil.copy(TEST_DPI_PCAP, copy)
        before = copy.read_bytes()

        simulate_ruleset(
            RuleManager(),
            _app_blocking(AppType.YOUTUBE),
            copy,
            output_dir=tmp_path,
        )

        assert copy.read_bytes() == before

    def test_an_inconsistent_pair_of_runs_is_refused_rather_than_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A simulation whose two halves disagree must raise, not report.

        The two figures -- the per-packet decision diff and the aggregate dropped
        counters -- are computed independently, so they can only cross-check each
        other. If they ever disagree, the run is not measuring anything real and
        every number downstream is fiction. Returning a plausible-looking report
        would be the worst outcome available, because the caller has no way to tell.

        Fault injection is the only way to reach this: with a fixed input the two
        runs always see the same packets, which is exactly what the guard asserts.
        """
        real_record_run = simulator._record_run

        def make_sabotage(corrupt: Callable[[dict[int, bool]], None]) -> object:
            """Builds a `_record_run` replacement that corrupts only the *second*
            run.

            The corruption must be conditional on the call count: an unconditional
            one applies to the baseline too, leaving the two runs equally corrupt
            and the guard correctly silent — which would look like a guard that
            does not fire.
            """
            calls = 0

            def sabotaged(input_path, rules, output):  # type: ignore[no-untyped-def]
                nonlocal calls
                calls += 1
                run = real_record_run(input_path, rules, output)
                if calls == 2:
                    corrupt(run.decisions)
                return run

            return sabotaged

        def drop_a_packet(decisions: dict[int, bool]) -> None:
            # The candidate read fewer packets than the baseline.
            decisions.pop(0, None)

        def add_a_packet(decisions: dict[int, bool]) -> None:
            # The candidate read *more*. Both directions must be refused: a guard
            # that only tested one would let the other through, and every diff
            # derived from the two runs would be meaningless.
            decisions[10_000] = True

        for corrupt in (drop_a_packet, add_a_packet):
            monkeypatch.setattr(simulator, "_record_run", make_sabotage(corrupt))
            with pytest.raises(RuntimeError, match="simulation is inconsistent"):
                simulate_ruleset(
                    RuleManager(),
                    _app_blocking(AppType.YOUTUBE),
                    TEST_DPI_PCAP,
                    output_dir=tmp_path,
                )
        monkeypatch.undo()

    def test_each_run_writes_its_own_output_and_does_not_clobber_the_other(
        self, tmp_path: Path
    ) -> None:
        report = simulate_ruleset(
            RuleManager(),
            _app_blocking(AppType.YOUTUBE),
            TEST_DPI_PCAP,
            output_dir=tmp_path,
        )

        assert report.baseline_output.exists()
        assert report.candidate_output.exists()
        assert report.baseline_output != report.candidate_output
        # The candidate output is the more useful artefact, so it must be the one
        # that reflects the candidate ruleset: YouTube blocked means fewer packets.
        assert report.candidate_output.stat().st_size < report.baseline_output.stat().st_size
