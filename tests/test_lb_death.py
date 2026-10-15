"""`D-13` — a dead load balancer must not strand its fast paths forever.

The defect: only `_lb_main` sends `SHUTDOWN_SENTINEL` to the fast paths it feeds
(`pipeline.py:1054-1055`). If an LB dies, nothing sends those sentinels, so its
fast paths sit in `input_queue.get()` indefinitely, never report, and the parent
discovers the problem only via `_RESULT_TIMEOUT_SECONDS` — 120 seconds — with a
message that describes the *fast paths* ("only 3 of 4 workers reported") and never
mentions the process that actually died.

Both halves are wrong. It is slow, and the diagnosis points at the wrong component:
an operator reading "3 of 4 workers reported" would go and look at the fast paths.

**Why these drive `_collect_streaming` directly rather than killing a real process.**
The defect lives in the collection loop, and that loop is reachable without a
120-second wall-clock wait. `_RESULT_TIMEOUT_SECONDS` is shortened here for the
same reason `test_resource_bounds.py` shortens `_QUEUE_PUT_TIMEOUT_SECONDS`: the
timeout *is* the cost being fixed, so a test that kept the real value would take
two minutes to prove the absence of a two-minute wait. Process liveness is stubbed
with the same `_DeadConsumer`-style stand-in the existing suite uses, because
`_ensure_alive` asks exactly one question -- `is_alive()` -- so a stub exercises the
guard exactly and, unlike a spawned process, cannot be unpicklable.

One test does run the real staged pipeline end to end, to prove the liveness check
does not fire on a healthy run.
"""

from __future__ import annotations

import multiprocessing as mp
from pathlib import Path
from typing import Any

import pytest

from conftest import TEST_DPI_PCAP
from dpi_engine import pipeline
from dpi_engine.pipeline import run_pipeline_staged
from dpi_engine.types import AppType


class _DeadProcess:
    """A load balancer that has died.

    `exitcode` is 1 because `D-13`'s case is a *crash*: `_ensure_alive`
    deliberately ignores a process that exited 0, because a fast path that drained
    its queue and left cleanly is done, not dead (`T0-10`). A stub claiming to be
    dead-but-clean would test nothing.
    """

    name = "dpi-lb-0"

    def is_alive(self) -> bool:
        return False

    @property
    def exitcode(self) -> int:
        return 1


class _CleanProcess:
    """A worker that finished its queue and exited 0. Done, not dead."""

    name = "dpi-fp-0"

    def is_alive(self) -> bool:
        return False

    @property
    def exitcode(self) -> int:
        return 0


class _AliveProcess:
    """A healthy worker that simply has not reported yet."""

    name = "dpi-fp-1"

    def is_alive(self) -> bool:
        return True

    @property
    def exitcode(self) -> int | None:
        return None


def _worker_result(worker_id: int = 0) -> Any:
    from dpi_engine.connection_tracker import TrackerStats
    from dpi_engine.worker import WorkerResult

    return WorkerResult(worker_id=worker_id, tracker_stats=TrackerStats())


class TestCollectionDetectsDeadLoadBalancer:
    """The parent's collection loop is where `D-13` has to be caught."""

    def test_a_dead_lb_is_reported_instead_of_timing_out(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The stall must be diagnosed, not waited out.

        `D-13` says the parent "discovers it only via the 120 s timeout". So the
        behaviour under test is which of the two branches of the collection loop
        fires: a liveness diagnosis naming the dead LB, or a bare timeout.
        """
        monkeypatch.setattr(pipeline, "_RESULT_TIMEOUT_SECONDS", 0.2)
        queue: mp.Queue[Any] = mp.Queue()
        results: list[Any] = []

        with pytest.raises(RuntimeError) as excinfo:
            pipeline._collect_streaming(
                queue,
                expected=1,
                buffer=None,
                results=results,
                processes=[_DeadProcess()],
            )

        message = str(excinfo.value)
        assert "dpi-lb-0" in message, (
            "the failure must name the process that died, not merely that some "
            f"workers were silent: {message!r}"
        )
        queue.close()

    def test_the_timeout_message_is_not_what_reports_the_death(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A dead LB must be distinguishable from a merely slow one.

        This is the distinction the defect erases. If a dead load balancer and a
        healthy-but-slow one produced the same message, then during an incident
        there would be no way to tell a crash from slowness — which is exactly the
        ambiguity `_ensure_alive`'s own docstring says it exists to remove.
        """
        monkeypatch.setattr(pipeline, "_RESULT_TIMEOUT_SECONDS", 0.2)
        queue: mp.Queue[Any] = mp.Queue()
        results: list[Any] = []

        with pytest.raises(RuntimeError) as excinfo:
            pipeline._collect_streaming(
                queue,
                expected=1,
                buffer=None,
                results=results,
                processes=[_DeadProcess()],
            )

        message = str(excinfo.value)
        assert "only 0 of 1 workers reported" not in message, (
            "the old timeout wording is what misdirects an operator toward the "
            f"fast paths: {message!r}"
        )
        queue.close()

    def test_a_dead_lb_is_detected_before_the_timeout_fires(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Detection must be prompt, not merely eventual.

        A fix that still waited out `_RESULT_TIMEOUT_SECONDS` would pass the two
        tests above while leaving the real cost — two minutes of a stalled run —
        untouched. So the timeout is shortened well below the test's own budget and
        the test asserts the *dead-worker* message, which can only be produced by
        the liveness path.
        """
        monkeypatch.setattr(pipeline, "_RESULT_TIMEOUT_SECONDS", 30.0)
        monkeypatch.setattr(pipeline, "_LIVENESS_POLL_SECONDS", 0.1)
        queue: mp.Queue[Any] = mp.Queue()
        results: list[Any] = []

        with pytest.raises(RuntimeError, match="dpi-lb-0"):
            pipeline._collect_streaming(
                queue,
                expected=1,
                buffer=None,
                results=results,
                processes=[_DeadProcess()],
            )
        queue.close()

    def test_a_slow_but_healthy_worker_is_still_given_the_whole_budget(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Slicing the wait must not shorten it.

        The other half of `D-13`: re-checking liveness every second must not turn
        into "give up after a second". A worker that is merely slow has to be
        allowed the entire budget, so a fix that polled aggressively *and* treated
        each empty poll as failure would break healthy-but-busy runs. The worker
        here is alive and reports late.
        """
        monkeypatch.setattr(pipeline, "_RESULT_TIMEOUT_SECONDS", 3.0)
        monkeypatch.setattr(pipeline, "_LIVENESS_POLL_SECONDS", 0.05)
        queue: mp.Queue[Any] = mp.Queue()
        results: list[Any] = []

        import threading
        import time as _time

        def report_later() -> None:
            # Longer than several poll slices, so the collector must loop rather
            # than conclude the worker is silent.
            _time.sleep(0.4)
            queue.put(_worker_result(0))

        threading.Thread(target=report_later, daemon=True).start()

        collected = pipeline._collect_streaming(
            queue,
            expected=1,
            buffer=None,
            results=results,
            processes=[_AliveProcess()],
        )

        assert len(collected) == 1, "a slow worker must not be abandoned"
        queue.close()

    def test_the_budget_is_still_enforced_when_everything_is_alive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Polling forever would trade one hang for another.

        With every process healthy and none reporting, the collector must still
        give up at the budget. This is the counterweight to the test above: prompt
        detection of the dead must not have been achieved by removing the deadline.
        """
        monkeypatch.setattr(pipeline, "_RESULT_TIMEOUT_SECONDS", 0.3)
        monkeypatch.setattr(pipeline, "_LIVENESS_POLL_SECONDS", 0.05)
        queue: mp.Queue[Any] = mp.Queue()
        results: list[Any] = []
        queue.put(_worker_result(0))

        with pytest.raises(RuntimeError, match=r"only 1 of 2 workers reported within 0\.3s"):
            pipeline._collect_streaming(
                queue,
                expected=2,
                buffer=None,
                results=results,
                processes=[_AliveProcess()],
            )
        queue.close()

    def test_a_cleanly_exited_worker_is_not_treated_as_dead(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A worker that drained its queue and left is *done*, not dead.

        With more workers than a small capture has flows this is the common case,
        not an exception — so a liveness check that flagged it would fail healthy
        runs. This is `T0-10`'s distinction and it has to survive the `D-13` fix.
        """
        monkeypatch.setattr(pipeline, "_RESULT_TIMEOUT_SECONDS", 0.2)
        queue: mp.Queue[Any] = mp.Queue()
        results: list[Any] = []

        queue.put(_worker_result(0))
        queue.put(_worker_result(1))

        # expected=2 and both aggregates are already present, so the loop exits
        # without waiting -- and must do so without complaining about the
        # cleanly-exited stand-in.
        collected = pipeline._collect_streaming(
            queue,
            expected=2,
            buffer=None,
            results=results,
            processes=[_CleanProcess()],
        )

        assert len(collected) == 2
        queue.close()

    def test_a_worker_that_dies_mid_stream_is_caught_while_results_arrive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A death *during* a healthy stream must also be caught.

        The stall case is the one the defect names, but a worker can die after
        reporting some results, and then the queue is still producing messages.
        Checking liveness only on the empty-poll path would miss that entirely --
        the collector would sit in its normal loop waiting for an aggregate that
        will never come, and time out without naming the corpse.
        """
        monkeypatch.setattr(pipeline, "_RESULT_TIMEOUT_SECONDS", 2.0)
        monkeypatch.setattr(pipeline, "_LIVENESS_POLL_SECONDS", 0.05)
        queue: mp.Queue[Any] = mp.Queue()
        results: list[Any] = []

        # One genuine result, then silence. The process list says the worker died.
        queue.put(_worker_result(0))

        with pytest.raises(RuntimeError, match="dpi-lb-0"):
            pipeline._collect_streaming(
                queue,
                expected=2,
                buffer=None,
                results=results,
                processes=[_DeadProcess()],
            )
        queue.close()

    def test_progress_is_accepted_before_the_death_is_reported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The result that *did* arrive must not be discarded with the error.

        A collector that raised on noticing the death would lose the results it had
        already collected, and a caller that wants to know *how far* the run got
        before it broke would be left with nothing. The collected list is passed in
        and extended in place precisely so this survives.
        """
        monkeypatch.setattr(pipeline, "_RESULT_TIMEOUT_SECONDS", 2.0)
        monkeypatch.setattr(pipeline, "_LIVENESS_POLL_SECONDS", 0.05)
        queue: mp.Queue[Any] = mp.Queue()
        results: list[Any] = []

        queue.put(_worker_result(0))

        with pytest.raises(RuntimeError):
            pipeline._collect_streaming(
                queue,
                expected=2,
                buffer=None,
                results=results,
                processes=[_DeadProcess()],
            )

        assert len(results) == 1, "the aggregate received before the death was lost"
        queue.close()

    def test_detection_is_prompt_rather_than_budget_length(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Promptness is the defect, so it is asserted as elapsed time.

        Three separate fixes would each make every other test here pass while
        leaving the two-minute stall intact, because all of them still raise the
        same message naming the dead LB:

        - polling with the whole remaining budget, so the first check lands at the
          deadline;
        - a poll slice equal to the budget;
        - an unbounded poll interval.

        All three are invisible to a test that only checks *what* was raised. This
        one checks *when*. The budget is set an order of magnitude above the poll
        slice, so a collector that honours the slice returns while a collector that
        ignores it blocks for the full budget.
        """
        import time as _time

        monkeypatch.setattr(pipeline, "_RESULT_TIMEOUT_SECONDS", 5.0)
        monkeypatch.setattr(pipeline, "_LIVENESS_POLL_SECONDS", 0.05)
        queue: mp.Queue[Any] = mp.Queue()
        results: list[Any] = []

        started = _time.monotonic()
        with pytest.raises(RuntimeError, match="dpi-lb-0"):
            pipeline._collect_streaming(
                queue,
                expected=1,
                buffer=None,
                results=results,
                processes=[_DeadProcess()],
            )
        elapsed = _time.monotonic() - started

        # Generous next to the 0.05 s slice, and far below the 5 s budget.
        assert elapsed < 2.0, (
            f"detection took {elapsed:.2f}s, so the poll slice is not being "
            "honoured and the full budget would still be spent waiting"
        )
        queue.close()

    def test_a_death_is_caught_even_when_the_queue_is_never_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Liveness must be checked on the progress path, not only when idle.

        The empty-poll check catches a stalled collector. It cannot catch a worker
        that dies while other workers keep the queue busy, because that collector
        never idles -- it sits in the normal loop, keeps receiving, and eventually
        waits for one aggregate that will never arrive. So the post-message check
        is load-bearing, and this is the only test that exercises it: the queue
        below is pre-filled and never drained, so the `Empty` branch cannot run.
        """
        monkeypatch.setattr(pipeline, "_RESULT_TIMEOUT_SECONDS", 2.0)
        monkeypatch.setattr(pipeline, "_LIVENESS_POLL_SECONDS", 0.05)
        queue: mp.Queue[Any] = mp.Queue()
        results: list[Any] = []

        # Messages already queued, so the collector reaches its post-message
        # liveness check while it still has work to do -- the branch the idle
        # check cannot cover. `expected` is beyond what is queued, so the loop
        # cannot exit on its own and cannot fall through to an empty poll before
        # the check has run.
        #
        # Four messages, not more: `mp.Queue.put` blocks once the OS pipe buffer
        # fills, so a large pre-fill deadlocks before any assertion runs. The
        # earlier feeder-thread version of this test hit exactly that.
        for i in range(4):
            queue.put(_worker_result(i))

        with pytest.raises(RuntimeError, match="dpi-lb-0"):
            pipeline._collect_streaming(
                queue,
                expected=99,
                buffer=None,
                results=results,
                processes=[_DeadProcess()],
            )

        # The check fires on the *first* message, before the queue can drain --
        # which is exactly why this differs from the stalled-collector test. It
        # also proves the death was noticed without waiting for the queue to empty.
        assert len(results) == 1, (
            "the death should be noticed on the first message, not after the "
            f"queue drains ({len(results)} collected)"
        )
        queue.close()


def test_the_liveness_poll_is_far_shorter_than_the_budget() -> None:
    """The shipped constants must keep detection prompt.

    The promptness test monkeypatches `_LIVENESS_POLL_SECONDS` to make itself fast,
    so it proves the *mechanism* honours the slice but says nothing about whether
    the shipped value is any good. This asserts the real values: a poll interval
    equal to the budget would restore the exact 120 s stall the fix removes, while
    passing every behavioural test above.
    """
    assert pipeline._LIVENESS_POLL_SECONDS < pipeline._RESULT_TIMEOUT_SECONDS / 10, (
        f"poll slice {pipeline._LIVENESS_POLL_SECONDS}s is not meaningfully "
        f"shorter than the {pipeline._RESULT_TIMEOUT_SECONDS}s budget, so "
        "detection would still be slow in production"
    )
    # And bounded in absolute terms, so an incident is diagnosed in seconds rather
    # than in minutes regardless of how the budget is later retuned.
    assert pipeline._LIVENESS_POLL_SECONDS <= 5.0


class TestHealthyRunUnaffected:
    def test_a_normal_staged_run_still_succeeds(self, tmp_path: Path) -> None:
        """The end-to-end check: supervision must not break the happy path.

        The cheapest possible "fix" for `D-13` is to raise whenever a process is
        not alive, which would pass every unit test above and break every real run.
        """
        result = run_pipeline_staged(
            TEST_DPI_PCAP,
            tmp_path / "out.pcap",
            num_load_balancers=2,
            fps_per_lb=2,
        )

        assert result.stats.total_packets > 0
        assert result.load_balancer_stats is not None
        assert result.fast_path_stats is not None

    def test_a_staged_run_with_blocking_still_reports_its_blocked_flows(
        self, tmp_path: Path
    ) -> None:
        """Supervision is orthogonal to policy; a blocked flow must still be found."""
        from dpi_engine.rule_manager import RuleManager

        rules = RuleManager()
        rules.block_app(AppType.YOUTUBE)

        result = run_pipeline_staged(
            TEST_DPI_PCAP,
            tmp_path / "out.pcap",
            rules,
            num_load_balancers=2,
            fps_per_lb=2,
        )

        assert any(app is AppType.YOUTUBE for _, app, _ in result.blocked_flows)
