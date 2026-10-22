"""CLI-level tests for the `run` subcommand."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest

from conftest import TEST_DPI_PCAP
from dpi_engine.cli import main
from dpi_engine.pcap_io import PcapReader
from dpi_engine.run_store import RunStore
from dpi_mcp.tools.runs import query_flows


def test_run_produces_filtered_output_and_report(tmp_path: Path, capsys) -> None:
    output = tmp_path / "output.pcap"

    exit_code = main(
        ["run", str(TEST_DPI_PCAP), str(output), "--block-app", "YouTube"]
    )

    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Total packets read:  77" in out
    assert "Dropped:" in out
    assert "=== Blocked Flows" in out
    assert "YouTube" in out
    assert output.exists()

    with PcapReader(output) as reader:
        packets = list(reader)
    assert len(packets) < 77


def test_run_with_no_rules_forwards_everything(tmp_path: Path, capsys) -> None:
    output = tmp_path / "output.pcap"

    exit_code = main(["run", str(TEST_DPI_PCAP), str(output)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Dropped:             0" in out


def test_run_unknown_app_reports_clean_error(capsys) -> None:
    exit_code = main(
        ["run", str(TEST_DPI_PCAP), "out.pcap", "--block-app", "NotARealApp"]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error:" in captured.err


def test_run_unsupported_domain_pattern_is_rejected(capsys) -> None:
    """A '*' in a position the matcher cannot honour must fail loudly at rule
    construction time, not become a rule that silently never matches (which is
    what OSC's original did)."""
    exit_code = main(
        ["run", str(TEST_DPI_PCAP), "out.pcap", "--block-domain", "foo*.com"]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Unsupported domain pattern" in captured.err


def test_run_save_rules_writes_the_effective_rule_set(tmp_path: Path) -> None:
    output = tmp_path / "output.pcap"
    rules_path = tmp_path / "rules.json"

    exit_code = main(
        [
            "run",
            str(TEST_DPI_PCAP),
            str(output),
            "--block-app",
            "YouTube",
            "--save-rules",
            str(rules_path),
        ]
    )
    assert exit_code == 0
    assert rules_path.exists()

    saved = json.loads(rules_path.read_text(encoding="utf-8"))
    assert saved["blocked_apps"] == ["YOUTUBE"]


def test_version_flag(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "dpi-engine" in out


def test_run_with_workers_flag_uses_multiprocess_and_reports_per_stage(
    tmp_path: Path, capsys
) -> None:
    output = tmp_path / "output.pcap"

    exit_code = main(["run", str(TEST_DPI_PCAP), str(output), "--workers", "4"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "4 fast-path worker process(es)" in out
    assert "Per-stage packets:" in out
    assert "Total packets read:  77" in out

    with PcapReader(output) as reader:
        packets = list(reader)
    assert len(packets) == 77


def test_run_with_load_balancers_uses_the_staged_pipeline(tmp_path: Path, capsys) -> None:
    output = tmp_path / "output.pcap"

    exit_code = main(
        [
            "run",
            str(TEST_DPI_PCAP),
            str(output),
            "--load-balancers",
            "2",
            "--fps-per-lb",
            "2",
        ]
    )
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "2 load balancer(s) -> 4 fast-path process(es)" in out
    # Both tiers report, which is the point of reproducing the two-tier shape.
    assert "=== Pipeline Stages ===" in out
    assert "Load balancers:" in out
    assert "Fast paths (aggregate):" in out
    assert "to fast-path" in out

    with PcapReader(output) as reader:
        assert len(list(reader)) == 77


def test_run_rejects_workers_and_load_balancers_together(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "run",
            str(TEST_DPI_PCAP),
            str(tmp_path / "o.pcap"),
            "--workers",
            "4",
            "--load-balancers",
            "2",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "mutually exclusive" in captured.err


def test_run_rejects_zero_workers(capsys) -> None:
    exit_code = main(["run", str(TEST_DPI_PCAP), "out.pcap", "--workers", "0"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "--workers must be >= 1" in captured.err


def test_run_json_output_is_machine_readable(tmp_path: Path, capsys) -> None:
    output = tmp_path / "output.pcap"

    exit_code = main(
        ["run", str(TEST_DPI_PCAP), str(output), "--json", "--block-app", "YouTube"]
    )
    out = capsys.readouterr().out
    assert exit_code == 0

    payload = json.loads(out)
    assert payload["stats"]["total_packets"] == 77
    assert payload["stats"]["dropped_packets"] > 0
    assert "YouTube" in payload["app_counts"]
    assert payload["quic"]["sni_extraction_supported"] in (True, False)
    # One blocked flow per dropped five-tuple, and YouTube has exactly two
    # five-tuples in this fixture (the TLS flow and its DNS query).
    assert len(payload["blocked_flows"]) == 2
    assert all(entry["app"] == "YouTube" for entry in payload["blocked_flows"])
    # Top names and flow states are the previously-dead global report, and must
    # now actually appear in normal output.
    assert payload["flows"]["top_domains"]
    assert payload["flows"]["states"]


def test_run_flow_timeout_zero_is_accepted(tmp_path: Path, capsys) -> None:
    output = tmp_path / "output.pcap"
    exit_code = main(
        ["run", str(TEST_DPI_PCAP), str(output), "--flow-timeout", "0"]
    )
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Total packets read:  77" in out


def test_run_refuses_to_overwrite_input(capsys) -> None:
    exit_code = main(["run", str(TEST_DPI_PCAP), str(TEST_DPI_PCAP)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error:" in captured.err


def test_run_reports_unwritable_output_path_as_an_error_not_a_traceback(
    tmp_path: Path, capsys
) -> None:
    """D-04. When the output path cannot be opened, the CLI must exit 1 with an
    `error: ...` line on stderr.

    Before the fix, `PcapWriter.__init__` called `open()` unguarded, so the bare
    `FileNotFoundError` escaped `main()` entirely -- no exit code, no message,
    and a raw traceback in the user's terminal."""
    unwritable = tmp_path / "no-such-dir" / "out.pcap"

    try:
        exit_code = main(["run", str(TEST_DPI_PCAP), str(unwritable)])
    except OSError as exc:
        pytest.fail(
            f"an unwritable output path escaped main() as {type(exc).__name__}: {exc}"
        )

    captured = capsys.readouterr()
    assert exit_code == 1, f"expected exit code 1, got {exit_code}"
    assert "error:" in captured.err, f"expected an error on stderr, got {captured.err!r}"
    assert "Traceback" not in captured.err, f"a traceback leaked to the user: {captured.err!r}"


def test_run_unwritable_output_path_creates_nothing(tmp_path: Path) -> None:
    """A failed run must not leave a truncated file that a later run could
    mistake for real output. Asserted regardless of which exception the CLI
    raises, so this checks the filesystem state rather than the error path."""
    unwritable = tmp_path / "no-such-dir" / "out.pcap"

    with contextlib.suppress(OSError):
        main(["run", str(TEST_DPI_PCAP), str(unwritable)])

    assert not unwritable.exists()
    assert not unwritable.parent.exists()


# ---------------------------------------------------------------------------
# D-03: --live-rules must not be a silent no-op
# ---------------------------------------------------------------------------


def test_cli_passes_live_rules_to_the_staged_pipeline(
    tmp_path: Path, monkeypatch
) -> None:
    """`--live-rules` must actually reach `run_pipeline_staged`.

    `cli._execute` assembles one `common` kwargs dict and splats it into
    whichever variant is selected. Anything absent from that dict is dropped
    without a trace -- which is exactly how `--live-rules` came to be ignored
    under `--load-balancers`. This spies on the call rather than inferring
    behaviour from the run's output, because the failure mode *is* silence: the
    run produced perfectly plausible results either way.
    """
    from dpi_engine import cli

    captured: dict[str, object] = {}
    real = cli.run_pipeline_staged

    def spy(*args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(cli, "run_pipeline_staged", spy)
    exit_code = main(
        [
            "run",
            str(TEST_DPI_PCAP),
            str(tmp_path / "out.pcap"),
            "--load-balancers",
            "2",
            "--live-rules",
        ]
    )

    assert exit_code == 0, f"run failed with exit code {exit_code}"
    assert captured.get("live_rules") is True, (
        f"--live-rules was not forwarded to run_pipeline_staged; kwargs were "
        f"{sorted(captured)}. The flag was accepted and then silently ignored (D-03)."
    )


def test_live_rules_help_states_that_single_process_ignores_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The flag's help text is part of the defect.

    It promised a per-worker control channel unconditionally, but in
    single-process mode there is nothing that could mutate the ruleset mid-run
    (a one-shot CLI run owns its RuleManager and nothing else touches it), so
    the channel is deliberately not opened there. That is correct behaviour
    with no warning attached -- the promise simply has to be qualified.

    Asserted against what `run --help` actually prints, rather than against the
    argparse internals: the flag is registered on the `run` subparser, and the
    text a user reads is the contract.
    """
    with pytest.raises(SystemExit):
        main(["run", "--help"])

    out = capsys.readouterr().out
    assert "--live-rules" in out
    assert "single-process" in out or "single process" in out, (
        "--live-rules does nothing in single-process mode, and the help text "
        "must say so rather than promising a control channel unconditionally (D-03)"
    )


# ---------------------------------------------------------------------------
# The store: `dpi-engine run --store-root` (`T3-09`)
# ---------------------------------------------------------------------------
#
# Phase 3 left a gap: the store is the agent tree's data layer, and the only
# thing that populated it was the MCP server -- so an operator with the CLI had
# no way to create a stored run. These are the CLI's half of that loop.


def _printed_run_id(err: str) -> str:
    """The run id the CLI printed, or a failure that says what was missing."""
    for line in err.splitlines():
        if line.startswith("Stored run: "):
            return line.removeprefix("Stored run: ").strip()
    raise AssertionError(f"the CLI printed no run id; stderr was:\n{err}")


def test_run_with_store_root_writes_a_stored_run(tmp_path: Path, capsys) -> None:
    output = tmp_path / "output.pcap"
    store_root = tmp_path / "store"

    exit_code = main(
        ["run", str(TEST_DPI_PCAP), str(output), "--store-root", str(store_root)]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    run_id = _printed_run_id(captured.err)
    store = RunStore(store_root)
    assert [summary.run_id for summary in store.list_runs()] == [run_id]
    record = store.load(run_id)
    assert record.run_id == run_id
    assert record.flows, "a stored run with no flows cannot answer a question about them"


def test_the_stored_run_is_queryable_by_the_agent_tool(tmp_path: Path, capsys) -> None:
    """The point of storing a run: an agent asks questions about it afterwards.

    The MCP layer's `query_flows` reads the store, so the CLI's run and the
    agent's tool are one pipeline -- not two stores and a manual copy between
    them.
    """
    output = tmp_path / "output.pcap"
    store_root = tmp_path / "store"

    assert (
        main(["run", str(TEST_DPI_PCAP), str(output), "--store-root", str(store_root)])
        == 0
    )
    run_id = _printed_run_id(capsys.readouterr().err)

    answer = query_flows(run_id, store_root=store_root)
    assert answer["flows"], "the agent's tool found no flows in the CLI's stored run"
    assert answer["matched"] == answer["returned"]


def test_the_run_id_does_not_pollute_machine_readable_output(
    tmp_path: Path, capsys
) -> None:
    """`--json` promises stdout is machine-readable, so the id goes to stderr.

    The report and the run id are two different things: one is the answer, the
    other is a handle on it.
    """
    output = tmp_path / "output.pcap"
    store_root = tmp_path / "store"

    exit_code = main(
        [
            "run",
            str(TEST_DPI_PCAP),
            str(output),
            "--store-root",
            str(store_root),
            "--json",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    json.loads(captured.out)  # pure JSON, or this raises
    assert _printed_run_id(captured.err)


def test_an_unusable_store_root_is_an_error_and_not_a_traceback(
    tmp_path: Path, capsys
) -> None:
    """A store that cannot be written is a failure the operator can act on."""
    output = tmp_path / "output.pcap"
    not_a_directory = tmp_path / "a-file"
    not_a_directory.write_text("not a directory", encoding="utf-8")

    exit_code = main(
        [
            "run",
            str(TEST_DPI_PCAP),
            str(output),
            "--store-root",
            str(not_a_directory),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "error:" in captured.err
    assert "Traceback" not in captured.err


def test_without_the_flag_nothing_is_stored(tmp_path: Path, capsys) -> None:
    """The flag is what stores a run, and the per-flow rows are only kept for it.

    Without it nothing is written and nothing is asked, so the flow table is
    not built -- the memory a run costs is the memory it needs.
    """
    output = tmp_path / "output.pcap"
    store_root = tmp_path / "store"

    assert main(["run", str(TEST_DPI_PCAP), str(output)]) == 0
    captured = capsys.readouterr()

    assert "Stored run:" not in captured.err
    assert not store_root.exists()


def test_cli_run_help_documents_the_store_flag(capsys) -> None:
    """A flag nobody can find is a flag nobody uses."""
    with pytest.raises(SystemExit):
        main(["run", "--help"])

    out = capsys.readouterr().out
    assert "--store-root" in out
    assert "run id" in out


def test_the_stored_run_records_the_rules_in_force(tmp_path: Path, capsys) -> None:
    """The ruleset fingerprint is part of the observation, so it is recorded.

    An empty fingerprint would mean "no rules", and a run that blocked an app
    would be stored as if it had blocked nothing.
    """
    output = tmp_path / "output.pcap"
    store_root = tmp_path / "store"

    assert (
        main(
            [
                "run",
                str(TEST_DPI_PCAP),
                str(output),
                "--store-root",
                str(store_root),
                "--block-app",
                "YouTube",
            ]
        )
        == 0
    )
    run_id = _printed_run_id(capsys.readouterr().err)

    record = RunStore(store_root).load(run_id)
    assert record.ruleset, "the stored run records no ruleset fingerprint"
    assert len(record.ruleset) == 16, (
        f"the ruleset fingerprint is {record.ruleset!r}; it is a 16-character hash"
    )


def test_storing_the_same_run_twice_is_idempotent(tmp_path: Path, capsys) -> None:
    """The run id is content-addressed, so the same observation is one record.

    Re-storing it is a no-op rather than a second file, and the second attempt
    does not fail: a job that runs the same capture twice has not found two
    different runs.
    """
    output = tmp_path / "output.pcap"
    store_root = tmp_path / "store"

    assert main(["run", str(TEST_DPI_PCAP), str(output), "--store-root", str(store_root)]) == 0
    first = _printed_run_id(capsys.readouterr().err)
    assert main(["run", str(TEST_DPI_PCAP), str(output), "--store-root", str(store_root)]) == 0
    second = _printed_run_id(capsys.readouterr().err)

    assert first == second
    assert len(RunStore(store_root).list_runs()) == 1
