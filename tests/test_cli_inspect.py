"""CLI-level test for the `inspect` subcommand (Task 2)."""

from __future__ import annotations

from pathlib import Path

from dpi_engine.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
TEST_DPI_PCAP = FIXTURES / "test_dpi.pcap"


def test_inspect_reports_known_packet_count_and_bytes(capsys) -> None:
    exit_code = main(["inspect", str(TEST_DPI_PCAP)])

    captured = capsys.readouterr()
    assert exit_code == 0
    # These exact figures are cross-checked against the original OSC engine's
    # own sample report in OSC/README.md ("Total Packets: 77",
    # "Total Bytes: 5738"), giving early confidence the port reads pcaps
    # identically to the original for this fixture.
    assert "Packet count:   77" in captured.out
    assert "Total bytes:    5738" in captured.out


def test_inspect_missing_file_reports_clean_error(capsys) -> None:
    exit_code = main(["inspect", "does_not_exist.pcap"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "error:" in captured.err


def test_dump_prints_one_line_per_packet(capsys) -> None:
    exit_code = main(["dump", str(TEST_DPI_PCAP)])

    captured = capsys.readouterr()
    assert exit_code == 0
    lines = [line for line in captured.out.splitlines() if line.strip()]
    assert len(lines) == 77
    assert "192.168.1.100" in lines[0]
    assert "[SYN]" in lines[0]


def test_no_subcommand_prints_help(capsys) -> None:
    exit_code = main([])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "usage" in captured.out.lower()
