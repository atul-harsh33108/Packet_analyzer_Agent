"""Differential tests against crafted edge-case pcaps (Task 9).

Runs both the Python pipeline and the real compiled C++ binary against
adversarial/malformed fixtures crafted specifically to exercise the bugs
fixed during the port (truncated Client Hello, truncated TCP header,
oversized declared-length fields). See fixtures/generate_edge_cases.py for
how these were built and DESIGN_DECISIONS.md for the bugs being targeted.

These fixtures were verified NOT to crash the C++ binary either (the
specific bugs found are subtler over-reads that don't necessarily crash on
every malformed input -- see individual test docstrings for what's actually
being asserted). The key property under test is that BOTH implementations
handle this input safely and, where behavior should be identical (no
SNI/domain extractable), actually agree.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dpi_engine.pipeline import run_pipeline

from .cpp_reference import CppReferenceUnavailable, run_cpp_reference

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def cpp_available():
    """See test_differential.py's identical fixture docstring for why this
    also does a real run_cpp_reference() call, not just build_reference_binary()."""
    from .cpp_reference import build_reference_binary

    try:
        build_reference_binary()
        run_cpp_reference(FIXTURES / "control_normal_capture.pcap")
    except CppReferenceUnavailable as exc:
        pytest.skip(f"C++ reference toolchain unavailable: {exc}")


def test_control_fixture_extracts_sni_identically(cpp_available, tmp_path: Path) -> None:
    """Sanity check for the harness itself: on a well-formed capture with
    no edge cases, both sides must extract the same SNI/app for the same
    domain. If this test fails, the harness or fixture is broken -- not
    the port's bug-fix logic (see the other tests in this file for that)."""
    fixture = FIXTURES / "control_normal_capture.pcap"

    cpp_result = run_cpp_reference(fixture)
    py_result = run_pipeline(fixture, tmp_path / "out.pcap")

    assert cpp_result.total_packets == py_result.stats.total_packets == 4
    assert cpp_result.forwarded_packets == py_result.stats.forwarded_packets == 4
    assert cpp_result.detected_domains == {"control.example.com": "HTTPS"}
    assert py_result.detected_domains["control.example.com"].name == "HTTPS"


def test_truncated_client_hello_does_not_crash_either_implementation(
    cpp_available, tmp_path: Path
) -> None:
    """Direct regression test for DESIGN_DECISIONS.md bug #2: a Client
    Hello truncated at offset 43 (exactly where the original had zero
    bounds check before reading the session ID length byte). Neither
    implementation should crash; neither should extract an SNI from a
    truncated handshake (there isn't one to find)."""
    fixture = FIXTURES / "truncated_client_hello.pcap"

    cpp_result = run_cpp_reference(fixture)  # must not raise/crash
    py_result = run_pipeline(fixture, tmp_path / "out.pcap")  # must not raise

    assert cpp_result.total_packets == py_result.stats.total_packets == 4
    assert cpp_result.forwarded_packets == py_result.stats.forwarded_packets == 4
    assert "truncated-test.example" not in cpp_result.detected_domains
    assert "truncated-test.example" not in py_result.detected_domains


def test_truncated_tcp_header_does_not_crash_either_implementation(
    cpp_available, tmp_path: Path
) -> None:
    """Direct regression test for the createPacketJob/packet_parser.cpp
    TCP-header-over-read bug class: an IP packet claiming TCP follows with
    fewer than 20 bytes actually present. Neither implementation should
    crash; both should treat this packet as not-TCP-parseable and skip
    classification (it's still counted as a total packet, just not
    forwarded/classified as TCP)."""
    fixture = FIXTURES / "truncated_tcp_header.pcap"

    cpp_result = run_cpp_reference(fixture)
    py_result = run_pipeline(fixture, tmp_path / "out.pcap")

    assert cpp_result.total_packets == py_result.stats.total_packets == 1
    assert cpp_result.forwarded_packets == py_result.stats.forwarded_packets == 0
    assert py_result.stats.other_packets == 1


def test_oversized_declared_lengths_does_not_crash_either_implementation(
    cpp_available, tmp_path: Path
) -> None:
    """Direct regression test for the "validate the length prefix but not
    the skipped region" bug class: a Client Hello whose session-ID-length
    byte claims 200 bytes when none actually follow. Neither implementation
    should crash or read out of bounds; both should fail to extract an SNI
    and simply forward the packet unclassified."""
    fixture = FIXTURES / "oversized_declared_lengths.pcap"

    cpp_result = run_cpp_reference(fixture)
    py_result = run_pipeline(fixture, tmp_path / "out.pcap")

    assert cpp_result.total_packets == py_result.stats.total_packets == 1
    assert cpp_result.forwarded_packets == py_result.stats.forwarded_packets == 1
    assert cpp_result.detected_domains == {}
    assert py_result.detected_domains == {}
