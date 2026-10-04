"""Shared test configuration for the whole suite.

This file exists to remove duplication that had accreted across nine test
modules: each one independently declared its own fixture paths, using three
different expressions for what turned out to be two directories. That was not
merely repetitive -- it was ambiguous, because `FIXTURES` resolved to a
*different directory* depending on which file you read:

    tests/test_differential.py           FIXTURES = parents[1]/"fixtures"
                                         -> tests/fixtures            (shared)
    tests/test_differential_edge_cases.py FIXTURES = parent/"fixtures"
                                         -> tests/differential/fixtures (local)

Two directories, one name. Every path now comes from here, with names that say
which directory they mean.

The constants are module-level rather than pytest fixtures because the test
modules that use them reference them inside test bodies, and importing keeps
the diff to one line per file instead of adding a parameter to every test
signature. `tests/` has no `__init__.py`, so pytest's default "prepend" import
mode puts it on `sys.path` and `from conftest import ...` resolves for every
module beneath it.

`test_environment.py` asserts that no test module re-declares these paths, so
this cannot silently grow back.
"""

from __future__ import annotations

from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent

#: Captures shared across the suite: the real OSC sample capture.
SHARED_FIXTURES = TESTS_DIR / "fixtures"

#: Hand-built adversarial fixtures for the differential suite. Local to
#: ``tests/differential/`` -- deliberately *not* the same directory as
#: ``SHARED_FIXTURES``, which was the whole point of renaming.
DIFFERENTIAL_FIXTURES = TESTS_DIR / "differential" / "fixtures"

#: The sample capture most tests read. 77 packets, mixed TCP/UDP, carrying
#: TLS ClientHellos, HTTP Host headers and DNS queries.
TEST_DPI_PCAP = SHARED_FIXTURES / "test_dpi.pcap"

#: Filenames (not paths) of the differential edge-case fixtures.
EDGE_CASE_FIXTURE_NAMES = (
    "control_normal_capture.pcap",
    "truncated_client_hello.pcap",
    "truncated_tcp_header.pcap",
    "oversized_declared_lengths.pcap",
)

__all__ = [
    "DIFFERENTIAL_FIXTURES",
    "EDGE_CASE_FIXTURE_NAMES",
    "SHARED_FIXTURES",
    "TESTS_DIR",
    "TEST_DPI_PCAP",
]
