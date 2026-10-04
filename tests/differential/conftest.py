"""Fixtures local to the differential suite.

`cpp_available` lived here twice -- once in `test_differential.py` and once,
near-identically, in `test_differential_edge_cases.py`. Two copies of a fixture
whose whole job is to decide whether the suite can run at all is exactly the
kind of thing that drifts, so there is now one, here.

It lives in `tests/differential/` rather than the top-level `tests/conftest.py`
because only the differential tests need it, and because this directory *is* a
package (`__init__.py` present), which makes the relative import to
`cpp_reference` work exactly as it does in the test modules themselves.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from .cpp_reference import CppReferenceUnavailable, build_reference_binary, run_cpp_reference

if TYPE_CHECKING:
    from collections.abc import Iterator

# `tests/` has no __init__.py, so pytest's default "prepend" import mode puts it
# on sys.path and this resolves to tests/conftest.py -- the single source of
# truth for fixture paths. (A relative `..conftest` import is not available
# because `tests` is not itself a package.)
from conftest import TEST_DPI_PCAP


@pytest.fixture(scope="session")
def cpp_available() -> Iterator[None]:
    """Confirms the reference binary is built AND Docker is actually
    reachable right now.

    `build_reference_binary()` alone is not enough, since it returns early
    (without touching Docker) if the binary is already cached on disk from an
    earlier session. That would let a test proceed to call
    `run_cpp_reference()` and fail there, instead of skipping cleanly because
    the Docker daemon is not currently running.

    The connectivity probe is the cheapest real invocation of the binary, so it
    doubles as the check that the harness works and not just that a file
    exists.
    """
    try:
        build_reference_binary()
        run_cpp_reference(TEST_DPI_PCAP)  # cheap connectivity probe
    except CppReferenceUnavailable as exc:
        pytest.skip(f"C++ reference toolchain unavailable: {exc}")
    yield
