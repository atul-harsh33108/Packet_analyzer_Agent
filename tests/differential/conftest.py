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

__all__ = ["run_pipeline", "run_pipeline_multiprocess"]


def run_pipeline(*args: object, **kwargs: object) -> object:
    """`dpi_engine.pipeline.run_pipeline`, pinned to the C++ reference behaviour.

    `DEC-05` folds each flow together with its reverse direction by default.
    The C++ original never does -- it keys every direction separately -- so
    leaving folding on here would show up as a lower active-flow count, combined
    per-flow byte totals, and a populated `packets_in`/`bytes_in` on *every*
    fixture with bidirectional traffic. That would drown the real signal this
    suite exists to detect.

    Differential mode is where parity is the entire point, so it opts out. Every
    other suite should exercise the default (folding on): the product-correct
    behaviour needs coverage too, and `tests/test_staged_pipeline.py` and
    `tests/test_worker.py` supply it.
    """
    kwargs.setdefault("fold_bidirectional", False)
    from dpi_engine.pipeline import run_pipeline as _run_pipeline

    return _run_pipeline(*args, **kwargs)  # type: ignore[arg-type]


def run_pipeline_multiprocess(*args: object, **kwargs: object) -> object:
    """As `run_pipeline`, for the multiprocessing variant -- the differential
    suite dispatches on the same canonical key, so folding would skew which
    worker sees which flow as well as the counts."""
    kwargs.setdefault("fold_bidirectional", False)
    from dpi_engine.pipeline import run_pipeline_multiprocess as _run_mp

    return _run_mp(*args, **kwargs)  # type: ignore[arg-type]


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
