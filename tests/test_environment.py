"""Environment and test-suite hygiene verification.

Confirms the toolchain requirements from DESIGN_DECISIONS.md are actually
satisfied in the active environment: Python 3.13, and both the runtime
dependency (dpkt) and the dev/test-only dependency (scapy) import cleanly.

dpkt's PyPI classifiers only list Python up to 3.9, but it is pure Python
with no version ceiling pin. This test is the empirical verification called
for in DESIGN_DECISIONS.md before committing to dpkt for Task 2.

The second half guards the test suite's own structure -- see
`test_no_test_module_redeclares_fixture_paths`.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent


def test_python_version_is_313_or_compatible() -> None:
    assert sys.version_info >= (3, 13), (
        f"Expected Python >= 3.13, got {sys.version_info.major}."
        f"{sys.version_info.minor}.{sys.version_info.micro}"
    )
    assert sys.version_info < (3, 14), (
        "pyproject.toml pins requires-python to <3.14; environment drifted."
    )


def test_dpkt_imports() -> None:
    import dpkt

    # Touch a couple of the specific symbols this project relies on to make
    # sure the pure-Python package is fully usable under 3.13, not just
    # importable.
    assert hasattr(dpkt, "pcap")
    assert hasattr(dpkt, "ethernet")
    assert hasattr(dpkt.ethernet, "Ethernet")


def test_scapy_imports() -> None:
    # scapy is a dev/test-only dependency (see DESIGN_DECISIONS.md) used to
    # cross-check hand-rolled TLS parsing in the differential test suite.
    import scapy  # noqa: F401
    from scapy.layers import tls  # noqa: F401


def test_dpi_engine_package_imports() -> None:
    import dpi_engine

    assert dpi_engine.__version__


# --- suite structure -------------------------------------------------------------


def _modules_under_tests() -> list[Path]:
    return sorted(
        p
        for p in TESTS_DIR.rglob("test_*.py")
        # tests/differential/fixtures/ holds a generator script, not tests.
        if "fixtures" not in p.parts
    )


def test_no_test_module_redeclares_fixture_paths() -> None:
    """Fixture paths must have exactly one home: tests/conftest.py.

    Nine test modules used to declare their own, via three different
    expressions for two directories -- and `FIXTURES` meant a *different
    directory* depending on which file you read, which is the kind of trap
    that produces a confusing failure much later. This makes the
    single-source rule mechanical rather than a convention.
    """
    offenders: list[str] = []
    for module in _modules_under_tests():
        tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
        for node in tree.body:
            targets: list[str] = []
            if isinstance(node, ast.Assign):
                targets = [
                    t.id for t in node.targets if isinstance(t, ast.Name)
                ]
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                targets = [node.target.id]
            for name in targets:
                if name in {"FIXTURES", "DIFF_FIXTURES", "SHARED_FIXTURES", "TEST_DPI_PCAP"}:
                    offenders.append(f"{module.relative_to(TESTS_DIR)}:{node.lineno} {name}")

    assert not offenders, (
        "fixture paths must come from tests/conftest.py, not be re-declared:\n  "
        + "\n  ".join(offenders)
    )


def test_fixture_paths_point_at_real_directories() -> None:
    """The canonical paths must resolve, and to two *distinct* directories.

    Guards the specific confusion this refactor removed: if the shared and
    differential fixture directories ever collapse to the same path, tests
    would silently read the wrong files.
    """
    import conftest

    assert conftest.SHARED_FIXTURES.is_dir(), conftest.SHARED_FIXTURES
    assert conftest.DIFFERENTIAL_FIXTURES.is_dir(), conftest.DIFFERENTIAL_FIXTURES
    assert conftest.SHARED_FIXTURES != conftest.DIFFERENTIAL_FIXTURES
    assert conftest.TEST_DPI_PCAP.is_file(), conftest.TEST_DPI_PCAP


def test_cpp_available_fixture_is_defined_exactly_once() -> None:
    """`cpp_available` decides whether the parity suite runs at all.

    It was defined twice, with different scopes and each probing Docker with a
    different capture. There must now be exactly one definition, and it belongs
    in tests/differential/conftest.py rather than in a test module.
    """
    differential_conftest = TESTS_DIR / "differential" / "conftest.py"

    def _defines_it(path: Path) -> bool:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        return any(
            isinstance(node, ast.FunctionDef) and node.name == "cpp_available"
            for node in ast.walk(tree)
        )

    offenders = [str(m.relative_to(TESTS_DIR)) for m in _modules_under_tests() if _defines_it(m)]

    assert not offenders, (
        "cpp_available belongs in tests/differential/conftest.py, not in a test "
        f"module; found it in {offenders}"
    )
    assert _defines_it(differential_conftest), (
        f"{differential_conftest} must define the cpp_available fixture; "
        "the differential tests depend on it"
    )
