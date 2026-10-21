"""Every package under `src/` must be packaged *and* type-checked (`T3-01`).

Adding `src/dpi_mcp/` as the second package exposed two silent omissions, neither of
which announced itself:

1. **The built wheel omitted it entirely.** `[tool.uv.build-backend]` had
   `module-name = "dpi_engine"`, and the uv backend packages exactly the modules it
   is told to. Verified by building a wheel and listing its contents:
   `dpi_mcp entries: 0`. Running from a source checkout, `import dpi_mcp` worked
   fine -- so the failure would have appeared only for someone who installed the
   package, which is the worst possible time to discover it.
2. **`mypy` was not checking it.** `[tool.mypy] packages` also named only
   `dpi_engine`, so `mypy` reported *"Success: no issues found"* having inspected
   none of the new code -- reported 17 files while 18 existed.

Both are the same class of defect this project has now hit repeatedly: a guarantee
that is true for the thing you remember to check and silently not true otherwise.
The fix is declaration, and this is the declaration being asserted.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
PYPROJECT = REPO / "pyproject.toml"


@pytest.fixture(scope="module")
def pyproject() -> dict:
    if not PYPROJECT.exists():
        pytest.fail(f"{PYPROJECT} is missing")
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def shipped_packages() -> set[str]:
    """Every package directory under `src/`, by the same definition the build uses."""
    return {
        d.name
        for d in SRC.iterdir()
        if d.is_dir() and (d / "__init__.py").exists()
    }


class TestEveryPackageIsTypeChecked:
    def test_mypy_is_told_about_every_package(self, pyproject: dict) -> None:
        declared = set(pyproject.get("tool", {}).get("mypy", {}).get("packages", []))
        missing = sorted(shipped_packages() - declared)
        assert not missing, (
            f"mypy is not checking {missing}. `[tool.mypy] packages` must list every "
            "package under src/, or mypy reports success having inspected none of "
            "them -- a green result that means nothing."
        )

    def test_the_mypy_list_is_not_a_bare_string(self, pyproject: dict) -> None:
        """A bare string would iterate character by character, or be ignored.

        Cheap, and it turns a plausible future edit into a clear failure rather than
        a silently narrowed check.
        """
        declared = pyproject.get("tool", {}).get("mypy", {}).get("packages")
        assert isinstance(declared, list), (
            f"[tool.mypy] packages is {type(declared).__name__}, expected a list"
        )

    def test_mypy_actually_reports_more_than_one_package(self, pyproject: dict) -> None:
        """Sanity: more than one package is declared, so this file is not vacuous."""
        declared = pyproject.get("tool", {}).get("mypy", {}).get("packages", [])
        assert len(declared) >= 2, (
            f"only {declared} declared; if that is right, this whole module is "
            "checking a condition that cannot occur"
        )


class TestEveryPackageIsShipped:
    def test_the_build_backend_is_told_about_every_package(
        self, pyproject: dict
    ) -> None:
        backend = pyproject.get("tool", {}).get("uv", {}).get("build-backend", {})
        module_name = backend.get("module-name")
        declared = (
            set(module_name) if isinstance(module_name, list) else {module_name}
        )
        missing = sorted(p for p in shipped_packages() - declared if p)
        assert not missing, (
            f"the wheel will not contain {missing}. "
            "`[tool.uv.build-backend] module-name` must list every package under "
            "src/ as a **list** -- with a single name the backend packages only that "
            "one module and silently leaves the rest out of the built wheel, which "
            "fails only for someone who installs the package."
        )

    def test_module_name_is_a_list(self, pyproject: dict) -> None:
        """**The exact bug this module was written for.**

        `module-name = "dpi_engine"` built a wheel with `dpi_mcp entries: 0`, and
        nothing in the test suite, the type checker, or a source-checkout import
        noticed.
        """
        module_name = (
            pyproject.get("tool", {})
            .get("uv", {})
            .get("build-backend", {})
            .get("module-name")
        )
        assert isinstance(module_name, list), (
            f"module-name is {type(module_name).__name__} ({module_name!r}); the uv "
            "backend needs a list to package more than one module"
        )

    def test_module_root_is_src(self, pyproject: dict) -> None:
        """The packages must be found where they actually live."""
        backend = pyproject.get("tool", {}).get("uv", {}).get("build-backend", {})
        assert backend.get("module-root") == "src", (
            "packages live under src/; a different module-root would build an empty "
            "wheel or fail loudly, and neither is obvious from reading the config"
        )


class TestEveryPackageDeclaresItIsTyped:
    def test_every_package_ships_a_py_typed_marker(self) -> None:
        """PEP 561: an annotated package without the marker is untyped to consumers.

        The existing config comment says the marker "would be excluded from the
        wheel" without being listed, so this is a real risk rather than a formality.
        """
        missing = sorted(
            name
            for name in shipped_packages()
            if not (SRC / name / "py.typed").exists()
        )
        assert not missing, (
            f"{missing} are fully annotated but ship no py.typed marker, so "
            "downstream users get no types from them"
        )

    def test_the_markers_are_empty_files(self) -> None:
        """A non-empty marker is ignored by type checkers, so it is decoration.

        Cheap, and it keeps the marker meaning what it claims to mean.
        """
        for name in shipped_packages():
            marker = SRC / name / "py.typed"
            if marker.exists():
                assert marker.read_text(encoding="utf-8").strip() == "", (
                    f"{marker} is not empty; PEP 561 markers must be empty files"
                )


class TestTheMcpSdkIsAnExtraAndNotADependency:
    """`DEC-09`: the SDK is optional, and the duplication that makes it so is guarded.

    The SDK is named twice -- once as the `[mcp]` extra that an end user opts
    into, and once in the dev group so the test suite actually runs against it.
    Two names for one pin is two facts, and facts drift. This asserts they have
    not.
    """

    def test_the_sdk_is_not_a_runtime_dependency(self, pyproject: dict) -> None:
        runtime = pyproject.get("project", {}).get("dependencies", [])
        assert not any(spec.startswith("mcp") for spec in runtime), (
            f"the SDK must stay an optional extra, not a runtime dependency: {runtime}. "
            "It brings an ASGI server and a web framework with it, and a pcap "
            "analyser should not make every user install a web stack."
        )

    def test_the_extra_and_the_dev_group_pin_the_same_version(
        self, pyproject: dict
    ) -> None:
        extra = pyproject.get("project", {}).get("optional-dependencies", {}).get("mcp", [])
        dev = pyproject.get("dependency-groups", {}).get("dev", [])
        assert extra, "the SDK must be offered as the [mcp] extra"
        assert any(spec.startswith("mcp") for spec in dev), (
            f"the SDK must be in the dev group so the stdio tests run instead of "
            f"skipping: {dev}"
        )
        assert sorted(extra) == sorted(spec for spec in dev if spec.startswith("mcp")), (
            f"the extra pins {extra} and the dev group pins "
            f"{[s for s in dev if s.startswith('mcp')]}. They are the same dependency "
            "and must be the same pin."
        )


class TestTheSharedFixturesAreTheSharedFixtures:
    """The fixtures directory holds the shared fixtures, and nothing else.

    A test that writes beside a shared fixture leaves a file **in the tree**,
    and the suite stays green while it does \u2014 the failure is invisible until
    someone commits it. That is exactly what happened once: an engine run wrote
    its output pcap next to `tests/fixtures/test_dpi.pcap` and the file was
    committed. So the directory is pinned, and adding a fixture is a deliberate
    act with a failing test attached.
    """

    EXPECTED = {"test_dpi.pcap"}

    def test_nothing_else_is_in_there(self) -> None:
        fixtures = SRC.parent / "tests" / "fixtures"
        present = {path.name for path in fixtures.iterdir() if path.is_file()}
        assert present == self.EXPECTED, (
            f"the fixtures directory holds {sorted(present)}; expected "
            f"{sorted(self.EXPECTED)}. A file here is usually a test that wrote "
            "beside a shared fixture."
        )


class TestTheScanIsReal:
    def test_there_are_more_than_one_packages(self) -> None:
        """Non-vacuity for this whole module.

        With one package under `src/`, every assertion above is satisfied trivially
        -- which is exactly how the two omissions survived until a second package
        arrived.
        """
        found = shipped_packages()
        assert len(found) >= 2, (
            f"only {sorted(found)} under src/; the omissions this guards against "
            "cannot occur with one package, so this module is currently vacuous"
        )
        assert "dpi_engine" in found
        assert "dpi_mcp" in found, (
            "dpi_mcp should be the second package; if it has gone, the guards below "
            "are testing a world that no longer exists"
        )
