"""Runs the Layer 2 tools with `mcp` made impossible to import (`T3-03`).

Separate from the test module because it has to run in a fresh interpreter: `mcp` is
not installed here, so *any* in-process assertion that the tools work without it passes
vacuously. This probe blocks the import actively and then checks that the block worked,
so the guarantee is measured rather than assumed.

Prints one machine-readable `RESULT` line for the caller to parse.
"""

from __future__ import annotations

import importlib.abc
import importlib.machinery
import pathlib
import sys
import tempfile

_REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))
sys.path.insert(0, str(_REPO / "tests"))


class _BlockMCP(importlib.abc.MetaPathFinder):
    """Refuses every `mcp` and `mcp.*` import, so an SDK dependency cannot hide."""

    def find_spec(
        self,
        fullname: str,
        path: object = None,
        target: object = None,
    ) -> importlib.machinery.ModuleSpec | None:
        if fullname == "mcp" or fullname.startswith("mcp."):
            raise ImportError(f"blocked by the T3-03 probe: {fullname}")
        return None


def main() -> int:
    sys.meta_path.insert(0, _BlockMCP())

    # Prove the block is real before trusting anything below it. Without this the probe
    # passes whether or not the tools depend on the SDK -- the trap it exists to avoid.
    try:
        import mcp  # noqa: F401
    except ImportError:
        pass
    else:
        print("BLOCK DID NOT WORK: `import mcp` succeeded", file=sys.stderr)
        return 2

    from conftest import TEST_DPI_PCAP
    from dpi_mcp.tools import RunMode, inspect_capture, run_dpi

    out = pathlib.Path(tempfile.mkdtemp()) / "out.pcap"
    profile = inspect_capture(TEST_DPI_PCAP)
    result = run_dpi(TEST_DPI_PCAP, out, mode=RunMode.SINGLE)

    print(
        f"RESULT packets={profile.packet_count} bytes={profile.captured_bytes} "
        f"ran={result.stats.total_packets} wrote={out.exists()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
