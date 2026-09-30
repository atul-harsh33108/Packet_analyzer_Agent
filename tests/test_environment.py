"""Task 1 environment verification.

Confirms the toolchain requirements from DESIGN_DECISIONS.md are actually
satisfied in the active environment: Python 3.13, and both the runtime
dependency (dpkt) and the dev/test-only dependency (scapy) import cleanly.

dpkt's PyPI classifiers only list Python up to 3.9, but it is pure Python
with no version ceiling pin. This test is the empirical verification called
for in DESIGN_DECISIONS.md before committing to dpkt for Task 2.
"""

from __future__ import annotations

import sys


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
