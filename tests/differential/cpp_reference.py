"""Build and run the OSC C++ reference binary via Docker, and parse its
text report output into a structure comparable to
dpi_engine.pipeline.PipelineResult.

See README.md in this directory for why Docker is used (the host's only
installed g++ predates C++17).

Safety note: OSC/ is always bind-mounted read-only (`:ro`) when building.
The compiler never writes anything back into OSC/; build output goes to
`tests/differential/bin/`, a gitignored build-artifact directory.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

OSC_DIR = Path(__file__).resolve().parents[2] / "OSC"
BIN_DIR = Path(__file__).resolve().parent / "bin"
BINARY_NAME = "dpi_simple"
DOCKER_IMAGE = "gcc:13"

_SOURCES = [
    "src/main_working.cpp",
    "src/pcap_reader.cpp",
    "src/packet_parser.cpp",
    "src/sni_extractor.cpp",
    "src/types.cpp",
]


class CppReferenceUnavailable(Exception):
    """Raised when Docker isn't available or the reference binary can't be
    built/run. Tests depending on this should skip (not fail) when this is
    raised -- the differential suite is a supplementary check, not a
    replacement for the unit/integration suites that don't depend on any
    external toolchain."""


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def build_reference_binary(force_rebuild: bool = False) -> Path:
    """Builds tests/differential/bin/dpi_simple via a gcc:13 Docker
    container if it doesn't already exist (or if force_rebuild=True).
    Returns the path to the built binary (Linux ELF binary, only runnable
    inside a Linux container -- see run_cpp_reference).
    """
    binary_path = BIN_DIR / BINARY_NAME
    if binary_path.exists() and not force_rebuild:
        return binary_path

    if not _docker_available():
        raise CppReferenceUnavailable(
            "Docker is not available on PATH; cannot build the C++ reference binary."
        )

    BIN_DIR.mkdir(parents=True, exist_ok=True)

    build_cmd = (
        "cd /tmp && cp -r /src/* . && "
        f"g++ -std=c++17 -O2 -I include -o /out/{BINARY_NAME} " + " ".join(_SOURCES)
    )
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{OSC_DIR}:/src:ro",
            "-v",
            f"{BIN_DIR}:/out",
            DOCKER_IMAGE,
            "bash",
            "-c",
            build_cmd,
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )

    if result.returncode != 0 or not binary_path.exists():
        raise CppReferenceUnavailable(
            f"Failed to build C++ reference binary.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    return binary_path


@dataclass(slots=True)
class CppRunResult:
    """Parsed output of a dpi_simple run, structured comparably to
    dpi_engine.pipeline.PipelineResult."""

    total_packets: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    active_flows: int = 0
    app_counts: dict[str, int] = field(default_factory=dict)  # keyed by display name
    detected_domains: dict[str, str] = field(default_factory=dict)  # domain -> app display name
    blocked_lines: list[str] = field(default_factory=list)
    raw_stdout: str = ""


_REPORT_FIELD_RE = re.compile(r"║\s*(Total Packets|Forwarded|Dropped|Active Flows):\s*(\d+)")
_APP_LINE_RE = re.compile(r"║\s*([A-Za-z0-9_/]+(?:\s[A-Za-z0-9_/]+)*)\s+(\d+)\s+([\d.]+)%")
_DOMAIN_LINE_RE = re.compile(r"^\s*-\s*(\S+)\s*->\s*(.+?)\s*$")
_BLOCKED_LINE_RE = re.compile(r"^\[BLOCKED\]\s*(.+)$")


def parse_cpp_report(stdout: str) -> CppRunResult:
    result = CppRunResult(raw_stdout=stdout)
    in_app_breakdown = False
    in_domains = False

    for line in stdout.splitlines():
        field_match = _REPORT_FIELD_RE.search(line)
        if field_match:
            name, value = field_match.group(1), int(field_match.group(2))
            if name == "Total Packets":
                result.total_packets = value
            elif name == "Forwarded":
                result.forwarded_packets = value
            elif name == "Dropped":
                result.dropped_packets = value
            elif name == "Active Flows":
                result.active_flows = value
            continue

        if "APPLICATION BREAKDOWN" in line:
            in_app_breakdown = True
            continue
        if "[Detected Applications/Domains]" in line:
            in_app_breakdown = False
            in_domains = True
            continue

        if in_app_breakdown:
            app_match = _APP_LINE_RE.search(line)
            if app_match:
                result.app_counts[app_match.group(1).strip()] = int(app_match.group(2))
            continue

        if in_domains:
            domain_match = _DOMAIN_LINE_RE.match(line)
            if domain_match:
                result.detected_domains[domain_match.group(1)] = domain_match.group(2)
            continue

        blocked_match = _BLOCKED_LINE_RE.match(line)
        if blocked_match:
            result.blocked_lines.append(blocked_match.group(1))

    return result


def run_cpp_reference(
    input_pcap: Path,
    args: list[str] | None = None,
) -> CppRunResult:
    """Runs the built reference binary (inside the same gcc:13 container,
    so no host-side execution of the Linux ELF binary is needed) against
    `input_pcap` with optional extra CLI args (e.g. ["--block-app",
    "YouTube"]). Returns the parsed report.

    Raises CppReferenceUnavailable if Docker or the binary aren't
    available/buildable.
    """
    binary_path = build_reference_binary()

    if not _docker_available():
        raise CppReferenceUnavailable("Docker is not available on PATH.")

    input_pcap = Path(input_pcap).resolve()
    run_cmd = (
        f"cp /bin_dir/{BINARY_NAME} /tmp/{BINARY_NAME} && chmod +x /tmp/{BINARY_NAME} && cd /tmp && "
        f"cp /input/{input_pcap.name} . && "
        f"./{BINARY_NAME} {input_pcap.name} output_cpp.pcap"
    )
    if args:
        run_cmd += " " + " ".join(args)

    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{binary_path.parent}:/bin_dir:ro",
            "-v",
            f"{input_pcap.parent}:/input:ro",
            DOCKER_IMAGE,
            "bash",
            "-c",
            run_cmd,
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )

    if result.returncode != 0:
        raise CppReferenceUnavailable(
            f"C++ reference binary failed to run.\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

    return parse_cpp_report(result.stdout)
