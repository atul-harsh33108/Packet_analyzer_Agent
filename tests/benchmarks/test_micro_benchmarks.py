"""Per-packet microbenchmarks: dissect, extract, classify.

**Not run by default.** `--benchmark-disable` is set in the project's pytest
`addopts`. Note that pytest-benchmark then reports them as *passed* rather than
skipped, because the test body never executes -- so "all green" on this
directory does not mean the benchmarks ran. Run them with:

    uv run pytest tests/benchmarks --benchmark-enable

The point of this file is the baseline number, not the test result. `P-15` in
`AUDIT.md` records that per-packet throughput is *unmeasured* -- which is how
the port ended up in a state where nobody could say whether it is fast enough
for a real capture. These are the numbers that will change if a refactor makes
the hot path slower, and the ones to compare against when `T0-11` replaces
the per-packet result with a decision bitmap.

First baseline, 4000-packet synthetic capture / Windows / Python 3.13:

    sni_to_app_type      0.6 us
    extract_sni          1.4 us
    extract_dns_query    1.6 us
    extract_http_host    6.5 us   <- 5x the other extractors
    parse_packet        11.3 us   <- the dominant per-packet cost

`extract_http_host` being an outlier is `AUDIT.md`'s O(payload) claim measured
rather than asserted; `T0-07` replaces that scan with a bounded one.

Timings are only comparable within a machine. `pytest-benchmark` writes a
`.benchmarks/` directory with the machine's calibration for reference.
"""

from __future__ import annotations

import sys
from pathlib import Path

from dpi_engine.packet_parser import parse_packet
from dpi_engine.pcap_io import RawPacket
from dpi_engine.sni_extractor import extract_dns_query, extract_http_host, extract_sni
from dpi_engine.types import sni_to_app_type

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_resource_bounds import _build_tiny_tcp_packet


def _client_hello(hostname: bytes = b"benchmark.example.com") -> bytes:
    """A minimal but structurally valid TLS ClientHello carrying an SNI."""
    server_name = hostname
    sni_list = b"\x00" + len(server_name).to_bytes(2, "big") + server_name
    sni_ext = b"\x00\x00" + (len(sni_list) + 2).to_bytes(2, "big") + sni_list
    extensions = sni_ext
    body = (
        b"\x03\x03"  # client version
        + b"\x00" * 32  # random
        + b"\x00"  # session id length
        + b"\x00\x02\x00\x2f"  # cipher suites
        + b"\x01\x00"  # compression methods
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def _http_request() -> bytes:
    return b"GET /index.html HTTP/1.1\r\nHost: www.benchmark.example\r\nUser-Agent: bench\r\n\r\n"


def _dns_query() -> bytes:
    labels = b"".join(
        bytes([len(p)]) + p for p in (b"www", b"benchmark", b"example", b"com")
    )
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x00\x01\x00\x01"


# Fixtures built once at module scope; building them inside the timed loop
# would measure the fixture, not the operation under test.
TCP_FRAME = _build_tiny_tcp_packet(1)
TCP_RAW = RawPacket(ts_sec=1700000000, ts_usec=0, data=TCP_FRAME, orig_len=len(TCP_FRAME))
CLIENT_HELLO = _client_hello()
HTTP = _http_request()
DNS = _dns_query()
NAMES = [
    "www.google.com",
    "youtube.com",
    "api.facebook.com",
    "cdn.example.net",
    "unknown-host.example",
]


def test_benchmark_parse_packet(benchmark) -> None:  # type: ignore[no-untyped-def]
    benchmark(parse_packet, TCP_RAW)


def test_benchmark_extract_sni(benchmark) -> None:  # type: ignore[no-untyped-def]
    benchmark(extract_sni, CLIENT_HELLO)


def test_benchmark_extract_http_host(benchmark) -> None:  # type: ignore[no-untyped-def]
    benchmark(extract_http_host, HTTP)


def test_benchmark_extract_dns_query(benchmark) -> None:  # type: ignore[no-untyped-def]
    benchmark(extract_dns_query, DNS)


def test_benchmark_sni_to_app_type(benchmark) -> None:  # type: ignore[no-untyped-def]
    """The classification table itself. OSC did this with a chain of
    `std::string::find`; this port uses an ordered table of rules, so this is
    the number that says whether that rewrite was worth it."""
    benchmark(sni_to_app_type, NAMES[0])
