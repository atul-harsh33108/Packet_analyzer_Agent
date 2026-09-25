# DPI Engine Python Port — Design & Decisions

Reference document for the Python port of the C++ DPI engine (original preserved under /OSC).
Read this before touching code — it records *why*, not just *what*.

## Scope
Full feature parity with the original: PCAP read/write, Ethernet/IP/TCP/UDP parsing,
SNI/HTTP-Host/DNS classification, IP/app/domain/port blocking rules (with persistence),
classification reporting, filtered output PCAP. Multi-threaded C++ pipeline is replaced
with a multiprocessing pipeline (see Architecture).

Explicitly OUT of scope for this port: the future "agentic AI project" layer. This port
must stay clean and modular so that layer can wrap it later, but no agent-facing API is
built now.

## Toolchain
- Python 3.13, managed via `uv` (project init, dependency resolution, lockfile, venv).
- Package layout: `src/dpi_engine/` (importable package) + `tests/`.
- `pyproject.toml` pins `requires-python = ">=3.13,<3.14"`.

## Library choices (and why)
- **dpkt** — PCAP file I/O and Ethernet/IP/TCP/UDP header parsing. Chosen over hand-rolling
  this layer because it's a solved, well-tested problem and hand-rolling it is exactly where
  the original C++ code's alignment/strict-aliasing bugs came from. PyPI classifiers only
  list up to Python 3.9 but the package is pure Python with no version ceiling pin —
  verified working under 3.13 as the first task in execution; if that verification fails,
  fallback is a stdlib `struct`-only reader (already half-designed as the parsing fallback).
- **Hand-rolled SNI/HTTP-Host/DNS extraction** — kept hand-rolled (not delegated to scapy)
  specifically because this is the layer with the interesting, security-relevant bugs to fix,
  and because direct control over every bounds check is the whole point of the fix. Comments
  in this module should cross-reference the original bug (e.g. "fixes OSC bug: QUIC pointer
  underflow, see analysis").
- **scapy** — dev/test dependency only, used to cross-check hand-rolled TLS parsing against
  a trusted independent implementation in the differential test suite. Never a runtime
  dependency of the shipped tool.
- **ipaddress (stdlib)** — replaces the original's hand-rolled, unvalidated IP octet parser.
- **JSON** — replaces the original's hand-rolled INI-like rules file format. Safer parsing,
  no unguarded `stoi`-equivalent crash path on malformed input.

## Architecture: multiprocessing, hash-partitioned by five-tuple
Mirrors the original's LB→FP consistent-hashing design:
- Reader process (main process) parses packets, computes `hash(five_tuple) % N`, dispatches
  to one of N worker processes via `multiprocessing.Queue`.
- Each worker owns a private, bounded flow table (classification + rule-check happens here).
  Consistent hashing guarantees all packets of one connection land on the same worker, so
  flow state and SNI-based classification stay correct — this is why hash-partitioning was
  chosen over splitting the file into contiguous chunks (which would break flows spanning
  a chunk boundary).
- Workers push (packet, decision) results to a shared output queue; a writer in the main
  process writes the filtered PCAP and aggregates stats.
- Shutdown uses an explicit sentinel-drain protocol (not a fixed sleep) — every worker
  processes all queued input before exiting. This directly fixes the original's
  silent-packet-loss-on-shutdown bug.
- Rules are loaded once and passed to workers as an immutable snapshot at startup. Rule
  changes mid-run are out of scope for v1 (documented limitation, not a bug).

## Bugs fixed during the port (intentional behavioral differences from OSC)
These are expected differential-test deltas — document them there too so tests don't fight
the fix:
1. QUIC SNI extractor: `payload + i - 5` with no `i >= 5` guard caused an out-of-bounds read
   before the buffer start. Fixed by guarding the loop start, or omitting QUIC heuristic
   support entirely (decide during Task 5; default to omitting with a documented TODO).
2. TLS ClientHello parser: missing bounds check after skipping version+random (fixed offset
   43) before reading session ID length — could over-read on a short ClientHello.
3. `createPacketJob`-equivalent: TCP data-offset byte read without checking the full 20-byte
   TCP header actually fits in the buffer — heap over-read on truncated packets.
4. Unaligned/strict-aliasing struct-overlay reads for EtherType/TCP ports/seq/ack — replaced
   by dpkt's parsing, which does this correctly.
5. Domain rule matching: case-sensitive exact match vs. case-insensitive wildcard match
   allowed a case-swap bypass. Fixed: both normalize case consistently.
6. IP rule parsing: no octet validation, malformed strings silently corrupted rules. Fixed
   via `ipaddress` module, which rejects invalid input cleanly.
7. `classifyConnection` "CLASSIFIED is terminal" bug: a port-based fallback guess (e.g. plain
   HTTPS) permanently blocked a later, more accurate SNI-based reclassification. Fixed: only
   SNI/HTTP-confirmed states are terminal; port-guess states can be upgraded.
8. Connection eviction: O(n) linear scan for least-recently-used entry. Fixed via
   `collections.OrderedDict`-based O(1) LRU.
9. Rules file `stoi`-equivalent on port numbers: unguarded, could crash the whole process on
   a malformed rules file. Fixed via JSON parsing + caught `ValueError` with a clear message.

Found during porting (Task 4), not part of the original prior analysis, but the same bug
class as #5 above -- unanchored substring matching on short, generic-looking patterns:
10. `sniToAppType`'s Twitter/X pattern list included the bare substrings "x.com" and "t.co".
    "x.com" is a substring of "netflix.com" ("netfli" + "x.com"), misclassifying Netflix as
    Twitter. "t.co" is a substring of almost any ".com" domain ending in "t" before the dot
    (e.g. "microsoft.com" contains "t.co" as "microsof" + "t.com"), misclassifying Microsoft
    (and others, e.g. "wechat.com") as Twitter. Fixed: both patterns are now anchored to
    domain boundaries (exact match or proper subdomain) instead of bare substrings.

## Safety constraints (binding for all tasks, not just Task 11)
- Passive/offline, file-based only. No raw sockets, no live interface capture, no packet
  injection/replay, no elevated privileges required at any point.
- No network calls anywhere in the tool (runtime or test setup beyond fetching pinned deps).
- Output path must never silently overwrite the input path.
- Resource bounds enforced at every untrusted-input boundary: max packet size, max flow-table
  size (LRU-bounded), sane handling of adversarially large/many-packet files (bounded time
  and memory, no unbounded loops).
- Worker processes are pure compute — no filesystem or network access inside a worker.
- These constraints are tested explicitly in Task 11, but must not be violated by any earlier
  task's implementation.

## Testing strategy
- Unit tests per module with hand-crafted byte fixtures (Tasks 2-7).
- Integration test for the single-process pipeline before multiprocessing is introduced
  (Task 8) — isolates "pipeline logic" bugs from "multiprocessing" bugs.
- Differential test suite against the original OSC binary (Task 9), with an explicit,
  documented allowlist of intentional differences (the bug-fix list above).
- Multiprocessing output re-validated against the single-process output (Task 10), proving
  partitioning didn't change behavior, independent of the C++ comparison.
- Manual testing pass with real/sample captures as the final human acceptance gate (Task 12).

## Differential testing findings (Task 9)

Building and running the actual OSC C++ binary (via a gcc:13 Docker container --
the only C++17-capable compiler available; the host's installed MinGW g++ 6.3.0
predates C++17 `<optional>` support) against the same fixture confirmed both
suspected bugs empirically and surfaced one additional real scope difference:

1. **Confirmed empirically**: the compiled original classifies `www.netflix.com`
   and `www.microsoft.com` as `Twitter/X` (not `Netflix`/`Microsoft`), exactly as
   predicted by the "x.com"/"t.co" substring false-positive bugs found and fixed
   in Task 4. This is not a differential-testing failure -- it is the expected,
   documented, intentional difference (item 10 in "Bugs fixed during the port").
2. **New finding, not a bug**: `main_working.cpp`'s main loop classifies all DNS
   traffic (port 53) with a flat `AppType::DNS` tag and never calls
   `DNSExtractor::extractQuery` to resolve the actual queried domain, even
   though that extractor exists and is fully implemented elsewhere in the
   codebase. This port's pipeline.py DOES attempt DNS query resolution (via
   sni_extractor.extract_dns_query) and classifies DNS traffic by the specific
   app/domain queried when resolvable, falling back to generic DNS only when it
   isn't. This is a functional improvement over `main_working.cpp`'s scope, not
   a "fix" for a defined bug -- documented here as an accepted, intentional
   difference in the differential test's allowlist.
   - **Concrete consequence, found by actually running `--block-app YouTube`
     against both implementations**: the Python port drops one MORE packet
     than the C++ original for this fixture -- the DNS query for
     youtube.com. Because the original never resolves DNS query domains, a
     DNS packet can never be attributed to a specific app and therefore can
     never match an app-based block rule in the C++ binary; only the TLS
     ClientHello flow gets blocked there. The Python port's DNS-resolution
     improvement means app-based blocking now also correctly covers DNS
     traffic for that app. This is pinned as an exact, expected +1 packet
     delta in the differential test suite, not merely tolerated as noise.

## Bugs found and fixed in this port itself (not inherited from the original)

Found during Task 11's resource-bound testing, not present in the original C++ code
at all (it has no multiprocessing pipeline of this shape to have the bug in):
`run_pipeline_multiprocess` started worker processes before reading the input file,
but if `PcapReader` raised partway through dispatch (e.g. `PcapLimitExceededError`
from `max_total_packets`), the exception propagated straight out of the function
without ever sending the workers their shutdown sentinel or joining them --
leaving every started worker process permanently blocked on `input_queue.get()`
forever, hanging the calling process (observed directly: a pytest run reported
"5 passed" but the shell never returned control afterward). Fixed by wrapping
worker startup and packet dispatch in a `try/finally` that terminates and joins
all worker processes on any exception during dispatch, and only sends the normal
shutdown sentinel on the success path. This is the same bug *class* documented
elsewhere in this file (workers left running with no shutdown signal) but arising
from a different code path (an exception during dispatch, not a normal-but-early
stop) than the original's shutdown-races-with-push bug -- worth tracking
separately since it's specific to this port's multiprocessing design.

## Known behavioral quirks carried forward from the original (not bugs, not fixed)
- `sni_to_app_type` labels any recognized-but-unmapped SNI/Host as `AppType.HTTPS`,
  even when the underlying traffic is plain HTTP (port 80) rather than TLS. This
  matches the original's documented fallback intent ("if SNI is present but not
  recognized, still mark as TLS/HTTPS") and is preserved as-is rather than "fixed"
  into a more semantically correct label, since changing it would alter
  classification output beyond what was requested. Noted for the README.

## Known limitation found during Task 11 manual testing
If `run_pipeline`/`run_pipeline_multiprocess` fails partway through processing
(e.g. `max_total_packets` exceeded after some packets were already forwarded),
the output file is left on disk containing whatever packets were successfully
written before the failure, rather than being deleted. This is a valid,
non-corrupt pcap (bounded, no partial/garbage bytes), and the failure is still
reported clearly with a non-zero exit code -- so this does not violate any
safety constraint (no crash, no hang, no unbounded resource use, no silent
success). It is called out here because a caller re-running after fixing the
underlying issue (e.g. raising the limit) should be aware the previous partial
output will be overwritten, not appended to. Deleting partial output
automatically on failure was considered but not implemented, since it would
discard partially-successful work with no explicit request to prioritize
"clean failure" over "preserve partial progress" -- a genuine design tradeoff,
not a clear-cut bug.

## Minor efficiency note (not a safety issue) found during Task 11 manual testing
In `run_pipeline_multiprocess`, the output-path-equals-input-path check only fires
when `PcapWriter` is constructed, which happens *after* all worker processes have
been spawned, dispatched every packet, and been shut down/joined. This means a
run doomed to fail the overwrite check still pays the full cost of spawning
processes and processing every packet before reporting the error -- wasteful, but
not unsafe (confirmed: no hang, no crash, clean error, ~0.5s for the sample
fixture). A future optimization could validate the output path before spawning
workers; not done here since it's a performance nicety, not a correctness or
safety requirement.

## Open decisions deferred to implementation time
- Whether to implement QUIC SNI heuristic at all (default: omit, documented limitation).
- Exact default values for max packet size / max flow table size / max total packets
  (pick conservative defaults in Task 2/7, make configurable via CLI flags).
