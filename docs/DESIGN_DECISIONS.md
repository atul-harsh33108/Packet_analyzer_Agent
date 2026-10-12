# DPI Engine Python Port — Design & Decisions

Reference document for the Python port of the C++ DPI engine (original preserved under
[`../OSC/`](../OSC/)). Read this before touching code — it records *why*, not just *what*.

> **Current status (2026-10-03):** the port is functionally complete against the original
> and clean under `ruff` and `mypy --strict`, with 404 passing tests. A full engineering
> audit found 22 open defects, 10 missing engineering rails, and 3 stale
> documentation cross-references. **Read [`AUDIT.md`](AUDIT.md) alongside this file** —
> it supersedes this document wherever the two disagree.
>
> | Document | Role |
> |---|---|
> | [`AUDIT.md`](AUDIT.md) | The verified findings. Wins on any disagreement. |
> | [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) | How the findings get fixed (30 tasks) |
> | [`TASK_TRACKER.md`](TASK_TRACKER.md) | Current state |
> | this file | *Why* the port is built this way |
> | [`WORKFLOW.md`](WORKFLOW.md) | Architecture diagrams (rewritten 2026-10-03) |

## Scope
Full feature parity with the original: PCAP read/write, Ethernet/IP/TCP/UDP parsing,
SNI/HTTP-Host/DNS/QUIC classification, IP/app/domain/port blocking rules (with
persistence and live mutation), classification reporting, filtered output PCAP,
and the original's two-tier load-balancer/fast-path topology. The C++ thread
pipeline is replaced with an equivalent multiprocessing pipeline (see
Architecture).

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
- **cryptography (optional extra `[quic]`)** — QUIC Initial packets need AES for header
  protection removal and payload decryption. This project will not hand-roll a block cipher,
  so the dependency is optional rather than required: QUIC *detection* and classification
  as "QUIC" must keep working on a minimal install, and the resulting limitation is reported
  rather than silently swallowed. See "Gap analysis" item 16.
- **scapy** — dev/test dependency only, used to cross-check hand-rolled TLS parsing against
  a trusted independent implementation. Implemented by `tests/property/test_scapy_cross_check.py`
  (`T1-07` increment 2, `DEC-03` decided 2026-10-12), which drives *both* directions: scapy
  parses our fixtures, and — the half that is not circular — `extract_sni` parses
  handshakes scapy constructs. Never a runtime dependency of the shipped tool.
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
  changes mid-run are supported via a per-worker control channel (`RuleBroadcaster`); the
  default is off because it costs one non-blocking queue drain per packet per worker.

Three entry points share one decision engine (`worker.FlowProcessor`), which is what makes
them provably equivalent rather than three implementations that happen to agree:
`run_pipeline` (single process), `run_pipeline_multiprocess` (one hop), and
`run_pipeline_staged` (the original's two-tier LB→FP graph). Tests assert all three
produce byte-identical output pcaps.

## Bugs fixed during the port (intentional behavioral differences from OSC)
These are expected differential-test deltas — document them there too so tests don't fight
the fix:
1. ~~QUIC SNI extractor: `payload + i - 5` with no `i >= 5` guard caused an out-of-bounds read
   before the buffer start.~~ **Superseded — see "Gap analysis" item 16.** This entry was
   written when the intended fix was "guard the loop start, or omit QUIC heuristic support
   entirely". Neither happened: the original extractor was not ported at all, and `quic.py`
   implements the full RFC 9000/9001 path instead. `QUICSNIExtractor::extract` is memory-unsafe
   *and* a functional no-op (it is never called by any OSC engine path, and even if it were,
   `payload[i-5]` is almost never `0x16` so `isTLSClientHello` would always reject). Kept here
   as the record of the original bug; the fix is item 16, not this item.
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

All five layers below are implemented and green. This section records what each one is for;
for the current counts and status see [`TASK_TRACKER.md`](TASK_TRACKER.md).

- **Unit tests per module** with hand-crafted byte fixtures. Covers every module including
  `quic.py` (39 tests, including the RFC 9001 Appendix A.1 key-derivation vectors) and
  `report.py` (28 tests).
- **Integration tests for the single-process pipeline** were written *before* multiprocessing
  was introduced, so "pipeline logic" bugs were never conflated with "multiprocessing" bugs.
  `tests/test_integration.py` builds real Ethernet/IP/UDP frames byte by byte and runs the
  whole pipeline over them — necessary because per-module unit tests cannot catch a feature
  that is fully implemented and still unreachable from the packet path. That is exactly how
  item 18's two QUIC defects were found.
- **Differential test suite** against the original OSC binary, compiled with `gcc:13` in a
  Docker container (the host's MinGW g++ 6.3.0 predates C++17 `<optional>`). Carries an
  explicit allowlist of intentional differences — the bug-fix list above plus the divergences
  recorded under item 17. Skips rather than fails when Docker is unavailable, since it is a
  supplementary cross-check.
- **Cross-variant equivalence**: all three pipeline entry points are asserted to produce
  byte-identical output pcaps, and a regression test
  (`test_every_flow_lands_on_exactly_one_fast_path`) pins the partitioning invariant that makes
  this possible.
- **Safety-constraint tests** (`tests/test_safety_constraints.py`) AST-scan the shipped
  source for forbidden constructs — raw sockets, `subprocess`, `eval`/`exec`, `urllib`, and
  more — and self-check that the scan is not passing vacuously.

### Known gaps in the test strategy

Honest list, tracked as `R-##` in [`AUDIT.md`](AUDIT.md) §3:

- **No property-based or fuzz testing.** For a codebase that exists because of byte-level
  parsing bugs, this is the wrong place to skip it. `hypothesis` is planned (`T1-07`).
- **No benchmark suite.** Three ad-hoc wall-clock assertions with large slack factors instead.
  The port's per-packet throughput is therefore **unmeasured** — see `P-15`.
- **No coverage measurement and no CI.** Not one command has ever run automatically.
- ~~`scapy`'s stated purpose is unimplemented~~ **Closed** (`T1-07` increment 2, 2026-10-12).
  It was declared here as a cross-check of the hand-rolled TLS parsing and no test performed
  that cross-check; `tests/property/test_scapy_cross_check.py` now does, in both directions.
  Verified to bite by mutating `_TLS_RECORD_HEADER_LEN` from 5 to 6: 16 of 25 tests fail,
  including "hand-rolled extractor failed on a ClientHello built by scapy".
- **Three flaky-by-construction tests** assert on wall-clock with large slack, and no
  `pytest-timeout` is installed — so a regression into the known hang path would hang the
  suite rather than fail it.

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

## Gap analysis against OSC, and the closing work (v0.2)

A full re-comparison of the port against every OSC source file found seven
capabilities present in the original but missing or dead in the port. All are
now implemented; the entries below record what was missing, why, and what
changed.

### 11. TCP connection state machine was declared but never driven
`Connection` carried `syn_seen`/`syn_ack_seen`/`fin_seen` and `ConnectionState`
carried `ESTABLISHED`, but nothing in the pipeline ever set any of them --
`FastPathProcessor::updateTCPState` (fast_path.cpp:246-277) was simply not
ported. Implemented as `ConnectionTracker.update_tcp_state` and called for every
TCP packet. Two invariants the original lacked: RST closes the flow immediately
instead of waiting for FIN+ACK, and CLOSED is absorbing (a later packet cannot
re-open a dead flow, which OSC would happily do). State precedence is now an
explicit total order, `BLOCKED > CLOSED > CLASSIFIED/ESTABLISHED > NEW`, so a
policy block is never masked by a later transport teardown. This changes no
forward/drop decision -- that comes from the pipeline's own monotonic per-flow
block set -- so it is a reporting and correctness improvement, not a behaviour
change.

### 12. `cleanup_stale` was implemented but never called
`FastPathProcessor::run` reaped idle flows every 100ms (fast_path.cpp:56); the
port's `cleanup_stale` was only reachable from tests, so idle flows were
reclaimed solely under LRU pressure. Now invoked automatically from
`get_or_create_connection` on a bounded cadence (`reap_interval_packets`,
default 65536) so the amortized cost stays negligible, and `update_connection`
refreshes LRU position so an actively-used flow is never a reaping candidate.
`--flow-timeout 0` disables the idle reaper, restoring the old behaviour.

### 13. The two-tier load-balancer topology was dropped entirely
`LoadBalancer`/`LBManager` (load_balancer.cpp) and the `reader -> LB* -> FP*`
graph in `dpi_engine.cpp:47-56` had no counterpart. Restored as
`load_balancer.py` + `run_pipeline_staged`.

Building it surfaced a bug that a faithful-looking port would have inherited:
**the original's two hash levels are degenerate.** `getLBForPacket` computes
`hash % lbs_.size()` and `selectFP` computes `hash % num_fps_` -- the same hash
modulo the same modulus -- so with the default 2 LBs x 2 FPs the two levels
always agree and only 2 of the 4 fast-paths ever receive a packet. Half the
worker pool idles permanently. Each level now mixes in its own salt
(`_SALT_TIER_2`), so the levels are independent.

A second, more serious bug surfaced while validating the topology. The obvious
way to make the LB stage worthwhile is to move *parsing* into it, so the parse
cost parallelises. That is wrong: a stateless reader holding only raw bytes can
only distribute by round-robin, so the two halves of one connection land in
different shards and the flow's state gets split across two fast-paths.
Measured on the sample capture: **61 tracked "connections" for 43 real ones**,
with per-flow classification half-applied. Routing by five-tuple requires
parsing first, which is exactly what OSC's reader did, so the faithful topology
is the correct one. Consequence, stated plainly in the code and README: the
reader still parses, the LB tier is queue-decoupling and observability rather
than throughput, and `--workers N` is the faster choice. A regression test
(`test_every_flow_lands_on_exactly_one_fast_path`) pins the invariant.

### 14. `GlobalConnectionTable`'s report was dead code in the original
`DPIEngine::initialize` builds a `GlobalConnectionTable` and registers every
tracker with it, and `GlobalConnectionTable::generateReport`
(connection_tracker.cpp:218-270) is a complete renderer -- app breakdown with
percentages and top-20 domains. `DPIEngine::processFile` calls
`generateReport()` and `generateClassificationReport()` and **never** calls
`global_conn_table_->generateReport()`. The port repeated this: it had
`combine_tracker_reports` and a `GlobalStats` type, used only by tests. Now the
aggregation runs on every run, and `report.render_top_domains` /
`render_flow_states` surface the result in normal `dpi-engine run` output.

### 15. Runtime rule mutation was removed
`DPIEngine` exposed `blockIP`/`unblockIP`/`blockApp`/`unblockDomain`/
`loadRules`/`saveRules` as callable *during* a run, backed by per-category
`std::shared_mutex`es (dpi_engine.cpp:335-402). The port's `RuleManager` was
documented as deliberately not-thread-safe and rules were fixed at startup.

Restored, and made safer in the process. `RuleManager` is now copy-on-write: it
holds one lock, and every mutation rebuilds an immutable `_RuleState` and
atomically rebinds it. Readers use a frozen `RuleSnapshot` whose every container
is immutable, so the packet hot path takes **no lock at all** and cannot observe
a torn update -- a stronger guarantee than the original's per-category
`shared_mutex`, and cheaper on the hot path. `RuleBroadcaster` ships new
snapshots to workers over a per-worker control queue (never mixed into the
packet queue, so an update can never be mistaken for a packet or reordered
relative to one); `run_pipeline_multiprocess(live_rules=True)` enables it and
`FlowProcessor.refresh_rules` costs one integer comparison per packet in the
steady state.

Two performance regressions were fixed while doing this. Rules are now keyed by
32-bit int, so the hot path no longer formats the source IP to a dotted quad and
re-parses it with `ipaddress` on **every packet** (the previous version did).
And `RuleSnapshot` is picklable, so shipping rules to a worker is a pickle
rather than re-deriving them.

### 16. `QUICSNIExtractor` was omitted
Deliberately dropped in v0.1, because the original's implementation is not a
QUIC parser: it scans for a `0x01` byte and calls `extract(payload + i - 5, ...)`
from `i = 0`, which reads before the buffer start whenever `i < 5`, and QUIC
Initial packets carry the ClientHello inside *encrypted* CRYPTO frames that
cannot be byte-scanned at all.

Implemented properly in v0.2 as `quic.py`: long-header parse, HKDF-SHA256 key
derivation from the DCID and the version's initial salt, header-protection
removal, packet-number reconstruction, AES-128-GCM payload protection, frame
walk, and CRYPTO-stream reassembly across packets -- the full RFC 9000/9001
path. Verified against the RFC 9001 Appendix A.1 key-derivation vectors.

`cryptography` is an **optional extra** rather than a hard dependency: this
project will not hand-roll a block cipher, and detection/classification as
"QUIC" must keep working without it. The degradation is reported rather than
swallowed (`quic_sni_supported()`, `unsupported_reason()`, a line in
`dpi-engine inspect`, and separate `quic_packets` / `quic_undecryptable`
counters), so "we saw QUIC but could not read it" is never mistaken for "there
was no QUIC".

### 17. Undeclared divergences found by the re-comparison
Two behavioural differences existed that the differential allowlist did not
record, i.e. they were effectively undocumented:

- **Classification priority order.** v0.1 checked the anchored `x.com`/`t.co`
  Twitter patterns *above the whole table*, but the original checks Twitter at
  position 6 (after WhatsApp, before Netflix). This silently re-prioritised it:
  `google.x.com` classified as `TWITTER` instead of `GOOGLE`, and likewise
  `meta.x.com`/`facebook.x.com`. The table in `types.py` is now a single
  ordered list of `_SniRule`s with anchored and substring patterns side by
  side, so there is exactly one place where order is expressed and it matches
  the original's `if/else-if` chain exactly. `types.py` carries an explicit
  warning not to hoist that check again.
- **Domain-rule semantics.** `main_working.cpp:60-62` does an unanchored
  substring search, so `--block-domain youtube` also blocks
  `notyoutube.example.org`. The port follows `rule_manager.cpp` instead --
  exact match, or explicit `*.suffix` for subdomains. Blocking *less* is the
  safe direction for a blocking tool, and the intent is now spelled out in the
  rule instead of being implicit. Pinned by two differential tests, one per
  direction.

Also fixed, as ordinary cleanups rather than behaviour changes:
`DomainPattern` now rejects a `*` in any position it cannot honour
(`foo*.com`) at insertion time, instead of storing a rule that silently never
matched; and `is_quic_initial` no longer accepts Version Negotiation, Retry,
0-RTT, Handshake or pre-draft-29 versions as "Initial", which OSC's
`isQUICInitial` did.

### 18. Two defects in the v0.2 QUIC integration, found by the new end-to-end tests

`tests/test_integration.py` builds real Ethernet/IP/UDP frames byte by byte and
runs the whole pipeline over them, precisely because per-module unit tests
cannot catch a feature that is fully implemented and still not reachable from
the packet path. It immediately found two things:

- **Non-Initial QUIC was reported as UNKNOWN.** The pipeline's QUIC branch was
  gated on `is_quic_initial`, so a Handshake or 1-RTT packet -- which is the
  overwhelming majority of QUIC on a real network -- never entered it and fell
  through to UNKNOWN. That made a capture full of modern encrypted traffic look
  like a capture full of unrecognisable noise, and it contradicted what the
  README claimed. Fixed by asking the two questions separately: `is_quic` (is
  this QUIC at all?) for classification and counting, then `is_quic_initial`
  (can we decrypt it?) before attempting extraction. `quic_undecryptable` now
  covers both "not an Initial" and "an Initial we could not read", so the
  coverage figure is honest in both cases.
- **`stale_timeout_seconds=None` silently disabled *all* reaping**, including
  reclamation of CLOSED flows, because `reap_if_due` short-circuited on the
  idle timeout being unset. A closed flow can never change again, so sweeping
  it is unconditionally safe and free; turning off idle timeouts must not leak
  every closed flow for the whole run. `reap_if_due` now always honours the
  cadence and passes the (possibly absent) timeout through, so `cleanup_stale`
  reaps terminal flows and skips only the idle comparison.

`reap_interval_packets` was also promoted from a module-private constant to a
parameter on all three pipeline entry points plus a `--reap-interval` CLI flag,
because DESIGN_DECISIONS had claimed the reaper cadence was configurable and it
was not.

### Dead code removed

- `combine_tracker_reports` / `GlobalStats` were implemented and tested but
  unreachable from any production path -- the same failure the original had
  with `GlobalConnectionTable::generateReport`. Now wired in (item 14).
- `LoadBalancer.select_fp` and `FastPath` were briefly written as a
  "wiring graph" that the staged pipeline then bypassed by passing flat queue
  lists to `_lb_main`, which would have left two copies of the selection logic.
  `_lb_main` now takes the `LoadBalancer` and calls `select_fp`, so there is
  one implementation.
- `src/dpi_engine/demo_classify.py` (the Task-7 scaffolding demo) was deleted.
  Nothing referenced it, and it carried its own `classify_packet` that had
  already diverged from the real pipeline (it ignored `src_port == 53`, did
  not handle QUIC, and performed no rule checks). A stale parallel
  implementation of the hot path is a liability, not documentation.
- `SNIExtractor::extractExtensions` (an OSC stub whose body was
  `// ... (abbreviated for brevity)`) is correctly *not* ported.

## Tooling added alongside v0.2

`ruff` (configured for E/W/F/I/UP/B/SIM/RUF, `OSC/` excluded as preserved
reference material) and `mypy --strict` are now dev dependencies with their
configuration in `pyproject.toml`, so `uv run ruff check .` and `uv run mypy`
are reproducible. The package also ships a `py.typed` marker (PEP 561), since
it is fully annotated and there is no reason to withhold the types from
downstream users.

mypy strict earned its keep immediately, by flagging three things that were
real: a heterogeneous `dict` of parsed rule deltas (restructured into typed
locals, which also separates the validation pass from the state swap), loop
variables shadowing across loops in the same function with incompatible queue
types, and a control queue typed as carrying only `RuleSnapshot` while the code
correctly also tolerated a `None` sentinel.

## Reporting: one denominator per quantity, and a dead table revived

OSC computes percentages over inconsistent denominators: `main_working.cpp:298`
divides per-app counts by *total packets read* (including ARP and other frames
that were never candidates for a rule), while `fast_path.cpp:387` divides by
*classified + unknown connections*, so two reports from the same run disagree.
The port now uses one documented denominator per quantity, stated in the output:
the drop rate is over *inspected* (TCP+UDP) packets, and the application
breakdown self-normalises over its own histogram. `report.py` also adds a JSON
form, which OSC had no equivalent of, and clamps bar widths instead of relying
on fixed-width box drawing that breaks as soon as a value exceeds its column.

## Known behavioural quirks carried forward from the original (not bugs, not fixed)
- `sni_to_app_type` labels any recognized-but-unmapped SNI/Host as `AppType.HTTPS`,
  even when the underlying traffic is plain HTTP (port 80) rather than TLS. This
  matches the original's documented fallback intent ("if SNI is present but not
  recognized, still mark as TLS/HTTPS") and is preserved as-is rather than "fixed"
  into a more semantically correct label, since changing it would alter
  classification output beyond what was requested. Noted for the README.
- Flows are keyed by the packet's exact five-tuple, not folded with the reverse
  direction, so a block on the client→server half of a connection does not
  automatically apply to the server→client half. `main_working.cpp` never calls
  `FiveTuple::reverse()` in its main loop; this is preserved deliberately.
- HTTP methods are matched on their first 4 bytes, so `DELETE` is recognised via
  `DELE` and `OPTIONS` via `OPTI`. A classification-accuracy nit, not a safety
  issue. Kept for behavioural parity; see the README's known limitations.

## Known limitation: output file left on disk after a mid-run failure

**The behaviour differs by pipeline variant. An earlier revision of this section described only
the single-process case.**

| Variant | Written when? | On mid-run failure the output file is… |
|---|---|---|
| `run_pipeline` | streamed in the read loop | **partial** — contains every packet forwarded before the failure |
| `run_pipeline_multiprocess` | after `_collect` and `join` | **empty** — created (truncated) at dispatch start, but no packet is written until every worker has joined |
| `run_pipeline_staged` | after `_collect` and `join` | **empty** — same |

Reason: the two multiprocess variants buffer forward/drop decisions and only write once all
workers have finished (`pipeline.py:587`), so a failure partway through dispatch — the
`max_total_packets` case — leaves a valid but empty 24-byte-header pcap. `run_pipeline` writes
as it goes (`pipeline.py:412`), so it genuinely contains partial progress.

In every case the file is a **valid, bounded, non-corrupt** pcap and the failure is still
reported with a non-zero exit code, so no safety constraint is violated (no crash, no hang, no
unbounded resource use, no silent success). It is recorded here because a caller re-running
after raising a limit should know the previous output will be **overwritten, not appended**.

Deleting partial output on failure was considered and not implemented: it would discard
partially-successful work with no explicit request to prefer "clean failure" over "preserve
partial progress". That trade-off is still open.

## Minor efficiency note: output-path validation happens after worker spawn

The output-path-equals-input-path check fires when the first `PcapWriter` is constructed, which
in `run_pipeline_multiprocess` happens **after** all worker processes are spawned
(`pipeline.py:526` then `:535`). A run doomed to fail the overwrite check therefore still pays
the cost of spawning N worker processes before reporting the error.

**Corrected from an earlier revision of this note**, which claimed the check also happened after
"dispatched every packet, and been shut down/joined". That is no longer true: the writer is
opened at the top of the dispatch block, so the check fires **before the first packet is
dispatched**. The remaining cost is process startup only.

Still only a performance nicety — not a correctness or safety requirement (confirmed: no hang,
no crash, clean error, ~0.5 s for the sample fixture). Note that on Windows' `spawn` start
method, process startup is tens of milliseconds per worker, so this is not negligible at high
`--workers`. Validating the path before spawning is tracked as `T0-11` adjacent cleanup; it was
not done here because it is a performance nicety.

## Open decisions deferred to implementation time
- ~~Whether to implement QUIC SNI heuristic at all (default: omit, documented
  limitation).~~ **Resolved in v0.2**: implemented properly rather than as a heuristic,
  gated behind the optional `[quic]` extra. See "Gap analysis" item 16.
- ~~Exact default values for max packet size / max flow table size / max total packets
  (pick conservative defaults in Task 2/7, make configurable via CLI flags).~~ **Resolved**:
  65535 / 100_000 per process / 10_000_000, all overridable via CLI flags
  (`--max-packet-size`, `--max-connections`, `--max-total-packets`), plus
  `--flow-timeout` for idle reaping and `--reap-interval` for reaper cadence.

### New open decisions (2026-10-03)

Raised by the audit. Each is blocking one or more planned tasks and **requires a human** —
they are deliberately not resolved in this document. Full detail in
[`TASK_TRACKER.md`](TASK_TRACKER.md) §2.

| ID | Question | Blocks |
|---|---|---|
| `DEC-01` | Output-ordering guarantee under streaming. Fixing the unbounded-memory defect removes the global sort that currently makes output deterministic, so a choice is forced. **Decided 2026-10-12: bounded reorder window (option B)** — deterministic within a window of size *W*, a late packet emitted out of order rather than held, *W* a memory/latency tunable. | `T1-01`, `T1-03` |
| `DEC-02` | pcapng: full reader, or a precise "not supported, here's how to convert" diagnostic? **Decided 2026-10-12: option 2, the diagnostic** — a wrong reader is worse than an honest refusal, and roughly a third of real captures are pcapng so the diagnostic is the high-value half. | `T05-02` (done) |
| `DEC-03` | scapy: implement the cross-check this document already claims, or delete the dependency and the claim? **Decided 2026-10-12: implement it.** It is also the stated substitute for the fuzzing gap, which is now closed — so what remains is the thing the substitute stood in for. | `T1-07` (increment 2, done) |
| `DEC-04` | Rule-file persistence key: migrate display names to stable `AppType.name` keys? **Decided 2026-10-12: (a)** — persist the stable key, keep display names as input-only aliases, one-shot migration on load with a deprecation warning. Rejected (b): it hard-fails every existing saved file. Rejected (c): two keys that can disagree are a worse invariant than one. | `T1-05` |
| `DEC-05` | Bidirectional flow folding: default on, or on only in streaming mode? **Decided 2026-10-12: default ON** — the product-correct behaviour, and it **unblocks `D-25`**: with flows unfolded there is no shared state to correlate a SYN with the SYN-ACK answering it. A deliberate parity break, recorded in the differential allowlist like the VLAN peel. | `T1-03` |

## Open trade-offs, deliberately not resolved

- **A hand-rolled block cipher for QUIC** was considered and rejected. `cryptography` is a
  compiled dependency; making it optional keeps the core install tiny at the cost of a
  feature that silently needs more setup. Chosen: optional extra + reported degradation.
- **Two-phase commit for live rule updates** was considered and rejected. A worker dying
  mid-run loses the update; the parent reports the failure. Versioned acknowledgement and
  rollback would add real complexity for what is, in an offline file-processing tool, a
  batch-shaped problem.
- **Partial-output cleanup on failure** — see "Known limitation" above. Still undecided;
  both "preserve partial progress" and "fail clean" are defensible. Note the two
  multiprocess variants already produce an *empty* file rather than a partial one, so the
  question is currently live only for `run_pipeline`.
- **Validating the output path before spawning workers** — still a performance nicety, not
  correctness. Recorded in "Minor efficiency note" above.
- **Direction-folding of flows** (one table entry per bidirectional connection instead of
  two) would be more correct, but changes blocking scope, so it is preserved as-is from the
  original rather than changed under cover of a bug fix. Now tracked as `DEC-05`.
- **No backpressure on the packet queues.** All `multiprocessing.Queue`s are unbounded, which
  guarantees the parent's dispatch loop cannot deadlock — bought at the cost of memory being
  the only backpressure, and therefore the source of the unbounded-memory defect `D-01`.
  Bounded queues are the fix; see `T0-11`.

## Known issues in the current port

Recorded here so this document does not imply the port is defect-free. Full detail,
severity and remediation in [`AUDIT.md`](AUDIT.md) §2.

The most serious, in order:

- **`D-01` / `D-02` / `D-22` — unbounded memory.** Workers accumulate every packet's full
  `RawPacket` for the entire run and return it as one pickled `WorkerResult`; the packet
  queues have no `maxsize`, so the dispatch loop cannot apply backpressure. At the documented
  defaults this can reach hundreds of gigabytes. **This defeats every other resource bound in
  the codebase**, including the ones asserted above. It is a regression against the original,
  whose bounded `ThreadSafeQueue` provided real backpressure.
- **`D-14` — no VLAN/802.1Q unwrapping.** 100% of VLAN-tagged traffic is silently discarded.
  Correct as documented, but enterprise captures are commonly tagged.
- **`D-03` — `--live-rules` is silently ignored with `--load-balancers`.** `run_pipeline_staged`
  has no `live_rules` parameter and creates no control queues, and the CLI never warns. The
  flag's help text promises a control channel unconditionally. Item 15 below describes the
  mutation channel as working; that is true only for the single-tier variant.
- **`D-06` / `D-07` — pcap bounds claims are not fully implemented.** `orig_len` is
  `len(buf)` rather than the on-wire `origlen`, so byte counters under-report on truncated
  captures; and `max_packet_size` is checked *after* dpkt has already read `caplen` bytes, so
  the stated threat model (an adversarial `caplen` triggering an unbounded allocation) is not
  actually prevented.
- **`P-15` — per-packet throughput is unmeasured and likely worse than the C++ original.**
  Pickling a `WorkItem` per packet across a process boundary, a pure-Python hash mix per
  packet, Python-level dissection, and a full accumulate→pickle→sort return path. The CLI
  defaults to `--workers 1`, so the path that exists to scale is not the default and has never
  been benchmarked.
