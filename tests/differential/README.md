# Differential test harness (Task 9)

Compares the Python port's single-process pipeline (`dpi_engine.pipeline.run_pipeline`)
against the actual compiled OSC C++ reference implementation (`main_working.cpp`, the
most complete single-threaded reference -- see DESIGN_DECISIONS.md).

## Why Docker

The host machine's only installed C++ compiler is MinGW g++ 6.3.0 (from 2016), which
predates C++17's `<optional>` header support and cannot compile this codebase at all
(fails with `fatal error: optional: No such file or directory`). Docker (already
installed on this machine) is used to run a `gcc:13` container purely as a build/run
environment for the *reference* binary -- it does not touch the Python port, and it
does not modify `OSC/` (the source is bind-mounted read-only; the compiler output goes
to `tests/differential/bin/`, which is gitignored since it's a build artifact, not
source).

## What gets built

`main_working.cpp` + `pcap_reader.cpp` + `packet_parser.cpp` + `sni_extractor.cpp` +
`types.cpp`, exactly the single-threaded reference this port's Task 8 `pipeline.py`
was modeled on -- not the multi-threaded `dpi_mt.cpp` (out of scope until Task 10, and
even then Task 10's multiprocessing output is validated against *this* port's own
single-process output per DESIGN_DECISIONS.md, not against the C++ multi-threaded code).

## Documented allowlist of intentional differences

These are *expected* deltas between the Python port and the C++ original's output,
not bugs in the harness or the port. See DESIGN_DECISIONS.md "Bugs fixed during the
port" and "Differential testing findings" for full detail:

1. Any SNI/domain containing the substring "x.com" (e.g. "netflix.com") or "t.co"
   (e.g. "microsoft.com") will be misclassified as `Twitter/X` by the original C++
   binary, but correctly classified by the Python port. Confirmed empirically by
   actually running the compiled binary against `test_dpi.pcap`.
2. Any domain containing the substring "cf-" would be misclassified as `Cloudflare`
   by the original; the Python port does not carry this pattern forward. (Not
   triggered by `test_dpi.pcap`, but documented for any new fixture.)
3. DNS traffic (port 53): the original tags all of it with a flat `AppType.DNS` and
   never resolves the actual queried domain. The Python port resolves the query when
   possible and classifies by the specific app/domain, falling back to generic DNS
   only when resolution fails. This means DNS-related entries in `app_counts` and
   `detected_domains` will differ in kind (Python: more specific) between the two.
4. Case-sensitivity/IP-validation/rules-file-parsing fixes (Task 6) are input-layer
   fixes that don't manifest in a basic pcap-processing run with well-formed CLI
   flags -- they only differ when a malformed rules file or mixed-case domain rule
   is used, which the crafted edge-case fixtures in this directory exercise
   specifically.

## Files

- `bin/dpi_simple` -- the compiled OSC reference binary (gitignored, rebuilt on demand
  by `build_reference_binary()` in `conftest.py`/`cpp_reference.py`).
- `cpp_reference.py` -- helpers to build (if needed) and run the C++ binary via Docker,
  and parse its stdout report into a structure comparable to `PipelineResult`.
- `fixtures/` -- edge-case pcaps crafted for this test suite specifically (truncated
  packets, etc.), distinct from `tests/fixtures/test_dpi.pcap` (the shared real sample).
- `test_differential.py` -- the actual comparison tests.
