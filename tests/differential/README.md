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
   `detected_domains` will differ in kind (Python: more specific) between the two,
   and it means app- and domain-based rules drop **exactly one more packet** than the
   original for a fixture whose DNS query names a blocked app. That +1 delta is
   asserted exactly, not merely tolerated, in
   `test_dns_resolution_is_a_documented_improvement_not_a_bug` and
   `test_total_and_dropped_counts_differ_by_exactly_the_dns_scope_improvement`.
4. Case-sensitivity/IP-validation/rules-file-parsing fixes (Task 6) are input-layer
   fixes that don't manifest in a basic pcap-processing run with well-formed CLI
   flags -- they only differ when a malformed rules file or mixed-case domain rule
   is used, which the crafted edge-case fixtures in this directory exercise
   specifically.
5. **Domain-rule matching is anchored, not substring.** The reference binary
   (`main_working.cpp:60-62`) does `sni.find(dom) != npos`, so
   `--block-domain youtube` also blocks any domain merely *containing* "youtube".
   The Python port follows `rule_manager.cpp` instead: an exact domain matches only
   itself, and subdomains require the explicit `*.example.com` form. So a bare
   domain rule blocks **less** in Python. Blocking less is the safe direction for a
   blocking tool, and the intent is now explicit in the rule rather than implicit.
   Pinned in both directions by
   `test_bare_domain_rule_blocks_less_than_the_cpp_substring_match` and
   `test_wildcard_domain_rule_matches_the_cpp_substring_result`.

6. **Bidirectional flow folding (`DEC-05`).** The Python port keys each flow by a
   canonical five-tuple (the lexicographically smaller of a tuple and its
   reverse), so a connection and its reverse direction are one `Connection`. The
   C++ original keys each direction separately. Consequences on any fixture with
   bidirectional traffic: a *lower* active-flow count, per-flow packet/byte totals
   combined rather than split, and populated `packets_in`/`bytes_in` where the
   original reports zero. This is a deliberate parity break (`D-25`, `DEC-05`).
   The differential suite therefore runs with `fold_bidirectional=False`, pinned
   in `tests/differential/conftest.py` rather than at each call site, so adding a
   new differential test cannot silently reintroduce folding. `--exact-tuple-flows`
   selects the reference behaviour from the CLI.
7. **VLAN-tagged frames (`T05-01`).** The port peels an 802.1Q tag before parsing
   and reports the inner protocol, where the original treated the whole thing as
   a non-IP frame and counted it as such. Only reachable on captures that carry
   VLAN tags, which none of the committed fixtures do.
8. **IP rules match either endpoint (`DEC-06`).** `should_block` in the original
   takes the *source* address only, so a rule written to block an IP never fired
   when that IP was the destination (`D-21`). The port checks source and then
   destination within the IP category, so a blocked address is blocked in both
   directions. The difference only surfaces on a fixture that carries an IP rule
   *and* a packet flowing toward a blocked address; the committed fixtures carry
   no IP rules at all, so this is recorded rather than observed. There is no
   opt-out switch: unlike `DEC-05`'s flow folding, a source-only IP rule is not a
   behaviour anyone would want to select deliberately.

## Sweep tests

Beyond the specific allowlist items, two tests assert *no other* difference crept in:

- `test_python_resolves_exactly_the_cpp_names_plus_dns_query_names` — the Python port
  must resolve every name the C++ binary resolves, and every *additional* name it
  resolves must be a DNS query name (the one thing the C++ binary structurally cannot
  see). The DNS name set is recomputed independently of the pipeline, so the assertion
  cannot be satisfied by the code it is checking.
- `test_total_and_dropped_counts_match_for_no_rules` — packet, byte, forward, drop and
  active-flow counts must match exactly with no rules active.

If either of these fails, the classification table or an extractor has drifted; re-verify
this allowlist before adjusting anything.

## Files

- `bin/dpi_simple` -- the compiled OSC reference binary (gitignored, rebuilt on demand
  by `build_reference_binary()` in `cpp_reference.py`).
- `conftest.py` -- the single `cpp_available` fixture: confirms the binary is built *and*
  that Docker is actually reachable right now, skipping cleanly if not.
- `cpp_reference.py` -- helpers to build (if needed) and run the C++ binary via Docker,
  and parse its stdout report into a structure comparable to `PipelineResult`.
- `fixtures/` -- edge-case pcaps crafted for this test suite specifically (truncated
  packets, etc.), distinct from `tests/fixtures/test_dpi.pcap` (the shared real sample).
- `test_differential.py` -- the actual comparison tests.
