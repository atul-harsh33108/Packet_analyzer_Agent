# Workflow — `dpi-engine` Complete Architecture

How a packet travels through the Python port, end to end.

> **Rewritten 2026-10-03** against the current tree. The previous version of this
> document described the pre-refactor codebase: it documented a deleted module,
> cited five wrong line numbers, omitted 3 of 13 modules and 7 of 13 CLI flags,
> and re-drew a classification bug that had already been fixed. See
> [`AUDIT.md`](AUDIT.md) §5.3 for that defect list.
>
> **Cite symbols, not line numbers.** Line numbers in this document were verified
> when it was written and will drift. Where one is given it is a navigation aid,
> not a reference. `WORKFLOW.md` rotted last time precisely because it was built on
> line numbers.

| Document | Role |
|---|---|
| [`DESIGN_DECISIONS.md`](DESIGN_DECISIONS.md) | *Why* the port is built this way |
| [`AUDIT.md`](AUDIT.md) | Known defects and their severity — read this alongside this file |
| [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) | How the defects get fixed |
| [`TASK_TRACKER.md`](TASK_TRACKER.md) | Current state |

---

## Table of contents

1. [Module map](#1-module-map)
2. [Pipeline variants](#2-pipeline-variants)
3. [The shared decision engine](#3-the-shared-decision-engine-flowprocessor)
4. [Input path — `PcapReader`](#4-input-path--pcapreader)
5. [Dissection — `parse_packet`](#5-dissection--parse_packet)
6. [Classification — `FlowProcessor.classify`](#6-classification--flowprocessorclassify)
   - [6.1 Name → app mapping](#61-name--app-mapping-sni_to_app_type)
   - [6.2 TLS SNI](#62-tls-sni-extract_sni)
   - [6.3 HTTP `Host`](#63-http-host-extract_http_host)
   - [6.4 DNS query name](#64-dns-query-name-extract_dns_query)
   - [6.5 QUIC Initial](#65-quic-initial-quicpy)
7. [Flow state machine](#7-flow-state-machine-connection_tracker)
8. [Rule evaluation](#8-rule-evaluation-rule_manager)
9. [The three entry points](#9-the-three-entry-points)
10. [Shutdown protocol](#10-shutdown-protocol)
11. [Reporting](#11-reporting-reportpy)
12. [CLI reference](#12-cli-reference)
13. [Safety envelope](#13-safety-envelope)
14. [End-to-end data flow](#14-end-to-end-data-flow)
15. [Where the flow differs from the C++ original](#15-where-this-flow-differs-from-the-c-original)

---

## 1. Module map

13 modules, ~5,200 lines. Runtime dependency: `dpkt` only.

```
                          ┌──────────────────────────────────────┐
   dpi-engine run ──────► │ cli.py            argparse front end   │
                          └──────────┬───────────────────────────┘
                                     │ picks an entry point
                          ┌──────────▼───────────────────────────┐
                          │ pipeline.py     the 3 entry points    │
                          │                 _lb_main (staged)    │
                          │                 RuleBroadcaster        │
                          └──┬──────────────┬──────────────┬───────┘
                             │              │              │
        ┌────────────────────▼───┐  ┌───────▼────────┐  ┌──▼──────────────────┐
        │ pcap_io.py              │  │ load_balancer  │  │ worker.py           │
        │  RawPacket             │  │  flow_hash     │  │  FlowProcessor      │
        │  PcapReader/Writer     │  │  hash_select   │  │  worker_main        │
        └───────────┬────────────┘  │  LB/FP records │  │  WorkerResult       │
                    │               └────────────────┘  └──┬──────────────────┘
        ┌───────────▼────────────┐                         │
        │ packet_parser.py       │                         │
        │  ParsedPacket          │                         │
        │  parse_packet          │                         │
        └───────────┬────────────┘                         │
                    │                                      │
              ┌─────▼──────────────────────────────────────▼─────┐
              │ types.py      FiveTuple AppType Connection       │
              │ sni_extractor.py  extract_sni / _http_host / _dns│
              │ quic.py           QuicFlowInspector (RFC 9001)    │
              │ connection_tracker.py  flow table + LRU + reaper │
              │ rule_manager.py   RuleManager + RuleSnapshot     │
              └────────────────────┬─────────────────────────────┘
                                   │
                          ┌────────▼─────────┐
                          │ report.py        │──► stdout / --json
                          └──────────────────┘
```

**Import direction is strictly downward.** `pipeline.py` imports `worker` at module
top level; `worker` does not import `pipeline`. The previous architecture had a
genuine circular import, resolved by a function-local import — that is gone.

---

## 2. Pipeline variants

Three entry points, one decision engine.

```
                         ┌───────────────────────────────────────────┐
                         │  parent: read → parse → compute five-tuple │
                         └─────────────────┬─────────────────────────┘
                                           │
        ┌──────────────────────────────────┼──────────────────────────────────┐
        │                                  │                                  │
        ▼                                  ▼                                  ▼
┌───────────────────┐        ┌──────────────────────────┐        ┌────────────────────────────┐
│ run_pipeline      │        │ run_pipeline_            │        │ run_pipeline_staged       │
│                   │        │ multiprocess             │        │                            │
│ 1 process         │        │                          │        │ 1 process                  │
│ no IPC            │        │ parent parses            │        │ K load balancers          │
│ no queues         │        │   │                      │        │ K x F fast paths          │
│                   │        │   ├─► FP0  ─┐            │        │   │                        │
│ FlowProcessor     │        │   ├─► FP1  ─┼─► result  │        │   ├─hash(t1)─► LB0         │
│ runs inline       │        │   ├─► FP2  ─┤   queue    │        │   │      ├─hash(t2)─► FP0,FP1│
│                   │        │   └─► FP3  ─┘            │        │   ├─hash(t1)─► LB1         │
│                   │        │                          │        │   │      ├─hash(t2)─► FP2,FP3│
│                   │        │  1 hop                    │        │                            │
│                   │        │  N queues in, 1 out       │        │  2 hops                    │
│ (default)         │        │  (--workers N)            │        │  (--load-balancers K)     │
└───────────────────┘        └──────────────────────────┘        └────────────────────────────┘
```

**The invariant all three rely on:** every packet of a given five-tuple reaches the
same fast-path process, so per-flow state — TCP lifecycle, classification, block
decisions — is never split. Pinned by
`test_every_flow_lands_on_exactly_one_fast_path`.

All three produce **byte-identical** output pcaps for the same input and rules;
asserted for every staged topology.

### Choosing one

| Variant | Use when | Cost |
|---|---|---|
| `run_pipeline` | small captures, debugging — **the default** | none: no IPC, no process startup |
| `run_pipeline_multiprocess` | large captures, many cores | 1 IPC hop; pickles a `WorkItem` per packet |
| `run_pipeline_staged` | reproducing OSC's original two-tier topology; per-shard observability | 2 hops. **Not faster than `--workers`** |

> **The staged topology is not a throughput optimisation.** The reader must parse
> in order to route by five-tuple — a stateless reader holding only raw bytes can
> only distribute round-robin, which splits a connection's two halves across
> shards. Measured on the sample capture: 61 tracked "connections" for 43 real
> ones, with per-flow classification half-applied. The LB tier is
> queue-decoupling and observability. See `DESIGN_DECISIONS.md` item 13.
>
> ⚠️ `load_balancer.py`'s module docstring claims the LB stage does the parsing.
> **That is wrong** — `_lb_main` receives already-parsed `WorkItem`s. Tracked as `T0-10`.

### The two-tier hash

Both tiers hash the five-tuple, but with **different salts**
(`_SALT_TIER_1 = 0`, `_SALT_TIER_2 = 0x85EBCA6B`).

The C++ original used the *same* hash modulo the *same* modulus at both levels, so
with the default 2 LBs × 2 FPs the levels always agreed and only 2 of the 4
fast-paths ever received a packet. Half the pool idled permanently.

`flow_hash` is spelled out rather than using builtin `hash()`, because
`PYTHONHASHSEED` randomises `hash()` for strings across processes and the mapping
must be stable between parent and children.

---

## 3. The shared decision engine — `FlowProcessor`

All three variants delegate every per-packet decision to
`worker.FlowProcessor` (`worker.py`). This is what makes them *provably* equivalent
rather than three implementations that happen to agree.

```python
@dataclass(slots=True)
class FlowProcessor:
    tracker:   ConnectionTracker          # private, bounded flow table
    rules:     RuleSnapshot               # immutable; replaced wholesale
    blocked_tuples:   set[FiveTuple]      # monotonic per-worker block set
    blocked_flows:    list[...]           # report payload
    app_counts:       dict[AppType, int]
    detected_domains: dict[str, AppType]
    quic_packets / quic_undecryptable: int
    _quic_inspectors: dict[FiveTuple, QuicFlowInspector]
```

### `FlowProcessor.process` — the whole decision, in order

```
 1. refresh_rules()                  one int compare; swap snapshot if version changed
 2. stats.packets_processed += 1
 3. tcp_packets / udp_packets += 1
 4. conn = tracker.get_or_create_connection(tuple_)
       └─ reap_if_due() runs FIRST, on a bounded cadence (default every 65536 packets)
       └─ LRU-evict if at max_connections (O(1) OrderedDict.popitem)
 5. tracker.update_connection(conn, orig_len, is_outbound=True)
 6. if TCP: tracker.update_tcp_state(conn, tcp_flags)
 7. blocked = tuple_ in self.blocked_tuples          ← monotonic set, not the tracker
 8. if conn.state is not BLOCKED:                     ← gate 1
      if conn.state is not CLOSED:                    ← gate 2
          new_app, new_sni, confirmed = self.classify(...)
          if changed: tracker.classify_connection(...)
      if not blocked:                                 ← gate 3
          reason = rules.should_block(src_ip, dst_port, app, domain)
          if reason: add to blocked_tuples; block_connection; record; blocked = True
 9. _record_stats(conn)              per-packet app count + domain→app map
10. return ProcessedPacket(sequence_index, raw, forwarded=not blocked)
```

**Three independent gates**, and the distinction matters:

| Gate | Effect | Why |
|---|---|---|
| `state is not BLOCKED` | skip **both** classification and rule check | a blocked flow is already decided; this is the fast path on drop-heavy captures |
| `state is not CLOSED` | skip **classification only** | a dead flow must not be re-classified — but policy still applies to surviving packets |
| `not blocked` | skip the rule check only | the monotonic set is authoritative for forward/drop, independent of `Connection.state` |

> The last row is deliberate: **forward/drop never depends on `Connection.state`
> being `BLOCKED`.** It comes from the worker's own monotonic set. `Connection.state`
> is reporting, not control.

---

## 4. Input path — `PcapReader`

```
PcapReader.__init__  ──►  _open()
                            ├─ open(path, "rb")            OSError → PcapError
                            ├─ dpkt.pcap.Reader(file)      ValueError → PcapFormatError
                            └─ require_ethernet?
                                 datalink() != DLT_EN10MB → PcapLinktypeError
```

`__iter__` is a generator yielding `RawPacket(ts_sec, ts_usec, data, orig_len)`.
Two bounds are enforced while iterating: total packet count
(`DEFAULT_MAX_TOTAL_PACKETS = 10_000_000`) and per-packet size
(`DEFAULT_MAX_PACKET_SIZE = 65535`).

`PcapWriter` **refuses to overwrite its own input** — checked at construction via
`samefile()` or resolved-path equality, not just at the CLI layer.

### Known gaps in this layer

| Gap | Finding |
|---|---|
| `orig_len` is `len(buf)`, never the on-wire `origlen` — dpkt discards it, so byte counters under-report on truncated captures | `D-06` |
| `max_packet_size` is checked **after** dpkt already read `caplen` bytes, so an adversarial `caplen` allocates before rejection | `D-07` |
| No pcapng; a valid pcapng gets a misleading "not a valid pcap file" | `D-15` |
| `PcapWriter.__init__` open is unguarded → raw `FileNotFoundError` escapes | `D-04` |

---

## 5. Dissection — `parse_packet`

```
RawPacket
   │
   ├─ dpkt NeedData / UnpackError ─────────────────────► None   (counted other_packets)
   ▼
Ethernet (14 B)
   ├─ EtherType != 0x0800 (IPv4) ──────────────────────► has_ip = False   ← IPv6/ARP/VLAN all stop here
   ▼
IPv4 (20 B)
   ├─ version != 4 ───────────────────────────────────► has_ip = False
   ├─ ihl*4 < 20 ─────────────────────────────────────► has_ip = False
   ├─ protocol: 6 = TCP · 17 = UDP
   ▼
transport
   ├─ TCP: src/dst port, seq, ack, flags ──► has_tcp = True
   ├─ UDP: src/dst port ────────────────────► has_udp = True
   └─ isinstance guard: a truncated transport layer degrades to
      has_tcp/has_udp = False with empty payload, rather than garbage fields
```

Returns `ParsedPacket`. IP addresses are stored as **host-order uint32**, with
`_ip_bytes_to_int` normalising byte order — this fixes a big-endian-host bug in the
original.

**Never parsed** (same as the original): IP `total_length`, `identification`,
`flags_fragment`, checksum, TOS; UDP length/checksum; TCP window/checksum/urgent
pointer.

### Known gaps

| Gap | Finding |
|---|---|
| **No VLAN/802.1Q unwrapping** — 100% of VLAN-tagged traffic is silently discarded as non-IP. Ubiquitous in enterprise captures | `D-14` |
| No IPv6 — every IPv6 packet becomes `has_ip=False` and is dropped | `D-19` |
| No IP fragment handling | inherited |

---

## 6. Classification — `FlowProcessor.classify`

Attempted only when `unconfirmed` — that is, the flow has no SNI yet and its app
type is still `UNKNOWN`/`HTTPS`/`HTTP`/`QUIC`. Order matters; first hit wins.

```
 TCP + dst_port 443 + len(payload) > 5
   └─► extract_sni(payload)          → named()  [confirmed]
 TCP + dst_port 80
   └─► extract_http_host(payload)    → named()  [confirmed]
 UDP + enable_quic + is_quic(payload)
   ├─► quic_packets += 1
   ├─ is_quic_initial?  no  ────────► quic_undecryptable += 1 ; return QUIC  [guess]
   └─ yes → QuicFlowInspector.feed()
        ├─ SNI found ───────────────► named()  [confirmed]
        └─ not yet ──────────────────► quic_undecryptable? ; return QUIC  [guess]
 UDP + (src_port == 53 or dst_port == 53)
   ├─► extract_dns_query(payload)    → named()  [confirmed]
   └─ no name ──────────────────────► return DNS       [guess]
 TCP + dst_port 443 ─────────────────► return HTTPS     [guess]
 TCP + dst_port 80 ──────────────────► return HTTP      [guess]
 else ───────────────────────────────► unchanged        [no-op]
```

`named(name)` = `sni_to_app_type(name)` + bump `classification_hits` when the result
is neither `UNKNOWN` nor `HTTPS`.

**QUIC is deliberately not port-gated.** Modern QUIC runs on UDP/443 but also
elsewhere; gating on a port would miss it. The two questions are asked separately:
`is_quic` (is this QUIC at all — for classification and counting) then
`is_quic_initial` (can we decrypt it — before attempting extraction). Without this
split, Handshake and 1-RTT packets — the overwhelming majority of QUIC on a real
network — fell through to `UNKNOWN`, making a modern capture look like noise.

**Confirmed vs. guessed** is the load-bearing distinction. A *guess* (bare port
fallback) does **not** lock the flow, so a later ClientHello can still upgrade it. A
*confirmation* (a real extracted name) is terminal. This is the fix for OSC's
`classifyConnection` bug, where any classification — including a bare port-443 guess
— permanently blocked a later, more accurate SNI result.

### 6.1 Name → app mapping — `sni_to_app_type`

17 ordered `_SniRule`s. **Order is load-bearing** and mirrors the original's
`if/else-if` chain exactly. First match wins.

| # | App | Matched by |
|---|---|---|
| 1 | Google | `google` `gstatic` `googleapis` `ggpht` `gvt1` |
| 2 | YouTube | `youtube` `ytimg` `youtu.be` `yt3.ggpht` |
| 3 | Facebook | `facebook` `fbcdn` `fb.com` `fbsbx` `meta.com` |
| 4 | Instagram | `instagram` `cdninstagram` |
| 5 | WhatsApp | `whatsapp` `wa.me` |
| 6 | Twitter/X | `twitter` `twimg` + **anchored** `x.com`, `t.co` |
| 7 | Netflix | `netflix` `nflxvideo` `nflximg` |
| 8 | Amazon | `amazon` `amazonaws` `cloudfront` `aws` |
| 9 | Microsoft | `microsoft` `msn.com` `office` `azure` `live.com` `outlook` `bing` |
| 10 | Apple | `apple` `icloud` `mzstatic` `itunes` |
| 11 | Telegram | `telegram` `t.me` |
| 12 | TikTok | `tiktok` `tiktokcdn` `musical.ly` `bytedance` |
| 13 | Spotify | `spotify` `scdn.co` |
| 14 | Zoom | `zoom` |
| 15 | Discord | `discord` `discordapp` |
| 16 | GitHub | `github` `githubusercontent` |
| 17 | Cloudflare | `cloudflare` — **only**; the original's bare `cf-` was dropped |
| — | *fallthrough* | non-empty name, nothing matched → `HTTPS` |

Two deliberate deviations from the original, both fixing false positives:

- **`x.com` and `t.co` are anchored, not bare substrings.** Verified:
  `'x.com' in 'netflix.com'` is `True` and `'t.co' in 'microsoft.com'` is `True` —
  so the original classified **`www.netflix.com` as Twitter/X** and
  `www.microsoft.com` likewise. Anchoring restricts them to exact-or-subdomain.
- **The Twitter/X check sits at position 6, not above the table.** An earlier
  revision hoisted it above everything, which silently re-prioritised it and made
  `google.x.com` classify as TWITTER instead of GOOGLE. `types.py` carries an
  explicit warning against doing this again. *(The previous version of this
  document drew the buggy ordering.)*

### 6.2 TLS SNI — `extract_sni`

Gate `is_tls_client_hello`: `length >= 9`, content type `0x16`, version in
`[0x0300, 0x0304]`, `record_length <= length - 5`, handshake type `0x01`.

Then an offset walk: record header → handshake length → client version + 32-byte
random → session id → cipher suites → compression → extensions → SNI extension
(`0x0000`) → name type `0x00`.

**The governing rule:** every "skip N bytes" step validates that N bytes actually
remain *before* advancing — not merely that the length prefix was readable. The
original did not do this consistently; it skipped version+random with no bounds check
at all, then read past the end of a short ClientHello. See `DESIGN_DECISIONS.md`
"Bugs fixed during the port" items 2–3.

The extension block is **clamped** rather than rejected, preserving OSC's tolerance
for truncated extensions.

| Gap | Finding |
|---|---|
| `length` is not clamped to `len(payload)` — passing a larger `length` raises `IndexError` despite the "never raises" contract | `D-05` |
| An SNI extension whose *first* name entry is not `host_name` aborts the **whole extension loop**; every other early-out in the function is correctly scoped | `D-18` |
| No hostname length/charset validation — up to 65535 bytes accepted, then scanned against ~60 patterns and pickled across processes | `D-19` |

### 6.3 HTTP `Host` — `extract_http_host`

Gate `is_http_request`: first 4 bytes match one of 7 method prefixes (`GET `,
`POST`, `PUT `, `HEAD`, `DELE`, `PATC`, `OPTI`). Then scan for a case-insensitive
`Host:`, skip spaces/tabs, read to CR/LF, strip a port suffix.

| Gap | Finding |
|---|---|
| Scans the **entire payload** with no CRLF header-section boundary. `GET /?u=http://Host:x HTTP/1.1` yields `"x HTTP/1.1"`. A POST body, `Location:`, or `User-Agent` can produce a bogus host, which then feeds **both** app classification and domain-rule matching — an attacker-controllable false-classification and false-blocking vector | `D-09` |
| No preceding-boundary requirement: matches `Xhost:` | `D-09` |
| Strips at the first colon, so `Host: [2001:db8::1]:8080` yields `'[2001'` | `D-10` |
| `CONNECT` and `TRACE` are not in the method list — tunnels are invisible | `D-09` |
| Only the first 4 bytes are compared, and the HTTP version is never verified. Deliberate parity nit | `P-18` |

### 6.4 DNS query name — `extract_dns_query`

Gate `is_dns_query`: `length >= 12`, QR bit clear (query, not response),
`QDCOUNT != 0`. Then a label walk from offset 12: zero-length label terminates, a
label longer than 63 signals a compression pointer and stops the walk, each label
is bounds-checked before being appended.

| Gap | Finding |
|---|---|
| Compression pointers are not followed — parsing stops and may return a truncated name. Legal but rare in a question section | `P-19` |
| No 255-byte total-name limit, and labels are never validated as LDH | `D-19` |

### 6.5 QUIC Initial — `quic.py`

The full RFC 9000/9001 path. Replaces the original's `QUICSNIExtractor`, which was
**memory-unsafe and a functional no-op**.

```
is_quic(payload)                    long-header bit 0x80 · fixed bit 0x40
                                    plausible version · plausible length
   └─► parse_long_header()          every length prefix bounds-checked
   └─► is_quic_initial()            packet type == 0x00
        └─► QuicFlowInspector.feed()   per-flow, stateful
             ├─ derive_initial_secrets(dcid, version)   HKDF-SHA256 + version salt
             ├─ _initial_keys()                         client AND server
             ├─ remove header protection                AES-128-ECB sample at pn+4
             ├─ reconstruct_packet_number()             RFC 9000 App. A.2
             ├─ decrypt_initial()                       AES-128-GCM, deferred cryptography import
             ├─ extract_crypto_frames()                 PADDING PING ACK ACK_ECN CRYPTO
             └─ reassemble CRYPTO stream               sparse bytearray + presence mask,
                                                       capped at MAX_CRYPTO_BUFFER = 64 KiB
```

An `InvalidTag` from GCM is **expected, not exceptional** — it means "not an Initial
we can read", and is counted, not raised. `feed()` never raises.

**Optional dependency.** Real AES is required, and this project will not hand-roll a
block cipher, so `cryptography` is an optional `[quic]` extra. Without it, QUIC
detection and classification still work; only SNI extraction is unavailable, and the
degradation is **reported** via `quic_sni_supported()`, `unsupported_reason()`, a line
in `dpi-engine inspect`, and separate `quic_packets` / `quic_undecryptable` counters
— so "we saw QUIC but could not read it" is never mistaken for "there was no QUIC".

Only v1 and v2 initial salts are known. Draft-29+ is *detected* but never decrypted.

| Gap | Finding |
|---|---|
| `quic_undecryptable` **over-counts** — bumped whenever the cumulative `inspector.undecryptable_packets` is truthy, so after the first failure every later Initial on that flow counts too | `D-08` |
| `_quic_inspectors` is never pruned, so it is not covered by `--max-connections`; up to 64 KiB per flow | `D-22` |

---

## 7. Flow state machine — `connection_tracker`

`ConnectionTracker` is per-worker and **private**. No locking is needed or wanted;
the partitioning invariant is what makes that safe. The C++ original had a genuine
data race here (`GlobalConnectionTable` read live maps being mutated by their owning
thread) — that class of bug is structurally impossible in this design.

```
                     ┌────────┐
                     │  NEW   │
                     └───┬────┘
       SYN+ACK and both halves seen, and state is NEW
                         ▼
                 ┌───────────────┐
                 │ ESTABLISHED   │◄──┐
                 └───┬───────┬───┘   │ classification confirmed
        RST ──────────┤       └───────┘
        │             │              (only a *confirmed* name locks)
        ▼             │ FIN + ACK
   ┌──────────┐       │
   │  CLOSED  │◄──────┤   absorbing: a later packet cannot re-open it
   └──────────┘       │
        ▲             │
        └─────────────┤
                 ┌────┴─────┐
   rule match ──►│ BLOCKED  │  absorbing, and outranks CLOSED for reporting
                 └──────────┘
```

**Precedence is an explicit total order:** `BLOCKED > CLOSED > CLASSIFIED/ESTABLISHED > NEW`.
A policy block is never masked by a later transport teardown.

| Behaviour | Detail |
|---|---|
| SYN | sets `syn_seen`; **SYN+ACK sets `syn_ack_seen`** (not `syn_seen`) — distinguishes a half-open scan from a real client SYN |
| ESTABLISHED | requires *both* handshake halves plus a current ACK, **and** `state is NEW` — never drags a classified flow backwards |
| RST | closes immediately instead of waiting for FIN+ACK |
| FIN + ACK | closes |
| `is_terminal` | `{BLOCKED, CLOSED}` — `classify_connection` returns early on either, so the port **cannot** re-classify or re-block a dead flow |

The original lacked the RST-immediate and CLOSED-absorbing rules and would happily
re-open a dead flow.

### Reaping and eviction

| Mechanism | Detail |
|---|---|
| O(1) LRU | every use does `move_to_end`; eviction is `popitem(last=False)` |
| Cadence reaper | `reap_if_due` runs inside `get_or_create_connection` every `reap_interval_packets` (default 65536) |
| `cleanup_stale` | removes flows idle beyond `timeout_seconds` **or** already `CLOSED` |
| `--flow-timeout 0` | sets `stale_timeout_seconds=None`, which disables the *idle* comparison only — CLOSED flows are still reclaimed, because a closed flow can never change again |

> The C++ reaper ran only on the branch where the fast-path's input queue was empty
> for 100 ms — i.e. **never under sustained load**, so stale flows accumulated until
> the 100,000-entry eviction cliff. Cadence-triggering is the fix.

---

## 8. Rule evaluation — `rule_manager`

Copy-on-write. One lock guards *admin* mutations only; the packet hot path takes
**no lock at all**.

```
RuleManager  ──(lock)──►  rebuild immutable _RuleState  ──►  atomically rebind
                                                                   │
                                                                   ▼
                                              RuleSnapshot (frozen; every container immutable)
```

`RuleSnapshot.should_block` is the per-packet entry point. Fixed priority order —
**first match wins**, so the reported reason is the most specific one:

```
1. IP        src_ip in frozenset[int]     ← int-keyed; NO string formatting per packet
2. PORT      dst_port in frozenset[int]
3. APP       app in frozenset[AppType]
4. DOMAIN    domain in exact_set
           or any(pattern.matches(domain) for pattern in domain_patterns)
                                             → BlockReason(category, detail) | None
```

The original formatted the source IP to a dotted quad and re-parsed it with
`ipaddress` on **every packet**, and allocated two string copies per wildcard rule
per packet while holding a shared lock. This port does none of that.

### Domain rule grammar

`DomainPattern.parse` accepts exactly two forms and **rejects anything else at
insertion time**:

| Rule form | Matches | Does not match |
|---|---|---|
| `facebook.com` (exact) | `facebook.com` | `www.facebook.com` |
| `*.facebook.com` | `facebook.com`, `www.facebook.com`, `a.b.facebook.com` | `notfacebook.com`, `facebook.com.evil.net` |

Rejected with a clear `RuleManagerError`: `foo*.com`, `*foo`, bare `*`.

**Why this is stricter than the original:** `main_working.cpp:60-62` did an
unanchored substring search, so `--block-domain youtube` also blocked
`notyoutube.example.org`. This port follows `rule_manager.cpp` instead — exact match
or explicit `*.suffix`. Blocking *less* is the safe direction for a blocking tool.
Pinned by two differential tests, one per direction.

> The C++ `RuleManager` had the opposite failure, and it was worse: `blockDomain`
> classified a rule as a wildcard if it contained `*` **anywhere**, but only `*.`
> patterns ever matched. So `example.*`, `foo*bar`, `*` and `a*b.example.com` were
> stored, counted, echoed, persisted — **and silently never matched anything**. A
> security control that did nothing, with no error and no log. Rejection at
> insertion is the fix.

### Live rule mutation

```
RuleManager mutation
   └─► version += 1
        └─► RuleBroadcaster.publish()      parent-side, polled once per packet
             └─► per-worker control queue  (NEVER mixed into the packet queue, so an
                                            update can never be mistaken for a packet
                                            or reordered relative to one)
                  └─► worker: _drain_control()   non-blocking, between packets
                       └─► FlowProcessor.refresh_rules()   one int compare
                            └─► apply_snapshot()           rebind + bump rule_updates_applied
```

Off by default: it costs one non-blocking queue drain per packet per worker.

> ⚠️ **`--live-rules` is silently ignored when combined with `--load-balancers`.**
> `run_pipeline_staged` has no `live_rules` parameter and creates no control queues,
> and the CLI does not warn. The flag's help text promises a control channel
> unconditionally. Finding `D-03`, task `T0-09`.

| Gap | Finding |
|---|---|
| Persistence keys are display names (`"Twitter/X"`), so renaming a display string silently invalidates every saved rules file | `D-16` |
| No CIDR/subnet rules — blocking `10.0.0.0/8` needs 16,777,216 rules | `D-20` |
| No destination-IP blocking — `should_block` takes `src_ip` only | `D-21` |

---

## 9. The three entry points

### `run_pipeline` — single process

```
open reader + writer
for each packet:
    update stats
    classify/track/check via FlowProcessor  (inline, no queue)
    forward → writer.write(raw)   |   drop → stats only
aggregate → PipelineResult
```

Streams the output as it goes, so it holds no packet list. **This is the default**,
and the only variant with genuinely bounded memory today.

### `run_pipeline_multiprocess` — flat worker pool

```
build RuleSource (FixedRuleSource wrapping an immutable snapshot)
spawn N workers, each: worker_main(fp_id, input_queue, output_queue, rule_source, …)
open reader + writer                      ← writer opened BEFORE dispatch
for (seq, raw, parsed, tuple) in reader:
    broadcaster.publish()                 if live_rules
    input_queues[hash_select(tuple, N)].put(WorkItem(seq, raw, parsed, tuple))
finally:
    dispatch_succeeded ? put SHUTDOWN_SENTINEL in each queue
                       : terminate + join (partial results are untrustworthy)
collect N WorkerResults (120 s timeout) → join → close queues
accumulate stats / app_counts / blocked_flows / global_stats / quic counters
write forwarded packets in sequence_index order
```

### `run_pipeline_staged` — LB → FP two-tier

Same dispatch shape, but packets are routed to a **load-balancer** process first,
which hash-selects one of its own fast-paths:

```
build_pipeline_graph(num_load_balancers, fps_per_lb) → lbs[] each with fps[]
open reader
for each packet:
    lbs[hash_select(tuple, K, salt=_SALT_TIER_1)].input_queue.put(WorkItem)
put SHUTDOWN_SENTINEL in each LB queue                       ← LBs only

_lb_main(input_queue, lb, output_queue):
    loop:  get() → break on sentinel → stats.received += 1
                        → fp = lb.select_fp(tuple)        ← salt=_SALT_TIER_2
                        → stats.per_fp_packets[fp.fp_id] += 1
                        → fp.input_queue.put(item)
    ── drain complete ──
    for fp in lb.fps: fp.input_queue.put(SHUTDOWN_SENTINEL)   ← LBs fan out
    output_queue.put(_LoadBalancerResult(stats))

collect K _LoadBalancerResults, K*F WorkerResults → join → close
```

**The LB holds no flow state, needs no reaping, and cannot re-classify anything** —
that is the whole point of the shard.

> ⚠️ **An LB death orphans all of its fast-paths forever.** Only `_lb_main` sends FP
> sentinels, so if an LB dies its FPs block indefinitely and the parent notices only
> via the 120 s timeout. Finding `D-13`.

---

## 10. Shutdown protocol

**Dispatch everything, then signal shutdown.** This ordering is the whole point, and
it is what the original got wrong.

```
1. parent pushes ALL packets
2. parent puts exactly one SHUTDOWN_SENTINEL (a bare None) per consumer
     single-tier : one per worker input queue
     staged      : one per LB queue only — LBs drain, then fan out to their FPs
3. worker_main breaks on sentinel → finalize() → puts ONE WorkerResult → exits
4. _lb_main breaks on sentinel → fans out sentinels → puts ONE _LoadBalancerResult
5. parent _collect(...) with a 120 s timeout → RuntimeError, never a silent hang
6. join all processes
7. _close_quietly every queue
```

Why each piece exists:

| Mechanism | Prevents |
|---|---|
| dispatch-then-signal | a worker exiting while packets are still in flight — the original's silent packet loss |
| LB drains before fanning out | fast-paths exiting before their LB is done pushing |
| `SHUTDOWN_SENTINEL` is a distinct `None` | any real value being mistaken for a control message |
| `finally` terminate path | workers blocked forever if dispatch raises (e.g. `PcapLimitExceededError` mid-file) |
| 120 s `_collect` timeout | a lost worker hanging the parent forever with no error |
| `_close_quietly` | teardown exceptions masking the original error |

The C++ original instead set `running_ = false` while fast-paths were still pushing,
causing the output thread to exit mid-drain and subsequent pushes to be silently
discarded, added 700 ms of unconditional `sleep_for`, and had the reader thread
possibly write the output header *after* packet records — a corrupt pcap.

### Known gaps in the shutdown path

| Gap | Finding |
|---|---|
| `_collect` / `join` / `_close_quietly` are **not** wrapped in `try/finally` — a `RuntimeError` leaks live processes and unclosed queues | `D-12` |
| The 120 s budget is a constant, so a legitimately slow multi-GB capture is reported as a `RuntimeError` | `D-11` |
| An LB death orphans its FPs (above) | `D-13` |

---

## 11. Reporting — `report.py`

Nine text renderers plus a JSON form the original never had.

| Section | Denominator |
|---|---|
| Processing Report | drop rate over **inspected** packets (TCP+UDP), not total read |
| Pipeline Stages | per-FP and per-LB counts (multiprocess / staged only) |
| Inspection Coverage | SNI / HTTP Host / DNS / QUIC extraction counts |
| Application Breakdown | self-normalising over its own histogram |
| Flow State | state histogram across all workers |
| Top N Names by Active Flows | `--top-domains`, default 20 |
| Active Rules | rule counts per category |
| Blocked Flows | five-tuple + app + name |
| Resolved Names | every extracted name → app |

`result_to_dict` / `result_to_json` emit the same content machine-readably; enums are
rendered as display names so the JSON is directly consumable.

The original divided per-app counts by *total packets read* in one report and by
*classified + unknown connections* in another — two reports from the same run
disagreed. This port uses one documented denominator per quantity and states it in
the output. `GlobalConnectionTable::generateReport` was dead code in the original
(built, never printed); here it is wired into normal `run` output.

---

## 12. CLI reference

```
dpi-engine --version           print the package version
dpi-engine inspect <pcap>    header, size histogram, capabilities
dpi-engine dump <pcap>       per-packet five-tuple, protocol, TCP flags, payload size
dpi-engine rules             build/modify a ruleset; save/load as JSON
dpi-engine run <in> <out>    the full pipeline + report
```

### `run` flags

| Group | Flag | Default | Meaning |
|---|---|---|---|
| rules | `--block-ip` / `--block-app` / `--block-domain` / `--block-port` | — | append a block rule (repeatable) |
| | `--load-rules` / `--save-rules` | — | JSON ruleset in/out |
| staging | `--workers N` | 1 | fast-path process count; `> 1` selects multiprocess |
| | `--load-balancers K` | 0 | LB process count; `> 0` selects staged |
| | `--fps-per-lb F` | 2 | fast-paths per LB |
| | `--live-rules` | off | per-worker control channel (**ignored with `--load-balancers`**) |
| tuning | `--max-connections N` | 100,000 | tracked flows per process (LRU-evicted) |
| | `--flow-timeout S` | 300 | idle-flow reaping; `0` disables idle only |
| | `--reap-interval N` | 65536 | packets between reaper sweeps; `0` disables |
| | `--no-quic` | off | disable QUIC detection |
| output | `--top-domains N` | 20 | rows in the top-names table |
| | `--json` | off | emit the report as JSON |
| bounds | `--max-packet-size B` | 65535 | reject any larger packet |
| | `--max-total-packets N` | 10,000,000 | reject files with more packets |

`rules` additionally accepts `--unblock-ip` / `--unblock-app` /
`--unblock-domain` / `--unblock-port`.

### Dispatch

```
run
 ├─ apply --load-rules, then --block-*, then --save-rules
 ├─ validate: workers >= 1 · workers and load-balancers mutually exclusive
 │            load-balancers >= 1 · fps-per-lb >= 1
 ├─ --json ? suppress the human header
 ├─ load-balancers > 0 ? run_pipeline_staged
 │  : workers > 1        ? run_pipeline_multiprocess
 │  :                      run_pipeline
 └─ render_full_report  |  result_to_json
```

> Note: rules are applied and `--save-rules` is written **before** `--workers` and
> `--load-balancers` are validated, so an invalid combination still writes the rules
> file and then exits 1.

> **Windows/macOS:** the multiprocessing start method is `spawn`, so the MP entry
> points must be called from an `if __name__ == "__main__":` guard. The `dpi-engine`
> console script already is. Because children **re-import** modules, anything a test
> needs to pass to a worker must go through picklable arguments or environment
> variables — which is why `worker.py` carries a documented test-delay env-var hook.

---

## 13. Safety envelope

Binding constraints, enforced by `tests/test_safety_constraints.py`, which AST-scans
the shipped source for forbidden constructs and self-checks that the scan is not
passing vacuously.

| Constraint | Enforcement |
|---|---|
| Passive and offline — no raw sockets, no live interface capture, no injection/replay, no elevated privileges | AST scan for `socket.socket(`, etc. |
| No network calls at runtime | AST scan for `urllib.request`, `requests`, … |
| Never overwrite the input | enforced in `PcapWriter.__init__` itself, not just at the CLI |
| Bounded resources at every untrusted-input boundary | max packet size · max total packets · LRU-bounded flow table · stale-flow reaper |
| Workers are pure compute | only the parent process touches the filesystem |

### Where the bounds do **not** currently hold

The envelope above is the intent; these are the places the implementation does not
yet meet it. All are quantified in [`AUDIT.md`](AUDIT.md) §2.

| Gap | Finding |
|---|---|
| **Unbounded memory.** Workers accumulate every packet's full `RawPacket` for the whole run and return it as one pickled `WorkerResult`; queues have no `maxsize`, so the dispatch loop cannot apply backpressure. This **defeats every other bound in the table above** | `D-01` `D-02` |
| `_quic_inspectors`, `blocked_tuples` and `blocked_flows` are never pruned and are not covered by `--max-connections` | `D-22` |
| `max_packet_size` is enforced after dpkt has already allocated | `D-07` |

---

## 14. End-to-end data flow

```
pcap file
   │  PcapReader           bounds: count, packet size
   ▼
RawPacket(ts, bytes)
   │  parse_packet         Ethernet → IPv4 → TCP/UDP → ParsedPacket
   ▼
ParsedPacket + FiveTuple
   │  hash_select(tuple, N)      salt per tier; consistent across processes
   ├─────────────────────────────┬──────────────────────────────┐
   ▼                             ▼                              ▼
 worker / fast-path          (LB tier, staged only)        _FlowEngine
   │  refresh_rules                                     (single-process inline)
   │  get_or_create_connection  ← reap_if_due, LRU evict
   │  update_connection
   │  update_tcp_state        NEW→ESTABLISHED→…→BLOCKED/CLOSED
   │  classify                SNI │ HTTP Host │ QUIC │ DNS │ port guess
   │  classify_connection     confirmed locks; guess does not
   │  should_block            IP → PORT → APP → DOMAIN
   │  block                   monotonic set + tracker
   ▼
ProcessedPacket(sequence_index, raw, forwarded)
   │  accumulate / reorder by sequence_index
   ▼
forwarded ──► PcapWriter ──► filtered output pcap
dropped  ──► counter only
   │
   ▼
PipelineResult ──► report.render_full_report ──► stdout
                └─► report.result_to_json      ──► --json
```

### Safety envelope at each untrusted boundary

| Boundary | Bound | Finding if broken |
|---|---|---|
| pcap global header | magic, linktype | `PcapFormatError`, `PcapLinktypeError` |
| per-packet record | size, total count | `PcapLimitExceededError` |
| Ethernet/IPv4/truncation | never raises; degrades to `None` | counted `other_packets` |
| TLS/HTTP/DNS payload | bounds-checked before every offset advance | returns `None` |
| `--max-connections` | O(1) LRU eviction | oldest flow evicted |
| `--flow-timeout` / `--reap-interval` | cadence reaper | idle and CLOSED flows reclaimed |
| QUIC CRYPTO stream | `MAX_CRYPTO_BUFFER` 64 KiB | reassembly capped |
| worker → parent | — | **currently unbounded — `D-01`** |

---

## 15. Where this flow differs from the C++ original

Full rationale in [`DESIGN_DECISIONS.md`](DESIGN_DECISIONS.md); this is the summary.

| Aspect | Original | This port |
|---|---|---|
| Concurrency | threads, with two genuine data races | processes; no shared mutable state |
| Rule hot path | 4 × `std::shared_mutex`, per-packet IP→string→re-parse | copy-on-write; lock-free immutable snapshot; int-keyed |
| Domain rule `*` handling | any `*` stored as a wildcard, silently never matching | rejected at insertion |
| Domain case | exact path case-sensitive, pattern path insensitive | consistent everywhere |
| Flow eviction | O(n) full scan per insert when full | O(1) `popitem` |
| Stale reaping | only when the input queue was idle 100 ms — never under load | cadence-triggered in the hot path |
| Classification lock-in | *any* classification locked the flow | guess vs. confirmed; only confirmed is terminal |
| Two-tier hash | same hash, same modulus — half the pool idle | per-tier salts |
| Output ordering | header could be written after packet records | sentinel protocol + explicit sort |
| Classification accuracy | `netflix.com` → Twitter/X; `cf-` false positives | anchored patterns |
| QUIC | memory-unsafe, never called, functionally a no-op | full RFC 9001 Initial decryption |
| Dead code | report built but never printed; `payload_data` dangling | report wired in; stubs documented |
| Memory | bounded queues, streamed output | **regression — unbounded, see `D-01`** |
| Throughput | no serialization; reused buffers | **likely worse — unmeasured, see `P-15`** |