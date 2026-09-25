# DPI Engine (Python port) — Complete Workflow

Scope: `src/dpi_engine/` only. The original C++ engine under `OSC/` is excluded.

---

## 1. High-level architecture

```mermaid
flowchart TB
    subgraph CLI["cli.py — argparse console script `dpi-engine`"]
        C0{{"User invocation"}}
        C1["inspect — header + packet size summary"]
        C2["dump — per-packet 5-tuple / protocol / flags / payload size"]
        C3["rules — build / load / save blocking rules (JSON)"]
        C4["run — full DPI pipeline"]
        C0 --> C1
        C0 --> C2
        C0 --> C3
        C0 --> C4
    end

    subgraph LIB["Core library"]
        PIO["pcap_io.py<br/>PcapReader / PcapWriter<br/>RawPacket"]
        PAR["packet_parser.py<br/>parse_packet (dpkt)"]
        TRK["connection_tracker.py<br/>ConnectionTracker (LRU)<br/>TrackerStats / GlobalStats"]
        SNI["sni_extractor.py<br/>extract_sni / extract_http_host / extract_dns_query"]
        TYP["types.py<br/>FiveTuple / AppType / Connection<br/>sni_to_app_type / DPIStats"]
        RUL["rule_manager.py<br/>RuleManager.should_block"]
        PL["pipeline.py<br/>run_pipeline / run_pipeline_multiprocess"]
        WRK["worker.py<br/>worker_main"]
        DEMO["demo_classify.py<br/>standalone Task-7 demo"]
    end

    C1 --> PIO
    C2 --> PIO
    C2 --> PAR
    C3 --> RUL
    C4 --> RUL
    C4 --> PL
    DEMO --> PIO
    DEMO --> PAR
    DEMO --> TRK
    DEMO --> SNI
    DEMO --> TYP

    PL --> PIO
    PL --> PAR
    PL --> TRK
    PL --> SNI
    PL --> TYP
    PL --> RUL
    PL -.spawn.-> WRK
    WRK --> TRK
    WRK --> RUL
    WRK --> TYP

    PIO --> DP[("dpkt<br/>Ethernet / IP / TCP / UDP")]
    PAR --> DP
```

---

## 2. CLI command dispatch

```mermaid
flowchart TB
    A["main argv"] --> B["build_parser()"]
    B --> C{"subcommand?"}
    C -- none --> C1["print help, exit 0"]
    C -- inspect --> D["_cmd_inspect"]
    C -- dump --> D2["_cmd_dump"]
    C -- rules --> E["_cmd_rules"]
    C -- run --> F["_cmd_run"]

    subgraph INSPECT["inspect"]
        D --> D1["PcapReader(max_packet_size,<br/>max_total_packets)"]
        D1 --> D2["Iterate: count, total bytes,<br/>min/max pkt length"]
        D2 --> D3["Print linktype, snaplen, stats"]
    end

    subgraph DUMP["dump"]
        D2 --> E1["Iterate PcapReader"]
        E1 --> E2["parse_packet"]
        E2 --> E3{"parsed?"}
        E3 -- no --> E4["print unparseable frame"]
        E3 -- yes --> E5{"has_ip?"}
        E5 -- no --> E6["print non-IP frame"]
        E5 -- yes --> E7["print proto, ip:port -> ip:port,<br/>TCP flags, payload bytes"]
    end

    subgraph RULES["rules"]
        E --> E1["RuleManager() or load_rules(path)"]
        E1 --> E2["Apply --block-ip / -app / -domain / -port"]
        E2 --> E3["Validate: ipaddress IPv4,<br/>port 0-65535, known app name"]
        E3 --> E4{"valid?"}
        E4 -- RuleManagerError --> E5["stderr 'error:', exit 1"]
        E4 -- ok --> E6["Print RuleStats; save_rules JSON if asked"]
        E6 --> E7["exit 0"]
    end

    subgraph RUN["run"]
        F --> F1["RuleManager() or load_rules"]
        F1 --> F2["Apply --block-* flags"]
        F2 --> F3{"--save-rules?"}
        F3 -- yes --> F4["save_rules JSON"]
        F3 -- no --> F5
        F4 --> F5["Print header: version, mode, input, output"]
        F5 --> F6{"workers > 1?"}
        F6 -- yes --> F7["run_pipeline_multiprocess(num_workers)"]
        F6 -- no --> F8["run_pipeline"]
        F7 --> F9{"PcapError / ValueError?"}
        F8 --> F9
        F9 -- yes --> F10["stderr 'error:', exit 1"]
        F9 -- no --> F11["Print Processing Report<br/>(totals, TCP, UDP, fwd, drop, flows, per-worker)"]
        F11 --> F12["Print Application Breakdown with % bars"]
        F12 --> F13["Print Detected Domains/SNIs"]
        F13 --> F14["Print Blocked Flows"]
        F14 --> F15["exit 0"]
    end
```

---

## 3. `PcapReader` / `PcapWriter` (pcap_io.py)

```mermaid
flowchart TB
    subgraph RD["PcapReader(path, max_packet_size, max_total_packets, require_ethernet)"]
        R1["open(path,'rb')"] --> R2{"OSError?"}
        R2 -- yes --> RX1["PcapError: cannot open"]
        R2 -- no --> R3["dpkt.pcap.Reader(file)"]
        R3 --> R4{"parse error?"}
        R4 -- yes --> RX2["PcapFormatError: not a valid pcap"]
        R4 -- no --> R5{"datalink == DLT_EN10MB?"}
        R5 -- no --> RX3["PcapLinktypeError: only Ethernet supported"]
        R5 -- yes --> R6["ready — iterate (ts, buf)"]
        R6 --> R7{"packets_read >= max_total_packets?"}
        R7 -- yes --> RX4["PcapLimitExceededError"]
        R7 -- no --> R8{"len(buf) > max_packet_size?"}
        R8 -- yes --> RX5["PcapLimitExceededError: oversized packet"]
        R8 -- no --> R9["yield RawPacket(ts_sec, ts_usec,<br/>data=buf, orig_len=len(buf))"]
        R9 --> R6
    end

    subgraph WR["PcapWriter(path, linktype, snaplen, source_path)"]
        W1{"source_path given and<br/>resolves to same file?"} --> W2{"samefile or<br/>resolve() equal?"}
        W2 -- yes --> WX1["PcapError: refuse to overwrite input"]
        W2 -- no --> W3["open(path,'wb') + dpkt.pcap.Writer"]
        W3 --> W4["write(raw): writepkt(data, ts)"]
        W4 --> W5["close() on context exit"]
    end
```

---

## 4. `parse_packet` (packet_parser.py)

```mermaid
flowchart TB
    A["RawPacket"] --> B["dpkt.ethernet.Ethernet(data)"]
    B --> C{"NeedData / UnpackError?"}
    C -- yes --> CX["return None"]
    C -- no --> D["ParsedPacket(src_mac, dst_mac, ether_type)"]
    D --> E{"eth.type == ETH_TYPE_IP?"}
    E -- no --> F["return parsed (has_ip=False)<br/>ARP / IPv6 / VLAN"]
    E -- yes --> G{"ip.data is dpkt.ip.IP?"}
    G -- no --> H["return parsed (EtherType lied)"]
    G -- yes --> I["has_ip=True; src_ip, dst_ip<br/>(big-endian uint32), ttl, protocol"]
    I --> J{"ip.p == TCP and<br/>transport is dpkt.tcp.TCP?"}
    J -- yes --> K["has_tcp; sport, dport, seq, ack,<br/>flags, payload = transport.data"]
    J -- no --> L{"ip.p == UDP and<br/>transport is dpkt.udp.UDP?"}
    L -- yes --> M["has_udp; sport, dport, payload"]
    L -- no --> N["truncated sub-layer:<br/>degrade to no transport, empty payload"]
    K --> O["return parsed"]
    M --> O
    N --> O
    F --> O
    H --> O
```

---

## 5. Classification logic — `classify_flow_from_packet` (pipeline.py:73)

```mermaid
flowchart TB
    S["parsed packet + flow's current (app_type, sni)"] --> A{"retry_ok =<br/>app in (UNKNOWN, HTTPS)<br/>and sni == '' ?"}

    A -- yes --> B{"TCP and dst_port == 443?"}
    B -- yes --> B1{"len(payload) > 5?"}
    B1 -- yes --> B2["extract_sni(payload)"]
    B2 --> B3{"SNI found?"}
    B3 -- yes --> B4["RETURN (sni_to_app_type(sni), sni, confirmed=True)"]
    B3 -- no --> C
    B1 -- no --> C
    B -- no --> C

    A -- no --> C
    C{"retry_ok_http =<br/>app in (UNKNOWN, HTTP)<br/>and sni == '' ?"}
    C -- yes --> D{"TCP and dst_port == 80?"}
    D -- yes --> D1["extract_http_host(payload)"]
    D1 --> D2{"Host found?"}
    D2 -- yes --> D3["RETURN (app, host, confirmed=True)"]
    D2 -- no --> E
    D -- no --> E

    C -- no --> E
    E{"app == UNKNOWN and UDP and<br/>(dst_port or src_port == 53)?"}
    E -- yes --> E1["extract_dns_query(payload)"]
    E1 --> E2{"query found?"}
    E2 -- yes --> E3["RETURN (sni_to_app_type(query), query, confirmed=True)"]
    E2 -- no --> E4["RETURN (DNS, sni, confirmed=False)"]
    E -- no --> F

    F{"app == UNKNOWN?"}
    F -- yes --> G{"TCP dst_port == 443?"}
    G -- yes --> G1["RETURN (HTTPS, sni, confirmed=False) — port guess"]
    G -- no --> H{"TCP dst_port == 80?"}
    H -- yes --> H1["RETURN (HTTP, sni, confirmed=False) — port guess"]
    H -- no --> I
    F -- no --> I
    I["RETURN (app_type, sni, confirmed=False) — no-op"]
```

### `sni_to_app_type` domain → app mapping (types.py:179)

```mermaid
flowchart LR
    IN["SNI / Host / DNS query<br/>(lowercased)"] --> X{"exact match or<br/>subdomain of<br/>x.com or t.co ?"}
    X -- yes --> TW["Twitter/X"]
    X -- no --> P["first substring hit in fixed priority order:"]
    P --> P1["Google: google, gstatic, googleapis, ggpht, gvt1"]
    P --> P2["YouTube: youtube, ytimg, youtu.be, yt3.ggpht"]
    P --> P3["Facebook: facebook, fbcdn, fb.com, fbsbx, meta.com"]
    P --> P4["Instagram · WhatsApp · Twitter: twitter, twimg"]
    P --> P5["Netflix: netflix, nflxvideo, nflximg"]
    P --> P6["Amazon: amazon, amazonaws, cloudfront, aws"]
    P --> P7["Microsoft: microsoft, msn.com, office, azure, live.com, outlook, bing"]
    P --> P8["Apple: apple, icloud, mzstatic, itunes"]
    P --> P9["Telegram · TikTok · Spotify · Zoom · Discord · GitHub · Cloudflare"]
    P1 & P2 & P3 & P4 & P5 & P6 & P7 & P8 & P9 --> NO["no match"]
    NO --> FB["fallback AppType.HTTPS<br/>(preserved quirk)"]
    EMPTY["empty string"] --> UNK["AppType.UNKNOWN"]
```

### Extractors (sni_extractor.py) — bounds-checked, never raise

```mermaid
flowchart TB
    subgraph TLS["extract_sni(payload) — every skip bounds-checked first"]
        T0{"is_tls_client_hello?<br/>len >= 9, type 0x16,<br/>version 0x0300-0x0304,<br/>rec_len fits, hs type 0x01"}
        T0 -- no --> TN["None"]
        T0 -- yes --> T1["skip 5B record hdr<br/>check +4B handshake hdr"]
        T1 --> T2["check +2B version +32B random"]
        T2 --> T3["session_id_len byte,<br/>check +len"]
        T3 --> T4["cipher_suites_len u16,<br/>check +len"]
        T4 --> T5["compression_len byte,<br/>check +len"]
        T5 --> T6["extensions_len u16,<br/>clamp extensions_end to length"]
        T6 --> T7{"walk extensions<br/>while offset+4 <= end"}
        T7 --> T8{"type == 0x0000 (SNI)?"}
        T8 -- no --> T9["offset += ext_len, continue"]
        T8 -- yes --> T10{"ext_len >= 5, list_len >= 3,<br/>sni_type == 0x00,<br/>sni_len <= ext_len-5 ?"}
        T10 -- no --> TN
        T10 -- yes --> T11["decode ascii, else latin-1"]
        T9 --> T7
        T11 --> TOK["SNI string (confirmed)"]
    end

    subgraph HTTP["extract_http_host(payload)"]
        H0{"is_http_request?<br/>first 4B in GET /POST / PUT / HEAD / DELE / PATC / OPTI"} -- no --> HN["None"]
        H0 -- yes --> H1["scan for case-insensitive 'Host:'"]
        H1 --> H2["skip spaces/tabs, read to CR/LF"]
        H2 --> H3{"value non-empty?"}
        H3 -- yes --> H4["strip ':port' suffix, decode ascii"]
        H3 -- no --> H1
        H4 --> HOK["Host string (confirmed)"]
    end

    subgraph DNS["extract_dns_query(payload)"]
        D0{"is_dns_query?<br/>len >= 12, QR bit clear,<br/>qdcount != 0"} -- no --> DN["None"]
        D0 -- yes --> D1["walk labels from offset 12"]
        D1 --> D2{"label_len == 0?"} -- yes --> D3{"labels?"}
        D2 -- no --> D4{"label_len > 63?<br/>(compression ptr / invalid)"} -- yes --> D3
        D4 -- no --> D5{"offset+label_len <= length?"} -- no --> D3
        D5 -- yes --> D6["append label, advance"] --> D1
        D3 -- yes --> D7["join labels with '.'"]
        D3 -- no --> DN
        D7 --> DOK["queried domain (confirmed)"]
    end
```

---

## 6. Connection / flow state machine (connection_tracker.py + types.py)

```mermaid
stateDiagram-v2
    [*] --> NEW : get_or_create_connection
    NEW --> CLASSIFIED : first classification<br/>(guess or confirmed)
    CLASSIFIED --> CLASSIFIED : later guess replaces earlier guess
    CLASSIFIED --> CLASSIFIED : later CONFIRMED (SNI/Host) upgrades guess
    CLASSIFIED --> BLOCKED : should_block() matched<br/>state=DROP, once per 5-tuple
    BLOCKED --> [*] : connection stays blocked (terminal, sticky)
    CLOSED --> [*] : cleanup_stale / close_connection
    CLASSIFIED --> CLOSED : idle > timeout

    note right of CLASSIFIED
      Confirmed = SNI / HTTP Host / DNS query
      observed directly -> TERMINAL, never overwritten.
      Guess (port 443->HTTPS, port 80->HTTP, DNS)
      -> upgradable by a later guess or confirmed result.
      This is the fix for OSC's classification lock-in bug.
    end note

    note right of BLOCKED
      blocked_tuples set in pipeline/worker
      short-circuits should_block() after
      the first match — the rule is only
      evaluated once per five-tuple.
    end note
```

```mermaid
flowchart TB
    A["get_or_create_connection(tuple)"] --> B{"in OrderedDict?"}
    B -- yes --> B1["move_to_end (LRU touch)"]
    B1 --> R["return Connection"]
    B -- no --> C{"len >= max_connections?"}
    C -- yes --> C1["_evict_oldest(): popitem(last=False)<br/>O(1) — OSC did an O(n) scan"]
    C1 --> D
    C -- no --> D["create Connection(state=NEW,<br/>counters zeroed, timestamps)"]
    D --> R
```

---

## 7. Rule evaluation (rule_manager.py)

```mermaid
flowchart TB
    S["should_block(src_ip, dst_port, app, domain)"] --> A{"is_ip_blocked(src_ip)?<br/>ipaddress.IPv4Address validated"}
    A -- yes --> Z1["BlockReason(IP)"]
    A -- no --> B{"is_port_blocked(dst_port)?"}
    B -- yes --> Z2["BlockReason(PORT)"]
    B -- no --> C{"is_app_blocked(app)?"}
    C -- yes --> Z3["BlockReason(APP)"]
    C -- no --> D{"domain non-empty and<br/>is_domain_blocked(domain)?"}
    D -- yes --> Z4["BlockReason(DOMAIN)"]
    D -- no --> N["None -> FORWARD"]
    Z1 & Z2 & Z3 & Z4 --> BL["tracker.block_connection()<br/>tuple added to blocked_tuples<br/>recorded in blocked_flows"]
    BL --> DR["every later packet of this tuple:<br/>stats.dropped_packets += 1 (not written)"]

    subgraph DOM["domain matching — both paths lowercased"]
        D1["exact set: lowercased apex domains"]
        D2["wildcard list: '*.example.com' matches<br/>any subdomain AND the bare apex"]
        D1 --> D3
        D2 --> D3
    end

    subgraph PERS["JSON persistence"]
        P1["to_dict: blocked_ips, blocked_apps,<br/>blocked_domains, domain_patterns, blocked_ports"]
        P2["save_rules -> write_text(json.dumps)"]
        P3["load_rules -> json.loads + per-field validation"]
        P3 --> P4{"bad IP / port / app name<br/>or malformed JSON?"}
        P4 -- yes --> P5["RuleManagerError (never a raw stoi/JSON crash)"]
        P4 -- no --> P6["populated RuleManager"]
        P1 --> P2
    end
```

---

## 8. Single-process pipeline — `run_pipeline` (pipeline.py:119)

```mermaid
flowchart TB
    A["run_pipeline(input, output, rules,<br/>max_connections, max_packet_size, max_total_packets)"] --> B["rules = rules or RuleManager()"]
    B --> C["tracker = ConnectionTracker(fp_id=0)"]
    C --> D["blocked_tuples = set()<br/>stats / app_counts / detected_domains / blocked_flows"]
    D --> E["open PcapReader(input) + PcapWriter(output, source_path=input)"]
    E --> F["for raw in reader"]

    F --> G["stats.total_packets += 1<br/>stats.total_bytes += raw.orig_len"]
    G --> H["parsed = parse_packet(raw)"]
    H --> I{"parsed and has_ip and<br/>(has_tcp or has_udp)?"}
    I -- no --> I1["stats.other_packets += 1<br/>CONTINUE (not written to output)"]
    I -- yes --> J["stats.tcp_packets / udp_packets += 1"]
    J --> K["five_tuple = FiveTuple(src_ip, dst_ip,<br/>src_port, dst_port, protocol)"]
    K --> L["conn = tracker.get_or_create_connection(five_tuple)<br/>tracker.update_connection(..., is_outbound=True)"]
    L --> M["classify_flow_from_packet(parsed,<br/>conn.app_type, conn.sni)"]
    M --> N{"app or sni changed?"}
    N -- yes --> N1["tracker.classify_connection(<br/>new_app, new_sni, confirmed)"]
    N -- no --> O
    N1 --> O{"five_tuple not yet in blocked_tuples?"}
    O -- yes --> P["rules.should_block(src_ip_str, dst_port,<br/>conn.app_type, conn.sni)"]
    P --> Q{"reason?"}
    Q -- yes --> Q1["blocked_tuples.add; tracker.block_connection;<br/>blocked_flows.append((tuple, app, sni))"]
    Q -- no --> R
    Q1 --> R["app_counts[conn.app_type] += 1<br/>detected_domains[sni] = app (if sni)"]
    O -- no --> R
    R --> S{"tuple in blocked_tuples?"}
    S -- yes --> S1["stats.dropped_packets += 1"]
    S -- no --> S2["stats.forwarded_packets += 1<br/>writer.write(raw)"]
    S1 --> F
    S2 --> F
    I1 --> F

    F --> T["close reader + writer"]
    T --> U["stats.active_connections =<br/>tracker.get_stats().active_connections"]
    U --> V["return PipelineResult(stats, app_counts,<br/>detected_domains, blocked_flows)"]
    V --> W["cli prints Processing Report,<br/>App Breakdown, Domains, Blocked Flows"]
```

---

## 9. Hash-partitioned multiprocess pipeline — `run_pipeline_multiprocess` (pipeline.py:219)

```mermaid
flowchart TB
    A["run_pipeline_multiprocess(input, output, rules, num_workers, ...)"] --> A1{"num_workers < 1?"}
    A1 -- yes --> AX["ValueError -> CLI exit 1"]
    A1 -- no --> B["rules = rules or RuleManager()"]
    B --> C["Create N input queues + 1 shared output queue<br/>(local import of worker module avoids circular dep)"]
    C --> D["Spawn N processes targeting worker_main(worker_id,<br/>input_q, output_q, rules_snapshot, max_connections)"]
    D --> E["Start all processes"]
    E --> F["stats = DPIStats(); dispatch_succeeded = False"]

    F --> G["PcapReader(input) — iterate with sequence_index"]
    G --> H["stats.total_packets / total_bytes += ..."]
    H --> I["parse_packet"]
    I --> J{"parseable IPv4 + TCP/UDP?"}
    J -- no --> J1["stats.other_packets += 1; continue"]
    J -- yes --> K["build FiveTuple"]
    K --> L["worker_id = hash(five_tuple) % num_workers"]
    L --> M["input_queues[worker_id].put(WorkItem(sequence_index,<br/>raw, parsed, five_tuple))"]
    M --> G
    J1 --> G
    G --> N["reader exhausted -> dispatch_succeeded = True"]

    N --> O{"dispatch_succeeded?"}
    O -- yes --> P["put exactly ONE SHUTDOWN_SENTINEL (None)<br/>per worker queue — AFTER all packets were pushed"]
    P --> Q["Collect N WorkerResult from output_queue<br/>join all processes"]
    O -- no --> R["finally: terminate all workers,<br/>join(timeout=5), close queues"]
    R --> S["exception propagates out of the function<br/>(partial output pcap may remain on disk)"]
    S --> AX2["CLI: PcapError -> stderr, exit 1"]

    Q --> T["Sort results by worker_id;<br/>flatten processed_packets and re-sort by sequence_index<br/>(restores exact input order in the output)"]
    T --> U["Merge: per_worker_packet_counts,<br/>tcp/udp counts, blocked_flows, app_counts,<br/>detected_domains, combined TrackerStats"]
    U --> V["PcapWriter(output, source_path=input)"]
    V --> W{"pp.forwarded?"}
    W -- yes --> W1["stats.forwarded_packets += 1<br/>writer.write(pp.raw)"]
    W -- no --> W2["stats.dropped_packets += 1"]
    W1 --> X["close writer"]
    W2 --> X
    X --> Y["return PipelineResult(..., per_worker_packet_counts)"]
```

### Worker process loop (worker.py:119)

```mermaid
flowchart TB
    subgraph INIT["worker_main startup"]
        I1["tracker = ConnectionTracker(fp_id=worker_id)<br/>private, LRU-bounded, no sharing"] --> I2["blocked_tuples = set(); local counters"]
        I2 --> I3["NO filesystem / NO network in the worker<br/>rules are a read-only pickled snapshot"]
    end

    I3 --> L1["item = input_queue.get() — blocking,<br/>no shutdown(), no timeout polling"]
    L1 --> L2{"item is SHUTDOWN_SENTINEL (None)?"}
    L2 -- yes --> E1["build WorkerResult(worker_id, tracker_stats,<br/>all connections, processed_packets,<br/>app_counts, blocked_flows, tcp_count, udp_count)"]
    E1 --> E2["output_queue.put(result); process exits"]
    L2 -- no --> L3["tcp_count / udp_count += 1"]
    L3 --> L4["_maybe_apply_test_delay()<br/>(test-only env hook)"]
    L4 --> L5["conn = tracker.get_or_create_connection(five_tuple)<br/>update_connection(is_outbound=True)"]
    L5 --> L6["classify_flow_from_packet —<br/>identical logic to the single-process path"]
    L6 --> L7["if changed: tracker.classify_connection(...)"]
    L7 --> L8{"tuple not blocked yet?"}
    L8 -- yes --> L9["rules.should_block(...)"]
    L9 --> L10{"reason?"}
    L10 -- yes --> L11["blocked_tuples.add; block_connection;<br/>blocked_flows.append"]
    L10 -- no --> L12
    L11 --> L12["app_counts[conn.app_type] += 1"]
    L8 -- no --> L12
    L12 --> L13["forwarded = tuple not in blocked_tuples<br/>append ProcessedPacket(sequence_index, raw, forwarded)"]
    L13 --> L1
```

### Why hash-partitioning + the drain protocol

```mermaid
flowchart LR
    subgraph CONN["one five-tuple -> exactly one worker"]
        C1["pkt 0"] --> W["worker_id =<br/>hash(five_tuple) % N"]
        C2["pkt 1"] --> W
        C3["pkt 2"] --> W
        W --> W0["flow state (classification,<br/>blocked, counters) stays coherent"]
    end

    subgraph SAFE["shutdown ordering (fixes OSC packet loss)"]
        S1["push ALL WorkItems"] --> S2["push sentinel"] --> S3["worker drains<br/>its whole FIFO"] --> S4["push WorkerResult"] --> S5["main joins"]
    end

    subgraph ERR["exception during dispatch"]
        E1["PcapReader raises<br/>(e.g. PcapLimitExceededError)"] --> E2["finally: terminate() + join(5)<br/>— never leaves workers blocked on get()"]
    end
```

---

## 10. `demo_classify.py` — standalone classification demo

```mermaid
flowchart LR
    A["python -m dpi_engine.demo_classify file.pcap"] --> B["PcapReader"]
    B --> C["parse_packet"] --> D["skip if not has_ip"]
    D --> E["FiveTuple + get_or_create_connection<br/>update_connection"]
    E --> F["classify_packet(parsed)<br/>SNI : HTTPS; HTTP Host : HTTP;<br/>DNS query : app; else port guess"]
    F --> G["classify_connection(...)"]
    G --> H["print per-flow table:<br/>Flow / App / SNI-Host / Pkts"]
    H --> I["print TrackerStats:<br/>total seen, classified"]
```

---

## 11. End-to-end data flow summary

```mermaid
flowchart LR
    subgraph MAIN["Main process (only place that touches the filesystem)"]
        direction TB
        M1["Input .pcap"] --> M2["PcapReader<br/>(bounds-checked)"]
        M2 --> M3["parse_packet<br/>(dpkt Ethernet/IP/TCP/UDP)"]
        M3 --> M4{"single-process<br/>or hash-partitioned?"}
        M4 -- single --> M5["in-process classify + should_block"]
        M4 -- "--workers N" --> M6["hash(5-tuple) % N -> input queue"]
        M6 --> M7["collect WorkerResults,<br/>re-sort by sequence_index"]
        M5 --> M8["merge stats + write Output .pcap"]
        M7 --> M8
    end

    subgraph W["Worker process 0..N-1 (pure compute)"]
        direction TB
        W1["WorkItem in FIFO"] --> W2["private ConnectionTracker"]
        W2 --> W3["extract_sni / extract_http_host /<br/>extract_dns_query -> AppType"]
        W3 --> W4["RuleManager.should_block<br/>(immutable snapshot)"]
        W4 --> W5["ProcessedPacket(outcome)"]
        W5 --> W6["WorkerResult on sentinel"]
    end

    M6 -.mp.Queue.-> W1
    W6 -.mp.Queue.-> M7

    M8 --> M9["Filtered output .pcap<br/>(blocked flows removed)"]
    M8 --> M10["CLI report:<br/>Processing / App Breakdown /<br/>Domains / Blocked Flows"]
```

### Safety envelope (enforced at every untrusted boundary)

```mermaid
flowchart TB
    S1["Passive, offline, file-based only"] --> S2["no raw sockets / live capture / injection"]
    S2 --> S3["no network calls at runtime"]
    S3 --> S4["PcapWriter refuses output path == input path"]
    S4 --> S5["max_packet_size (default 65535)"]
    S5 --> S6["max_total_packets (default 10,000,000)"]
    S6 --> S7["max_connections (default 100,000)<br/>+ O(1) LRU eviction"]
    S7 --> S8["parsers/extractors return None on malformed input<br/>— never raise on packet content"]
    S8 --> S9["workers are pure compute:<br/>no filesystem, no network, no shared mutable state"]
```
