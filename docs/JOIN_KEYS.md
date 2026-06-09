# Join Keys — Quick Reference

One-page cheat sheet for which key to use when correlating across log types.

## Decision flow

```
Need to join two logs together?
│
├── Both are per-connection logs (dns, http, ssl, ssh, etc.)?
│   └── YES → JOIN ON uid
│
├── One side is files / x509 / pe?
│   └── YES → JOIN ON fuid (file ↔ file metadata)
│              JOIN ON UNNEST(conn_uids[]) → uid (file ↔ conn)
│
├── One side is an aggregation log (known_hosts, known_services, software, known_devices)?
│   └── YES → JOIN ON IP or MAC, WITH TIME WINDOW
│
├── Cross-tool join (Zeek ↔ Suricata ↔ Wireshark ↔ osquery)?
│   ├── Corelight integrated Suricata → JOIN ON uid (Corelight preserves it)
│   └── Anything else → JOIN ON community_id
│
└── No uid available, no community_id?
    └── JOIN ON 5-tuple + ts window (fallback)
```

## Quick lookup by scenario

| Scenario | Join key | Example |
|---|---|---|
| Enrich a conn with DNS, HTTP, SSL, SSH details | `uid` | `JOIN dns ON dns.uid = c.uid` |
| Link a file to the connection that carried it | `conn_uids[]` array | `JOIN conn c ON c.uid = ANY(f.conn_uids)` |
| Link a cert to its file record | `fuid` | `JOIN files f ON f.fuid = x.fuid` |
| Link a cert chain back to a TLS handshake | `cert_chain_fuids[]` array | `JOIN x509 x ON x.fuid = ANY(ssl.cert_chain_fuids)` |
| Add asset metadata to a conn | IP/MAC + time window | `JOIN known_devices kd ON kd.mac = c.src.mac AND c.ts BETWEEN kd.first_seen AND ...` |
| Add software fingerprint to a host's conn | IP + time window | `JOIN software s ON s.host = c.id.orig.h AND c.ts BETWEEN s.first_seen AND ...` |
| Add Suricata alert context to a conn (Corelight) | `uid` | `JOIN corelight_suricata cs ON cs.uid = c.uid` |
| Add Suricata alert context (non-Corelight) | `community_id` | `JOIN suricata s ON s.community_id = c.community_id` |
| Add threat intel hits to a conn | `uid` | `LEFT JOIN intel i ON i.uid = c.uid` |
| Add Zeek notices to a conn | `uid` (nullable) | `LEFT JOIN notice n ON n.uid = c.uid` (handle NULLs) |

## When to LEFT JOIN vs INNER JOIN

- **`LEFT JOIN` for enrichment** — add optional context to a base set of rows (e.g., add CVE data to assets, where some assets won't match)
- **`INNER JOIN` for filtering** — keep only rows that match (e.g., keep only conns where one endpoint is an IOC)
- **`LEFT JOIN` whenever the join might miss** — per-event logs (`notice`, `weird`) where `uid` can be null; aggregation logs where time windows might not match

## Cardinality cheat sheet

Knowing what to expect helps you spot when something is wrong (e.g., row counts exploding):

| Pattern | Cardinality | Cause |
|---|---|---|
| conn ↔ dns | 1 : N | One TCP/UDP DNS connection can carry many queries |
| conn ↔ http | 1 : N | HTTP keep-alive lets one TCP connection handle many requests |
| conn ↔ ssl | 1 : 1 | Usually one TLS handshake per connection |
| conn ↔ ssh | 1 : 1 | One SSH session per connection |
| conn ↔ files | 1 : N | One connection can transfer multiple files |
| files ↔ conn | 1 : 1+ | One file is usually in one conn but can span multiple (cached, multi-path) |
| ssl ↔ x509 | 1 : N | TLS handshake delivers a chain of N certs |
| conn ↔ known_hosts | many : 1 | Many connections per known host |
| conn ↔ known_services | many : 1 | Many connections per service |
| conn ↔ software | many : 1 or many : N | Host may have multiple software entries |
| conn ↔ corelight_suricata | 1 : N | One conn can trigger multiple Suricata alerts |

If you see cardinality you don't expect (e.g., 1:200 between conn and ssl), something is wrong — usually a missing join key (joining on IP alone, no time window) producing a Cartesian-like expansion.

## What kills the join

| Symptom | Likely cause | Fix |
|---|---|---|
| Zero rows from a uid join | Cross-sensor data, expired data, or one side is empty | Verify both tables have data for the same time window and same sensor |
| Cartesian explosion (millions of rows) | Joining on something that isn't unique (IP only, no time window) | Add the missing key (time window, port, protocol) |
| Inconsistent matches | Schema variation (conn_uids as scalar in some records, array in others) | Use array-aware syntax that handles both |
| Stale matches | Joining to an aggregation log without time window | Add the time-window predicate to anchor to the conn's `ts` |
