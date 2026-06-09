# Corelight / Zeek Log Correlation Reference

How the different log types relate to each other, what join keys exist, and what each log can tell you. This is the canonical reference for writing SQL that correlates across log types.

## The TL;DR

- **`conn.log` is the spine.** Every per-connection log links back to it via `uid` (called `event.id` in some normalized schemas).
- **Aggregation logs (`known_hosts`, `known_services`, `known_devices`, `software`) don't carry `uid`.** They're keyed by IP or MAC and must be joined with a time window.
- **`files.log` uses `conn_uids` as an array** linking to the connection(s) that carried the file.
- **`community_id` is the cross-tool join key** — it's a deterministic 5-tuple hash that lets you correlate Zeek to Suricata, Wireshark, osquery, or anything else that computes it.
- **Corelight preserves `uid` inside `corelight_suricata.log`.** When using Corelight's integrated Suricata specifically, prefer `uid` over `community_id`.

## Three principles to internalize

### 1. State Anchor Logic

When joining to aggregation logs (`known_hosts`, `known_devices`, `software`, `known_services`), never join on IP alone. Because IPs are reassigned (DHCP churn), you must anchor your join by ensuring the connection timestamp (`conn.ts`) falls within the host's active window:

```sql
-- Wrong: IP-only join, gives wrong matches after any DHCP reassignment
JOIN known_devices kd ON kd.ip = c.source.ip.value

-- Right: anchored to the conn's timestamp
JOIN known_devices kd
  ON kd.ip = c.source.ip.value
  AND c.timestamp BETWEEN kd.first_seen AND COALESCE(kd.last_seen, NOW())
```

### 2. Leverage the Suricata Advantage

Corelight uniquely preserves the Zeek `uid` inside `corelight_suricata.log`. That means a Suricata alert in a Corelight deployment can be joined directly to the corresponding Zeek protocol log (HTTP, DNS, SSL) on `uid` — no `community_id` hash, no 5-tuple reconstruction. This is cleaner and faster.

For stock Suricata or any non-Corelight pipeline that ships Suricata separately, fall back to `community_id`.

### 3. Beware of Many-to-Many Cardinality

Logs like `software.log` or `smtp.log` (with attachments) can produce massive result sets if joined naively. A single host can have dozens of fingerprinted software entries; a single SMTP transaction can reference many file attachments. Always filter your target set before committing to a join, or use aggregation (`ARRAY_AGG`, `LISTAGG`) to collapse one-to-many relationships.

If you see your dashboard row counts exploding, this is usually why.

## The four flavors of log

### Per-connection protocol logs

One row per protocol observation tied to a network connection. All carry `uid`.

Examples: `dns`, `http`, `ssl`, `ssh`, `ftp`, `smtp`, `kerberos`, `ntlm`, `rdp`, `smb_files`, `smb_mapping`, `dce_rpc`, `radius`, `snmp`, `sip`, `ntp`, `mysql`, `mqtt_publish`, `modbus`, `dnp3`, `tunnel`, `syslog`, `dpd`.

Join pattern: `<protocol>.uid = conn.uid`

### Per-connection file logs

Track files extracted from connections. Use `fuid` (file UID) and `conn_uids` (array of connection UIDs the file traversed).

Logs: `files`, `x509`, `pe`.

Join pattern: array-aware. `c.uid IN UNNEST(f.conn_uids)` or equivalent platform-specific syntax.

### Aggregation / state logs

One row per *discovered fact about a host or service*, not per connection. **No `uid`.** Keyed by IP and/or MAC, often with a time window.

Logs: `known_hosts`, `known_services`, `known_certs`, `software`, `known_devices` (Corelight).

Join pattern: IP or MAC + time window.

### Per-event / optional logs

Carry `uid` when the event is bound to a connection, but `uid` can be null.

Logs: `notice`, `weird`, `intel`, `signatures`.

Join pattern: `LEFT JOIN` on uid, handle NULLs.

## Join key hierarchy

When you have a choice, prefer in this order:

1. **`uid`** — exact connection match, single-sensor. The cleanest join.
2. **`fuid` / `conn_uids`** — for file-related joins, after array expansion.
3. **`community_id`** — cross-tool / cross-sensor. Deterministic 5-tuple hash.
4. **5-tuple (`id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto`) + time window** — fallback when no UID is available.
5. **IP + time window** — only for aggregation logs that don't carry connection-level keys.

## Log inventory

| Log | Category | uid? | community_id? | Asset key | Notes |
|---|---|---|---|---|---|
| `conn.log` | Per-connection (backbone) | Yes | Yes | id.orig_h, id.resp_h | The spine. Start every join chain here. |
| `dns.log` | Per-connection protocol | Yes | Yes (if enabled) | id.orig_h, id.resp_h | 1 conn : N DNS queries |
| `http.log` | Per-connection protocol | Yes | Yes (if enabled) | id.orig_h, id.resp_h, host | Keep-alive means 1 conn : N requests |
| `ssl.log` | Per-connection protocol | Yes | Yes (if enabled) | id.orig_h, id.resp_h, server_name | Has `cert_chain_fuids[]` for chaining to x509 |
| `ssh.log` | Per-connection protocol | Yes | Yes (if enabled) | id.orig_h, id.resp_h | 1:1 with conn typically |
| `ftp.log` | Per-connection protocol | Yes | Yes (if enabled) | id.orig_h, id.resp_h | 1 conn : N commands |
| `smtp.log` | Per-connection protocol | Yes | Yes (if enabled) | id.orig_h, id.resp_h, mailfrom | 1 conn : N transactions |
| `smb_files.log` | Per-connection protocol | Yes | Yes (if enabled) | id.orig_h, id.resp_h | Joins to files.log via fuid |
| `smb_mapping.log` | Per-connection protocol | Yes | Yes (if enabled) | id.orig_h, id.resp_h | SMB share access |
| `dce_rpc.log` | Per-connection protocol | Yes | Yes (if enabled) | id.orig_h, id.resp_h | Often relevant for lateral movement |
| `kerberos.log` | Per-connection protocol | Yes | Yes (if enabled) | id.orig_h, id.resp_h, client, service | Kerberos auth events |
| `ntlm.log` | Per-connection protocol | Yes | Yes (if enabled) | id.orig_h, id.resp_h, username | NTLM auth |
| `rdp.log` | Per-connection protocol | Yes | Yes (if enabled) | id.orig_h, id.resp_h | RDP sessions |
| `dhcp.log` | Per-connection protocol | No (uses uids[]) | No | mac, assigned_addr | DHCP DISCOVER/OFFER/REQUEST/ACK aggregated |
| `files.log` | Per-connection (file) | No (uses conn_uids[]) | No | tx_hosts[], rx_hosts[] | Primary key is fuid |
| `x509.log` | File metadata | No | No | N/A (key is fuid) | Joins to ssl via cert_chain_fuids |
| `pe.log` | File metadata | No | No | N/A (key is fuid) | PE (Windows executable) metadata |
| `notice.log` | Per-event (optional uid) | Sometimes | Sometimes | id.orig_h, id.resp_h (when present) | uid can be null |
| `weird.log` | Per-event (optional uid) | Sometimes | No | id.orig_h, id.resp_h (when present) | Protocol anomalies |
| `intel.log` | Per-event (optional uid) | Yes (when in conn) | No | id.orig_h, id.resp_h, indicator | Threat intel hits |
| `known_hosts.log` | Aggregation / state | No | No | host (IP) | NO uid. IP + time window required. |
| `known_services.log` | Aggregation / state | No | No | host (IP), port_num | Server-side join (id.resp_*) |
| `known_certs.log` | Aggregation / state | No | No | host, port_num, serial | Cert posture queries |
| `software.log` | Aggregation / state | No | No | host (IP), name, version | The CVE-mapping gold mine |
| `known_devices.log` | Aggregation / state (Corelight) | No | No | mac, ip | Corelight-specific. Schema may vary by sensor version. |
| `corelight_suricata.log` | Cross-tool (Corelight) | **Yes (Zeek uid preserved)** | Yes | src_ip, dest_ip | Corelight preserves uid here — use it. |
| `encrypted_dns.log` | Per-connection (Corelight) | Yes | Yes | id.orig_h, id.resp_h | DoH / DoT detection |

## Join matrix

Common joins, in priority order:

| From | To | Join key | Type | Cardinality | What it answers |
|---|---|---|---|---|---|
| `dns` | `conn` | uid | Exact | 1 conn : N dns | Link DNS queries to underlying connection |
| `http` | `conn` | uid | Exact | 1 conn : N http | Link HTTP to underlying TCP conn |
| `ssl` | `conn` | uid | Exact | 1:1 typical | Link TLS handshake to connection |
| `ssh` | `conn` | uid | Exact | 1:1 | Link SSH session to connection |
| `files` | `conn` | UNNEST(conn_uids[]) → uid | Exact (after expansion) | 1 file : 1+ conns | Link file to carrying conn(s) |
| `x509` | `files` | fuid | Exact | 1:1 | Link cert to file record |
| `x509` | `ssl` | UNNEST(ssl.cert_chain_fuids[]) → x509.fuid | Exact (after expansion) | 1 ssl : N x509 | Link certs to TLS handshake |
| `pe` | `files` | id (fuid) | Exact | 1:1 | Link PE metadata to file |
| `notice` | `conn` | uid (when present) | Exact when present | 1:1 when bound | Link Zeek notice to conn |
| `weird` | `conn` | uid (when present) | Exact when present | 1:1 when bound | Link anomaly to conn |
| `intel` | `conn` | uid | Exact | 1:1 | Link threat intel hit to conn |
| `dhcp` | `conn` | UNNEST(uids[]) → uid | Exact (after expansion) | 1 dhcp : N conns | Link DHCP transaction to packets |
| `conn` | `known_hosts` | id.orig_h or id.resp_h = host | Time-windowed | many:1 | "Is this host known?" context |
| `conn` | `known_services` | (id.resp_h, id.resp_p, proto) = (host, port_num, port_proto) | Time-windowed | many:1 | Server-side service identification |
| `conn` | `software` | id.orig_h or id.resp_h = host | Time-windowed | many:1 or many:many | Software fingerprinting per host |
| `conn` | `known_certs` | (id.resp_h, id.resp_p) = (host, port_num) | Time-windowed | many:1 | Cert posture for destination |
| `conn` | `known_devices` | id.orig_h via dhcp.log → mac → known_devices | Time-windowed | many:1 | Asset attribution (Corelight) |
| `dhcp` | `known_devices` | mac | Time-windowed | 1:1 expected | DHCP lease to asset record |
| `corelight_suricata` | `conn` | uid | Exact | 1 conn : N Suricata alerts | IDS alert to flow data |
| (any Zeek log) | (non-Corelight Suricata, other tools) | community_id | Exact (deterministic) | 1:N typical | Cross-tool correlation |

## Common pitfalls

### IP-only joins to aggregation logs

`known_hosts`, `known_services`, `software` don't have `uid`. Joining on IP without a time window will give you wrong matches when IPs are reassigned across hosts (which they will be in any DHCP environment).

**Wrong:**
```sql
JOIN known_hosts kh ON kh.host = c.id.orig_h
```

**Right:**
```sql
JOIN known_hosts kh
  ON kh.host = c.id.orig_h
  AND c.ts BETWEEN kh.first_seen AND COALESCE(kh.last_seen, NOW())
```

### Destination MAC for cross-subnet traffic

The destination MAC in a `conn.log` record is the gateway/router MAC when the traffic crosses subnets, not the destination host's MAC. Joining `known_devices` on `c.id.resp.mac` for outbound traffic will return nothing useful (or the gateway record, if it's tracked).

Recognize a locally-administered MAC by checking the second bit of the first octet — it's the universal/local (U/L) bit. If it's set, the MAC was assigned manually rather than burned in by a vendor, which usually means a router, firewall, virtual interface, or similar infrastructure device.

### conn_uids as scalar vs array

In native Zeek, `conn_uids` is an array. Some normalized schemas may flatten it to a single value when there's only one element. To be safe, always use array-aware syntax:

```sql
-- Works whether conn_uids is array or scalar
JOIN conn c ON c.uid = ANY(f.conn_uids)
-- Or platform-specific:
JOIN conn c ON ARRAY_CONTAINS(f.conn_uids, c.uid)
JOIN conn c ON c.uid IN UNNEST(f.conn_uids)
```

### HTTP join to HTTPS traffic

HTTPS connections produce records in `ssl.log`, not `http.log`. If you're hunting for HTTP server headers and your target is on port 443, look in `ssl.log` for the SNI and consider that the content is encrypted — server fingerprinting requires TLS-side signals (JA3, JA4, cipher suites).

### community_id vs uid for Suricata

Corelight's integrated `corelight_suricata.log` preserves the Zeek `uid`. Stock Suricata does not — it computes `community_id` instead. Prefer `uid` when joining to Corelight's Suricata, `community_id` when joining to stock Suricata or to alerts from other tools.

## Standalone logs (cannot be joined)

Some logs carry no connection-level identifiers and are not joinable to traffic. They exist for sensor operations, telemetry, and Zeek-internal diagnostics — useful in their own right, just not as enrichment to connections.

| Log | Purpose | Why you care |
|---|---|---|
| `stats.log` | Zeek process performance telemetry | Use to validate sensor health, not for traffic correlation |
| `capture_loss.log` | Sensor capture-loss telemetry | If `capture_loss` shows high percentages, your alerts are likely missing data. Use to validate log integrity. |
| `broker.log` | Zeek inter-process communication | Manager / Logger / Worker communications. Errors here mean the sensor is crashing or bottlenecked. |
| `cluster.log` | Zeek cluster coordination | Similar to broker — sensor-health signal, not traffic data |
| `config.log` | Zeek configuration changes | Audit trail for sensor config |
| `reporter.log` | Zeek internal warnings | "Weird traffic that couldn't be parsed." Worth checking when data seems missing. |
| `loaded_scripts.log` | List of Zeek scripts loaded at startup | Inventory of what detection content is active |
| `packet_filter.log` | BPF filter changes | Records when capture filters change |
| `print.log` | Output of `print()` statements in scripts | Usually empty in production. Populated only if a custom script uses `print()`. |
| `corelight_audit.log` | Corelight appliance admin actions | Who logged in, what settings changed. Corelight-specific. |
| `corelight_license_capacity.log` | License and capacity telemetry | Sensor capacity metrics |

These do not have a `uid`, `community_id`, or any other join key, and trying to correlate them to traffic will not work. They live alongside the traffic logs in dashboards as their own panels.

## See also

- [`JOIN_KEYS.md`](JOIN_KEYS.md) — Quick reference card for the join keys
- [`GLOSSARY.md`](GLOSSARY.md) — Plain-English definitions of the terms used above
- [Book of Zeek log reference](https://docs.zeek.org/en/current/script-reference/log-files.html) — the authoritative reference for Zeek's native logs
- [Corelight Zeek log cheatsheets](https://github.com/corelight/zeek-cheatsheets) — quick reference cards by log type
- [Corelight ecs-mapping repo](https://github.com/corelight/ecs-mapping) — schema mappings to ECS, useful as a field inventory even if you're not using ECS
