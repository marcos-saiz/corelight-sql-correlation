# Schema Notes

Corelight ships Zeek-format JSON logs, but downstream parsing pipelines often normalize the data into a different shape before it lands in a queryable store. This page captures the differences worth knowing if you're comparing field names across documentation sources.

## Native Zeek vs. normalized schemas

### Native Zeek log format

Zeek emits TSV (default) or JSON. In JSON mode, fields are mostly flat with dotted naming for nested structures:

```json
{
  "ts": 1735689784.043,
  "uid": "CFdJNt4FB4PwTJjpS4",
  "id.orig_h": "10.50.180.66",
  "id.orig_p": 52837,
  "id.resp_h": "13.107.42.16",
  "id.resp_p": 443,
  "proto": "tcp",
  "service": "ssl",
  "duration": 2.34,
  "orig_bytes": 1024,
  "resp_bytes": 8192
}
```

### Normalized / ECS-aligned schema

Pipelines that target [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) restructure the same data into a nested object hierarchy:

```json
{
  "@timestamp": "2026-01-01T14:43:04.043+00:00",
  "event": { "id": "CFdJNt4FB4PwTJjpS4" },
  "source":      { "ip": "10.50.180.66",   "port": 52837 },
  "destination": { "ip": "13.107.42.16",   "port": 443 },
  "network": { "transport": "tcp", "protocol": "ssl" },
  "host": { "ip": "10.50.180.66" }
}
```

[Corelight's `ecs-mapping`](https://github.com/corelight/ecs-mapping) repo documents the field-by-field mapping between native Zeek and ECS.

### Custom organizational schemas

Some downstream pipelines apply additional normalization on top of ECS:

- Field values may be wrapped in objects with metadata (`{"value": "...", "_acp": "..."}`) for data sensitivity labeling
- Arrays may be flattened to single values when only one element is present
- Mission / engagement metadata may be attached to every record (`mission.id`, `mission.partner`, etc.)
- Access-control labels (`_acp`) may decorate sensitive fields

## Field name mapping cheat sheet

| Concept | Native Zeek | ECS / Normalized |
|---|---|---|
| Connection UID | `uid` | `event.id` |
| Event timestamp | `ts` | `@timestamp` or `timestamp` |
| Source IP | `id.orig_h` | `source.ip` |
| Source port | `id.orig_p` | `source.port` |
| Destination IP | `id.resp_h` | `destination.ip` |
| Destination port | `id.resp_p` | `destination.port` |
| Transport protocol | `proto` | `network.transport` |
| Application protocol | `service` | `network.protocol` |
| File-to-conn link | `conn_uids[]` | `log.id.conn_uids` or `event.id[]` |
| File UID | `fuid` | `file.uid` |
| Bytes from originator | `orig_bytes` | `source.bytes` |
| Bytes from responder | `resp_bytes` | `destination.bytes` |

## SQL implications

When writing queries you'll need to know which schema layout you're against. A few common patterns:

### Native Zeek (flat dotted)

```sql
SELECT uid, "id.orig_h", "id.resp_h"
FROM conn_log
WHERE ts > '2026-01-01'
```

Note the quotes around dotted field names — most SQL parsers won't accept `id.orig_h` as a bare identifier.

### Nested object (Snowflake VARIANT, BigQuery STRUCT, etc.)

```sql
SELECT
  event.id,
  source.ip   AS src_ip,
  destination.ip AS dst_ip
FROM conn_log
WHERE timestamp > '2026-01-01'
```

### JSON column (Postgres, MySQL JSON_EXTRACT)

```sql
SELECT
  data->'event'->>'id' AS uid,
  data->'source'->>'ip' AS src_ip
FROM conn_log
WHERE (data->>'timestamp')::timestamptz > '2026-01-01'
```

### Wrapped values with metadata

If your data uses the wrapped pattern, you may need to dereference an additional layer:

```sql
-- Wrapped: source.ip.value rather than source.ip
SELECT
  source.ip.value AS src_ip,
  source.ip._acp  AS src_ip_sensitivity
FROM conn_log
```

## A note on field stability

Field names occasionally change between major Corelight releases, and downstream parsers may not be updated immediately. If a query that worked stops returning rows, suspect a schema rename or a sensor upgrade before assuming the data is gone.

Common signs of schema drift:
- `NULL` values where you used to see data
- Empty join results despite both tables being populated
- Fields described in vendor docs that don't exist in your data (or vice versa)

The fix is usually to compare the live schema (`DESCRIBE TABLE` or `INFORMATION_SCHEMA.COLUMNS`) against what your queries assume, and update the queries.

## Arrays in the wild

Several fields are arrays even when they often contain a single element:

| Field | Type | Notes |
|---|---|---|
| `conn_uids` (in files.log) | Array of strings | One file can traverse multiple conns; usually has one entry |
| `cert_chain_fuids` (in ssl.log) | Array of strings | The full TLS certificate chain |
| `uids` (in dhcp.log) | Array of strings | DHCP DISCOVER/OFFER/REQUEST/ACK aggregated |
| `tx_hosts`, `rx_hosts` (in files.log) | Array of IPs | Transmitting and receiving hosts for the file |
| `fuids` (in smtp.log, http.log) | Array of strings | All files attached or transferred in this transaction |

Some normalized schemas flatten single-element arrays to scalar values. To be safe, always write joins that handle both cases (array containment rather than scalar equality). See [`JOIN_KEYS.md`](JOIN_KEYS.md) for the patterns.

## Verifying your schema

Before writing a complex query, run a one-row sample query to confirm the field structure:

```sql
SELECT * FROM conn_log LIMIT 1;
```

For nested data on platforms like Snowflake, `DESCRIBE` and `OBJECT_KEYS` are your friends. On platforms with JSON columns, `jq` against a downloaded sample is faster than guessing.
