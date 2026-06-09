# SQL Reference Queries

SQL patterns for the enrichment pipeline. These are written to be dialect-agnostic where possible, with notes where syntax diverges.

## Files

| File | Purpose | When to run |
|---|---|---|
| [`01_extract_assets.sql`](01_extract_assets.sql) | Pull device records from `known_devices.log` | First step — builds the anchor asset table |
| [`02_extract_software.sql`](02_extract_software.sql) | Pull software / version observations from `software.log`, `http.log`, `ssh.log`, `ssl.log` | After assets exist — populates the software observations |
| [`03_join_software_to_assets.sql`](03_join_software_to_assets.sql) | Time-anchored join of software observations to asset records | After 01 and 02 — produces the per-asset software inventory |
| [`04_enrich_with_cve_kev.sql`](04_enrich_with_cve_kev.sql) | Join the asset/software table against the CVE and KEV reference tables | After CVE/KEV reference tables are populated by the Python scripts |
| [`05_common_use_cases.sql`](05_common_use_cases.sql) | Five standalone patterns useful in network forensics (file origin, lateral movement, encrypted traffic decoding, asset attribution, data exfiltration hunt) | Use as templates — not part of the core pipeline |

## A note on SQL dialects

The queries target a generic SQL with nested-object access (Snowflake, BigQuery, Trino, Databricks). Where syntax differs significantly, notes are inline.

Common dialect-specific replacements:

| Operation | Snowflake | BigQuery | Trino / Athena | Postgres |
|---|---|---|---|---|
| Array contains | `ARRAY_CONTAINS(elem, arr)` | `elem IN UNNEST(arr)` | `CONTAINS(arr, elem)` or `elem = ANY(arr)` | `elem = ANY(arr)` |
| Array flatten | `LATERAL FLATTEN(arr)` | `UNNEST(arr)` | `UNNEST(arr)` | `UNNEST(arr)` |
| Nested field access | `obj:field` or `obj.field` | `obj.field` | `obj.field` | `obj->'field'` |
| Time window join | `BETWEEN` or `ASOF JOIN` | `BETWEEN` | `BETWEEN` | `BETWEEN` |

## Recommended execution pattern

1. Run `01_extract_assets.sql` and persist the result as a table or view called `assets`.
2. Run `02_extract_software.sql` and persist as `software_observations`.
3. Run `03_join_software_to_assets.sql` against the two tables, persist as `asset_software`.
4. Have the Python scripts populate `cve_reference` and `kev_reference` tables (or files).
5. Run `04_enrich_with_cve_kev.sql` to produce the final enriched view.

You can also chain everything as CTEs in a single query — see [`04_enrich_with_cve_kev.sql`](04_enrich_with_cve_kev.sql) for an example.

## Schema assumptions

These queries assume a normalized schema where Corelight JSON has been parsed into nested objects accessible via dotted paths (`source.ip.value`, `event.id`, `network.vlan.id`, etc.). If your pipeline uses a different shape (flat columns, ECS, raw JSON), adapt the field paths but the join logic remains the same.

See [`../docs/SCHEMA_NOTES.md`](../docs/SCHEMA_NOTES.md) for the equivalence table.
