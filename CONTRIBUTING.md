# Contributing

Ways to extend or improve this project.

## Adding a vendor to the CPE mapping

The most common improvement. When you encounter a vendor not in [`data/lookups/vendor_to_cpe.csv`](data/lookups/vendor_to_cpe.csv):

1. Find the right CPE vendor string. NVD's product search will tell you:
   ```bash
   curl -s "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=vendor-name" \
     | jq '.products[].cpe.cpeName' | head
   ```
   Look at the second segment of each `cpe:2.3:part:vendor:product:...` string.

2. Add a row to the CSV:
   ```csv
   raw_vendor,cpe_vendor,notes
   New Vendor LLC,newvendor,Brief description of what they make
   ```

3. Test:
   ```bash
   python -c "from scripts.normalize_vendors import normalize_vendor; print(normalize_vendor('New Vendor LLC'))"
   ```

4. Commit with a message like `Add CPE mapping for New Vendor`.

## Adding a new log type handler

If you want to extract software / version data from a log type that isn't already covered (e.g., `mysql.log`, `mqtt_publish.log`):

1. Add a new `WITH ... AS` block to [`sql/02_extract_software.sql`](sql/02_extract_software.sql) following the existing patterns.
2. Update the `UNION ALL` chain at the bottom to include the new branch.
3. Document the new log in [`docs/PIPELINE.md`](docs/PIPELINE.md).
4. If the parsing requires new normalization rules, extend [`scripts/normalize_vendors.py`](scripts/normalize_vendors.py).

## Adding a SQL pattern

The four SQL files cover the main pipeline. If you have additional patterns worth sharing (asset deduplication across engagements, time-series of vulnerabilities by VLAN, etc.):

1. Add a new file under `sql/` with a descriptive name.
2. Document its purpose, inputs, outputs, and dialect notes at the top.
3. List it in [`sql/README.md`](sql/README.md).

## Improving the parser

The accessors in [`scripts/corelight_parser.py`](scripts/corelight_parser.py) try multiple field paths to handle schema variation. If you discover a field path that should be added (e.g., a parser variant emits `host.ip.address` instead of `host.ip.value`):

1. Add the new path to the appropriate accessor in priority order.
2. If the variant is from a known parser, note it in a docstring comment.

## Reporting issues

Issues that are particularly welcome:

- Schema variations not handled by the parser
- New vendors that should be in the lookup table
- SQL dialect issues (the queries should work on Snowflake / BigQuery / Trino / Databricks; report any that don't)
- NVD API edge cases (rate limit handling, response shapes, etc.)
- KEV catalog format changes (CISA occasionally restructures it)

Open an issue describing what you observed, what you expected, and what dataset / environment produced it (sanitize anything sensitive).

## Code style

Python: PEP 8 with a soft 100-character line limit. Type hints where they help.

SQL: lowercase keywords (`SELECT`, `JOIN`) feel old-school. We use UPPERCASE for SQL keywords, `lowercase_with_underscores` for identifiers. Field paths from the source data preserve the original casing.

Markdown: GitHub-flavored. Code fences with language tags. Tables for any structured comparison.

## What's intentionally out of scope

A few things this project deliberately does *not* try to do:

- **Replace a vulnerability scanner.** Active scanning has access to more precise data and gets more accurate findings. This project complements scanning, it doesn't replace it.
- **Cover every CVE.** NVD has its own coverage gaps (some commercial products are sparsely covered; some niche software isn't there at all). This project does what it can with what NVD has.
- **Real-time analysis.** This is a batch pipeline against historical data, not a streaming engine.
- **Vendor-specific deep-dive.** The pipeline produces vendor-agnostic output. If you need vendor-specific risk scoring (Cisco PSIRT data, Microsoft Patch Tuesday correlation, etc.), build that on top of the enriched records.
