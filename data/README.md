# Data Directory

Static reference data and sample records used by the enrichment pipeline.

## Layout

| Path | Purpose |
|---|---|
| [`samples/`](samples/) | Sanitized example Corelight JSON records for testing |
| [`lookups/`](lookups/) | Reference tables (vendor-to-CPE mapping, etc.) |
| `cache/` | Local cache of NVD responses and the CISA KEV catalog. Created at runtime, gitignored. |
| `output/` | Enriched records written by `scripts/enrich_assets.py`. Created at runtime, gitignored. |

## Cache directory

Created automatically by the scripts. Don't commit anything from here — the NVD responses are large and the KEV catalog should be re-fetched on each clone.

Override the cache location by setting the `CACHE_DIR` environment variable or editing [`scripts/config.py`](../scripts/config.py).

## Output directory

Created automatically when you run the enrichment pipeline. The default output file is `output/enriched.json`. Override with `--output` on the script or by setting `OUTPUT_DIR`.

## What does and doesn't get committed

**Committed (under version control):**
- `samples/` — sanitized example records
- `lookups/` — reference data that the project depends on
- This README and the others in subdirectories

**Not committed (in `.gitignore`):**
- `cache/` — runtime API caches
- `output/` — runtime output files
- `raw/` — any raw data drops (in case you put real records here for testing)

**Never commit real records to a public repo.** They contain real IPs, MACs, hostnames, and engagement metadata.
