# Scripts

Python scripts for the enrichment pipeline.

| Script | Purpose |
|---|---|
| [`config.py`](config.py) | Central configuration — paths, API endpoints, defaults |
| [`corelight_parser.py`](corelight_parser.py) | Helpers for parsing Corelight JSON records (handles both flat and nested schemas) |
| [`normalize_vendors.py`](normalize_vendors.py) | Map raw vendor / product strings to CPE-compatible names |
| [`fetch_kev_catalog.py`](fetch_kev_catalog.py) | Download and cache the CISA KEV catalog |
| [`fetch_nvd_cves.py`](fetch_nvd_cves.py) | Query the NVD CVE API for CVEs matching a CPE string |
| [`enrich_assets.py`](enrich_assets.py) | End-to-end enrichment — takes a Corelight JSON record, returns an enriched record |

## Quick start

```bash
# Setup
python -m venv .venv
source .venv/bin/activate
pip install -r ../requirements.txt

# Pull down the CISA KEV catalog (one-time, then refresh periodically)
python fetch_kev_catalog.py

# Run enrichment on the sample asset record
python enrich_assets.py --input ../data/samples/known_devices_sample.json --output enriched.json
```

## With an NVD API key

The NVD API works without a key but rate-limits to 5 requests per 30 seconds. With a key (free, register at <https://nvd.nist.gov/developers/request-an-api-key>) you get 50 requests per 30 seconds.

Set the key as an environment variable:

```bash
export NVD_API_KEY="your-key-here"
```

The scripts will pick it up automatically.

## Cache directory

By default, scripts cache downloaded data (KEV catalog, NVD responses) under `data/cache/` at the repo root. Override with `--cache-dir` on the relevant scripts or by setting `CACHE_DIR` in [`config.py`](config.py).

## Production considerations

These scripts are written as a proof of concept — clear and inspectable rather than maximally performant. For production use:

- **Add a real database** instead of file-based caching for the NVD responses
- **Schedule the KEV catalog refresh** as a daily cron job
- **Use the NVD's modification date filtering** to fetch only CVEs that have changed since the last run
- **Parallelize NVD calls** with respect to rate limits (the [`tenacity`](https://tenacity.readthedocs.io/) library helps; an async client would be faster still)
- **Persist enriched records** somewhere queryable rather than spitting JSON to disk
