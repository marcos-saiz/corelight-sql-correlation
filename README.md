# corelight-sql-correlation

> Enrich Corelight NDR observations with CVE and CISA KEV context to produce risk-scored asset inventories from passive network telemetry.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](#requirements)

## What this is

A proof-of-concept enrichment pipeline that takes network observations from a [Corelight](https://corelight.com/) NDR sensor and turns them into a risk-scored asset inventory by joining them against:

- The [NVD CVE database](https://nvd.nist.gov/) (all published CVEs and their CPE mappings)
- The [CISA Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (CVEs confirmed exploited in the wild)

The goal is to take what would otherwise be raw network logs sitting in a data lake and turn them into something operationally useful: *"This device on this network is a model from this vendor with these known vulnerabilities, and N of them are on the KEV catalog."*

Patterns here apply to any [Zeek](https://docs.zeek.org/)-based NDR, not just Corelight. Field names and JSON shape will differ if you're not running Corelight or a Corelight-derived parser, but the join logic is the same.

## Why it exists

Most vulnerability enrichment work happens at the host level — a vulnerability scanner runs on or against a device and reports back. This project takes the inverse angle: **passive enrichment from network observation alone**. The trade-off is precision (less than active scanning) for reach (covers anything that touches the wire, including assets the scanner can't reach).

This is genuinely useful for:

- Sites where active scanning is restricted (OT environments, federal cyber response engagements, third-party networks during assessments)
- First-pass asset inventory before a scanner has been deployed
- Detection of unmanaged or rogue devices that aren't in any CMDB
- Cross-referencing scanner findings against an independent observation layer

## The enrichment pipeline at a glance

```
                   ┌────────────────────────────────┐
                   │      Corelight NDR Sensor      │
                   │  (Zeek + Corelight extensions) │
                   └────────────────┬───────────────┘
                                    │
                                    ▼
                  ┌────────────────────────────────────┐
                  │   Per-log JSON records ingested    │
                  │   to data lake / SQL warehouse     │
                  │   (known_devices, software,        │
                  │    http, ssl, ssh, conn, ...)      │
                  └────────────────┬───────────────────┘
                                   │
                                   ▼
         ┌──────────────────────────────────────────────────┐
         │           Asset extraction (this repo)           │
         │  known_devices → vendor, MAC, IP, OUI            │
         │  software.log → product name + version           │
         │  http.log     → server header, user-agent        │
         │  ssh.log      → SSH version string               │
         └──────────────────────────┬───────────────────────┘
                                    │
                                    ▼
         ┌──────────────────────────────────────────────────┐
         │           Vendor / product normalization         │
         │  "Axis Communications AB" → CPE vendor "axis"    │
         │  "OpenSSH_7.6" → CPE product "openssh" v7.6      │
         └──────────────────────────┬───────────────────────┘
                                    │
            ┌───────────────────────┴────────────────────────┐
            ▼                                                ▼
  ┌──────────────────────┐                       ┌───────────────────────┐
  │  NVD CVE API lookup  │                       │  CISA KEV catalog     │
  │  by CPE match string │                       │  (downloaded as JSON) │
  └─────────┬────────────┘                       └──────────┬────────────┘
            │                                               │
            └───────────────────────┬───────────────────────┘
                                    ▼
                  ┌────────────────────────────────────┐
                  │      Enriched asset records        │
                  │   asset + CVE list + KEV flags +   │
                  │   CVSS scores + patch status       │
                  └────────────────────────────────────┘
```

## What's in this repo

| Directory | Contents |
|---|---|
| [`docs/`](docs/) | Architecture, pipeline detail, Corelight log correlation reference, glossary |
| [`sql/`](sql/) | SQL queries — extract assets, join logs, enrich with CVE/KEV data |
| [`scripts/`](scripts/) | Python scripts — KEV downloader, NVD client, vendor normalizer, enrichment pipeline |
| [`data/samples/`](data/samples/) | Anonymized sample records showing the JSON structure |
| [`data/lookups/`](data/lookups/) | Vendor-to-CPE mapping table (extend this as you encounter new vendors) |
| [`examples/`](examples/) | Step-by-step walkthroughs of the pipeline on sample data |

## Quick start

```bash
# Clone and set up
git clone https://github.com/marcos-saiz/corelight-sql-correlation.git
cd corelight-sql-correlation
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Pull down the current CISA KEV catalog
python scripts/fetch_kev_catalog.py

# Try the enrichment pipeline on the sample known_devices record
python scripts/enrich_assets.py --input data/samples/known_devices_sample.json
```

See [`examples/01_known_devices_only.md`](examples/01_known_devices_only.md) for a full walkthrough.

## What you can do with `known_devices.log` alone

Vendor-level CVE lookup. You can identify the manufacturer of a device on the network and pull every CVE ever published against that vendor's products. **This is a starting point, not a precise vulnerability assessment** — without product and version data you're getting a vendor-wide list, not the specific CVEs that apply to that specific device.

## What you can do with `software.log` (and friends)

Product-and-version-level CVE lookup. This is where the real value lives:

- `software.log` — Zeek's software fingerprinting (Apache versions, OpenSSH versions, etc.)
- `ssl.log` / `x509.log` — TLS versions, cipher suites, certificate metadata
- `http.log` — server headers, user-agent strings
- `ssh.log` — SSH client/server version strings

With these, vendor-level lookups become product-and-version lookups, which map to specific CVEs, which map to specific KEV entries. That's the difference between "this device's vendor has 200 historical CVEs" and "this device is running Apache 2.4.49 which has CVE-2021-41773 listed in KEV."

See [`docs/PIPELINE.md`](docs/PIPELINE.md) for the full breakdown of which logs map to what.

## Beyond CVE enrichment

The same data supports several other use cases. See [`docs/BROADER_USE_CASES.md`](docs/BROADER_USE_CASES.md) for a fuller treatment, but in short:

- Asset inventory / CMDB population
- Network topology and VLAN documentation
- Procurement and lifecycle planning (what vendors are actually deployed?)
- Compliance reporting (NIST CSF, sector-specific requirements)
- Supply chain risk analysis across engagements
- OT visibility for environments where active scanning is restricted

## Requirements

- Python 3.10+
- Network access to:
  - `services.nvd.nist.gov` (NVD CVE API)
  - `www.cisa.gov` (CISA KEV catalog)
- Optionally: an NVD API key ([free, recommended for higher rate limits](https://nvd.nist.gov/developers/request-an-api-key))

See [`requirements.txt`](requirements.txt) for Python dependencies.

## A note on the SQL examples

The SQL in this repo assumes a data lake where Corelight JSON has been parsed and landed in queryable tables. Schemas vary by ingest pipeline — some flatten the nested JSON to top-level fields, others preserve the nesting and require `JSON_EXTRACT`-style access. Examples are written against a normalized layout where dotted field paths (`source.ip.value`, `event.id`, etc.) are accessible as nested attributes. Adapt to your own schema as needed.

## Acknowledgments

- [Corelight](https://corelight.com/) and the [Zeek](https://zeek.org/) project for the underlying network observation engine
- [NVD](https://nvd.nist.gov/) for the CVE database and API
- [CISA](https://www.cisa.gov/) for the KEV catalog
- [Book of Zeek](https://docs.zeek.org/en/current/script-reference/log-files.html) — the authoritative log reference used throughout the documentation
- [Corelight Zeek log cheatsheets](https://github.com/corelight/zeek-cheatsheets) — quick-reference cards informing several sections of `docs/CORELIGHT_LOG_REFERENCE.md`
- [Corelight `ecs-mapping`](https://github.com/corelight/ecs-mapping) — schema mapping documentation used to align field paths across schema flavors

## License

MIT. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to extend the vendor mapping, add new log type handlers, or contribute additional SQL patterns.
