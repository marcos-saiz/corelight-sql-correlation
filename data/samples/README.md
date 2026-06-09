# Sample Records

Sanitized example records showing the JSON structure the pipeline operates on. Useful for testing the scripts without needing access to a live Corelight installation.

## What's here

| File | What it shows |
|---|---|
| [`known_devices_sample.json`](known_devices_sample.json) | One asset record from `known_devices.log` — an Axis camera observed on a DHCP request |

## Anonymization

All identifiable detail (real IPs, MACs, hostnames, organizational labels, file paths) has been replaced with example values. The OUI prefix (`b8:a4:4f`) is genuine — it's a public IEEE registry entry for Axis Communications and is publicly available in the [IEEE OUI database](http://standards-oui.ieee.org/oui/oui.txt). The vendor name "Axis Communications AB" is the publicly-registered name; both are kept to make the example realistic.

## Generating your own samples

If you want to test against real records from your environment, dump a single line from a Corelight log file:

```bash
zcat known_devices/2026-01-01/known_devices_*.log.gz | head -1 > my_sample.json
```

Then run it through the pipeline:

```bash
python scripts/enrich_assets.py --input my_sample.json --output my_enriched.json
```

**Do not commit real records to a public repo.** They contain real IPs, MACs, and engagement metadata that should not be exposed.
