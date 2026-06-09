# Example 1 — Vendor-only enrichment from `known_devices.log`

End-to-end walkthrough of the pipeline against the sample record at [`../data/samples/known_devices_sample.json`](../data/samples/known_devices_sample.json).

This is the simplest case — you only have a vendor (no product, no version), so the resulting CVE list is vendor-wide rather than narrowed to a specific software version. The output is still useful as a starting point and demonstrates the pipeline end to end.

## What we have

The input record:

```json
{
  "asset": {
    "mac":    { "value": "b8:a4:4f:ab:cd:ef" },
    "oui":    "b8:a4:4f",
    "vendor": { "value": "Axis Communications AB" }
  },
  "host":    { "ip": { "value": "10.50.180.66" } },
  "network": { "vlan": { "id": "180" }, "protocol": "DHCP", "transport": "tcp" },
  "timestamp": "2026-01-01T14:43:04.043+00:00"
}
```

Key fields the pipeline cares about:

- `asset.vendor.value` — "Axis Communications AB" — this is the CVE join key
- `asset.oui` — "b8:a4:4f" — secondary vendor confirmation via IEEE OUI registry
- `host.ip.value` — "10.50.180.66" — the join key for richer logs (software, http, ssl) when they're available
- `network.vlan.id` — "180" — context for risk scoring

## Step 1 — Vendor normalization

The vendor string `"Axis Communications AB"` is normalized to CPE vendor `"axis"`:

1. Lookup table check: `data/lookups/vendor_to_cpe.csv` has an entry for `Axis Communications AB → axis`
2. Result: CPE match string `cpe:2.3:*:axis:*:*:*:*:*:*:*`

What this CPE string means in plain English: "any part type, vendor 'axis', any product, any version."

## Step 2 — Query NVD

```bash
python scripts/fetch_nvd_cves.py --cpe "cpe:2.3:*:axis:*:*:*:*:*:*:*" --summary
```

This returns every CVE NVD has ever associated with any Axis product. Expect ~50-150 results.

Why so many? Because we're querying vendor-only. Every Axis IP camera firmware bug ever published, every web interface CVE, every protocol issue — all of them come back. This is correct behavior for a vendor-only query but it's not yet operationally useful.

## Step 3 — Cross-reference KEV

The pipeline checks each CVE ID against the CISA KEV catalog:

```bash
python scripts/fetch_kev_catalog.py     # one-time KEV download (re-run daily)
```

For each CVE returned by NVD, we ask: is this CVE on the KEV list? If yes, the enriched record gets:
- `kev_listed: true`
- `kev_date_added`
- `kev_due_date`
- `known_ransomware_use` (Known / Unknown / null)
- `kev_required_action`

For an Axis vendor-wide query, the answer is usually that one or two CVEs are KEV-listed and the rest are not. Those KEV-listed ones are where attention should focus.

## Step 4 — Enrich

Run the full pipeline:

```bash
python scripts/enrich_assets.py \
  --input data/samples/known_devices_sample.json \
  --output enriched.json
```

The result is `enriched.json` with the original asset data plus:

```json
{
  "asset": {
    "mac":  "b8:a4:4f:ab:cd:ef",
    "oui":  "b8:a4:4f",
    "vendor_raw": "Axis Communications AB",
    "vendor_cpe": "axis",
    "cpe_match_string": "cpe:2.3:*:axis:*:*:*:*:*:*:*",
    "ip":   "10.50.180.66",
    "vlan": "180"
  },
  "cve_summary": {
    "total_cves": 87,
    "kev_listed_cves": 1,
    "max_cvss": 9.8,
    "ransomware_used_cves": 0
  },
  "cves": [
    {
      "cve_id": "CVE-EXAMPLE-XXXXX",
      "cvss_score": 9.8,
      "kev_listed": true,
      "kev_date_added": "2022-XX-XX",
      "kev_due_date": "2022-XX-XX",
      "kev_required_action": "Apply updates per vendor instructions.",
      "known_ransomware_use": "Unknown",
      "description": "..."
    }
  ],
  "notes": [
    "Vendor-only lookup. For precise CVE matches, supplement with software.log / http.log / ssh.log observations to obtain product and version data."
  ]
}
```

## What we learned

From this one record:

- The device is an Axis Communications product (IP camera, encoder, or access control hardware based on Axis's product line)
- It's on VLAN 180 with an internal IP, doing DHCP
- It has ~87 historical CVEs across Axis's product line
- One of those CVEs is on the CISA KEV catalog — meaning attackers are actively exploiting it somewhere in the world

## What we can't do yet

We can't say *which* of those 87 CVEs apply to *this specific* Axis device, because we don't know what model it is or what firmware version. That's where the next example comes in.

## Next step

Get richer logs from the cyber team. See [`02_with_software_log.md`](02_with_software_log.md) for the version that actually pins down product and version.
