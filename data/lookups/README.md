# Lookup Tables

Reference data used by the normalization step. These are starter mappings — extend them as you encounter new vendors.

## Files

| File | What it does |
|---|---|
| [`vendor_to_cpe.csv`](vendor_to_cpe.csv) | Maps raw vendor names (as they appear in Corelight records) to CPE vendor strings |

## Why this needs a manual table

The CPE 2.3 vendor name is not always the obvious lowercased form of the brand name:

| Raw observed vendor | CPE vendor | Why |
|---|---|---|
| `OpenSSH` | `openbsd` | OpenSSH is maintained by the OpenBSD project, so NVD records OpenSSH CVEs under vendor `openbsd` |
| `Microsoft-IIS` | `microsoft` (product `internet_information_services`) | IIS is a Microsoft product; CPE records the parent vendor |
| `Aruba Networks` | `arubanetworks` | No spaces in CPE; spaces become underscores or are removed |
| `Cisco, Inc.` | `cisco` | Legal suffixes get stripped |

The mapping covers the common transformations (legal suffixes, spacing), but for edge cases like OpenSSH/OpenBSD you need the explicit lookup.

## Extending the table

When you encounter a vendor not in the table, add a row:

```csv
raw_vendor,cpe_vendor,notes
New Vendor LLC,newvendor,Description of what they make
```

To find the right CPE vendor string for a new entry, you can search NVD directly:

```bash
# Find the CPE vendor string for a known product
curl -s "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=acme" | jq '.products[].cpe.cpeName'
```

Look for the second segment of the CPE string (`cpe:2.3:part:VENDOR:product:...`).

Then re-run the pipeline. The normalization module reads this file at startup and caches the result.

## A note on completeness

This list is not exhaustive — NVD has thousands of registered vendors. Add entries as you need them rather than trying to populate everything upfront. The pipeline will fall back to a wildcard CPE query (`cpe:2.3:*:vendor:*:*:*:*:*:*:*`) for unknown vendors, which still works but is broader than necessary.
