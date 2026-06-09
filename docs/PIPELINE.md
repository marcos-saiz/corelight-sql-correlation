# The Enrichment Pipeline

Detailed walkthrough of what each pipeline stage does, what it consumes, what it produces, and where the failure modes are.

## Stage 1 — Asset extraction from `known_devices.log`

**Input:** Records from `known_devices.log` (Corelight) or `known_hosts.log` + DHCP correlation (open-source Zeek).

**Output:** One row per discovered device with vendor, MAC, IP, OUI, VLAN, and observation timestamp.

**Example input (anonymized):**

```json
{
  "asset": {
    "mac":    { "value": "b8:a4:4f:ab:cd:ef" },
    "oui":    "b8:a4:4f",
    "vendor": { "value": "Axis Communications AB" }
  },
  "host":    { "ip": { "value": "10.50.180.66" } },
  "network": { "vlan": { "id": "180" }, "protocol": "DHCP" },
  "event":   { "ingested": "2026-01-01T03:09:37.018+00:00" },
  "timestamp": "2026-01-01T14:43:04.043+00:00"
}
```

**Example output row (after extraction):**

| field | value |
|---|---|
| `mac` | `b8:a4:4f:ab:cd:ef` |
| `oui` | `b8:a4:4f` |
| `vendor_raw` | `Axis Communications AB` |
| `ip` | `10.50.180.66` |
| `vlan` | `180` |
| `first_seen` | `2026-01-01T14:43:04Z` |

**Failure modes:**

- Vendor field can be `null` for unrecognized OUI prefixes — fall back to OUI-based vendor lookup using the IEEE OUI database
- MAC can be the gateway/router for cross-subnet traffic when the source is on a different VLAN — verify by checking the OUI for locally-administered bits (LSB of first octet)
- A single device can appear in many `known_devices` records over time as its DHCP lease churns — deduplicate by MAC, keep most recent

SQL: see [`../sql/01_extract_assets.sql`](../sql/01_extract_assets.sql).

## Stage 2 — Software/product extraction from richer logs

**Input:** Records from log types that carry product-and-version observations:

| Log | What it gives you |
|---|---|
| `software.log` | The richest source. Zeek fingerprints software and emits `name`, `version`, `software_type` |
| `http.log` | `server` header (e.g., `Apache/2.4.49`), `user_agent` strings |
| `ssh.log` | Client and server version strings (e.g., `SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7`) |
| `ssl.log` | TLS version, cipher suite, server name (SNI) |
| `x509.log` | Cert subject/issuer organization names |

**Output:** Observations linked to an IP and time, ready for CPE normalization.

**Join back to assets:** by IP address. Note that IP-to-asset bindings can change over time (DHCP churn), so the join needs to be time-windowed:

```sql
-- Conceptual — see actual SQL in ../sql/
JOIN assets a ON s.ip = a.ip
  AND s.timestamp BETWEEN a.first_seen AND COALESCE(a.last_seen, NOW())
```

**Failure modes:**

- HTTPS traffic doesn't show up in `http.log` — it lives in `ssl.log`. If you're only looking at HTTP, you'll miss anything modern.
- Version strings can be deliberately obfuscated (`Server: nginx`, no version). Some sites strip version banners as a hardening measure.
- Some products have generic names — `Server: lighttpd` doesn't tell you the version. Cross-reference with other logs to narrow it down.

SQL: see [`../sql/02_extract_software.sql`](../sql/02_extract_software.sql).

## Stage 3 — Vendor / product normalization to CPE

**Input:** Raw vendor and product strings from stages 1 and 2.

**Output:** CPE 2.3 match strings ready for NVD lookup.

**Normalization is partly mechanical, partly judgment:**

| Raw observation | Normalization rule | CPE match string |
|---|---|---|
| `Axis Communications AB` | Drop legal suffix, lowercase, drop spaces | `cpe:2.3:*:axis:*:*:*:*:*:*:*` |
| `Microsoft Corporation` | Drop legal suffix, lowercase | `cpe:2.3:*:microsoft:*:*:*:*:*:*:*` |
| `Apache/2.4.49` | Split on `/`, identify vendor as `apache`, product as `http_server`, version as `2.4.49` | `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*` |
| `SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7` | Strip protocol prefix, identify `OpenSSH_7.6p1`, normalize | `cpe:2.3:a:openbsd:openssh:7.6:*:*:*:*:*` |
| `Microsoft-IIS/10.0` | Recognize as IIS, version 10.0 | `cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*` |

**Why this is partly manual:** CPE vendor strings aren't always the obvious lowercased name. OpenSSH's CPE vendor is `openbsd`, not `openssh`. IIS lives under `microsoft`, not `iis`. There's no programmatic way to know these mappings — you build a lookup table and grow it as you encounter new vendors.

See [`../data/lookups/vendor_to_cpe.csv`](../data/lookups/vendor_to_cpe.csv) for the starter mapping.

**Failure modes:**

- The vendor-name canonicalization is incomplete. Unknown vendors fall through to a wildcard search that may return nothing or too much.
- Version strings can have non-standard formats. `1.2.3-beta.4+build.567` may not match how NVD records the same version.
- Some products have moved between vendors over time (acquisitions, project transfers). CPE history doesn't always track this perfectly.

Python: see [`../scripts/normalize_vendors.py`](../scripts/normalize_vendors.py).

## Stage 4 — Query NVD for matching CVEs

**Input:** CPE match strings from stage 3.

**Output:** For each CPE, a list of CVE records with metadata.

**API:** `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=<encoded-cpe-string>`

**Pagination:** NVD returns 2000 results per page by default. Use `startIndex` and `resultsPerPage` for paging.

**Rate limits:**
- Without API key: 5 requests per 30 seconds
- With API key: 50 requests per 30 seconds
- Get a key at <https://nvd.nist.gov/developers/request-an-api-key>

**Failure modes:**

- API can be slow or transiently unavailable. Build in retries with exponential backoff (the [`tenacity`](https://tenacity.readthedocs.io/) library handles this well).
- Wildcard CPE queries (vendor only, no product or version) can return thousands of CVEs. Filter down by date, CVSS score, or product when possible.
- NVD's data quality varies — some CVEs have rich CPE configurations, others are sparse. Coverage is best for major commercial products and weakest for niche/old software.

Python: see [`../scripts/fetch_nvd_cves.py`](../scripts/fetch_nvd_cves.py).

## Stage 5 — Cross-reference against the CISA KEV catalog

**Input:** Local cached copy of the KEV catalog plus the list of CVE IDs from stage 4.

**Output:** Each CVE annotated with a `kev_listed` flag and (when applicable) the KEV metadata.

**The KEV catalog URL:**
<https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>

**Refresh frequency:** Daily is usually enough. CISA typically adds a handful of entries per week.

**The KEV record shape:**

```json
{
  "cveID": "CVE-2021-41773",
  "vendorProject": "Apache",
  "product": "HTTP Server",
  "vulnerabilityName": "Apache HTTP Server Path Traversal Vulnerability",
  "dateAdded": "2021-11-03",
  "shortDescription": "...",
  "requiredAction": "Apply updates per vendor instructions.",
  "dueDate": "2021-11-17",
  "knownRansomwareCampaignUse": "Known",
  "notes": "...",
  "cwes": ["CWE-22"]
}
```

The enrichment is a simple set-membership test: load the KEV CVE IDs into a Python set, then for each CVE from stage 4 check `cve_id in kev_set`.

Python: see [`../scripts/fetch_kev_catalog.py`](../scripts/fetch_kev_catalog.py) for the download script and [`../scripts/enrich_assets.py`](../scripts/enrich_assets.py) for the cross-reference.

## Stage 6 — Enriched record output

**Input:** Asset records from stage 1, software observations from stage 2, CVE matches from stage 4, KEV flags from stage 5.

**Output:** One record per asset with all enrichment attached.

**Example enriched record:**

```json
{
  "asset": {
    "mac": "b8:a4:4f:ab:cd:ef",
    "oui": "b8:a4:4f",
    "vendor_raw": "Axis Communications AB",
    "vendor_cpe": "axis",
    "ip": "10.50.180.66",
    "vlan": "180",
    "first_seen": "2026-01-01T14:43:04Z"
  },
  "software_observed": [
    {
      "source_log": "http.log",
      "raw": "Apache/2.4.49",
      "cpe": "cpe:2.3:a:apache:http_server:2.4.49"
    }
  ],
  "cve_summary": {
    "total_cves": 14,
    "kev_listed_cves": 2,
    "max_cvss": 9.8,
    "cves_with_known_ransomware_use": 1
  },
  "cves": [
    {
      "cve_id": "CVE-2021-41773",
      "cvss_v31": 9.8,
      "kev_listed": true,
      "kev_dueDate": "2021-11-17",
      "knownRansomwareCampaignUse": "Known",
      "summary": "Apache HTTP Server path traversal..."
    }
  ]
}
```

**This record is now actionable.** A dashboard can rank assets by KEV count. A triage process can prioritize the path-traversal CVE because it's on KEV and has known ransomware use. A report can summarize the network's exposure to KEV-listed CVEs by vendor or VLAN.

## Where the value comes from

Each stage adds context. The cumulative effect:

| Stage | What you have | What you can ask |
|---|---|---|
| 0 (raw logs) | JSON records | None operationally — it's a haystack |
| 1 | Asset inventory | "What's on this network?" |
| 2 | + Software observations | "What versions are running?" |
| 3 | + Normalized identifiers | "Which CVEs could apply?" |
| 4 | + CVE lookups | "What's vulnerable?" |
| 5 | + KEV flags | "What's actually being exploited?" |
| 6 | Enriched records | "What's the operational risk by asset / vendor / VLAN / mission?" |

You can stop at any stage. Just running stages 1 and 2 already gives you an asset inventory most organizations don't have.
