# Example 2 — Product + version enrichment with `software.log`

When you have records from `software.log` (or `http.log` server headers, or `ssh.log` banners), you can identify specific products and versions rather than just vendors. This is where the pipeline starts producing operationally useful results.

This example is a walkthrough — the cyber team needs to provide actual `software.log` records before you can run it end to end against your own data. The pipeline pattern is what matters here.

## What changes vs. Example 1

In Example 1 we only had vendor information from `known_devices.log`, so our CPE query was `cpe:2.3:*:axis:*:*:*:*:*:*:*` (vendor-only, wildcards everywhere else). That returns every Axis CVE ever published.

With `software.log` we can produce CPE strings like `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*` — vendor, product, *and* version. NVD returns just the CVEs that apply to that specific version. That's the difference between "200 historical CVEs across the vendor" and "8 CVEs that apply to this specific running version."

## Hypothetical input

A row from `software.log` (sanitized example):

```json
{
  "host":     { "ip": { "value": "10.50.180.66" } },
  "software": {
    "name":             "Apache",
    "version": {
      "major": 2, "minor": 4, "minor2": 49,
      "addl": null
    },
    "unparsed_version": "Apache/2.4.49",
    "software_type":    "WEB_SERVER"
  },
  "timestamp": "2026-01-01T15:02:10.000+00:00"
}
```

## Step 1 — Parse the version

The `parse_banner` function in `scripts/normalize_vendors.py` recognizes the format and extracts:
- Product: `Apache`
- Version: `2.4.49`

The `banner_to_cpe` helper then maps this to:
- CPE vendor: `apache`
- CPE product: `http_server`
- CPE version: `2.4.49`
- CPE part: `a` (application)

Resulting CPE string: `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*`

## Step 2 — Join back to the asset

Using `host.ip` from the software record and a time window:

```sql
SELECT
    a.mac, a.vendor_raw, a.most_recent_ip, a.most_recent_vlan,
    s.software_product, s.software_version
FROM assets a
JOIN software_observations s
    ON s.host_ip = a.most_recent_ip
    AND s.observed_at BETWEEN a.first_seen AND COALESCE(a.last_seen, NOW())
WHERE s.host_ip = '10.50.180.66'
```

Result row:

| asset_mac | asset_vendor | asset_ip | asset_vlan | software_product | software_version |
|---|---|---|---|---|---|
| b8:a4:4f:ab:cd:ef | Axis Communications AB | 10.50.180.66 | 180 | Apache | 2.4.49 |

## Step 3 — Query NVD with the precise CPE

```bash
python scripts/fetch_nvd_cves.py \
  --cpe "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*" \
  --summary
```

This returns only CVEs that specifically affect Apache HTTP Server 2.4.49. Typical result count: 8–12 CVEs (vs. 200+ for vendor-only).

## Step 4 — Cross-reference KEV

Among those 8–12 CVEs, one of them — `CVE-2021-41773` — is on the KEV catalog with a notation of known ransomware use:

```json
{
  "cve_id": "CVE-2021-41773",
  "cvss_score": 9.8,
  "kev_listed": true,
  "kev_date_added": "2021-11-03",
  "kev_due_date":   "2021-11-17",
  "kev_required_action": "Apply updates per vendor instructions.",
  "known_ransomware_use": "Known",
  "description": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49..."
}
```

This is the kind of result that goes into a SOC's triage queue. You're no longer saying "this device's vendor has CVEs" — you're saying "this specific device is running Apache 2.4.49, which is vulnerable to a path-traversal flaw that's on KEV and has known ransomware use, and the federal patch deadline was 2021-11-17."

## What the enriched output looks like

```json
{
  "asset": {
    "mac":  "b8:a4:4f:ab:cd:ef",
    "vendor_raw": "Axis Communications AB",
    "ip":   "10.50.180.66",
    "vlan": "180"
  },
  "software_observed": [
    {
      "source_log": "software.log",
      "product":    "Apache",
      "version":    "2.4.49",
      "cpe":        "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*",
      "observed_at": "2026-01-01T15:02:10.000+00:00"
    }
  ],
  "cve_summary": {
    "total_cves": 9,
    "kev_listed_cves": 2,
    "max_cvss": 9.8,
    "ransomware_used_cves": 1
  },
  "cves": [
    {
      "cve_id": "CVE-2021-41773",
      "cvss_score": 9.8,
      "kev_listed": true,
      "known_ransomware_use": "Known",
      "description": "..."
    }
  ]
}
```

## A note on the implicit assumption

This example assumes the Apache observation belongs to the Axis device on `10.50.180.66`. That assumption holds *if* the same IP wasn't reassigned to a different device between the two observations. For DHCP environments this is usually fine over short time windows but can fail over longer ones. The SQL in `03_join_software_to_assets.sql` uses a time window to mitigate this, but if you're working with months of data you'll want to confirm bindings via DHCP lease history.

## Generalizing this pattern

Same approach works with:

| Log | Yields | Example CPE |
|---|---|---|
| `http.log` server header `Apache/2.4.49` | apache / http_server / 2.4.49 | `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*` |
| `ssh.log` server banner `OpenSSH_7.6p1` | openbsd / openssh / 7.6 | `cpe:2.3:a:openbsd:openssh:7.6:*:*:*:*:*` |
| `http.log` `Microsoft-IIS/10.0` | microsoft / internet_information_services / 10.0 | `cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*` |
| `ssl.log` `TLSv1.0` cipher suite | tls protocol CVEs | varies |
| `software.log` `nginx 1.18.0` | nginx / nginx / 1.18.0 | `cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*` |

See [`docs/PIPELINE.md`](../docs/PIPELINE.md) for the full list of supported logs and what each one yields.
