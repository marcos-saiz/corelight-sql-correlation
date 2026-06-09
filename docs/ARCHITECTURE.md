# Architecture

High-level view of how the pieces fit together.

## Data flow

```
┌────────────────────────────────────────────────────────────────┐
│                    Network being monitored                     │
│  ┌──────────┐   ┌────────┐   ┌──────────────┐   ┌──────────┐   │
│  │ Servers  │   │ Cameras│   │ Workstations │   │ IoT/OT   │   │
│  └────┬─────┘   └───┬────┘   └──────┬───────┘   └────┬─────┘   │
│       └─────────────┴───────────────┴────────────────┘         │
└────────────────────────────┬───────────────────────────────────┘
                             │ Traffic (TAP / SPAN)
                             ▼
              ┌─────────────────────────────────┐
              │     Corelight NDR sensor        │
              │  (Zeek + Corelight extensions   │
              │   + integrated Suricata)        │
              └────────────────┬────────────────┘
                               │ JSON log records
                               ▼
              ┌─────────────────────────────────┐
              │     Ingestion pipeline          │
              │  (parser, normalizer, schema    │
              │   mapper)                       │
              └────────────────┬────────────────┘
                               │ Parsed records
                               ▼
              ┌─────────────────────────────────┐
              │   Data lake / SQL warehouse     │
              │  Tables per log type:           │
              │  • known_devices                │
              │  • software                     │
              │  • http / ssl / ssh / x509      │
              │  • conn / dns / files           │
              │  • notice / weird               │
              └────────────────┬────────────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
              ▼                                 ▼
   ┌─────────────────────┐         ┌──────────────────────┐
   │  Asset extraction   │         │ Software extraction  │
   │  (known_devices,    │         │ (software, http,     │
   │   dhcp)             │         │  ssl, ssh, x509)     │
   └──────────┬──────────┘         └──────────┬───────────┘
              │                                │
              └────────────┬───────────────────┘
                           │
                           ▼
              ┌─────────────────────────────────┐
              │  Vendor / product normalization │
              │  Map raw strings to CPE format  │
              │  (cpe:2.3:a:vendor:product:ver) │
              └────────────────┬────────────────┘
                               │
              ┌────────────────┴────────────────┐
              ▼                                 ▼
   ┌─────────────────────┐         ┌──────────────────────┐
   │   NVD CVE API       │         │  CISA KEV catalog    │
   │   (live HTTPS)      │         │  (cached locally)    │
   └──────────┬──────────┘         └──────────┬───────────┘
              │                                │
              └────────────┬───────────────────┘
                           │
                           ▼
              ┌─────────────────────────────────┐
              │  Enriched asset records         │
              │  • Asset metadata (vendor,      │
              │    MAC, IP, location)           │
              │  • CVE list with CVSS scores    │
              │  • KEV flag per CVE             │
              │  • Patch availability           │
              │  • Mission/context metadata     │
              └────────────────┬────────────────┘
                               │
              ┌────────────────┴────────────────┐
              ▼                                 ▼
   ┌─────────────────────┐         ┌──────────────────────┐
   │  Dashboards / BI    │         │  SIEM / SOAR feeds   │
   └─────────────────────┘         └──────────────────────┘
```

## Component breakdown

### 1. The Corelight sensor (out of scope for this repo)

Corelight runs a customized Zeek build with proprietary detection packages and additional log types. Logs are emitted in JSON. See [`CORELIGHT_LOG_REFERENCE.md`](CORELIGHT_LOG_REFERENCE.md) for which logs carry which fields.

### 2. The data lake (out of scope, but informs the SQL)

Whatever sits between the sensor and your queries. Could be S3 + Athena, Snowflake, BigQuery, Databricks, ClickHouse, or any other SQL-queryable store. The SQL examples in this repo are dialect-agnostic with notes where syntax diverges.

### 3. Asset extraction

Pull device-level fields from `known_devices.log`. This is the anchor table — every other enrichment joins back to assets via IP or MAC.

Sample fields you care about per asset:
- `asset.mac.value` — MAC address
- `asset.oui` — vendor OUI prefix
- `asset.vendor.value` — vendor name (when populated)
- `host.ip.value` — IP address at observation time
- `network.vlan.id` — VLAN segment

### 4. Software extraction

For each asset, pull product-and-version observations from richer logs:

| Log | Yields |
|---|---|
| `software.log` | Best source — vendor, product name, version, from Zeek's fingerprinting |
| `http.log` | Server header (e.g., `Apache/2.4.49`), user-agent strings |
| `ssh.log` | Client and server version strings |
| `ssl.log` | TLS version, cipher suite |
| `x509.log` | Certificate subject/issuer (sometimes identifies the product) |

### 5. Vendor / product normalization

Map raw strings to the [CPE 2.3](https://nvd.nist.gov/products/cpe) naming convention used by NVD:

```
cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
```

For most enrichment work, you only need `part`, `vendor`, `product`, `version`. Examples:

| Raw observation | CPE match string |
|---|---|
| Vendor: "Axis Communications AB" | `cpe:2.3:*:axis:*:*:*:*:*:*:*` |
| HTTP server: "Apache/2.4.49" | `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*` |
| SSH banner: "SSH-2.0-OpenSSH_7.6p1" | `cpe:2.3:a:openbsd:openssh:7.6:*:*:*:*:*` |
| Microsoft IIS: "Microsoft-IIS/10.0" | `cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*` |

The mapping is partly automatable (string parsing) and partly manual (vendor-name canonicalization). See [`../data/lookups/vendor_to_cpe.csv`](../data/lookups/vendor_to_cpe.csv) for the starter table.

### 6. NVD CVE API

The NVD REST API ([docs](https://nvd.nist.gov/developers/vulnerabilities)) accepts CPE match strings and returns matching CVEs with metadata:

- CVE ID
- Description
- CVSS scores (v2, v3.0, v3.1, v4.0 where available)
- Published / modified dates
- References (patch links, advisories, exploit code)
- Affected configurations (which CPEs the CVE applies to)

Rate limits: 5 requests / 30s without an API key, 50 requests / 30s with one. Get a key at <https://nvd.nist.gov/developers/request-an-api-key>.

### 7. CISA KEV catalog

A JSON file maintained by CISA listing CVEs confirmed exploited in the wild. Downloaded directly from CISA, cached locally, refreshed daily.

URL: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>

Schema includes:
- `cveID` — the CVE in question
- `vendorProject` / `product`
- `vulnerabilityName`
- `dateAdded` — when CISA added it to KEV
- `requiredAction` — what federal agencies must do
- `dueDate` — federal patch deadline
- `knownRansomwareCampaignUse` — yes/no
- `notes`

The enrichment step is a simple set-membership check: for each CVE returned by NVD, is its ID in the KEV catalog? If yes, that CVE gets a `kev_listed: true` flag plus all of CISA's KEV metadata attached.

### 8. Output

The enriched record format is documented in [`PIPELINE.md`](PIPELINE.md). Common downstream consumers:

- **Dashboards** — count of CVEs and KEVs per asset, top vendors by risk
- **SIEM correlation** — feed enriched asset metadata into SIEM rules
- **Reports** — generate per-engagement vulnerability summaries
- **CMDB feeds** — push asset inventory to a configuration management database

## Design choices worth knowing

**Why passive observation instead of active scanning?** Both are valuable. Active scanning is more precise but isn't always available — OT environments forbid it, third-party networks during incident response don't permit it, federal cyber response engagements often deploy with passive collection only. Passive enrichment fills the gap.

**Why CISA KEV specifically?** It's the most actionable subset of CVEs. There are ~250,000 published CVEs as of late 2024. Most are not being exploited. The KEV list (~1,200 entries at last check) is curated by CISA based on actual observed exploitation. Flagging KEV-listed CVEs cuts noise dramatically.

**Why CPE instead of just vendor names?** CPE is the structured vocabulary NVD uses to link CVEs to affected software. Raw vendor strings ("Axis Communications AB" vs "Axis Communications" vs "AXIS") don't deduplicate; CPE vendor strings ("axis") do. Skipping CPE means accepting noisy lookups.

**Why a separate KEV download instead of querying CISA per CVE?** CISA's KEV file is a single ~500KB JSON download — far cheaper to pull once a day and do set-membership checks locally than to make 1000s of API calls.
