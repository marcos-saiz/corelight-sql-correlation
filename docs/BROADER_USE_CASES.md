# Broader Use Cases

The CVE/KEV enrichment pipeline is the first proof of concept, but the underlying data supports several other valuable analyses. Each of these is independently deployable using the same data pipeline.

This document is intentionally a forward-looking inventory of opportunities, not a delivery roadmap. Some are immediate wins; others depend on additional data sources or organizational sign-off.

## 1. Asset inventory / CMDB population

**The opportunity:** Most organizations don't have an accurate, current inventory of what's actually on their network. The `known_devices.log` (Corelight) or `known_hosts.log` + `dhcp.log` combination (open-source Zeek) is a network-derived hardware inventory that updates continuously, independent of whatever the CMDB thinks is deployed.

**What it produces:**
- Comprehensive list of every device that's been observed
- MAC, IP (at observation time), vendor (via OUI lookup)
- VLAN / network segment
- First seen / last seen timestamps

**Why this matters:** This is often the foundation work that needs to happen before any vulnerability management program can claim coverage. You can't patch what you don't know exists.

**Friction to delivery:** Low. The data is already there.

## 2. Network architecture documentation

**The opportunity:** Auto-generate network topology from observed traffic patterns. VLAN IDs, IP ranges, gateway identification, and device-to-device communication can be reconstructed from `conn.log` aggregated by source/destination patterns.

**What it produces:**
- VLAN inventory
- Subnet topology
- Inter-VLAN traffic patterns (which segments talk to which)
- Identification of choke points and gateways

**Why this matters:** Most organizations have outdated or no network topology diagrams. For OT/ICS environments and critical infrastructure, accurate topology is required for compliance frameworks (NIST CSF, IEC 62443, sector-specific directives) but rarely maintained.

**Friction to delivery:** Medium. The raw data is there, but turning it into a presentable diagram requires graph layout and visualization work.

## 3. Procurement and lifecycle planning

**The opportunity:** Vendor identification (from OUI and observed product strings) tells leadership what hardware and software they're actually running, at what scale.

**What it produces:**
- Top vendors by device count
- Vendor distribution by VLAN / location / mission type
- Devices nearing end-of-life (when cross-referenced with vendor EOL databases)
- Bulk-purchasing leverage points (where consolidating vendors could reduce cost)

**Why this matters:** Procurement decisions in many organizations are made without empirical data on what's actually deployed. This turns "we think we have around 200 IP cameras" into "we have 247 IP cameras, 81% Axis and 19% Hikvision, distributed across these sites."

**Friction to delivery:** Medium. Vendor name normalization is the same problem as the CPE normalization for CVE enrichment — solving one solves the other.

## 4. Compliance and regulatory readiness

**The opportunity:** Map observed assets to compliance frameworks automatically.

**Use cases by framework:**

- **NIST CSF** — Identify function: complete asset inventory, software inventory, vulnerability identification
- **NIST 800-53** — CM-8 (Information System Component Inventory), RA-5 (Vulnerability Scanning)
- **Sector-specific directives** — e.g., transportation, water, energy each have sector-specific cybersecurity requirements that include asset and vulnerability tracking
- **FISMA / federal** — Continuous monitoring requirements (M-21-31 and successor memos)

**What it produces:**
- Evidence packages for audits
- Continuous compliance dashboards
- Gap analyses against required asset/vuln tracking

**Friction to delivery:** Medium-high. Depends on which framework, what evidence format is needed, and whether the organization has an existing GRC platform to feed into.

## 5. Operational Technology (OT) visibility

**The opportunity:** Most cyber assessment of OT environments is constrained because active scanning can disrupt operational equipment. Passive observation via NDR is one of the few ways to safely inventory OT assets.

**What it produces:**
- OT asset inventory (PLCs, HMIs, RTUs, engineering workstations)
- Protocol mix on OT segments (Modbus, DNP3, EtherNet/IP, OPC-UA, S7)
- Communication patterns between OT zones (Purdue Model layers)
- Anomalies that suggest IT/OT crossover (a domain controller talking Modbus, for example)

**Why this matters:** OT environments are increasingly targeted (water utilities, manufacturing, transportation). Passive visibility is often the only acceptable cyber telemetry. The data this pipeline produces is directly useful for OT risk assessment.

**Friction to delivery:** Medium. Requires OT-specific protocol parsers to be enabled on the sensor (they generally are in Corelight builds) and OT-aware analysts to interpret the output.

## 6. Engagement / mission planning and resource allocation

**The opportunity:** When cyber response engagements run as projects (with start dates, end dates, partners, and locations), the metadata captured alongside the network data becomes a planning resource of its own.

**What it produces:**
- Duration analysis — which engagement types take longer than expected?
- Resource sizing — sites of this type tend to have N devices, M protocols, P vulnerabilities — staff accordingly
- Partner / sector patterns — which sectors generate the most findings? Where should investment go?
- Workload forecasting — based on historical patterns

**Why this matters:** Most cyber response teams plan engagements based on gut feel about scope. This turns scope into a data-driven estimate.

**Friction to delivery:** Low to medium, depending on whether mission metadata is consistently captured during ingest.

## 7. Cross-engagement trend analysis

**The opportunity:** When the same team conducts assessments at multiple sites over time, patterns emerge that aren't visible from any single engagement.

**What it produces:**
- Vendor concentration risk (are 80% of cameras at critical-infrastructure sites from the same manufacturer?)
- Recurring vulnerabilities (are the same CVEs showing up at every site in a given sector?)
- Effectiveness measurement (do sites that received our previous report come back with fewer findings?)
- Threat hypothesis generation (a single TTPs is interesting, the same TTP at three sites is a campaign)

**Why this matters:** This is the difference between a report and an intelligence product. Aggregating findings across engagements creates strategic, sector-wide insight that no single assessment can produce.

**Friction to delivery:** Medium-high. Requires consistent data formats across engagements, a data lake that retains historical data, and analytical tooling on top.

## 8. Supply chain risk analysis

**The opportunity:** Aggregate vendor data across all engagements to identify supply-chain concentration risk.

**What it produces:**
- "What % of our monitored infrastructure depends on Vendor X?"
- Critical infrastructure dependency on vendors with known supply-chain compromises (SolarWinds, MOVEit, 3CX, etc.)
- Geographic distribution of vendor presence

**Why this matters:** Supply-chain attacks affect downstream organizations en masse. Knowing where your concentration risk is means knowing where the next supply-chain compromise will hurt the most.

**Friction to delivery:** Medium. Built on top of #3 (procurement / lifecycle).

## How to pursue these

Each of the above can be a separate proof-of-concept. Suggested order of operations:

1. **Get the CVE/KEV pipeline working first** (this repo). It's the most visible deliverable and validates the data ingestion is sound.
2. **Then build #1 (asset inventory).** It's the foundation for everything else.
3. **Then #4 (compliance).** Highest perceived value for organizational sponsors.
4. **Then #5 (OT visibility) or #3 (procurement)** depending on where the most pressing need is.
5. **Cross-engagement work (#7, #8) comes last** because it requires historical data accumulation.

Each one is a separate conversation with the data scientists and developers. This repo is the template — same pipeline pattern (extract from logs, normalize, join, enrich, output) — just pointed at different questions.
