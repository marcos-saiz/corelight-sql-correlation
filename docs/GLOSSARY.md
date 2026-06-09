# Glossary

Plain-English definitions of the terms used throughout this project.

## Network observation

**Zeek**
The open-source network analysis framework (formerly called Bro) that parses traffic and emits structured logs. Maintained by the Zeek Project. <https://zeek.org/>

**Corelight**
A commercial vendor that ships Zeek-based NDR sensors with additional detection content, integrated Suricata, and proprietary log types. Many of the company's founders also created Zeek. <https://corelight.com/>

**NDR**
Network Detection and Response. The category of tools that analyze network traffic to detect threats and provide investigation context. Zeek and Corelight are NDR.

**Suricata**
An open-source intrusion detection / prevention engine that runs signature-based rules on network traffic. Corelight bundles Suricata with their Zeek sensors and preserves the Zeek connection identifier across the two engines.

**Sensor**
The hardware or virtual appliance that captures network traffic and runs the analysis engine.

**TAP / SPAN**
Two ways to deliver a copy of network traffic to a sensor without inserting the sensor into the data path. TAP is a hardware splitter; SPAN is a configured port-mirroring feature on a switch.

## Identifiers in the logs

**uid (Zeek connection UID)**
A unique identifier Zeek stamps onto each network connection (TCP, UDP, or ICMP flow). Every protocol-specific log derived from that connection (`dns.log`, `http.log`, `ssl.log`, etc.) carries the same `uid` back to a single row in `conn.log`. The cleanest, most reliable join key when both sides have it.

The format is a ~17-character alphanumeric string starting with `C` (e.g., `C7B3j12m1L5X3k8a7`).

In some normalized / ECS-derived schemas, this field is renamed to `event.id`.

**community_id**
A deterministic hash computed from the connection's 5-tuple. Different tools (Zeek, Suricata, Wireshark, osquery) compute the same hash for the same flow, so this is the standard for correlating across tools. Format: `1:<base64-encoded-hash>`.

community_id originated as a Corelight-led open standard and is now broadly adopted across the network-security tool ecosystem. Where uid is Zeek-specific, community_id lets you pivot to anything that calculates the same hash.

**fuid**
File Unique ID. Stamped on every file Zeek extracts metadata for. Appears in `files.log`, `x509.log`, `pe.log`. Used to chain file-related logs together.

If the same file is downloaded over HTTP and then sent as an SMTP attachment, both records carry the same `fuid` — so you can track a file entity across multiple connections and protocols.

**conn_uids**
An *array* column in `files.log` listing every connection UID the file traversed. Most files have one entry. Some (cached, multi-channel transfers, fragment reassembly) have several. SQL joins on this column need to flatten the array — `UNNEST` (Postgres / DuckDB / BigQuery), `LATERAL FLATTEN` (Snowflake), `ARRAY_CONTAINS` (Databricks / Spark / Trino), or equivalent.

**5-tuple**
The five fields that define a network connection:
- Source IP (`id.orig_h`)
- Source port (`id.orig_p`)
- Destination IP (`id.resp_h`)
- Destination port (`id.resp_p`)
- Protocol (`proto`)

Useful as a fallback join key but bulkier and less safe than `uid`. Port reuse (especially behind NAT or on high-traffic gateways) makes the 5-tuple collision-prone over long time windows — anchor with a `ts` window if you have to use it.

**ts (timestamp)**
The event timestamp. Always needed as a join constraint when joining to aggregation logs, because IPs get reassigned to different hosts over time.

## Log type categories

**Per-connection log**
A log where every row is tied to a specific network connection. These all carry `uid` back to `conn.log`. Examples: `dns`, `http`, `ssl`, `ssh`, `kerberos`, `ntlm`, `smb_files`, `dce_rpc`, `dhcp`.

**Aggregation / state log**
A log where every row is a discovered *fact about a host or service*, not a per-connection event. These do NOT carry `uid`. They are keyed off IP address (and sometimes MAC). Joining requires a time window. Examples: `known_hosts`, `known_services`, `known_certs`, `software`, `known_devices`.

**Standalone log**
A log that doesn't carry correlation keys and can't be joined to network traffic. Includes Zeek-internal logs (`stats`, `capture_loss`, `cluster`, `broker`, `reporter`, `loaded_scripts`, `packet_filter`, `print`) and Corelight-specific operational logs (`corelight_audit`, `corelight_license_capacity`).

## Join semantics

**Time-windowed join**
A join where the matching row must fall within a time window of the source row. Required for any IP-based join to aggregation/state logs, because an IP can belong to host A today and host B tomorrow. Pattern:
```sql
JOIN known_hosts kh
  ON kh.host = c.id.orig.h
  AND c.ts BETWEEN kh.first_seen AND COALESCE(kh.last_seen, NOW())
```

**Lossy join**
A join where some rows on the source side won't find a match on the target side, or where the match is approximate rather than exact. Aggregation-log joins are inherently lossy. Plan for `LEFT JOIN` and handle NULLs in the dashboard logic.

**Cardinality**
How many rows on each side of the join. `1:1` means one row each. `1:many` means one row on the source side maps to many rows on the target side. Affects how you aggregate (counts, sums) in dashboard queries.

**ASOF JOIN**
A specialized join type available on some platforms (Snowflake, ClickHouse, DuckDB) that automatically finds the most recent matching row at or before the source row's timestamp. The natural way to do time-anchored joins to state logs. Not all SQL dialects support it.

## Vulnerability data

**CVE**
Common Vulnerabilities and Exposures. A standardized identifier for publicly disclosed cybersecurity vulnerabilities. Format: `CVE-YYYY-NNNN+`. Maintained by [MITRE](https://cve.mitre.org/), assigned by CNAs (CVE Numbering Authorities).

**NVD**
National Vulnerability Database. The US-government-maintained enrichment of the CVE list with CVSS scores, CPE mappings, and other metadata. Run by NIST. <https://nvd.nist.gov/>

**CPE**
Common Platform Enumeration. A structured naming scheme for software, hardware, and operating systems. Used by NVD to link CVEs to affected products. Format:
```
cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
```
Most enrichment work only needs `part`, `vendor`, `product`, `version`.

**CVSS**
Common Vulnerability Scoring System. A numeric severity score (0.0-10.0) for CVEs. Versions 2.0, 3.0, 3.1, and 4.0 are in active use. CVSS 3.1 is the current default; CVSS 4.0 adoption is growing.

**KEV**
Known Exploited Vulnerabilities catalog. A subset of CVEs that CISA has confirmed are being exploited in the wild. Maintained by [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), published as a downloadable JSON. KEV-listed CVEs are the most operationally urgent.

**CISA**
Cybersecurity and Infrastructure Security Agency. The US federal civilian cybersecurity agency. Publishes the KEV catalog and many other security advisories.

**CWE**
Common Weakness Enumeration. A taxonomy of software weakness types (e.g., CWE-79 is cross-site scripting). KEV entries reference CWEs to categorize the weakness behind each vulnerability.

**CNA**
CVE Numbering Authority. An organization authorized to assign CVE IDs. Major vendors (Microsoft, Cisco, Apple) are CNAs for their own products. Independent researchers go through MITRE.

## Asset / network terms

**OUI**
Organizationally Unique Identifier. The first three bytes of a MAC address, registered to a hardware vendor by the IEEE. Lets you identify the manufacturer of a device from its MAC. The IEEE publishes the [OUI database](http://standards-oui.ieee.org/oui/oui.txt) publicly.

**MAC address**
The 48-bit hardware identifier of a network interface. Usually written as six pairs of hex digits separated by colons. The first three bytes are the OUI (vendor); the last three bytes are the vendor-assigned unique portion.

**Locally administered MAC**
A MAC address that was manually configured rather than burned in by a manufacturer. Recognizable by the U/L bit (second-least-significant bit of the first octet) being set. Usually indicates a router, firewall, virtual interface, or virtual machine — not a user device.

**DHCP**
Dynamic Host Configuration Protocol. The mechanism that assigns IP addresses to devices on a network. Zeek's `dhcp.log` aggregates the four-message DISCOVER / OFFER / REQUEST / ACK exchange into one row, with a `uids` array linking back to each underlying connection.

**VLAN**
Virtual LAN. A logical network segment within a physical network. The `network.vlan.id` field tells you which VLAN a connection was observed on, which is valuable context for risk assessment (a camera on an isolated IoT VLAN is a very different risk than one sharing a flat network with domain controllers).

## Pipeline / data engineering

**ECS**
Elastic Common Schema. A field-naming convention pushed by Elastic, used by many vendors (including Corelight, via their `ecs-mapping` repo) to normalize logs across sources. Even if you're not using Elastic, the mapping files document field equivalences usefully.

**Data lake**
A storage layer (usually cloud object storage like S3) that holds large volumes of structured and semi-structured data in their original format, queryable on demand by tools like Athena, Spark, or Trino.

**SQL warehouse**
A managed analytical database (Snowflake, BigQuery, Redshift, Databricks SQL) that runs queries against large datasets. Differs from a data lake mainly in that the storage and compute are more tightly integrated.
