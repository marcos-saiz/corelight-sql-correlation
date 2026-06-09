# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `sql/05_common_use_cases.sql` — five standalone SQL patterns for common network forensics tasks (malicious file origin, credential / lateral movement, encrypted traffic decoding, asset attribution via DHCP time-anchoring, PCR-based exfiltration hunt)
- `docs/CORELIGHT_LOG_REFERENCE.md` — explicit "Three principles" section (State Anchor Logic, Suricata Advantage, Many-to-Many Cardinality)
- `docs/CORELIGHT_LOG_REFERENCE.md` — standalone-logs section documenting logs that cannot be joined and what they're useful for
- Expanded glossary entries with format details (`uid` 17-char format, `community_id` as Corelight-led standard, 5-tuple collision-proneness, `fuid` cross-protocol tracking)
- Source citations for Book of Zeek and Corelight zeek-cheatsheets in addition to ecs-mapping

## [0.1.0] - 2026-06-09

Initial public release.

### Added
- End-to-end enrichment pipeline (asset → CPE → NVD → KEV → enriched record)
- Python scripts: KEV catalog downloader, NVD CVE fetcher, vendor normalizer, end-to-end enricher
- Corelight JSON parser with multi-schema field accessors
- SQL reference queries for asset extraction, software fingerprinting, and CVE/KEV enrichment
- Corelight / Zeek log correlation reference documentation
- Vendor-to-CPE starter lookup table (~80 vendors)
- Sample anonymized `known_devices.log` record for testing
- Two end-to-end walkthrough examples
- Architecture, pipeline, glossary, schema notes, and broader-use-case documentation
- Contributing guidelines
