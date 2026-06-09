#!/usr/bin/env python3
"""
End-to-end asset enrichment.

Takes a Corelight JSON record (typically from known_devices.log) and produces
an enriched record that includes CVE and KEV context for the device's vendor.

Pipeline:
  1. Parse the input record using corelight_parser.
  2. Normalize the vendor to a CPE-compatible string.
  3. Query NVD for CVEs matching that vendor (cached locally).
  4. Cross-reference each CVE against the CISA KEV catalog.
  5. Emit an enriched record with CVE list, KEV flags, and summary counts.

Usage:
    # Enrich a single record file
    python enrich_assets.py --input ../data/samples/known_devices_sample.json

    # Enrich and save to a specific output file
    python enrich_assets.py --input record.json --output enriched.json

    # Enrich from stdin
    cat record.json | python enrich_assets.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from config import OUTPUT_DIR, ensure_directories
from corelight_parser import extract_asset_summary, get_uid
from fetch_kev_catalog import get_kev_catalog, kev_by_cve_id
from fetch_nvd_cves import fetch_cves_for_cpe, summarize_cve
from normalize_vendors import vendor_only_cpe


def enrich_record(record: dict, kev_index: dict[str, dict] | None = None) -> dict:
    """
    Enrich a single Corelight asset record with CVE and KEV context.

    Args:
        record:    The input Corelight JSON record (parsed dict).
        kev_index: Optional pre-loaded KEV catalog indexed by CVE ID.
                   If None, the catalog is loaded automatically.

    Returns:
        The enriched record as a dict.
    """
    if kev_index is None:
        kev_index = kev_by_cve_id(get_kev_catalog())

    # --- Step 1: Extract asset summary ---
    asset = extract_asset_summary(record)
    vendor_raw = asset.get("vendor_raw")

    enriched = {
        "asset": asset,
        "uid": get_uid(record),
        "cve_summary": {
            "total_cves":             0,
            "kev_listed_cves":        0,
            "max_cvss":               None,
            "ransomware_used_cves":   0,
        },
        "cves": [],
        "notes": [],
    }

    # --- Step 2: Normalize vendor to CPE ---
    if not vendor_raw:
        enriched["notes"].append(
            "No vendor field on the record — cannot perform CVE lookup. "
            "Consider OUI-based vendor identification as a fallback."
        )
        return enriched

    cpe = vendor_only_cpe(vendor_raw)
    if not cpe:
        enriched["notes"].append(
            f"Could not normalize vendor {vendor_raw!r} to a CPE string. "
            f"Add an entry to data/lookups/vendor_to_cpe.csv."
        )
        return enriched

    enriched["asset"]["vendor_cpe"] = cpe.vendor
    enriched["asset"]["cpe_match_string"] = cpe.to_cpe_string()

    # --- Step 3: Fetch CVEs for the CPE ---
    try:
        cves = fetch_cves_for_cpe(cpe.to_cpe_string())
    except Exception as e:
        enriched["notes"].append(f"NVD lookup failed: {e}")
        return enriched

    enriched["notes"].append(
        f"Vendor-only lookup. For precise CVE matches, supplement with "
        f"software.log / http.log / ssh.log observations to obtain "
        f"product and version data."
    )

    # --- Step 4 & 5: Cross-reference with KEV and summarize ---
    cvss_scores: list[float] = []
    kev_count = 0
    ransomware_count = 0

    for cve in cves:
        summary = summarize_cve(cve)
        cve_id = summary["cve_id"]
        kev_entry = kev_index.get(cve_id)

        cve_record = {
            "cve_id":      cve_id,
            "cvss_score":  summary["cvss_score"],
            "published":   summary["published"],
            "description": summary["description"],
            "kev_listed":  kev_entry is not None,
        }

        if kev_entry:
            cve_record.update({
                "kev_date_added":           kev_entry.get("dateAdded"),
                "kev_due_date":             kev_entry.get("dueDate"),
                "kev_vulnerability_name":   kev_entry.get("vulnerabilityName"),
                "kev_required_action":      kev_entry.get("requiredAction"),
                "known_ransomware_use":     kev_entry.get("knownRansomwareCampaignUse"),
            })
            kev_count += 1
            if kev_entry.get("knownRansomwareCampaignUse") == "Known":
                ransomware_count += 1

        if summary["cvss_score"] is not None:
            cvss_scores.append(summary["cvss_score"])

        enriched["cves"].append(cve_record)

    # KEV-listed CVEs first, then by severity
    enriched["cves"].sort(
        key=lambda c: (
            not c.get("kev_listed", False),
            -(c.get("cvss_score") or 0),
        ),
    )

    enriched["cve_summary"] = {
        "total_cves":           len(cves),
        "kev_listed_cves":      kev_count,
        "max_cvss":             max(cvss_scores) if cvss_scores else None,
        "ransomware_used_cves": ransomware_count,
    }

    return enriched


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument(
        "--input",
        type=Path,
        help="Input Corelight JSON record. Reads stdin if not given.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output path. If omitted, writes to <OUTPUT_DIR>/enriched.json.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the output JSON (default for file output).",
    )
    args = parser.parse_args()

    ensure_directories()

    # --- Read input ---
    if args.input:
        with args.input.open(encoding="utf-8") as f:
            record = json.load(f)
    else:
        record = json.load(sys.stdin)

    # --- Enrich ---
    enriched = enrich_record(record)

    # --- Write output ---
    out_path = args.output or (OUTPUT_DIR / "enriched.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(enriched, f, indent=2 if args.pretty or True else None)

    summary = enriched["cve_summary"]
    print(
        f"Enriched record written to {out_path}\n"
        f"  Total CVEs:        {summary['total_cves']}\n"
        f"  KEV-listed:        {summary['kev_listed_cves']}\n"
        f"  Max CVSS:          {summary['max_cvss']}\n"
        f"  Ransomware-used:   {summary['ransomware_used_cves']}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
