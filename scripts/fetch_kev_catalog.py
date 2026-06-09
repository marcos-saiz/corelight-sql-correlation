#!/usr/bin/env python3
"""
Download and cache the CISA Known Exploited Vulnerabilities (KEV) catalog.

The KEV catalog is a single ~500KB JSON file maintained by CISA, listing
CVEs confirmed exploited in the wild. The pipeline does a simple
set-membership check against this list to flag which CVEs are most urgent.

Run this once a day (or whatever your refresh cadence is). The cache file
location and TTL are configured in config.py.

Usage:
    python fetch_kev_catalog.py                # Use defaults
    python fetch_kev_catalog.py --force        # Refresh even if cache is fresh
    python fetch_kev_catalog.py --json-only    # Print parsed JSON to stdout
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from config import (
    KEV_CACHE_FILE,
    KEV_CACHE_TTL_HOURS,
    KEV_CATALOG_URL,
    REQUEST_TIMEOUT_SECONDS,
    USER_AGENT,
    ensure_directories,
)


def cache_is_fresh(cache_file: Path, ttl_hours: int) -> bool:
    """Return True if the cache file exists and is younger than ttl_hours."""
    if not cache_file.exists():
        return False
    mtime = datetime.fromtimestamp(cache_file.stat().st_mtime, tz=timezone.utc)
    age = datetime.now(timezone.utc) - mtime
    return age < timedelta(hours=ttl_hours)


def fetch_kev_catalog(url: str = KEV_CATALOG_URL) -> dict:
    """Download the KEV catalog JSON. Returns the parsed dict."""
    headers = {"User-Agent": USER_AGENT}
    print(f"Downloading KEV catalog from {url}...", file=sys.stderr)
    response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()


def save_to_cache(catalog: dict, cache_file: Path) -> None:
    """Write the catalog dict to the cache file."""
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    with cache_file.open("w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)
    print(f"Cached to {cache_file}", file=sys.stderr)


def load_from_cache(cache_file: Path) -> dict:
    """Load the catalog dict from the cache file."""
    with cache_file.open(encoding="utf-8") as f:
        return json.load(f)


def get_kev_catalog(force_refresh: bool = False) -> dict:
    """
    Return the KEV catalog, fetching from CISA if the cache is stale or absent.
    """
    ensure_directories()

    if not force_refresh and cache_is_fresh(KEV_CACHE_FILE, KEV_CACHE_TTL_HOURS):
        print(f"Using cached KEV catalog at {KEV_CACHE_FILE}", file=sys.stderr)
        return load_from_cache(KEV_CACHE_FILE)

    catalog = fetch_kev_catalog()
    save_to_cache(catalog, KEV_CACHE_FILE)
    return catalog


def kev_cve_ids(catalog: dict) -> set[str]:
    """Extract the set of KEV-listed CVE IDs from the catalog."""
    return {entry["cveID"] for entry in catalog.get("vulnerabilities", [])}


def kev_by_cve_id(catalog: dict) -> dict[str, dict]:
    """Index the KEV catalog by CVE ID for O(1) lookup."""
    return {entry["cveID"]: entry for entry in catalog.get("vulnerabilities", [])}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument(
        "--force",
        action="store_true",
        help="Refresh even if the cache is still fresh.",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Print parsed JSON to stdout and exit (no file output).",
    )
    args = parser.parse_args()

    try:
        catalog = get_kev_catalog(force_refresh=args.force)
    except requests.HTTPError as e:
        print(f"HTTP error fetching KEV catalog: {e}", file=sys.stderr)
        return 1
    except requests.RequestException as e:
        print(f"Network error fetching KEV catalog: {e}", file=sys.stderr)
        return 1

    n = len(catalog.get("vulnerabilities", []))
    catalog_version = catalog.get("catalogVersion", "unknown")
    date_released = catalog.get("dateReleased", "unknown")

    if args.json_only:
        print(json.dumps(catalog, indent=2))
    else:
        print(
            f"KEV catalog v{catalog_version} (released {date_released}): "
            f"{n} entries.",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
