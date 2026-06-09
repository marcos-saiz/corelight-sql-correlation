#!/usr/bin/env python3
"""
Query the NVD CVE API for vulnerabilities matching a CPE string.

The NVD API returns one CVE per result, with all the metadata (CVSS scores,
affected configurations, references, etc.). This script handles:

  - CPE-based queries (vendor-only or vendor+product+version)
  - Pagination (NVD pages at up to 2000 results)
  - Rate limiting and retries
  - Optional API key for higher rate limits
  - Local response caching keyed by CPE string

Usage:
    # Vendor-only query (broad)
    python fetch_nvd_cves.py --cpe "cpe:2.3:*:axis:*:*:*:*:*:*:*"

    # Specific product+version (narrow)
    python fetch_nvd_cves.py --cpe "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*"

    # Show summary only
    python fetch_nvd_cves.py --cpe "..." --summary

    # Force a fresh fetch (bypass cache)
    python fetch_nvd_cves.py --cpe "..." --force
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import requests

try:
    from tenacity import (
        retry,
        retry_if_exception_type,
        stop_after_attempt,
        wait_exponential,
    )
    HAS_TENACITY = True
except ImportError:
    HAS_TENACITY = False

from config import (
    NVD_API_BASE,
    NVD_API_KEY,
    NVD_BASE_DELAY_SECONDS,
    NVD_CACHE_DIR,
    NVD_CACHE_TTL_HOURS,
    NVD_MAX_RETRIES,
    NVD_RESULTS_PER_PAGE,
    REQUEST_TIMEOUT_SECONDS,
    USER_AGENT,
    ensure_directories,
)


# -----------------------------------------------------------------------------
# Cache helpers
# -----------------------------------------------------------------------------


def _cache_key(cpe: str) -> str:
    """Stable hash of the CPE string for use as a cache filename."""
    return hashlib.sha1(cpe.encode("utf-8")).hexdigest()


def _cache_path(cpe: str) -> Path:
    return NVD_CACHE_DIR / f"{_cache_key(cpe)}.json"


def cache_is_fresh(cache_file: Path, ttl_hours: int = NVD_CACHE_TTL_HOURS) -> bool:
    if not cache_file.exists():
        return False
    mtime = datetime.fromtimestamp(cache_file.stat().st_mtime, tz=timezone.utc)
    return (datetime.now(timezone.utc) - mtime) < timedelta(hours=ttl_hours)


# -----------------------------------------------------------------------------
# API client
# -----------------------------------------------------------------------------


def _build_headers() -> dict[str, str]:
    headers = {"User-Agent": USER_AGENT}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


def _request_page(
    cpe: str,
    start_index: int,
    results_per_page: int = NVD_RESULTS_PER_PAGE,
) -> dict:
    """Fetch a single page of results from the NVD API."""
    params = {
        "cpeName": cpe,
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }
    response = requests.get(
        NVD_API_BASE,
        params=params,
        headers=_build_headers(),
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()


if HAS_TENACITY:
    _request_page = retry(
        retry=retry_if_exception_type(requests.RequestException),
        wait=wait_exponential(multiplier=NVD_BASE_DELAY_SECONDS, max=60),
        stop=stop_after_attempt(NVD_MAX_RETRIES),
        reraise=True,
    )(_request_page)


def _iterate_pages(cpe: str) -> Iterator[dict]:
    """Yield each page of NVD results for the given CPE."""
    start_index = 0
    while True:
        page = _request_page(cpe, start_index=start_index)
        yield page

        total_results = page.get("totalResults", 0)
        results_per_page = page.get("resultsPerPage", 0)
        next_index = start_index + results_per_page

        if next_index >= total_results:
            break

        # Conservative pacing between page requests
        time.sleep(NVD_BASE_DELAY_SECONDS if not NVD_API_KEY else 0.6)
        start_index = next_index


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def fetch_cves_for_cpe(cpe: str, force_refresh: bool = False) -> list[dict]:
    """
    Return the full list of CVE records for a CPE string.

    Each item in the returned list is the `cve` sub-object from a single
    NVD API result.
    """
    ensure_directories()
    cache_file = _cache_path(cpe)

    if not force_refresh and cache_is_fresh(cache_file):
        with cache_file.open(encoding="utf-8") as f:
            return json.load(f)

    print(f"Fetching CVEs for CPE: {cpe}", file=sys.stderr)
    all_cves: list[dict] = []

    for page in _iterate_pages(cpe):
        for item in page.get("vulnerabilities", []):
            cve = item.get("cve")
            if cve:
                all_cves.append(cve)

    cache_file.parent.mkdir(parents=True, exist_ok=True)
    with cache_file.open("w", encoding="utf-8") as f:
        json.dump(all_cves, f, indent=2)

    return all_cves


def summarize_cve(cve: dict) -> dict:
    """Extract the most useful fields from a full NVD CVE record."""
    cve_id = cve.get("id", "<no-id>")

    # CVSS scoring — NVD records carry multiple versions
    metrics = cve.get("metrics", {})
    cvss_v31 = _extract_cvss(metrics, "cvssMetricV31")
    cvss_v30 = _extract_cvss(metrics, "cvssMetricV30")
    cvss_v40 = _extract_cvss(metrics, "cvssMetricV40")

    # Take the best-available score
    cvss = cvss_v31 or cvss_v30 or cvss_v40

    # Description: prefer English
    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    return {
        "cve_id":       cve_id,
        "published":    cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "cvss_score":   cvss,
        "cvss_v31":     cvss_v31,
        "cvss_v30":     cvss_v30,
        "cvss_v40":     cvss_v40,
        "description":  description[:500],   # truncate long descriptions
    }


def _extract_cvss(metrics: dict, key: str) -> float | None:
    entries = metrics.get(key, [])
    if not entries:
        return None
    return entries[0].get("cvssData", {}).get("baseScore")


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument(
        "--cpe",
        required=True,
        help="CPE match string (e.g., cpe:2.3:*:axis:*:*:*:*:*:*:*)",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print one-line summaries instead of full CVE records",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Bypass the local response cache and re-query NVD",
    )
    args = parser.parse_args()

    if not NVD_API_KEY:
        print(
            "Note: no NVD_API_KEY set. Using anonymous rate limit (5 req / 30s). "
            "Set NVD_API_KEY env var to raise the limit.",
            file=sys.stderr,
        )

    try:
        cves = fetch_cves_for_cpe(args.cpe, force_refresh=args.force)
    except requests.HTTPError as e:
        print(f"NVD HTTP error: {e}", file=sys.stderr)
        return 1
    except requests.RequestException as e:
        print(f"NVD network error: {e}", file=sys.stderr)
        return 1

    print(f"Found {len(cves)} CVEs matching {args.cpe}", file=sys.stderr)

    if args.summary:
        for cve in cves:
            s = summarize_cve(cve)
            score = f"{s['cvss_score']:.1f}" if s["cvss_score"] is not None else "n/a"
            print(f"  {s['cve_id']:18}  CVSS {score:5}  {s['description'][:80]}")
    else:
        print(json.dumps(cves, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
