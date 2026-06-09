"""
Map raw vendor and product strings to CPE 2.3-compatible naming.

CPE uses canonical lowercase vendor and product names. Raw observed strings
('Axis Communications AB', 'Microsoft Corporation', 'OpenSSH_7.6p1') need
normalization before they can be looked up in the NVD CVE database.

The normalization is partly mechanical (lowercase, strip legal suffixes,
basic version parsing) and partly manual (a lookup table for cases where
the CPE name diverges from the obvious normalization — OpenSSH's CPE
vendor is 'openbsd', not 'openssh', for instance).

Maintain the lookup table at data/lookups/vendor_to_cpe.csv as you
encounter new vendors.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import NamedTuple

from config import LOOKUPS_DIR


class CPEParts(NamedTuple):
    """The fields that matter for CVE lookup."""
    part: str = "*"        # 'a' (application), 'h' (hardware), 'o' (OS), or '*'
    vendor: str = "*"
    product: str = "*"
    version: str = "*"

    def to_cpe_string(self) -> str:
        """Render as a CPE 2.3 URI string suitable for NVD API queries."""
        return (
            f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:"
            f"{self.version}:*:*:*:*:*:*:*"
        )


# -----------------------------------------------------------------------------
# Lookup table loading
# -----------------------------------------------------------------------------

_VENDOR_LOOKUP_CACHE: dict[str, str] | None = None


def _load_vendor_lookup() -> dict[str, str]:
    """Load and cache the vendor → CPE vendor mapping from CSV."""
    global _VENDOR_LOOKUP_CACHE
    if _VENDOR_LOOKUP_CACHE is not None:
        return _VENDOR_LOOKUP_CACHE

    lookup_file = LOOKUPS_DIR / "vendor_to_cpe.csv"
    mapping: dict[str, str] = {}

    if not lookup_file.exists():
        _VENDOR_LOOKUP_CACHE = mapping
        return mapping

    with lookup_file.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw = row.get("raw_vendor", "").strip().lower()
            cpe = row.get("cpe_vendor", "").strip().lower()
            if raw and cpe:
                mapping[raw] = cpe

    _VENDOR_LOOKUP_CACHE = mapping
    return mapping


# -----------------------------------------------------------------------------
# Vendor normalization
# -----------------------------------------------------------------------------

_LEGAL_SUFFIX_PATTERNS = [
    r"\s+AB$",            # Swedish AB
    r"\s+Inc\.?$",        # Inc / Inc.
    r"\s+LLC$",
    r"\s+Ltd\.?$",
    r"\s+Limited$",
    r"\s+Corporation$",
    r"\s+Corp\.?$",
    r"\s+GmbH$",
    r"\s+S\.A\.?$",
    r"\s+Pty\.?\s+Ltd\.?$",
    r"\s+plc$",
    r"\s+B\.V\.$",
    r"\s+N\.V\.$",
    r",?\s+Inc\.?$",      # "Cisco, Inc."
]


def normalize_vendor(raw_vendor: str | None) -> str | None:
    """
    Normalize a raw vendor string to its CPE vendor name.

    Steps:
      1. Look up in the manual mapping table first (handles edge cases).
      2. Strip legal-entity suffixes (AB, Inc., LLC, Corporation, etc.).
      3. Lowercase and strip whitespace.
      4. Replace spaces with underscores (CPE convention).

    Returns None for empty / unparseable input.
    """
    if not raw_vendor:
        return None

    raw_lower = raw_vendor.strip().lower()

    # 1. Check the manual lookup table
    lookup = _load_vendor_lookup()
    if raw_lower in lookup:
        return lookup[raw_lower]

    # 2. Strip legal suffixes
    cleaned = raw_vendor.strip()
    for pattern in _LEGAL_SUFFIX_PATTERNS:
        cleaned = re.sub(pattern, "", cleaned, flags=re.IGNORECASE)

    # 3. Lowercase and clean whitespace
    cleaned = cleaned.strip().lower()

    # 4. Replace spaces with underscores (CPE uses underscores for multi-word names)
    cleaned = re.sub(r"\s+", "_", cleaned)

    return cleaned or None


# -----------------------------------------------------------------------------
# Product / version parsing
# -----------------------------------------------------------------------------

# Common patterns for "Product/Version" style banner strings
_BANNER_PATTERNS = [
    # "Apache/2.4.49"
    re.compile(r"^(?P<product>[A-Za-z][A-Za-z0-9\-]*)/(?P<version>[0-9][0-9.]*)"),
    # "Microsoft-IIS/10.0"
    re.compile(r"^(?P<product>Microsoft-IIS)/(?P<version>[0-9][0-9.]*)"),
    # "OpenSSH_7.6p1"
    re.compile(r"^(?P<product>OpenSSH)_(?P<version>[0-9][0-9.p]*)"),
    # "nginx/1.18.0"
    re.compile(r"^(?P<product>nginx)/(?P<version>[0-9][0-9.]*)"),
]


def parse_banner(banner: str | None) -> tuple[str | None, str | None]:
    """
    Parse a product/version banner string.

    Returns (product, version) tuple. Either or both may be None if
    parsing fails.

    Examples:
      >>> parse_banner("Apache/2.4.49")
      ('Apache', '2.4.49')
      >>> parse_banner("OpenSSH_7.6p1 Ubuntu-4ubuntu0.7")
      ('OpenSSH', '7.6p1')
    """
    if not banner:
        return None, None

    banner = banner.strip()

    for pattern in _BANNER_PATTERNS:
        match = pattern.search(banner)
        if match:
            return match.group("product"), match.group("version")

    return None, None


def normalize_version(raw_version: str | None) -> str | None:
    """
    Normalize a version string by extracting the leading numeric.dotted form.

    Examples:
      >>> normalize_version("2.4.49")
      '2.4.49'
      >>> normalize_version("7.6p1")
      '7.6'
      >>> normalize_version("2.4.49-Ubuntu-amd64")
      '2.4.49'
    """
    if not raw_version:
        return None
    match = re.match(r"^([0-9]+(?:\.[0-9]+)*)", raw_version)
    if match:
        return match.group(1)
    return None


# -----------------------------------------------------------------------------
# High-level helpers
# -----------------------------------------------------------------------------


def vendor_only_cpe(raw_vendor: str | None) -> CPEParts | None:
    """
    Build a CPE-parts tuple with vendor only (product and version wildcarded).
    Use this when you only have vendor information — e.g., from a
    known_devices record without software-log enrichment.
    """
    cpe_vendor = normalize_vendor(raw_vendor)
    if not cpe_vendor:
        return None
    return CPEParts(part="*", vendor=cpe_vendor, product="*", version="*")


def banner_to_cpe(banner: str | None, vendor_hint: str | None = None) -> CPEParts | None:
    """
    Convert a product/version banner string into a CPE-parts tuple.

    Optionally takes a vendor_hint that takes precedence over what would
    be inferred from the banner alone.

    Examples:
      >>> banner_to_cpe("Apache/2.4.49")
      CPEParts(part='a', vendor='apache', product='http_server', version='2.4.49')
    """
    product_raw, version_raw = parse_banner(banner)
    if not product_raw:
        return None

    # The product name from the banner is often a hint, not the CPE product name.
    # Map common cases to their CPE names.
    product_to_cpe = {
        "apache": ("apache",   "http_server"),
        "Apache": ("apache",   "http_server"),
        "nginx":  ("nginx",    "nginx"),
        "Microsoft-IIS": ("microsoft", "internet_information_services"),
        "OpenSSH": ("openbsd", "openssh"),
        "openssh": ("openbsd", "openssh"),
        "PuTTY":   ("simon_tatham", "putty"),
        "lighttpd": ("lighttpd", "lighttpd"),
    }
    if product_raw in product_to_cpe:
        cpe_vendor, cpe_product = product_to_cpe[product_raw]
    else:
        cpe_vendor = vendor_hint or product_raw.lower()
        cpe_product = product_raw.lower()

    if vendor_hint:
        cpe_vendor = normalize_vendor(vendor_hint) or cpe_vendor

    return CPEParts(
        part="a",
        vendor=cpe_vendor,
        product=cpe_product,
        version=normalize_version(version_raw) or "*",
    )


if __name__ == "__main__":
    # Quick smoke test
    test_cases = [
        ("Axis Communications AB", None),
        ("Microsoft Corporation", None),
        ("Cisco, Inc.", None),
        (None, "Apache/2.4.49"),
        (None, "OpenSSH_7.6p1 Ubuntu-4ubuntu0.7"),
        (None, "Microsoft-IIS/10.0"),
    ]
    for vendor, banner in test_cases:
        if vendor:
            cpe = vendor_only_cpe(vendor)
            print(f"  vendor {vendor!r:42}  -> {cpe}")
        else:
            cpe = banner_to_cpe(banner)
            print(f"  banner {banner!r:42}  -> {cpe}")
