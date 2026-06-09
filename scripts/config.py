"""
Central configuration for the enrichment pipeline scripts.

Reads from environment variables where appropriate so the same code runs
in dev and prod without modification.
"""

import os
from pathlib import Path

# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------

# Repo root (this file lives in scripts/, so parent is repo root)
REPO_ROOT = Path(__file__).resolve().parent.parent

# Where downloaded data (KEV catalog, NVD responses) is cached.
# Override with CACHE_DIR env var.
CACHE_DIR = Path(os.environ.get("CACHE_DIR", REPO_ROOT / "data" / "cache"))

# Lookups directory (vendor mapping CSV, etc.)
LOOKUPS_DIR = REPO_ROOT / "data" / "lookups"

# Output directory for enriched records
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", REPO_ROOT / "data" / "output"))

# -----------------------------------------------------------------------------
# CISA KEV
# -----------------------------------------------------------------------------

KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_FILE = CACHE_DIR / "kev_catalog.json"

# How long the cached KEV file is considered fresh, in hours
KEV_CACHE_TTL_HOURS = 24

# -----------------------------------------------------------------------------
# NVD
# -----------------------------------------------------------------------------

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Free, optional. Without a key you get 5 req/30s; with one you get 50 req/30s.
# Register at https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY = os.environ.get("NVD_API_KEY")

# Pagination
NVD_RESULTS_PER_PAGE = 2000  # The NVD API maximum

# Retry / backoff
NVD_MAX_RETRIES = 5
NVD_BASE_DELAY_SECONDS = 6  # Conservative — adjust if you have an API key

# Local cache for NVD responses, keyed by CPE match string hash
NVD_CACHE_DIR = CACHE_DIR / "nvd"
NVD_CACHE_TTL_HOURS = 24

# -----------------------------------------------------------------------------
# HTTP
# -----------------------------------------------------------------------------

USER_AGENT = (
    "corelight-sql-correlation/0.1 "
    "(https://github.com/marcos-saiz/corelight-sql-correlation)"
)

REQUEST_TIMEOUT_SECONDS = 30


# -----------------------------------------------------------------------------
# Initialization
# -----------------------------------------------------------------------------

def ensure_directories() -> None:
    """Create cache and output directories if they do not exist yet."""
    for d in (CACHE_DIR, NVD_CACHE_DIR, OUTPUT_DIR):
        d.mkdir(parents=True, exist_ok=True)
