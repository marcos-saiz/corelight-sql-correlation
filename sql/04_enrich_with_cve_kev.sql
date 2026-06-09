-- =============================================================================
-- 04_enrich_with_cve_kev.sql
--
-- Purpose: Final enrichment step. Join the asset/software inventory against
--          the CVE reference table (loaded from NVD by the Python scripts)
--          and the KEV reference table (loaded from CISA), producing a
--          risk-scored asset inventory.
--
-- Inputs:  asset_software   (from 03_join_software_to_assets.sql)
--          cve_reference    (populated by scripts/fetch_nvd_cves.py)
--          kev_reference    (populated by scripts/fetch_kev_catalog.py)
--
-- Output:  Per-asset enriched view with CVE counts, KEV counts, max CVSS,
--          and ransomware-use flags.
--
-- Reference table shapes (see scripts/ for population logic):
--
--   cve_reference (
--     cpe_vendor   STRING,    -- 'apache'
--     cpe_product  STRING,    -- 'http_server'
--     cpe_version  STRING,    -- '2.4.49'
--     cve_id       STRING,    -- 'CVE-2021-41773'
--     cvss_v31     FLOAT,
--     cvss_v40     FLOAT,
--     published    TIMESTAMP,
--     description  STRING
--   )
--
--   kev_reference (
--     cve_id                        STRING,
--     vendor_project                STRING,
--     product                       STRING,
--     vulnerability_name            STRING,
--     date_added                    DATE,
--     required_action               STRING,
--     due_date                      DATE,
--     known_ransomware_campaign_use STRING,
--     cwes                          ARRAY<STRING>
--   )
-- =============================================================================

WITH
-- -----------------------------------------------------------------------------
-- Step 1: Normalize software observations to CPE-compatible vendor/product.
-- For this proof-of-concept the normalization is naive lowercase + simple
-- string parsing. The Python script (scripts/normalize_vendors.py) handles
-- the manual lookup table for vendors whose CPE name differs from their
-- raw observed name (e.g., 'OpenSSH' → cpe vendor 'openbsd').
-- -----------------------------------------------------------------------------
software_normalized AS (
    SELECT
        asset_mac,
        asset_vendor,
        asset_ip,
        asset_vlan,
        software_product,
        software_version,
        software_source_log,
        software_observed_at,
        LOWER(REPLACE(REPLACE(asset_vendor, ' AB',  ''), ' Inc.', '')) AS cpe_vendor_hint,
        LOWER(software_product)                                       AS cpe_product_hint,
        -- Extract leading numeric+dot sequence from version_raw
        REGEXP_SUBSTR(software_version, '[0-9]+(\\.[0-9]+)*')         AS cpe_version_hint
    FROM asset_software
),

-- -----------------------------------------------------------------------------
-- Step 2: Match against the CVE reference table.
-- -----------------------------------------------------------------------------
asset_cves AS (
    SELECT
        sn.asset_mac,
        sn.asset_vendor,
        sn.asset_ip,
        sn.asset_vlan,
        sn.software_product,
        sn.software_version,
        cr.cve_id,
        cr.cvss_v31,
        cr.cvss_v40,
        cr.published    AS cve_published,
        cr.description  AS cve_description
    FROM software_normalized sn
    LEFT JOIN cve_reference cr
        ON cr.cpe_vendor  = sn.cpe_vendor_hint
        AND (cr.cpe_product = sn.cpe_product_hint OR sn.cpe_product_hint IS NULL)
        AND (cr.cpe_version = sn.cpe_version_hint OR sn.cpe_version_hint IS NULL)
),

-- -----------------------------------------------------------------------------
-- Step 3: Annotate with KEV status.
-- -----------------------------------------------------------------------------
asset_cves_with_kev AS (
    SELECT
        ac.*,
        kr.cve_id IS NOT NULL                  AS kev_listed,
        kr.date_added                          AS kev_date_added,
        kr.due_date                            AS kev_due_date,
        kr.required_action                     AS kev_required_action,
        kr.known_ransomware_campaign_use       AS known_ransomware_use,
        kr.vulnerability_name                  AS kev_name
    FROM asset_cves ac
    LEFT JOIN kev_reference kr
        ON kr.cve_id = ac.cve_id
)

-- -----------------------------------------------------------------------------
-- Final output: one row per (asset, CVE) pair.
-- For a one-row-per-asset summary, see the alternative query below.
-- -----------------------------------------------------------------------------
SELECT
    asset_mac,
    asset_vendor,
    asset_ip,
    asset_vlan,
    software_product,
    software_version,
    cve_id,
    cvss_v31,
    cvss_v40,
    cve_published,
    cve_description,
    kev_listed,
    kev_date_added,
    kev_due_date,
    kev_required_action,
    known_ransomware_use,
    kev_name
FROM asset_cves_with_kev
ORDER BY
    kev_listed DESC,                       -- KEVs first
    COALESCE(cvss_v31, cvss_v40) DESC NULLS LAST,  -- Then by severity
    asset_mac
;

-- =============================================================================
-- ALTERNATIVE: One-row-per-asset summary view
-- =============================================================================
-- Useful for dashboards that show a leaderboard of assets by risk.
-- Uncomment and replace the SELECT above.
--
-- SELECT
--     asset_mac,
--     asset_vendor,
--     asset_ip,
--     asset_vlan,
--     COUNT(DISTINCT cve_id)                              AS total_cves,
--     COUNT(DISTINCT CASE WHEN kev_listed THEN cve_id END) AS kev_cves,
--     COUNT(DISTINCT CASE WHEN known_ransomware_use = 'Known' THEN cve_id END) AS ransomware_used_cves,
--     MAX(COALESCE(cvss_v31, cvss_v40))                   AS max_cvss,
--     ARRAY_AGG(DISTINCT CASE WHEN kev_listed THEN cve_id END) AS kev_cve_list,
--     MIN(kev_due_date) FILTER (WHERE kev_listed)         AS earliest_kev_due_date
-- FROM asset_cves_with_kev
-- GROUP BY asset_mac, asset_vendor, asset_ip, asset_vlan
-- ORDER BY kev_cves DESC, max_cvss DESC;
--
-- Note: ARRAY_AGG(DISTINCT) syntax varies. Snowflake uses ARRAY_AGG(DISTINCT col),
-- BigQuery uses ARRAY_AGG(DISTINCT col) but with caveats on ordering.
-- =============================================================================
