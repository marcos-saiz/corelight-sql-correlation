-- =============================================================================
-- 03_join_software_to_assets.sql
--
-- Purpose: Join software observations to asset records, anchored by IP +
--          time window. Produces the per-asset software inventory that
--          gets fed to the CVE/KEV enrichment stage.
--
-- Inputs:  assets (from 01_extract_assets.sql)
--          software_observations (from 02_extract_software.sql)
-- Output:  asset_software — one row per (asset, software observation) pair
--
-- Why time-windowed?
--   IP-to-asset bindings change over time. An IP that belonged to Asset A
--   in January may belong to Asset B in March. Joining only on IP without
--   a time window will produce wrong matches whenever a DHCP lease has
--   rotated. The time window ensures the software observation occurred
--   during a period when this asset actually held that IP.
--
-- Alternative: ASOF JOIN
--   Snowflake, ClickHouse, and DuckDB support ASOF JOIN, which is the
--   purpose-built operator for "find the matching row at or before this
--   time". Where supported, it's cleaner than a BETWEEN.
-- =============================================================================

SELECT
    a.mac                       AS asset_mac,
    a.oui                       AS asset_oui,
    a.vendor_raw                AS asset_vendor,
    a.most_recent_ip            AS asset_ip,
    a.most_recent_vlan          AS asset_vlan,
    a.first_seen                AS asset_first_seen,
    a.last_seen                 AS asset_last_seen,

    s.source_log                AS software_source_log,
    s.product_name              AS software_product,
    s.version_raw               AS software_version,
    s.software_type             AS software_type,
    s.observed_at               AS software_observed_at

FROM assets a
LEFT JOIN software_observations s
    -- Match on IP at the time of the software observation
    ON s.host_ip = a.most_recent_ip
    -- Anchor to the asset's lifespan window
    AND s.observed_at BETWEEN a.first_seen AND COALESCE(a.last_seen, CURRENT_TIMESTAMP)
;

-- =============================================================================
-- Variations to consider:
--
-- 1) Strict version of the above — INNER JOIN instead of LEFT JOIN if you only
--    want assets with at least one software observation.
--
-- 2) Asset-side aggregation — group by asset and use ARRAY_AGG / LISTAGG to
--    produce one row per asset with software as a list. Useful for dashboards
--    that want one row per device.
--
--    Snowflake:
--       SELECT a.mac, a.vendor_raw, ARRAY_AGG(s.product_name)
--       FROM assets a LEFT JOIN software_observations s ON ...
--       GROUP BY a.mac, a.vendor_raw
--
-- 3) ASOF JOIN version (Snowflake / ClickHouse / DuckDB):
--
--    SELECT ... FROM software_observations s
--    ASOF JOIN assets a
--      ON s.host_ip = a.most_recent_ip
--      AND s.observed_at >= a.first_seen
--    -- ASOF matches the most recent asset record at or before the observation
--
-- 4) If your data lake has a richer history of IP-to-MAC bindings (e.g.,
--    via DHCP leases), use that for the join instead of the IP on the
--    asset record. Pseudocode:
--
--    SELECT ... FROM software_observations s
--    JOIN dhcp_leases d ON s.host_ip = d.assigned_ip
--                      AND s.observed_at BETWEEN d.lease_start AND d.lease_end
--    JOIN assets a ON a.mac = d.mac
-- =============================================================================
