-- =============================================================================
-- 01_extract_assets.sql
--
-- Purpose: Extract one row per discovered device from known_devices.log.
--          This becomes the anchor table that all enrichment joins back to.
--
-- Input:   <db>.<schema>.known_devices  (Corelight known_devices log records)
-- Output:  An asset inventory with vendor, MAC, IP, OUI, VLAN, observation
--          timestamps.
--
-- Schema assumption: nested-object access (source.ip.value style). Adapt
--                    field paths to your data lake if your schema is flat
--                    or uses JSON_EXTRACT.
--
-- Notes:
--   - One device can appear in many known_devices records over time as
--     its DHCP lease churns. We dedupe by MAC and keep first_seen /
--     last_seen as a range.
--   - MAC is more stable than IP for asset identification. The vendor
--     field can be NULL when the OUI is not in the vendor database —
--     we capture both raw vendor name and OUI for downstream lookup.
-- =============================================================================

WITH device_observations AS (
    SELECT
        asset.mac.value           AS mac,
        asset.oui                 AS oui,
        asset.vendor.value        AS vendor_raw,
        host.ip.value             AS ip_at_observation,
        network.vlan.id           AS vlan_id,
        network.protocol          AS observation_protocol,
        timestamp                 AS observed_at,
        event.ingested            AS ingested_at
    FROM known_devices
    -- Restrict to the analysis window. Adjust as needed.
    WHERE timestamp BETWEEN '2026-01-01' AND CURRENT_DATE
      -- Filter out records with missing critical fields
      AND asset.mac.value IS NOT NULL
)

SELECT
    mac,
    oui,
    -- Take the most recently observed vendor name (best for cases where
    -- the parser improves over time and starts populating vendor for
    -- previously-unidentified OUIs)
    MAX_BY(vendor_raw,    observed_at) AS vendor_raw,
    -- Most recent IP (an asset can change IP via DHCP)
    MAX_BY(ip_at_observation, observed_at) AS most_recent_ip,
    -- Most recent VLAN
    MAX_BY(vlan_id,       observed_at) AS most_recent_vlan,
    -- Observation lifespan
    MIN(observed_at)               AS first_seen,
    MAX(observed_at)               AS last_seen,
    -- Count of observations (useful for noise filtering)
    COUNT(*)                       AS observation_count
FROM device_observations
GROUP BY mac, oui;

-- =============================================================================
-- Dialect notes:
--   - MAX_BY(col, sort_col) is Snowflake / BigQuery / Trino / Athena syntax.
--     Postgres equivalent: use DISTINCT ON (mac) with ORDER BY observed_at DESC.
--   - If your schema flattens asset/host/etc. into top-level columns, replace
--     the dotted paths with the equivalent flat column names.
-- =============================================================================
