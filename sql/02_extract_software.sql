-- =============================================================================
-- 02_extract_software.sql
--
-- Purpose: Pull software and version observations from the logs that carry
--          product-and-version data: software.log, http.log, ssl.log, ssh.log.
--          These observations are what get mapped to CPE strings, which is
--          what NVD uses to identify CVEs.
--
-- Inputs:  software, http, ssl, ssh (Corelight per-protocol logs)
-- Output:  A unified software_observations table with one row per
--          (host, software, version, observation_time) tuple, ready for CPE
--          normalization.
--
-- Notes:
--   - software.log is the richest source — Zeek explicitly fingerprints
--     software and emits a structured (name, version, software_type) tuple.
--   - http.log and ssl.log carry banners that are useful but require more
--     parsing to extract clean product / version strings.
--   - ssh.log has reliably structured version banners.
--   - This query is a UNION ALL of per-source extractions. Each branch
--     emits the same column shape so the union works.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Branch 1: software.log — the cleanest source
-- -----------------------------------------------------------------------------
WITH from_software_log AS (
    SELECT
        host.ip.value                AS host_ip,
        'software.log'               AS source_log,
        software.name                AS product_name,
        software.version.major       AS version_major,
        software.version.minor       AS version_minor,
        software.version.minor2      AS version_patch,
        software.unparsed_version    AS version_raw,
        software.software_type       AS software_type,    -- e.g., 'WEB_SERVER', 'OS', 'CLIENT'
        timestamp                    AS observed_at
    FROM software
    WHERE timestamp BETWEEN '2026-01-01' AND CURRENT_DATE
      AND software.name IS NOT NULL
),

-- -----------------------------------------------------------------------------
-- Branch 2: http.log server header
-- -----------------------------------------------------------------------------
from_http_server AS (
    SELECT
        destination.ip.value         AS host_ip,    -- server side
        'http.log (server)'          AS source_log,
        -- Parse "Apache/2.4.49" → product='Apache', version='2.4.49'
        SPLIT_PART(http.response.server.value, '/', 1) AS product_name,
        NULL                         AS version_major,
        NULL                         AS version_minor,
        NULL                         AS version_patch,
        SPLIT_PART(http.response.server.value, '/', 2) AS version_raw,
        'HTTP_SERVER'                AS software_type,
        timestamp                    AS observed_at
    FROM http
    WHERE timestamp BETWEEN '2026-01-01' AND CURRENT_DATE
      AND http.response.server.value IS NOT NULL
),

-- -----------------------------------------------------------------------------
-- Branch 3: ssh.log version strings
-- -----------------------------------------------------------------------------
from_ssh AS (
    -- Server side
    SELECT
        destination.ip.value         AS host_ip,
        'ssh.log (server)'           AS source_log,
        -- "SSH-2.0-OpenSSH_7.6p1" → product='OpenSSH', version='7.6p1'
        REGEXP_SUBSTR(ssh.server, 'OpenSSH_[0-9.p]+|libssh_[0-9.]+|dropbear_[0-9.]+') AS product_name,
        NULL                         AS version_major,
        NULL                         AS version_minor,
        NULL                         AS version_patch,
        ssh.server                   AS version_raw,
        'SSH_SERVER'                 AS software_type,
        timestamp                    AS observed_at
    FROM ssh
    WHERE timestamp BETWEEN '2026-01-01' AND CURRENT_DATE
      AND ssh.server IS NOT NULL

    UNION ALL

    -- Client side
    SELECT
        source.ip.value              AS host_ip,
        'ssh.log (client)'           AS source_log,
        REGEXP_SUBSTR(ssh.client, 'OpenSSH_[0-9.p]+|libssh_[0-9.]+|PuTTY_[0-9.]+') AS product_name,
        NULL                         AS version_major,
        NULL                         AS version_minor,
        NULL                         AS version_patch,
        ssh.client                   AS version_raw,
        'SSH_CLIENT'                 AS software_type,
        timestamp                    AS observed_at
    FROM ssh
    WHERE timestamp BETWEEN '2026-01-01' AND CURRENT_DATE
      AND ssh.client IS NOT NULL
)

-- -----------------------------------------------------------------------------
-- Union all sources
-- -----------------------------------------------------------------------------
SELECT * FROM from_software_log
UNION ALL
SELECT * FROM from_http_server
UNION ALL
SELECT * FROM from_ssh;

-- =============================================================================
-- Extending this query
--
-- Add additional branches for:
--   - ssl.log (TLS version, cipher suite) — useful for outdated-crypto findings
--   - x509.log (cert subject/issuer organization) — sometimes identifies product
--   - smb_mapping.log (SMB protocol version, OS hints)
--   - dce_rpc.log (Windows RPC service names → OS version inference)
--
-- The pattern is the same: SELECT into the common column shape, UNION ALL
-- with the others.
--
-- Dialect notes:
--   - SPLIT_PART available in Snowflake, BigQuery, Postgres, Trino. For older
--     SQL Server / MySQL replace with SUBSTRING + CHARINDEX.
--   - REGEXP_SUBSTR available in Snowflake, BigQuery, Oracle, Trino. Postgres
--     uses SUBSTRING(... FROM regex).
-- =============================================================================
