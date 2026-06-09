-- =============================================================================
-- 05_common_use_cases.sql
--
-- A collection of common Corelight / Zeek SQL patterns that come up
-- regularly in network forensics and threat hunting. Each pattern is
-- standalone — useful as a starting template rather than part of the core
-- enrichment pipeline (01-04).
--
-- All queries assume a nested-object schema where source.ip.value style
-- access works. Adapt field paths to your data lake as needed.
-- =============================================================================


-- =============================================================================
-- Pattern 1: Malicious File Origin
--
-- Goal: Given a file hash (MD5 / SHA1 / SHA256), find every connection that
--       carried that file and surface source / destination metadata.
--
-- Join: files.log → conn.log via UNNEST(conn_uids)
-- Cardinality: 1 file : 1+ connections (a single file can traverse multiple
--              conns in rare cases — cached, multi-channel, fragment reassembly)
-- =============================================================================

SELECT
    f.file.hash.md5         AS md5,
    f.file.hash.sha1        AS sha1,
    f.file.hash.sha256      AS sha256,
    f.file.mime_type        AS mime_type,
    f.file.name             AS filename,
    c.source.ip.value       AS source_ip,
    c.destination.ip.value  AS destination_ip,
    c.network.transport     AS proto,
    c.network.bytes         AS bytes_total,
    c.event.id              AS conn_uid
FROM files f
-- Flatten the conn_uids array so we can join on each uid
CROSS JOIN UNNEST(f.log.id.conn_uids) AS file_conn_uid
JOIN conn c
    ON c.event.id = file_conn_uid
WHERE f.file.hash.md5 = '<HASH_TO_INVESTIGATE>'
;


-- =============================================================================
-- Pattern 2: Credential & Lateral Movement
--
-- Goal: Identify which connections involved an authenticated user, so a raw
--       IP-to-IP relationship becomes a username-attributed flow.
--
-- Join: ntlm.log OR kerberos.log → conn.log on uid
-- Cardinality: 1:1 typical
-- =============================================================================

SELECT
    c.source.ip.value       AS source_ip,
    c.destination.ip.value  AS destination_ip,
    c.network.protocol      AS service,
    c.event.id              AS conn_uid,
    k.kerberos.client       AS kerberos_user,
    k.kerberos.service      AS kerberos_service,
    n.ntlm.username         AS ntlm_user,
    n.ntlm.hostname         AS ntlm_hostname
FROM conn c
LEFT JOIN kerberos k
    ON k.event.id = c.event.id
LEFT JOIN ntlm n
    ON n.event.id = c.event.id
WHERE c.source.ip.value = '<SUSPICIOUS_IP>'
  AND (k.kerberos.client IS NOT NULL OR n.ntlm.username IS NOT NULL)
;


-- =============================================================================
-- Pattern 3: Encrypted Traffic Decoder
--
-- Goal: For an encrypted connection (HTTPS, TLS-wrapped protocol), surface
--       the SNI (server name) so the actual destination is visible. The conn
--       record only shows IPs — joining ssl.log reveals the domain.
--
-- Join: ssl.log → conn.log on uid
-- Cardinality: 1:1 typical (TLS 1.3 session resumption can vary)
-- =============================================================================

SELECT
    c.source.ip.value       AS source_ip,
    c.destination.ip.value  AS destination_ip,
    c.destination.port      AS destination_port,
    s.ssl.server_name       AS sni_domain,
    s.ssl.next_protocol     AS next_protocol,
    s.ssl.cipher            AS cipher_suite,
    s.ssl.version           AS tls_version,
    s.ssl.established       AS handshake_succeeded
FROM conn c
JOIN ssl s
    ON s.event.id = c.event.id
WHERE c.destination.ip.value = '<DESTINATION_TO_INVESTIGATE>'
;


-- =============================================================================
-- Pattern 4: Asset Attribution
--
-- Goal: Map an internal IP to a physical device (MAC + hostname) at the time
--       the connection occurred. Accounts for DHCP churn — an IP can belong
--       to different devices at different times.
--
-- Join: conn.log → dhcp.log on (IP, time window)
-- Cardinality: many:1 (many connections per DHCP lease)
--
-- Critical: without the time anchor, IP reassignment over time will produce
--           wrong attributions.
-- =============================================================================

SELECT
    c.source.ip.value       AS internal_ip,
    d.dhcp.host_name        AS host_name,
    d.dhcp.mac              AS mac,
    d.dhcp.assigned_addr    AS leased_ip,
    d.event.start           AS lease_start,
    d.event.end             AS lease_end,
    c.timestamp             AS conn_time
FROM conn c
JOIN dhcp d
    ON c.source.ip.value = d.dhcp.assigned_addr
    -- Time anchor: ensure the IP was leased to this device at conn time
    AND c.timestamp BETWEEN d.event.start AND d.event.end
WHERE c.source.ip.value = '<INTERNAL_IP_TO_RESOLVE>'
;


-- =============================================================================
-- Pattern 5: Data Exfiltration Hunt (PCR-based)
--
-- Goal: Find connections where outbound bytes massively exceed inbound bytes,
--       a signature of data exfiltration. Uses Producer-Consumer Ratio (PCR),
--       a single metric for asymmetric flows.
--
--   PCR = (orig_bytes - resp_bytes) / (orig_bytes + resp_bytes)
--
--   PCR =  1.0  → pure outbound (exfil candidate)
--   PCR =  0.0  → symmetric (request/response)
--   PCR = -1.0  → pure inbound (download)
--
-- No join required — uses conn.log alone. Combine with DNS / SSL lookups
-- for context once you have candidate IPs.
-- =============================================================================

SELECT
    c.source.ip.value       AS internal_source,
    c.destination.ip.value  AS external_destination,
    c.destination.port      AS destination_port,
    c.source.bytes          AS orig_bytes,
    c.destination.bytes     AS resp_bytes,
    -- PCR calculation, guarding against zero-byte connections
    (c.source.bytes - c.destination.bytes)
        / NULLIF((c.source.bytes + c.destination.bytes), 0) AS pcr_score,
    c.event.id              AS conn_uid,
    c.timestamp             AS conn_time
FROM conn c
WHERE c.source.bytes > 1000000   -- Filter to transfers over 1 MB
  AND c.timestamp BETWEEN '<START_TS>' AND '<END_TS>'
ORDER BY pcr_score DESC
LIMIT 20
;


-- =============================================================================
-- Follow-up for Pattern 5
--
-- Once you have candidate exfil IPs, join to dns.log to see what domains
-- were resolved. Random-looking domains (DGA, beacon) are a red flag.
-- =============================================================================

-- SELECT
--     c.source.ip.value       AS internal_source,
--     d.dns.query             AS resolved_domain,
--     d.dns.qtype_name        AS query_type,
--     d.timestamp             AS query_time
-- FROM conn c
-- JOIN dns d ON d.event.id = c.event.id
-- WHERE c.source.ip.value = '<EXFIL_CANDIDATE_IP>'
--   AND c.timestamp BETWEEN '<START_TS>' AND '<END_TS>'
-- ORDER BY d.timestamp;
