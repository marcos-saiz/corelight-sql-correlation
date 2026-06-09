"""
Helpers for parsing Corelight JSON records.

Corelight ships logs as JSON. Downstream pipelines often normalize the
schema, so a single field can appear in different places depending on
where you're reading from. This module provides safe accessors that try
common locations.

The patterns here cover:
  - Native Zeek (flat with dotted names: "id.orig_h")
  - ECS-aligned (nested objects: source.ip)
  - Wrapped-with-metadata (source.ip.value, with _acp sidecar)
"""

from __future__ import annotations

from typing import Any, Iterable


def get_nested(record: dict, *paths: str, default: Any = None) -> Any:
    """
    Try multiple dotted paths in order; return the first match.

    Each `paths` argument is a dotted string like "source.ip.value".
    Useful when the same logical field appears at different locations
    in different schema flavors.

    Example:
        >>> rec = {"source": {"ip": {"value": "10.0.0.1"}}}
        >>> get_nested(rec, "source.ip.value", "id.orig_h")
        '10.0.0.1'
    """
    for path in paths:
        value = _walk(record, path)
        if value is not None:
            return value
    return default


def _walk(record: dict, dotted_path: str) -> Any:
    """Walk a dotted path through nested dicts. Returns None on miss."""
    parts = dotted_path.split(".")
    current: Any = record
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


# -----------------------------------------------------------------------------
# Field accessors — try multiple locations for each conceptual field
# -----------------------------------------------------------------------------


def get_uid(record: dict) -> str | None:
    """Connection UID. Native Zeek calls it 'uid'; normalized schemas use 'event.id'."""
    return get_nested(record, "event.id", "uid")


def get_timestamp(record: dict) -> str | None:
    """Event timestamp."""
    return get_nested(record, "timestamp", "@timestamp", "ts", "_timestamp")


def get_source_ip(record: dict) -> str | None:
    """Source / originator IP."""
    return get_nested(
        record,
        "source.ip.value",   # Wrapped with metadata sidecar
        "source.ip",          # ECS
        "id.orig_h",          # Native Zeek
    )


def get_destination_ip(record: dict) -> str | None:
    """Destination / responder IP."""
    return get_nested(
        record,
        "destination.ip.value",
        "destination.ip",
        "id.resp_h",
    )


def get_source_mac(record: dict) -> str | None:
    """Source MAC."""
    return get_nested(
        record,
        "source.mac.value",
        "source.mac",
        "orig_l2_addr",
    )


def get_destination_mac(record: dict) -> str | None:
    """Destination MAC (often the gateway for cross-subnet traffic)."""
    return get_nested(
        record,
        "destination.mac.value",
        "destination.mac",
        "resp_l2_addr",
    )


def get_asset_mac(record: dict) -> str | None:
    """MAC field on known_devices.log."""
    return get_nested(
        record,
        "asset.mac.value",
        "asset.mac",
    )


def get_asset_vendor(record: dict) -> str | None:
    """Vendor field on known_devices.log."""
    return get_nested(
        record,
        "asset.vendor.value",
        "asset.vendor",
    )


def get_asset_oui(record: dict) -> str | None:
    """OUI field on known_devices.log."""
    return get_nested(
        record,
        "asset.oui",
    )


def get_host_ip(record: dict) -> str | None:
    """Host IP — typically the asset's IP in known_devices records."""
    return get_nested(
        record,
        "host.ip.value",
        "host.ip",
    )


def get_vlan_id(record: dict) -> str | None:
    """VLAN ID."""
    return get_nested(
        record,
        "network.vlan.id",
        "vlan",
    )


def get_community_id(record: dict) -> str | None:
    """community_id (cross-tool 5-tuple hash)."""
    return get_nested(
        record,
        "community_id",
        "network.community_id",
    )


# -----------------------------------------------------------------------------
# Higher-level helpers
# -----------------------------------------------------------------------------


def is_locally_administered_mac(mac: str | None) -> bool | None:
    """
    Check whether a MAC address is locally administered (manually assigned)
    rather than vendor-burned-in. Useful for distinguishing router / firewall
    / virtual MACs from actual hardware.

    Returns True / False / None (for invalid input).

    The U/L bit is the second-least-significant bit of the first octet.
    """
    if not mac:
        return None
    try:
        first_octet = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return None
    # Bit 1 (0-indexed) of the first octet is the U/L bit.
    # If set: locally administered.
    return bool(first_octet & 0b00000010)


def extract_asset_summary(record: dict) -> dict:
    """
    Pull the standard asset fields from a known_devices.log record into a
    flat dict. Convenient for the enrichment pipeline.
    """
    return {
        "mac":        get_asset_mac(record),
        "oui":        get_asset_oui(record),
        "vendor_raw": get_asset_vendor(record),
        "ip":         get_host_ip(record),
        "vlan":       get_vlan_id(record),
        "timestamp":  get_timestamp(record),
        "locally_administered_mac":
            is_locally_administered_mac(get_asset_mac(record)),
    }


def asset_records_from_lines(lines: Iterable[str]) -> Iterable[dict]:
    """
    Yield parsed asset records from an iterable of JSON-line strings.
    Skips empty / malformed lines.
    """
    import json
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        yield extract_asset_summary(record)
