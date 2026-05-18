"""Tactical sync service: pull agents from Tactical RMM, normalise, and cache in SQLite."""
from __future__ import annotations

import json
import logging
from typing import Any

from db.database import (
    clear_tactical_agents,
    list_tactical_agents,
    upsert_tactical_agent,
    utc_now_iso,
)
from services.tactical_client import (
    TacticalError,
    get_agents,
    get_clients,
    get_sites,
)

logger = logging.getLogger(__name__)


def _normalise_ips(raw: Any) -> str | None:
    """Normalise IP data from Tactical (may be list, string, or None)."""
    if isinstance(raw, list):
        return ",".join(str(x) for x in raw if x)
    if isinstance(raw, str):
        return raw.strip() or None
    return None


def _normalise_agent(raw: dict[str, Any], clients: dict[str, str], sites: dict[str, str]) -> dict[str, Any]:
    """Map a raw Tactical agent dict to our cache schema."""
    agent_id = str(raw.get("agent_id") or raw.get("id") or raw.get("agentid") or "")
    hostname = str(raw.get("hostname") or raw.get("computername") or "unknown")

    # FQDN: try multiple field names
    fqdn = (
        raw.get("fqdn")
        or raw.get("dns_name")
        or raw.get("full_hostname")
        or None
    )

    # OS
    os_platform = raw.get("plat") or raw.get("platform") or raw.get("os_platform") or None
    os_full = raw.get("operating_system") or raw.get("os") or raw.get("os_full") or None

    # IPs
    local_ips = _normalise_ips(raw.get("local_ips") or raw.get("ip_addresses") or raw.get("ips"))
    public_ip = raw.get("public_ip") or raw.get("external_ip") or None

    # Last check-in
    last_checkin = (
        raw.get("last_seen")
        or raw.get("last_checkin")
        or raw.get("lastSeen")
        or None
    )

    # Status: online/offline/overdue
    status = raw.get("status") or ("online" if raw.get("is_online") else "offline")

    # User
    logged_user = raw.get("logged_username") or raw.get("logged_user") or None

    # Mesh
    mesh_node_id = raw.get("mesh_node_id") or raw.get("meshNodeId") or None

    # Client / Site names — look up by ID if available
    client_id = str(raw.get("client") or raw.get("client_id") or "")
    site_id = str(raw.get("site") or raw.get("site_id") or "")
    client_name = raw.get("client_name") or clients.get(client_id) or client_id or None
    site_name = raw.get("site_name") or sites.get(site_id) or site_id or None

    # Checks
    checks_failing = int(raw.get("checks_failing") or raw.get("failing_checks") or 0)
    needs_reboot = int(bool(raw.get("needs_reboot") or raw.get("pendingReboot")))

    return {
        "tactical_agent_id": agent_id,
        "hostname": hostname,
        "fqdn": fqdn,
        "description": raw.get("description"),
        "client_name": client_name,
        "site_name": site_name,
        "os_platform": os_platform,
        "os_full": os_full,
        "local_ips": local_ips,
        "public_ip": public_ip,
        "last_checkin": last_checkin,
        "status": status,
        "agent_version": raw.get("version") or raw.get("agent_version") or None,
        "logged_user": logged_user,
        "mesh_node_id": mesh_node_id,
        "checks_failing": checks_failing,
        "needs_reboot": needs_reboot,
        "raw_json": json.dumps(raw, default=str),
    }


def sync_tactical_agents() -> dict[str, Any]:
    """Pull all agents from Tactical RMM and update the local cache.

    Returns a summary dict with counts and any error messages.
    """
    result: dict[str, Any] = {
        "success": False,
        "agents_pulled": 0,
        "agents_cached": 0,
        "errors": [],
        "synced_at": utc_now_iso(),
    }

    # Build lookup maps for clients / sites (best-effort, ignore errors)
    clients: dict[str, str] = {}
    sites: dict[str, str] = {}
    try:
        for c in get_clients():
            cid = str(c.get("id") or "")
            if cid:
                clients[cid] = c.get("name") or cid
    except Exception:  # noqa: BLE001
        pass
    try:
        for s in get_sites():
            sid = str(s.get("id") or "")
            if sid:
                sites[sid] = s.get("name") or sid
    except Exception:  # noqa: BLE001
        pass

    # Pull agents
    try:
        raw_agents = get_agents()
    except TacticalError as exc:
        result["errors"].append(str(exc))
        return result

    result["agents_pulled"] = len(raw_agents)

    # Clear stale data and re-populate
    clear_tactical_agents()
    cached = 0
    for raw in raw_agents:
        try:
            normalised = _normalise_agent(raw, clients, sites)
            if normalised["tactical_agent_id"]:
                upsert_tactical_agent(normalised)
                cached += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to cache tactical agent: %s", exc)
            result["errors"].append(str(exc))

    result["agents_cached"] = cached
    result["success"] = True
    return result


def get_cached_agents() -> list[dict[str, Any]]:
    return list_tactical_agents()
