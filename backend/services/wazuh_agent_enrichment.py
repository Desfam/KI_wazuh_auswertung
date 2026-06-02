"""
wazuh_agent_enrichment.py
==========================
Enrich agent context from:
  1. Wazuh Manager API (if configured and reachable)
  2. Cached result (in-memory TTL cache, default 300 s)
  3. Event fields alone (final fallback)

Public API::

    from services.wazuh_agent_enrichment import enrich_agent_context, enrich_agent_contexts

    # Single
    ctx = enrich_agent_context(agent_id="001", agent_name="vm-miniservices")

    # Batch  (list of dicts with any of agent_id / agent_name / agent_ip)
    contexts = enrich_agent_contexts([{"agent_id": "001"}, {"agent_name": "dc01"}])
    # → {"id:001": {...}, "name:dc01": {...}}

Result shape::

    {
      "agent": {id, name, ip, status, version, os, groups, last_keep_alive,
                node_name, manager_name},
      "syscollector": {os/hardware/packages/ports/processes/services/users _available},
      "sca": {available, score, failed_checks, policies},
      "fim": {available, last_scan},
      "rootcheck": {available, last_scan},
      "source":            "manager_api" | "cache" | "event_only",
      "source_reason":     str,
      "cache_age_seconds": int | None,
      "warnings":          list[str],
    }
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

# ─── TTL cache ────────────────────────────────────────────────────────────────

_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, dict[str, Any]] = {}   # key → {"result": …, "cached_at": float}
_CACHE_TTL: int = int(os.environ.get("WAZUH_AGENT_CONTEXT_CACHE_TTL", "300"))


def _cache_get(key: str) -> dict | None:
    """Return cached result if still within TTL, else None."""
    with _CACHE_LOCK:
        entry = _CACHE.get(key)
    if not entry:
        return None
    age = time.time() - entry["cached_at"]
    if age > _CACHE_TTL:
        return None
    result = {**entry["result"]}   # shallow copy
    result["source"] = "cache"
    result["source_reason"] = entry["result"].get("source_reason", "") + " (from cache)"
    result["cache_age_seconds"] = int(age)
    return result


def _cache_set(key: str, result: dict) -> None:
    with _CACHE_LOCK:
        _CACHE[key] = {"result": result, "cached_at": time.time()}


def _cache_primary_key(
    agent_id: str | None,
    agent_name: str | None,
    agent_ip: str | None,
) -> str:
    """Best cache key — prefer id, then normalised name, then ip."""
    if agent_id:
        return f"id:{agent_id}"
    if agent_name:
        return f"name:{_norm_hostname(agent_name)}"
    if agent_ip:
        return f"ip:{agent_ip}"
    return "unknown"


# ─── Hostname normalisation ───────────────────────────────────────────────────

def _norm_hostname(name: str) -> str:
    """Lowercase + strip domain suffix → short hostname."""
    return name.lower().strip().split(".")[0]

# ─── Agent resolution from Manager API ───────────────────────────────────────

def _resolve_agent(
    client: Any,
    agent_id: str | None,
    agent_name: str | None,
    agent_ip: str | None,
    warnings: list[str],
) -> tuple[str | None, str]:
    """
    Returns (resolved_agent_id, source_reason).

    Resolution order:
      1. agent_id exact match (no list needed)
      2. exact agent.name match
      3. normalised short-hostname match
      4. agent.ip match
    """
    if agent_id:
        return agent_id, "Resolved by exact Wazuh agent ID"

    # Fetch full agent list once
    try:
        resp = client.get_agents(
            limit=500,
            fields="id,name,ip,status,version,os.name,os.platform,group,node_name,lastKeepAlive,manager",
        )
        items: list[dict] = resp.get("data", {}).get("affected_items", [])
    except Exception as exc:
        warnings.append(f"Agent list fetch failed: {exc}")
        return None, "Manager API unavailable; agent list could not be retrieved"

    if not items:
        return None, "No agents found on manager"

    # Pass 1 — exact name
    if agent_name:
        exact = [i for i in items if i.get("name", "") == agent_name]
        if len(exact) == 1:
            return str(exact[0]["id"]), f"Resolved by exact agent name '{agent_name}'"
        if len(exact) > 1:
            warnings.append(f"Multiple agents matched exact name '{agent_name}'; using first")
            return str(exact[0]["id"]), f"Resolved by exact agent name '{agent_name}' (multiple matches — first used)"

    # Pass 2 — normalised hostname
    if agent_name:
        norm = _norm_hostname(agent_name)
        matched = [i for i in items if _norm_hostname(i.get("name", "")) == norm]
        if len(matched) == 1:
            return str(matched[0]["id"]), f"Resolved by normalised hostname '{norm}'"
        if len(matched) > 1:
            warnings.append(f"Multiple agents matched hostname '{norm}'")
            return None, f"Multiple agents matched hostname '{norm}'; using event_only fallback"

    # Pass 3 — IP
    if agent_ip:
        ip_matched = [i for i in items if i.get("ip") == agent_ip]
        if len(ip_matched) == 1:
            return str(ip_matched[0]["id"]), f"Resolved by agent IP '{agent_ip}'"
        if len(ip_matched) > 1:
            warnings.append(f"Multiple agents matched IP '{agent_ip}'")
            return None, f"Multiple agents matched IP '{agent_ip}'; using event_only fallback"

    return None, "No matching agent found on manager"


# ─── Main public entry point ──────────────────────────────────────────────────

def enrich_agent_context(
    agent_id: str | None = None,
    agent_name: str | None = None,
    agent_ip: str | None = None,
    conn: Any | None = None,
) -> dict:
    """
    Return a rich agent context dict.
    Falls back gracefully if the Manager API is unavailable or unconfigured.
    Uses TTL cache (WAZUH_AGENT_CONTEXT_CACHE_TTL seconds, default 300).
    """
    cache_key = _cache_primary_key(agent_id, agent_name, agent_ip)

    # ── Cache hit ──────────────────────────────────────────────────────────
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    result: dict[str, Any] = _empty_context()
    warnings: list[str] = []

    # Always populate from event fields (baseline)
    if agent_name:
        result["agent"]["name"] = agent_name
    if agent_id:
        result["agent"]["id"] = agent_id
    if agent_ip:
        result["agent"]["ip"] = agent_ip

    # ── Try Manager API ────────────────────────────────────────────────────
    try:
        from services.wazuh_manager_api import WazuhManagerAPIClient, check_manager_configured

        _conn = conn
        if _conn is None:
            from db.database import get_active_connection
            _conn = get_active_connection()
        if _conn is None:
            result["source"] = "event_only"
            result["source_reason"] = "No active connection; using event fields only"
            result["warnings"] = warnings
            return result

        check = check_manager_configured(_conn)
        if not check["configured"]:
            result["source"] = "event_only"
            result["source_reason"] = f"Manager API not configured: {check['reason']}"
            result["warnings"] = warnings
            _cache_set(cache_key, result)
            return result

        client = WazuhManagerAPIClient.from_connection(_conn)
        resolved_id, source_reason = _resolve_agent(client, agent_id, agent_name, agent_ip, warnings)

        _enrich_from_api(client, result, resolved_id, warnings)
        result["source"] = "manager_api"
        result["source_reason"] = source_reason

    except Exception as exc:
        warnings.append(f"Manager API unavailable: {exc}")
        result["source"] = "event_only"
        result["source_reason"] = "Manager API unavailable; using event fields only"

    result["warnings"] = warnings
    result["cache_age_seconds"] = None
    _cache_set(cache_key, result)
    return result


# ─── Batch helper ─────────────────────────────────────────────────────────────

def enrich_agent_contexts(
    agents: list[dict[str, str | None]],
    conn: Any | None = None,
) -> dict[str, dict]:
    """
    Batch-enrich a list of agent descriptors.

    Each dict may have keys: agent_id, agent_name, agent_ip.
    Returns mapping keyed by _cache_primary_key (e.g. "id:001" / "name:dc01").
    Deduplicates — fetches each unique key exactly once.
    """
    out: dict[str, dict] = {}
    seen: set[str] = set()

    for ag in agents:
        aid  = ag.get("agent_id") or None
        name = ag.get("agent_name") or None
        ip   = ag.get("agent_ip") or None
        key  = _cache_primary_key(aid, name, ip)
        if key in seen or key == "unknown":
            continue
        seen.add(key)
        out[key] = enrich_agent_context(agent_id=aid, agent_name=name, agent_ip=ip, conn=conn)

    return out


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _enrich_from_api(
    client: Any,
    result: dict,
    resolved_id: str | None,
    warnings: list[str],
) -> None:
    if not resolved_id:
        warnings.append("Could not resolve agent ID — syscollector/SCA/FIM not fetched")
        return

    # ── Basic agent info ───────────────────────────────────────────────────
    try:
        r = client.get_agent(resolved_id)
        item = r.get("data", {}).get("affected_items", [{}])[0]
        result["agent"].update({
            "id":              str(item.get("id", resolved_id)),
            "name":            item.get("name"),
            "ip":              item.get("ip"),
            "status":          item.get("status"),
            "version":         item.get("version"),
            "os":              item.get("os"),
            "groups":          item.get("group", []),
            "last_keep_alive": item.get("lastKeepAlive"),
            "node_name":       item.get("node_name"),
            "manager_name":    item.get("manager"),
        })
    except Exception as exc:
        warnings.append(f"Agent info: {exc}")

    # ── Syscollector availability probe ────────────────────────────────────
    sc = result["syscollector"]
    for key, method_name in (
        ("os_available",        "get_syscollector_os"),
        ("hardware_available",  "get_syscollector_hardware"),
        ("packages_available",  "get_syscollector_packages"),
        ("ports_available",     "get_syscollector_ports"),
        ("processes_available", "get_syscollector_processes"),
        ("services_available",  "get_syscollector_services"),
        ("users_available",     "get_syscollector_users"),
    ):
        try:
            method = getattr(client, method_name)
            r = method(resolved_id)
            items = r.get("data", {}).get("affected_items", [])
            sc[key] = len(items) > 0
        except Exception:
            sc[key] = False

    # ── SCA ────────────────────────────────────────────────────────────────
    try:
        r = client.get_sca_results(resolved_id)
        items = r.get("data", {}).get("affected_items", [])
        if items:
            result["sca"]["available"]     = True
            result["sca"]["policies"]      = items
            first = items[0]
            result["sca"]["score"]         = first.get("score")
            result["sca"]["failed_checks"] = first.get("fail")
    except Exception as exc:
        warnings.append(f"SCA: {exc}")

    # ── FIM / syscheck ─────────────────────────────────────────────────────
    try:
        r = client.get_syscheck_last_scan(resolved_id)
        items = r.get("data", {}).get("affected_items", [])
        if items:
            result["fim"]["available"] = True
            result["fim"]["last_scan"] = items[0].get("end") or items[0].get("start")
    except Exception as exc:
        warnings.append(f"FIM: {exc}")

    # ── Rootcheck ──────────────────────────────────────────────────────────
    try:
        r = client.get_rootcheck_last_scan(resolved_id)
        items = r.get("data", {}).get("affected_items", [])
        if items:
            result["rootcheck"]["available"] = True
            result["rootcheck"]["last_scan"] = items[0].get("end") or items[0].get("start")
    except Exception as exc:
        warnings.append(f"Rootcheck: {exc}")


def _empty_context() -> dict:
    return {
        "agent": {
            "id":              None,
            "name":            None,
            "ip":              None,
            "status":          None,
            "version":         None,
            "os":              None,
            "groups":          [],
            "last_keep_alive": None,
            "node_name":       None,
            "manager_name":    None,
        },
        "syscollector": {
            "os_available":        False,
            "hardware_available":  False,
            "packages_available":  False,
            "ports_available":     False,
            "processes_available": False,
            "services_available":  False,
            "users_available":     False,
        },
        "sca": {
            "available":     False,
            "score":         None,
            "failed_checks": None,
            "policies":      [],
        },
        "fim": {
            "available":  False,
            "last_scan":  None,
        },
        "rootcheck": {
            "available":  False,
            "last_scan":  None,
        },
        "source":             "event_only",
        "source_reason":      "Not yet enriched",
        "cache_age_seconds":  None,
        "warnings":           [],
    }
