"""
wazuh_api_permissions.py
========================
Run a safe, read-only permission probe against the Wazuh Manager API.

Tests each relevant endpoint with a real authenticated call and reports
whether the API user (wazuh-wui) has the required RBAC permissions.

Never calls destructive or write endpoints.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any


PERMISSION_PROBES = [
    {
        "key": "manager_info",
        "label": "Manager info",
        "method": "GET",
        "path": "/manager/info",
        "required_for": ["Health check", "Connection card"],
        "impact_if_missing": "Manager version unavailable",
    },
    {
        "key": "agents_read",
        "label": "Agent inventory",
        "method": "GET",
        "path": "/agents",
        "params": {"limit": 1, "select": "id,name"},
        "required_for": ["Agent table", "Event Map Agent Context", "WazuhAgentDetailDrawer"],
        "impact_if_missing": "Agent list and details unavailable",
    },
    {
        "key": "agents_summary",
        "label": "Agent status summary",
        "method": "GET",
        "path": "/agents/summary/status",
        "required_for": ["Dashboard agent counts", "Health card"],
        "impact_if_missing": "Active/disconnected agent counts unavailable",
    },
    {
        "key": "rules_read",
        "label": "Rules",
        "method": "GET",
        "path": "/rules",
        "params": {"limit": 1},
        "required_for": ["Capability matrix"],
        "impact_if_missing": "Rule browsing unavailable",
    },
    {
        "key": "decoders_read",
        "label": "Decoders",
        "method": "GET",
        "path": "/decoders",
        "params": {"limit": 1},
        "required_for": ["Capability matrix"],
        "impact_if_missing": "Decoder browsing unavailable",
    },
    {
        "key": "mitre_read",
        "label": "MITRE techniques",
        "method": "GET",
        "path": "/mitre/techniques",
        "params": {"limit": 1},
        "required_for": ["Event enrichment", "MITRE tagging"],
        "impact_if_missing": "MITRE ATT&CK data unavailable",
    },
]

CONTROLLED_ACTION_PROBES = [
    {
        "key": "reconnect_single_agent",
        "label": "Reconnect single agent",
        "endpoint": "PUT /agents/reconnect",
        "safety": "controlled_action",
        "mass_action_allowed": False,
        # We verify permission by probing GET /agents — if the user can read agents, they likely
        # have the reconnect permission. A direct reconnect probe would modify state; instead we
        # report permission as "unknown" and rely on RBAC enforcement at execution time.
        "verify_via": "probe_read_agents",
        "required_for": ["WazuhAgentDetailDrawer Reconnect button", "Event Map Reconnect button"],
        "impact_if_missing": "Reconnect action will be denied by Wazuh RBAC",
    },
]

AGENT_PROBES = [
    {
        "key": "syscollector_os",
        "label": "Syscollector OS",
        "method": "GET",
        "path_template": "/syscollector/{agent_id}/os",
        "required_for": ["WazuhAgentDetailDrawer Syscollector tab"],
        "impact_if_missing": "OS inventory unavailable",
    },
    {
        "key": "syscollector_packages",
        "label": "Syscollector packages",
        "method": "GET",
        "path_template": "/syscollector/{agent_id}/packages",
        "params": {"limit": 1},
        "required_for": ["WazuhAgentDetailDrawer Syscollector tab"],
        "impact_if_missing": "Package inventory unavailable",
    },
    {
        "key": "sca_read",
        "label": "SCA policies",
        "method": "GET",
        "path_template": "/sca/{agent_id}",
        "required_for": ["WazuhAgentDetailDrawer SCA tab"],
        "impact_if_missing": "Security Configuration Assessment unavailable",
    },
    {
        "key": "syscheck_read",
        "label": "FIM / Syscheck",
        "method": "GET",
        "path_template": "/syscheck/{agent_id}",
        "params": {"limit": 1},
        "required_for": ["WazuhAgentDetailDrawer FIM tab"],
        "impact_if_missing": "File Integrity Monitoring data unavailable",
    },
    {
        "key": "rootcheck_read",
        "label": "Rootcheck",
        "method": "GET",
        "path_template": "/rootcheck/{agent_id}",
        "params": {"limit": 1},
        "required_for": ["WazuhAgentDetailDrawer Rootcheck tab"],
        "impact_if_missing": "Rootcheck scan results unavailable",
    },
]


def check_wazuh_api_permissions() -> dict:
    """
    Run all permission probes and return a structured result.

    Returns:
    {
        "checked_at": ISO timestamp,
        "overall": "ok" | "warning" | "error",
        "sample_agent_id": str | None,
        "permissions": [...],
        "warnings": [...]
    }
    """
    from services.wazuh_manager_api import get_manager_client
    from db.database import get_active_connection

    results: list[dict] = []
    warnings: list[str] = []

    # Ensure client is available
    try:
        conn = get_active_connection()
        client = get_manager_client()
    except Exception as exc:
        return {
            "checked_at": _now(),
            "overall": "error",
            "sample_agent_id": None,
            "permissions": [],
            "warnings": [f"Cannot build API client: {exc}"],
        }

    # ── non-agent probes ──────────────────────────────────────────────────────
    for probe in PERMISSION_PROBES:
        result = _probe(client, probe["method"], probe["path"],
                        probe.get("params"))
        results.append({
            "key": probe["key"],
            "label": probe["label"],
            "endpoint": f"{probe['method']} {probe['path']}",
            "status": result["status"],
            "http_status": result.get("http_status"),
            "message": result["message"],
            "required_for": probe["required_for"],
            "impact_if_missing": probe["impact_if_missing"],
        })

    # ── find a sample active agent for per-agent probes ───────────────────────
    sample_agent_id: str | None = None
    try:
        r = client.request("GET", "/agents",
                           params={"limit": 1, "status": "active", "select": "id"})
        items = (r.get("data") or {}).get("affected_items") or []
        if items:
            sample_agent_id = items[0].get("id")
    except Exception:
        pass

    if sample_agent_id is None:
        warnings.append("No active agent found — per-agent permission probes skipped")

    # ── per-agent probes ──────────────────────────────────────────────────────
    for probe in AGENT_PROBES:
        if sample_agent_id is None:
            results.append({
                "key": probe["key"],
                "label": probe["label"],
                "endpoint": probe["path_template"].replace("{agent_id}", "<agent>"),
                "status": "skipped",
                "http_status": None,
                "message": "No active agent available for probe",
                "required_for": probe["required_for"],
                "impact_if_missing": probe["impact_if_missing"],
            })
            continue

        path = probe["path_template"].replace("{agent_id}", sample_agent_id)
        result = _probe(client, probe["method"], path, probe.get("params"))
        results.append({
            "key": probe["key"],
            "label": probe["label"],
            "endpoint": f"{probe['method']} {probe['path_template']}",
            "status": result["status"],
            "http_status": result.get("http_status"),
            "message": result["message"],
            "required_for": probe["required_for"],
            "impact_if_missing": probe["impact_if_missing"],
        })

    # ── overall status ────────────────────────────────────────────────────────
    statuses = {r["status"] for r in results}
    if "error" in statuses or "denied" in statuses:
        overall = "error"
    elif "skipped" in statuses or "unavailable" in statuses:
        overall = "warning"
    else:
        overall = "ok"

    # ── controlled action probes (static — no live write call made) ───────────
    agents_read_status = next(
        (r["status"] for r in results if r["key"] == "agents_read"), None
    )
    controlled_actions: list[dict] = []
    for cap in CONTROLLED_ACTION_PROBES:
        if agents_read_status == "ok":
            # If we can read agents, the user is authenticated; Wazuh RBAC will
            # enforce the actual write permission at execution time.
            ca_status = "unknown"
            ca_message = "Permission will be verified when action is executed."
        elif agents_read_status in ("denied", "error"):
            ca_status = "denied"
            ca_message = f"Agent read access denied — {cap['label']} likely blocked by RBAC"
        else:
            ca_status = "unavailable"
            ca_message = "Cannot verify — Manager API unavailable or no active agent"
        controlled_actions.append({
            "key": cap["key"],
            "label": cap["label"],
            "endpoint": cap["endpoint"],
            "safety": cap["safety"],
            "mass_action_allowed": cap["mass_action_allowed"],
            "status": ca_status,
            "message": ca_message,
            "required_for": cap["required_for"],
            "impact_if_missing": cap["impact_if_missing"],
        })

    return {
        "checked_at": _now(),
        "overall": overall,
        "sample_agent_id": sample_agent_id,
        "permissions": results,
        "controlled_actions": controlled_actions,
        "warnings": warnings,
    }


# ── helpers ───────────────────────────────────────────────────────────────────

def _probe(client: Any, method: str, path: str, params: dict | None = None) -> dict:
    """Run a single probe call and classify the result."""
    try:
        client.request(method, path, params=params)
        return {"status": "ok", "message": "OK", "http_status": 200}
    except Exception as exc:
        msg = str(exc)
        # Extract HTTP status from httpx error messages
        http_status: int | None = None
        for code in (400, 401, 403, 404, 405, 429, 500, 502, 503):
            if str(code) in msg:
                http_status = code
                break

        if http_status == 401:
            return {"status": "denied", "message": "Unauthorized (401) — token invalid", "http_status": 401}
        if http_status == 403:
            return {"status": "denied", "message": "Permission denied (403) — RBAC policy blocks this", "http_status": 403}
        if http_status == 404:
            return {"status": "unavailable", "message": "Endpoint not found (404)", "http_status": 404}
        if http_status in (502, 503):
            return {"status": "unavailable", "message": f"Manager API error ({http_status})", "http_status": http_status}

        return {"status": "error", "message": msg[:200], "http_status": http_status}


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()
