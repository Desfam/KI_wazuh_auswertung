"""
routes_wazuh_manager.py
========================
Read-only Wazuh Manager REST API proxy.

All write/destructive endpoints remain intentionally unimplemented.
They are visible in GET /wazuh-manager/capabilities (classified as
controlled_action / dangerous) but cannot be called through this router.

Register in main.py:
    from api.routes_wazuh_manager import router as wazuh_manager_router
    app.include_router(wazuh_manager_router)
"""
from __future__ import annotations

import traceback
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter(prefix="/wazuh-manager", tags=["wazuh-manager"])


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_client():
    """Build a WazuhManagerAPIClient from the active connection, or raise 503."""
    try:
        from services.wazuh_manager_api import get_manager_client
        return get_manager_client()
    except ValueError as exc:
        raise HTTPException(status_code=503,
                            detail=f"Wazuh Manager API not configured: {exc}")


def _api_call(fn: Any, *args, **kwargs) -> dict:
    """Execute a client call and wrap errors as HTTP 502."""
    try:
        return fn(*args, **kwargs)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502,
                            detail=f"Wazuh Manager API error: {exc}")


# ── health / configuration check ─────────────────────────────────────────────

@router.get("/health")
def manager_health() -> dict:
    """
    Aggregate health: reachability + auth + manager info + agent summary.
    Returns structured result even on partial failure (never raises 5xx).
    """
    from services.wazuh_manager_api import check_manager_configured, WazuhManagerAPIClient
    from db.database import get_active_connection

    conn = get_active_connection()
    check = check_manager_configured(conn)
    if not check["configured"]:
        return {
            "configured": False,
            "reachable": False,
            "authenticated": False,
            "message": check["reason"],
        }

    try:
        client = WazuhManagerAPIClient.from_connection(conn)
        return client.health()
    except Exception as exc:
        return {
            "configured": True,
            "reachable": False,
            "authenticated": False,
            "message": str(exc),
        }


# ── step-by-step connectivity ping ───────────────────────────────────────────

@router.get("/ping")
def manager_ping() -> dict:
    """
    Four-step connectivity test: DNS → TCP → HTTP (no auth) → Authenticated.
    Returns a list of steps, each with: step, ok, detail, duration_ms.
    Never raises 5xx — always returns 200 with step results.
    """
    import socket
    import time
    import httpx
    from services.wazuh_manager_api import check_manager_configured, WazuhManagerAPIClient
    from db.database import get_active_connection

    conn = get_active_connection()
    check = check_manager_configured(conn)

    steps: list[dict] = []

    if not check["configured"]:
        return {
            "configured": False,
            "steps": [{"step": "config", "ok": False, "detail": check.get("reason", "Not configured"), "duration_ms": 0}],
        }

    # Derive host / port from the configured URL
    try:
        from services.wazuh_manager_api import _build_manager_base_url, _conn_attr, _build_verify
        base_url = _build_manager_base_url(conn)
        import urllib.parse as _up
        parsed = _up.urlparse(base_url)
        host = parsed.hostname or ""
        port = parsed.port or 55000
        username = _conn_attr(conn, "manager_username") or ""
        password = _conn_attr(conn, "manager_password") or ""
        verify   = _build_verify(conn)
    except Exception as exc:
        return {"configured": True, "steps": [{"step": "config", "ok": False, "detail": str(exc), "duration_ms": 0}]}

    # Step 1 — DNS resolution
    t0 = time.monotonic()
    try:
        addrs = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        resolved_ip = addrs[0][4][0] if addrs else "?"
        steps.append({"step": "dns", "ok": True, "detail": f"{host} → {resolved_ip}", "duration_ms": round((time.monotonic() - t0) * 1000)})
    except Exception as exc:
        steps.append({"step": "dns", "ok": False, "detail": str(exc), "duration_ms": round((time.monotonic() - t0) * 1000)})
        return {"configured": True, "steps": steps}

    # Step 2 — TCP connect
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
        steps.append({"step": "tcp", "ok": True, "detail": f"TCP {host}:{port} open", "duration_ms": round((time.monotonic() - t0) * 1000)})
    except Exception as exc:
        steps.append({"step": "tcp", "ok": False, "detail": str(exc), "duration_ms": round((time.monotonic() - t0) * 1000)})
        return {"configured": True, "steps": steps}

    # Step 3 — HTTP (no auth) root endpoint
    t0 = time.monotonic()
    try:
        with httpx.Client(verify=verify, timeout=8) as client:
            resp = client.get(base_url + "/", headers={"Content-Type": "application/json"})
        status = resp.status_code
        if status in (200, 401):
            steps.append({"step": "http", "ok": True, "detail": f"HTTP {status} from {base_url}/", "duration_ms": round((time.monotonic() - t0) * 1000)})
        else:
            steps.append({"step": "http", "ok": False, "detail": f"Unexpected HTTP {status}", "duration_ms": round((time.monotonic() - t0) * 1000)})
            return {"configured": True, "steps": steps}
    except Exception as exc:
        steps.append({"step": "http", "ok": False, "detail": str(exc), "duration_ms": round((time.monotonic() - t0) * 1000)})
        return {"configured": True, "steps": steps}

    # Step 4 — Authenticated API call
    t0 = time.monotonic()
    try:
        client_obj = WazuhManagerAPIClient(
            base_url=base_url, username=username, password=password, verify_tls=verify, timeout=10
        )
        info = client_obj.request("GET", "/")
        api_ver = (info.get("data") or {}).get("api_version", "?")
        steps.append({"step": "auth", "ok": True, "detail": f"Authenticated — API v{api_ver}", "duration_ms": round((time.monotonic() - t0) * 1000)})
    except Exception as exc:
        steps.append({"step": "auth", "ok": False, "detail": str(exc), "duration_ms": round((time.monotonic() - t0) * 1000)})

    return {"configured": True, "steps": steps}


# ── capabilities (OpenAPI spec) ───────────────────────────────────────────────

@router.get("/capabilities")
def capabilities(
    safety: str | None = Query(default=None,
        description="Filter by safety: read_only, safe_test, controlled_action, dangerous"),
    tag: str | None = Query(default=None,
        description="Filter by OpenAPI tag, e.g. Agents, Syscollector"),
) -> dict:
    """
    Return all Wazuh API endpoints from the OpenAPI spec with safety
    classification and implementation status.
    """
    from services.wazuh_api_capabilities import (
        get_cached_capabilities,
        get_cached_summary,
        get_spec_status,
    )
    caps = get_cached_capabilities()

    if safety:
        caps = [c for c in caps if c.get("safety") == safety]
    if tag:
        caps = [c for c in caps if c.get("tag", "").lower() == tag.lower()]

    spec = get_spec_status()
    return {
        "summary": get_cached_summary(),
        "spec_loaded": spec["loaded"],
        "spec_search_paths": spec["search_paths"],
        "capabilities": caps,
    }


# ── agents ────────────────────────────────────────────────────────────────────

@router.get("/agents")
def agents(
    limit: int = Query(default=500, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    status: str | None = Query(default=None),
    os_platform: str | None = Query(default=None),
    group: str | None = Query(default=None),
    name_contains: str | None = Query(default=None),
    search: str | None = Query(default=None),
    q: str | None = Query(default=None, description="Raw WQL expression (overrides other filters)"),
) -> dict:
    """
    List agents. Supports WQL filtering via q= (raw) or via convenience params
    (status, os_platform, group, name_contains) that are combined with AND.
    """
    from services.wazuh_wql import build_wql, validate_wql

    # If q was not provided explicitly, build it from convenience params
    if not q:
        wql_filters: dict = {}
        if status:
            wql_filters["status"] = status
        if os_platform:
            wql_filters["os_platform"] = os_platform
        if group:
            wql_filters["group"] = group
        if name_contains:
            wql_filters["name_contains"] = name_contains
        q = build_wql(wql_filters) or None

    if q:
        valid, msg = validate_wql(q)
        if not valid:
            raise HTTPException(status_code=400, detail=f"Invalid WQL: {msg}")

    client = _get_client()
    return _api_call(
        client.get_agents,
        limit=limit,
        offset=offset,
        status=status if not q else None,  # avoid double-filtering if q covers status
        search=search,
        q=q,
    )


@router.get("/agents/summary")
def agents_summary() -> dict:
    client = _get_client()
    status_summary = _api_call(client.get_agent_summary_status)
    os_summary     = _api_call(client.get_agent_summary_os)
    return {"status": status_summary, "os": os_summary}


@router.get("/agents/{agent_id}")
def agent_detail(agent_id: str) -> dict:
    client = _get_client()
    return _api_call(client.get_agent, agent_id)


@router.get("/agents/{agent_id}/config/{component}/{configuration}")
def agent_config(agent_id: str, component: str, configuration: str) -> dict:
    client = _get_client()
    return _api_call(
        client.request, "GET",
        f"/agents/{agent_id}/config/{component}/{configuration}"
    )


# ── syscollector ──────────────────────────────────────────────────────────────

@router.get("/agents/{agent_id}/syscollector/os")
def syscollector_os(agent_id: str) -> dict:
    return _api_call(_get_client().get_syscollector_os, agent_id)


@router.get("/agents/{agent_id}/syscollector/hardware")
def syscollector_hardware(agent_id: str) -> dict:
    return _api_call(_get_client().get_syscollector_hardware, agent_id)


@router.get("/agents/{agent_id}/syscollector/packages")
def syscollector_packages(
    agent_id: str,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    return _api_call(_get_client().get_syscollector_packages, agent_id, limit=limit)


@router.get("/agents/{agent_id}/syscollector/ports")
def syscollector_ports(
    agent_id: str,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    return _api_call(_get_client().get_syscollector_ports, agent_id, limit=limit)


@router.get("/agents/{agent_id}/syscollector/processes")
def syscollector_processes(
    agent_id: str,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    return _api_call(_get_client().get_syscollector_processes, agent_id, limit=limit)


@router.get("/agents/{agent_id}/syscollector/services")
def syscollector_services(
    agent_id: str,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    return _api_call(_get_client().get_syscollector_services, agent_id, limit=limit)


@router.get("/agents/{agent_id}/syscollector/users")
def syscollector_users(agent_id: str) -> dict:
    return _api_call(_get_client().get_syscollector_users, agent_id)


@router.get("/agents/{agent_id}/syscollector/groups")
def syscollector_groups(agent_id: str) -> dict:
    return _api_call(_get_client().get_syscollector_groups, agent_id)


# ── syscheck (FIM) ────────────────────────────────────────────────────────────

@router.get("/agents/{agent_id}/syscheck")
def syscheck_results(
    agent_id: str,
    limit: int = Query(default=50, ge=1, le=500),
) -> dict:
    return _api_call(_get_client().get_syscheck_results, agent_id, limit=limit)


@router.get("/agents/{agent_id}/syscheck/last-scan")
def syscheck_last_scan(agent_id: str) -> dict:
    return _api_call(_get_client().get_syscheck_last_scan, agent_id)


# ── SCA ───────────────────────────────────────────────────────────────────────

@router.get("/agents/{agent_id}/sca")
def sca_results(agent_id: str) -> dict:
    return _api_call(_get_client().get_sca_results, agent_id)


@router.get("/agents/{agent_id}/sca/{policy_id}/checks")
def sca_checks(
    agent_id: str,
    policy_id: str,
    limit: int = Query(default=50, ge=1, le=500),
) -> dict:
    return _api_call(_get_client().get_sca_checks, agent_id, policy_id, limit=limit)


# ── rootcheck ─────────────────────────────────────────────────────────────────

@router.get("/agents/{agent_id}/rootcheck")
def rootcheck_results(
    agent_id: str,
    limit: int = Query(default=50, ge=1, le=500),
) -> dict:
    return _api_call(_get_client().get_rootcheck_results, agent_id, limit=limit)


@router.get("/agents/{agent_id}/rootcheck/last-scan")
def rootcheck_last_scan(agent_id: str) -> dict:
    return _api_call(_get_client().get_rootcheck_last_scan, agent_id)


# ── rules / decoders / MITRE ─────────────────────────────────────────────────

@router.get("/rules")
def rules(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    return _api_call(_get_client().get_rules, limit=limit, offset=offset)


@router.get("/decoders")
def decoders(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    return _api_call(_get_client().get_decoders, limit=limit, offset=offset)


@router.get("/mitre/techniques")
def mitre_techniques(limit: int = Query(default=300, ge=1, le=1000)) -> dict:
    return _api_call(_get_client().get_mitre_techniques, limit=limit)


@router.get("/mitre/tactics")
def mitre_tactics(limit: int = Query(default=100, ge=1, le=500)) -> dict:
    return _api_call(_get_client().get_mitre_tactics, limit=limit)


# ── logtest (safe POST) ───────────────────────────────────────────────────────

class LogtestRequest(BaseModel):
    log_format: str = "syslog"
    location: str   = "test"
    event: str


@router.post("/logtest")
def logtest(body: LogtestRequest) -> dict:
    """
    Test a log string against Wazuh rules.
    This is read-only in effect — it does not modify any agent.
    """
    return _api_call(
        _get_client().run_logtest,
        log_format=body.log_format,
        location=body.location,
        log=body.event,
    )


# ── agent enrichment ─────────────────────────────────────────────────────────

@router.get("/agents/{agent_id}/enrich")
def agent_enrich(
    agent_id: str,
    agent_name: str | None = Query(default=None),
) -> dict:
    """
    Return rich agent context: status, OS, groups, syscollector
    availability flags, SCA score, FIM last scan, rootcheck status.
    """
    from services.wazuh_agent_enrichment import enrich_agent_context
    return enrich_agent_context(agent_id=agent_id, agent_name=agent_name)


@router.get("/agents/{agent_id}/sca/{policy_id}/checks")
def sca_policy_checks(
    agent_id: str,
    policy_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    result: str | None = Query(default=None, description="Filter: passed, failed, not applicable"),
) -> dict:
    """Return SCA check results for one policy on an agent (read-only)."""
    client = _get_client()
    kwargs: dict = {"limit": limit}
    if result:
        kwargs["q"] = f"result={result}"
    return _api_call(client.get_sca_checks, agent_id, policy_id, **kwargs)


@router.get("/agents/{agent_id}/syscheck/results")
def syscheck_results_detail(
    agent_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    type: str | None = Query(default=None, description="file, registry"),
) -> dict:
    """Return recent FIM/syscheck events for an agent (read-only)."""
    return _api_call(_get_client().get_syscheck_results, agent_id, limit=limit)


@router.get("/agents/{agent_id}/rootcheck/results")
def rootcheck_results_detail(
    agent_id: str,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    """Return rootcheck findings for an agent (read-only)."""
    return _api_call(_get_client().get_rootcheck_results, agent_id, limit=limit)


# ── docs knowledge ────────────────────────────────────────────────────────────

@router.get("/docs/sections")
def docs_sections() -> dict:
    """Return the catalogue of Wazuh API documentation sections."""
    from knowledge.wazuh_api_docs_knowledge import WAZUH_API_DOC_SECTIONS
    return {"sections": WAZUH_API_DOC_SECTIONS}


# ── permission probe ──────────────────────────────────────────────────────────

@router.get("/permissions")
def permissions_check() -> dict:
    """
    Run the read-only RBAC permission probe suite.
    Tests ~11 endpoints and reports which the current API user can access.
    """
    from services.wazuh_api_permissions import check_wazuh_api_permissions
    return check_wazuh_api_permissions()


# ── api recipes ───────────────────────────────────────────────────────────────

@router.get("/recipes")
def recipes() -> dict:
    """Return the catalogue of integration recipes."""
    from knowledge.wazuh_api_recipes import WAZUH_API_RECIPES
    return {"recipes": WAZUH_API_RECIPES}


# ── controlled action: single-agent reconnect ─────────────────────────────────

class AgentReconnectRequest(BaseModel):
    wait_for_complete: bool = False
    reason: str = ""
    source_page: str = "wazuh_integration"
    agent_name: str | None = None


def _classify_reconnect_error(exc: Exception) -> tuple[str, str]:
    """
    Return (status, message) from an exception raised by reconnect_agents().

    Classifies:
      - 401 → "denied"   authentication failed / token issue
      - 403 → "denied"   permission denied by Wazuh RBAC
      - connection/503 → "error"  Manager API unavailable
      - other HTTP → "error"
    """
    msg = str(exc)
    for code in (400, 401, 403, 404, 405, 429, 500, 502, 503):
        if str(code) in msg:
            if code == 401:
                return "denied", "Authentication failed (401) — token invalid or expired"
            if code == 403:
                return "denied", "Permission denied (403) — Wazuh RBAC blocks PUT /agents/reconnect"
            if code in (502, 503):
                return "error", f"Manager API unavailable ({code})"
            return "error", f"Wazuh Manager returned HTTP {code}: {msg[:200]}"
    # Connection-level errors
    lower = msg.lower()
    if any(k in lower for k in ("connection refused", "connection error", "connect", "timeout", "unreachable")):
        return "error", f"Manager API unreachable: {msg[:200]}"
    return "error", msg[:300]


@router.post("/agents/{agent_id}/reconnect")
def agent_reconnect(agent_id: str, body: AgentReconnectRequest) -> dict:
    """
    Reconnect a single Wazuh agent.

    This is a Phase-2 controlled action:
    - agent_id is required
    - reconnect-all is intentionally blocked (no route exists)
    - action is audited (requested → completed | failed)
    - returns structured result with policy, message, wazuh_response, audit IDs

    Safety:
      action_type: wazuh_agent_reconnect
      category: controlled_action
      risk: medium
      requires_confirmation: true
      requires_audit: true
      mass_action_allowed: false
    """
    from datetime import datetime, timezone
    from db.database import create_audit_entry

    agent_id = agent_id.strip()
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required and must not be empty")

    # Resolve agent name: use body-provided name or skip (avoids extra API call)
    agent_name: str | None = body.agent_name

    # ── action policy evaluation ────────────────────────────────────────────
    action_policy = "allowed"
    policy_reason: str | None = None

    try:
        from db.database import get_connection
        with get_connection() as db:
            row = db.execute(
                "SELECT id, match_confidence, wazuh_agent_id FROM unified_hosts "
                "WHERE wazuh_agent_id = ? LIMIT 1",
                (agent_id,),
            ).fetchone()
            if row:
                confidence = row[1] if len(row) > 1 else None
                if confidence == "conflict":
                    action_policy = "blocked"
                    policy_reason = "Host identity conflict — resolve before reconnecting"
                elif confidence in ("wazuh_only", None):
                    action_policy = "review_required"
                    policy_reason = "Wazuh-only host — no linked Tactical agent"
            else:
                action_policy = "review_required"
                policy_reason = "Agent not found in unified hosts — proceed with caution"
    except Exception:
        action_policy = "allowed"
        policy_reason = "Unified host check unavailable"

    # ── shared audit payload base ───────────────────────────────────────────
    def _audit_base(extra: dict) -> dict:
        return {
            "source_page": body.source_page,
            "wazuh_agent_id": agent_id,
            "host": agent_name,
            "action_policy": action_policy,
            "policy_reason": policy_reason,
            "details_json": {
                "agent_name": agent_name,
                "reason": body.reason,
                "wait_for_complete": body.wait_for_complete,
                **extra,
            },
        }

    def _safe_audit(payload: dict) -> int | None:
        try:
            return create_audit_entry(payload)
        except Exception:
            return None

    # ── blocked ─────────────────────────────────────────────────────────────
    if action_policy == "blocked":
        audit_id = _safe_audit({
            **_audit_base({"blocked_at": datetime.now(timezone.utc).isoformat()}),
            "action_type": "wazuh_agent_reconnect_requested",
            "status": "blocked",
        })
        return {
            "status": "blocked",
            "agent_id": agent_id,
            "action": "wazuh_agent_reconnect",
            "policy": action_policy,
            "policy_reason": policy_reason,
            "message": policy_reason or "Action blocked by policy",
            "wazuh_response": None,
            "audit_id_requested": audit_id,
            "audit_id_completed": None,
        }

    # ── audit: requested ───────────────────────────────────────────────────
    audit_id_requested = _safe_audit({
        **_audit_base({}),
        "action_type": "wazuh_agent_reconnect_requested",
        "status": "requested",
    })

    # ── execute ────────────────────────────────────────────────────────────
    try:
        client = _get_client()
    except HTTPException as exc:
        # Manager not configured / 503
        _safe_audit({
            **_audit_base({"error": exc.detail, "http_status": exc.status_code}),
            "action_type": "wazuh_agent_reconnect_failed",
            "status": "failed",
        })
        return {
            "status": "error",
            "agent_id": agent_id,
            "action": "wazuh_agent_reconnect",
            "policy": action_policy,
            "policy_reason": policy_reason,
            "message": f"Manager API unavailable: {exc.detail}",
            "wazuh_response": None,
            "audit_id_requested": audit_id_requested,
            "audit_id_completed": None,
        }

    try:
        wazuh_resp = client.reconnect_agents(
            agent_ids=[agent_id],
            wait_for_complete=body.wait_for_complete,
        )
        audit_id_completed = _safe_audit({
            **_audit_base({
                "affected_items": wazuh_resp.get("total_affected_items"),
                "failed_items": wazuh_resp.get("total_failed_items"),
                "wazuh_message": wazuh_resp.get("message"),
            }),
            "action_type": "wazuh_agent_reconnect_completed",
            "status": "success",
        })
        # Determine human message from response
        wazuh_msg: str | None = wazuh_resp.get("message")
        if wazuh_resp.get("total_failed_items", 0) > 0:
            msg_out = f"Completed with {wazuh_resp['total_failed_items']} failed item(s)"
        else:
            msg_out = wazuh_msg or "Reconnect signal sent"
        return {
            "status": "ok",
            "agent_id": agent_id,
            "action": "wazuh_agent_reconnect",
            "policy": action_policy,
            "policy_reason": policy_reason,
            "message": msg_out,
            "wazuh_response": wazuh_resp,
            "audit_id_requested": audit_id_requested,
            "audit_id_completed": audit_id_completed,
        }

    except Exception as exc:
        err_status, err_msg = _classify_reconnect_error(exc)
        _safe_audit({
            **_audit_base({"error": err_msg}),
            "action_type": "wazuh_agent_reconnect_failed",
            "status": "failed",
        })
        return {
            "status": err_status,  # "denied" or "error"
            "agent_id": agent_id,
            "action": "wazuh_agent_reconnect",
            "policy": action_policy,
            "policy_reason": policy_reason,
            "message": err_msg,
            "wazuh_response": None,
            "audit_id_requested": audit_id_requested,
            "audit_id_completed": None,
        }


@router.get("/agents/{agent_id}/recent-alerts")
def agent_recent_alerts(
    agent_id: str,
    agent_name: str | None = Query(default=None),
    lookback_hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict:
    """
    Query the Wazuh indexer for recent alerts associated with this agent.
    Returns raw alert list (not clustered) suitable for a timeline view.
    Uses agent_name as the host filter; agent_id is used for audit/logging.
    Read-only.
    """
    if not agent_name:
        # Try to resolve name from Manager API first
        try:
            client = _get_client()
            r = _api_call(client.get_agent, agent_id)
            item = r.get("data", {}).get("affected_items", [{}])[0]
            agent_name = item.get("name") or agent_name
        except Exception:
            pass

    if not agent_name:
        raise HTTPException(status_code=400, detail="agent_name required to query indexer")

    try:
        from db.database import get_active_connection
        from services.wazuh_indexer import fetch_alerts
        conn_record = get_active_connection()
        if not conn_record:
            raise HTTPException(status_code=503, detail="No active Wazuh connection")
        conn = dict(conn_record)
        raw = fetch_alerts(
            conn,
            lookback_hours=lookback_hours,
            query_size=limit,
            host_filter=agent_name,
        )
        # Return slim alert objects
        alerts = []
        for hit in raw[:limit]:
            agent_d = hit.get("agent") or {}
            rule_d  = hit.get("rule")  or {}
            data_d  = hit.get("data")  or {}
            win_d   = data_d.get("win") or {}
            sys_d   = win_d.get("system") or {} if isinstance(win_d, dict) else {}
            try:
                level = int(rule_d.get("level", 0))
            except (TypeError, ValueError):
                level = 0
            sev = (
                "critical" if level >= 12 else
                "high"     if level >= 10 else
                "medium"   if level >= 7  else
                "low"      if level >= 4  else
                "info"
            )
            eid = (
                sys_d.get("eventID") or sys_d.get("eventId") or
                data_d.get("eventid") or data_d.get("event_id")
            )
            alerts.append({
                "timestamp":  hit.get("timestamp") or hit.get("@timestamp"),
                "rule_id":    rule_d.get("id"),
                "rule_level": level,
                "severity":   sev,
                "description": rule_d.get("description"),
                "agent_name": agent_d.get("name"),
                "event_id":   eid,
                "mitre_tactic": (rule_d.get("mitre") or {}).get("tactic"),
                "mitre_id":     ((rule_d.get("mitre") or {}).get("id") or [None])[0]
                               if isinstance((rule_d.get("mitre") or {}).get("id"), list)
                               else (rule_d.get("mitre") or {}).get("id"),
            })
        return {"agent_id": agent_id, "agent_name": agent_name, "alerts": alerts, "total": len(alerts)}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Alert query failed: {exc}")


# ── Wazuh → unified-hosts sync ───────────────────────────────────────────────

@router.post("/sync-agents")
def sync_agents() -> dict:
    """
    Pull all Wazuh Manager agents and merge them into the unified_hosts table.

    Matching order: exact agent_id → exact hostname → normalised hostname/FQDN → IP.
    New agents are inserted as unmatched/blocked entries.
    Duplicate matches for the same host are flagged as conflicts.

    Returns a detailed WazuhSyncReport with match_methods, conflict_items,
    unmatched_items, and legacy TacticalSyncResult-compatible keys.
    """
    from db.database import get_active_connection
    from services.wazuh_host_sync import sync_wazuh_agents

    conn = get_active_connection()
    if not conn:
        raise HTTPException(status_code=503, detail="No active connection configured")

    return sync_wazuh_agents(conn)


@router.post("/recompute-policies")
def recompute_policies() -> dict:
    """
    Recompute action_policy and identity_status for all unified_hosts rows
    based on current wazuh_status, tactical_status, match_score, and conflict state.

    Run this after a Wazuh sync or Tactical sync to ensure policies reflect
    the latest trust signals.
    """
    from db.database import get_active_connection
    from services.wazuh_host_sync import recompute_action_policy_for_unified_hosts

    conn = get_active_connection()
    if not conn:
        raise HTTPException(status_code=503, detail="No active connection configured")

    result = recompute_action_policy_for_unified_hosts(conn)
    return {"status": "ok", **result}


# ── DISABLED ACTIONS (listed but not callable) ────────────────────────────────
# The following endpoints intentionally do NOT exist in this router.
# They are classified as controlled_action or dangerous in the capabilities
# endpoint and shown as disabled in the UI.
#
# Disabled until RBAC + Action Policy + Audit Phase:
#   PUT  /agents/{agent_id}/restart
#   PUT  /agents/restart
#   PUT  /active-response
#   PUT  /syscheck
#   PUT  /rootcheck
#   PUT  /manager/restart
#   PUT  /manager/configuration
#   PUT  /rules/files/{filename}
#   PUT  /decoders/files/{filename}
#   DELETE /agents
#   DELETE /syscheck/{agent_id}
#   DELETE /rootcheck/{agent_id}
