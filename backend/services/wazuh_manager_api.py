"""
wazuh_manager_api.py
====================
Read-only Wazuh Manager REST API client.

Authentication:
  POST /security/user/authenticate
  → returns { data: { token: "eyJ..." } }
  → cache token in memory; refresh on 401 or near expiry.

Config:
  Read from the active DB connection (manager_url / manager_username /
  manager_password / verify_ssl).  Callers can also pass a connection dict
  directly.

Dangerous actions (active-response, restart, upgrade, config changes,
DELETE) are intentionally NOT implemented.  They will remain disabled until
RBAC + Action Policy + Audit Phase are complete.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ── token cache ───────────────────────────────────────────────────────────────
# { base_url+user -> (token_str, expires_at_epoch) }
_TOKEN_CACHE: dict[str, tuple[str, float]] = {}
_TOKEN_TTL   = 840   # 14 min (Wazuh default is 900 s)


def _cache_key(base_url: str, username: str) -> str:
    return f"{base_url}|{username}"


def _get_cached_token(key: str) -> str | None:
    entry = _TOKEN_CACHE.get(key)
    if entry and time.time() < entry[1]:
        return entry[0]
    return None


def _set_cached_token(key: str, token: str) -> None:
    _TOKEN_CACHE[key] = (token, time.time() + _TOKEN_TTL)


def _clear_cached_token(key: str) -> None:
    _TOKEN_CACHE.pop(key, None)


# ── connection helpers ────────────────────────────────────────────────────────

def _conn_attr(conn: Any, key: str, default: Any = None) -> Any:
    """Get attribute from dict or object connection."""
    if isinstance(conn, dict):
        return conn.get(key, default)
    return getattr(conn, key, default)


def _build_manager_base_url(conn: Any) -> str | None:
    url = _conn_attr(conn, "manager_url")
    if not url:
        return None
    return str(url).rstrip("/")


def _build_verify(conn: Any) -> bool:
    return bool(_conn_attr(conn, "verify_ssl", False))


# ── core client ───────────────────────────────────────────────────────────────

class WazuhManagerAPIClient:
    """
    Thin, read-only Wazuh Manager REST API client.

    Example::

        from db.database import get_active_connection
        conn = get_active_connection()
        client = WazuhManagerAPIClient.from_connection(conn)
        health = client.health()
        agents = client.get_agents()
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_tls: bool = False,
        timeout: float = 20.0,
    ) -> None:
        self._base_url  = base_url.rstrip("/")
        self._username  = username
        self._password  = password
        self._verify    = verify_tls
        self._timeout   = timeout
        self._cache_key = _cache_key(self._base_url, self._username)

    # ── factory ───────────────────────────────────────────────────────────

    @classmethod
    def from_connection(cls, conn: Any) -> "WazuhManagerAPIClient":
        """Build client from DB connection record or dict."""
        base_url = _build_manager_base_url(conn)
        if not base_url:
            raise ValueError("manager_url is not set in the active connection")
        username = _conn_attr(conn, "manager_username") or ""
        password = _conn_attr(conn, "manager_password") or ""
        if not username or not password:
            raise ValueError("manager_username / manager_password not set in connection")
        return cls(
            base_url=base_url,
            username=username,
            password=password,
            verify_tls=_build_verify(conn),
        )

    # ── auth ──────────────────────────────────────────────────────────────

    def authenticate(self) -> str:
        """Fetch a new JWT token and cache it. Never logs the token."""
        token = _get_cached_token(self._cache_key)
        if token:
            return token

        url = f"{self._base_url}/security/user/authenticate"
        with httpx.Client(verify=self._verify, timeout=self._timeout) as client:
            resp = client.post(url, auth=(self._username, self._password))
            resp.raise_for_status()
        data = resp.json()
        token = data["data"]["token"]
        _set_cached_token(self._cache_key, token)
        logger.debug("Wazuh Manager API: token obtained for %s", self._base_url)
        return token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.authenticate()}"}

    # ── generic request ───────────────────────────────────────────────────

    def request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        json_body: dict | None = None,
    ) -> dict:
        """
        Execute a Manager API request.  Retries once on 401 (token expired).
        Only GET and safe POST (logtest) are expected callers.
        """
        url = f"{self._base_url}{path}"
        for attempt in range(2):
            headers = self._headers()
            with httpx.Client(verify=self._verify, timeout=self._timeout) as client:
                resp = client.request(
                    method.upper(),
                    url,
                    headers=headers,
                    params=params,
                    json=json_body,
                )
            if resp.status_code == 401 and attempt == 0:
                _clear_cached_token(self._cache_key)
                continue
            resp.raise_for_status()
            return resp.json()
        raise RuntimeError("Wazuh Manager API: authentication failed after retry")

    # ── health / info ─────────────────────────────────────────────────────

    def health(self) -> dict:
        """
        Aggregate health check: info + manager status + agent summary.
        Returns a structured dict; never raises (returns error keys instead).
        """
        result: dict[str, Any] = {
            "configured": True,
            "reachable": False,
            "authenticated": False,
            "api_version": None,
            "manager_version": None,
            "hostname": None,
            "cluster_enabled": None,
            "agent_status_summary": None,
            "message": None,
            "last_checked": _utcnow(),
        }
        try:
            info = self.request("GET", "/")
            result["reachable"] = True
            result["authenticated"] = True
            result["api_version"] = _dig(info, "data", "api_version")
            result["hostname"]    = _dig(info, "data", "hostname")
        except Exception as exc:
            result["message"] = f"Root endpoint error: {exc}"
            return result

        try:
            mgr_info = self.request("GET", "/manager/info")
            result["manager_version"] = _dig(mgr_info, "data", "version")
            result["cluster_enabled"] = _dig(mgr_info, "data", "cluster", "enabled")
        except Exception:
            pass

        try:
            summary = self.request("GET", "/agents/summary/status")
            result["agent_status_summary"] = _dig(summary, "data", "connection")
        except Exception:
            pass

        result["message"] = "OK"
        return result

    # ── agents ────────────────────────────────────────────────────────────

    def get_agents(
        self,
        limit: int = 500,
        offset: int = 0,
        status: str | None = None,
        fields: str = "id,name,ip,status,version,os.name,os.platform,os.version,group,node_name,lastKeepAlive,manager",
        search: str | None = None,
        q: str | None = None,
    ) -> dict:
        params: dict[str, Any] = {"limit": limit, "offset": offset, "select": fields}
        if status:
            params["status"] = status
        if search:
            params["search"] = search
        if q:
            params["q"] = q
        return self.request("GET", "/agents", params=params)

    def get_agent(self, agent_id: str) -> dict:
        return self.request("GET", "/agents", params={"agents_list": agent_id})

    def get_agent_summary_status(self) -> dict:
        return self.request("GET", "/agents/summary/status")

    def get_agent_summary_os(self) -> dict:
        return self.request("GET", "/agents/summary/os")

    # ── syscollector ─────────────────────────────────────────────────────

    def get_syscollector_os(self, agent_id: str) -> dict:
        return self.request("GET", f"/syscollector/{agent_id}/os")

    def get_syscollector_hardware(self, agent_id: str) -> dict:
        return self.request("GET", f"/syscollector/{agent_id}/hardware")

    def get_syscollector_packages(self, agent_id: str, limit: int = 100) -> dict:
        return self.request("GET", f"/syscollector/{agent_id}/packages",
                            params={"limit": limit})

    def get_syscollector_ports(self, agent_id: str, limit: int = 100) -> dict:
        return self.request("GET", f"/syscollector/{agent_id}/ports",
                            params={"limit": limit})

    def get_syscollector_processes(self, agent_id: str, limit: int = 100) -> dict:
        return self.request("GET", f"/syscollector/{agent_id}/processes",
                            params={"limit": limit})

    def get_syscollector_services(self, agent_id: str, limit: int = 100) -> dict:
        return self.request("GET", f"/syscollector/{agent_id}/services",
                            params={"limit": limit})

    def get_syscollector_users(self, agent_id: str) -> dict:
        return self.request("GET", f"/syscollector/{agent_id}/users")

    def get_syscollector_groups(self, agent_id: str) -> dict:
        return self.request("GET", f"/syscollector/{agent_id}/groups")

    # ── syscheck (FIM) ────────────────────────────────────────────────────

    def get_syscheck_results(self, agent_id: str, limit: int = 50) -> dict:
        return self.request("GET", f"/syscheck/{agent_id}",
                            params={"limit": limit})

    def get_syscheck_last_scan(self, agent_id: str) -> dict:
        return self.request("GET", f"/syscheck/{agent_id}/last_scan")

    # ── SCA ──────────────────────────────────────────────────────────────

    def get_sca_results(self, agent_id: str) -> dict:
        return self.request("GET", f"/sca/{agent_id}")

    def get_sca_checks(self, agent_id: str, policy_id: str, limit: int = 50) -> dict:
        return self.request("GET", f"/sca/{agent_id}/checks/{policy_id}",
                            params={"limit": limit})

    # ── rootcheck ────────────────────────────────────────────────────────

    def get_rootcheck_results(self, agent_id: str, limit: int = 50) -> dict:
        return self.request("GET", f"/rootcheck/{agent_id}",
                            params={"limit": limit})

    def get_rootcheck_last_scan(self, agent_id: str) -> dict:
        return self.request("GET", f"/rootcheck/{agent_id}/last_scan")

    # ── manager ──────────────────────────────────────────────────────────

    def get_manager_status(self) -> dict:
        return self.request("GET", "/manager/status")

    def get_manager_info(self) -> dict:
        return self.request("GET", "/manager/info")

    # ── rules / decoders / MITRE ─────────────────────────────────────────

    def get_rules(self, limit: int = 100, offset: int = 0) -> dict:
        return self.request("GET", "/rules", params={"limit": limit, "offset": offset})

    def get_decoders(self, limit: int = 100, offset: int = 0) -> dict:
        return self.request("GET", "/decoders", params={"limit": limit, "offset": offset})

    def get_mitre_techniques(self, limit: int = 300) -> dict:
        return self.request("GET", "/mitre/techniques", params={"limit": limit})

    def get_mitre_tactics(self, limit: int = 100) -> dict:
        return self.request("GET", "/mitre/tactics", params={"limit": limit})

    # ── logtest (safe, read-only in effect) ──────────────────────────────

    def run_logtest(self, log_format: str, location: str, log: str) -> dict:
        """Test a log line against rules — does NOT modify any agent."""
        return self.request("PUT", "/logtest", json_body={
            "log_format": log_format,
            "location": location,
            "event": log,
        })

    def close_logtest_session(self, token: str) -> dict:
        return self.request("DELETE", f"/logtest/sessions/{token}")

    # ── controlled actions (Phase 2) ─────────────────────────────────────

    def reconnect_agents(
        self,
        agent_ids: list[str],
        wait_for_complete: bool = False,
    ) -> dict:
        """
        Reconnect one or more Wazuh agents.

        Rules:
        - agent_ids must be non-empty (mass-reconnect without list is forbidden)
        - passes agents_list as a comma-separated string
        - uses PUT /agents/reconnect (Wazuh API v4.x)
        - returns a normalized response via wazuh_api_response.normalize_wazuh_response

        Raises ValueError if agent_ids is empty.
        """
        if not agent_ids:
            raise ValueError(
                "agent_ids must not be empty. "
                "Single-agent reconnect only — reconnect-all is not permitted."
            )
        from services.wazuh_api_response import normalize_wazuh_response

        agents_list = ",".join(str(a).strip() for a in agent_ids)
        params: dict[str, Any] = {"agents_list": agents_list}
        if wait_for_complete:
            params["wait_for_complete"] = "true"
        raw = self.request("PUT", "/agents/reconnect", params=params)
        return normalize_wazuh_response(raw)


# ── utilities ─────────────────────────────────────────────────────────────────

def _dig(d: Any, *keys: str) -> Any:
    """Safe nested dict access."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# ── convenience: build from active DB connection ──────────────────────────────

def get_manager_client() -> WazuhManagerAPIClient:
    """
    Build a client from the active DB connection.
    Raises ValueError if not configured.
    """
    from db.database import get_active_connection
    conn = get_active_connection()
    if not conn:
        raise ValueError("No active connection configured")
    return WazuhManagerAPIClient.from_connection(conn)


def check_manager_configured(conn: Any | None = None) -> dict:
    """
    Quick capability check: is the Manager API configured at all?
    Returns {"configured": bool, "reason": str | None}
    """
    if conn is None:
        from db.database import get_active_connection
        conn = get_active_connection()
    if conn is None:
        return {"configured": False, "reason": "No active connection"}
    url  = _conn_attr(conn, "manager_url")
    user = _conn_attr(conn, "manager_username")
    pwd  = _conn_attr(conn, "manager_password")
    if not url:
        return {"configured": False, "reason": "manager_url not set"}
    if not user or not pwd:
        return {"configured": False, "reason": "manager_username / manager_password not set"}
    return {"configured": True, "reason": None}
