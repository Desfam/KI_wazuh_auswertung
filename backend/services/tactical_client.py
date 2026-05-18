"""Tactical RMM API Client — read-only, Phase 1.

All secrets stay server-side. Never expose the API key to the frontend.
Uses httpx for synchronous requests with a configurable timeout.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration — read from environment, with sensible defaults
# ---------------------------------------------------------------------------

TACTICAL_BASE_URL: str = os.environ.get(
    "TACTICAL_RMM_BASE_URL", "https://tactical.rmm.local"
).rstrip("/")

TACTICAL_API_URL: str = os.environ.get(
    "TACTICAL_RMM_API_URL", f"{TACTICAL_BASE_URL}/api"
).rstrip("/")

TACTICAL_API_KEY: str = os.environ.get("TACTICAL_RMM_API_KEY", "")

# Whether to verify TLS certificates (set TACTICAL_RMM_VERIFY_SSL=false to skip)
_verify_raw = os.environ.get("TACTICAL_RMM_VERIFY_SSL", "true").strip().lower()
TACTICAL_VERIFY_SSL: bool = _verify_raw not in ("false", "0", "no")

TACTICAL_TIMEOUT: float = float(os.environ.get("TACTICAL_RMM_TIMEOUT", "15"))


# ---------------------------------------------------------------------------
# Low-level HTTP helper
# ---------------------------------------------------------------------------

def _headers() -> dict[str, str]:
    return {
        "X-API-KEY": TACTICAL_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _get(path: str, params: dict[str, Any] | None = None) -> Any:
    """Perform a GET request against the Tactical API. Raises on HTTP errors."""
    if not TACTICAL_API_KEY:
        raise TacticalConfigError("TACTICAL_RMM_API_KEY is not configured.")

    url = f"{TACTICAL_API_URL}/{path.lstrip('/')}"
    try:
        resp = httpx.get(
            url,
            headers=_headers(),
            params=params,
            verify=TACTICAL_VERIFY_SSL,
            timeout=TACTICAL_TIMEOUT,
            follow_redirects=True,
        )
        resp.raise_for_status()
        if not resp.content or resp.status_code == 204:
            return None
        ct = resp.headers.get("content-type", "")
        if "text/html" in ct:
            raise TacticalAPIError(
                f"Received HTML instead of JSON from {url} — "
                "check TACTICAL_RMM_API_URL (should point to the Django API, not the web frontend). "
                f"Content-Type: {ct}"
            )
        return resp.json()
    except httpx.HTTPStatusError as exc:
        logger.warning("Tactical API HTTP error %s for %s", exc.response.status_code, url)
        raise TacticalAPIError(
            f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
        ) from exc
    except httpx.RequestError as exc:
        logger.warning("Tactical API request error: %s", exc)
        raise TacticalConnectionError(str(exc)) from exc


# ---------------------------------------------------------------------------
# Typed exception hierarchy
# ---------------------------------------------------------------------------

class TacticalError(Exception):
    """Base class for all Tactical client errors."""


class TacticalConfigError(TacticalError):
    """API key or URL not configured."""


class TacticalConnectionError(TacticalError):
    """Network-level failure reaching the Tactical API."""


class TacticalAPIError(TacticalError):
    """Non-2xx response from the Tactical API."""


# ---------------------------------------------------------------------------
# Public API read-only functions
# ---------------------------------------------------------------------------

def check_health() -> dict[str, Any]:
    """Lightweight connectivity test — checks if the API responds with a valid status."""
    if not TACTICAL_API_KEY:
        return {"reachable": False, "detail": "TACTICAL_RMM_API_KEY is not configured."}
    url = f"{TACTICAL_API_URL}/agents/"
    try:
        resp = httpx.get(
            url,
            headers=_headers(),
            verify=TACTICAL_VERIFY_SSL,
            timeout=TACTICAL_TIMEOUT,
            follow_redirects=True,
        )
        resp.raise_for_status()
        return {"reachable": True, "detail": f"Tactical RMM API reachable (HTTP {resp.status_code})"}
    except httpx.HTTPStatusError as exc:
        return {"reachable": False, "detail": f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"}
    except httpx.RequestError as exc:
        return {"reachable": False, "detail": f"Connection error: {exc}"}


def get_agents() -> list[dict[str, Any]]:
    """Return all agents from Tactical RMM."""
    data = _get("agents/")
    if data is None:
        return []
    if isinstance(data, list):
        return data
    # Some versions wrap in {"agents": [...]}
    if isinstance(data, dict):
        for key in ("agents", "results", "data"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def get_agent(agent_id: str) -> dict[str, Any]:
    """Return a single agent by ID."""
    return _get(f"agents/{agent_id}/")


def get_clients() -> list[dict[str, Any]]:
    """Return all clients (tenants)."""
    data = _get("clients/")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("clients", "results", "data"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def get_sites() -> list[dict[str, Any]]:
    """Return all sites."""
    data = _get("sites/")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("sites", "results", "data"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def get_checks(agent_id: str) -> list[dict[str, Any]]:
    """Return checks for a specific agent."""
    data = _get(f"agents/{agent_id}/checks/")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("checks", "results", "data"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def get_alerts() -> list[dict[str, Any]]:
    """Return open alerts from Tactical RMM."""
    data = _get("alerts/")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("alerts", "results", "data"):
            if isinstance(data.get(key), list):
                return data[key]
    return []
