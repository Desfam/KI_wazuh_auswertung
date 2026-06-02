"""
wazuh_api_response.py
=====================
Central Wazuh API response normalizer.

The Wazuh Manager REST API wraps almost every response in the shape:

    {
      "data": {
        "affected_items": [...],
        "total_affected_items": <int>,
        "total_failed_items": <int>,
        "failed_items": [...]
      },
      "message": "...",
      "error": 0          # 0 = success, non-zero = partial/full error
    }

This module provides:

  normalize_wazuh_response(response)     → NormalizedResponse dict
  extract_affected_items(response)       → list
  summarize_wazuh_error(...)             → human-readable error dict

HTTP-level meanings:
  200  success
  400  bad request (e.g. invalid field name)
  401  unauthorized → token refresh needed
  403  permission denied (RBAC)
  405  method not allowed (wrong verb)
  429  rate limit exceeded
  5xx  server error
"""
from __future__ import annotations

from typing import Any

# ── public type alias ─────────────────────────────────────────────────────────

NormalizedResponse = dict  # keeps it simple; no runtime Pydantic overhead


# ── main normalizer ───────────────────────────────────────────────────────────

def normalize_wazuh_response(response: dict | None) -> NormalizedResponse:
    """
    Convert a raw Wazuh API response dict into a flat, predictable shape.

    Returns a NormalizedResponse:
    {
        "ok": bool,
        "error_code": int | None,
        "message": str,
        "affected_items": list,
        "total_affected_items": int,
        "failed_items": list,
        "total_failed_items": int,
        "raw": dict | None,
        "warnings": list[str]
    }
    """
    if response is None:
        return _empty(ok=False, message="No response received")

    warnings: list[str] = []
    data = response.get("data") or {}
    error_code: int = response.get("error", 0)
    message: str = response.get("message") or ("OK" if error_code == 0 else "Unknown error")

    affected_items: list = data.get("affected_items") or []
    total_affected: int  = int(data.get("total_affected_items") or len(affected_items))
    failed_items: list   = data.get("failed_items") or []
    total_failed: int    = int(data.get("total_failed_items") or len(failed_items))

    if total_failed > 0:
        warnings.append(f"{total_failed} item(s) failed in the API response")

    ok = error_code == 0

    return {
        "ok": ok,
        "error_code": error_code if error_code != 0 else None,
        "message": message,
        "affected_items": affected_items,
        "total_affected_items": total_affected,
        "failed_items": failed_items,
        "total_failed_items": total_failed,
        "raw": response,
        "warnings": warnings,
    }


# ── convenience extractor ─────────────────────────────────────────────────────

def extract_affected_items(response: dict | None) -> list:
    """Extract affected_items from a raw Wazuh response, or []."""
    if not isinstance(response, dict):
        return []
    data = response.get("data")
    if isinstance(data, dict):
        items = data.get("affected_items")
        if isinstance(items, list):
            return items
    return []


# ── HTTP-level error summarizer ───────────────────────────────────────────────

def summarize_wazuh_error(
    status_code: int | None = None,
    response: dict | None = None,
    exception: Exception | None = None,
) -> dict:
    """
    Produce a structured, human-readable error summary from an HTTP error.

    Returns:
    {
        "status_code": int | None,
        "category": str,        # "auth" | "permission" | "not_found" | "bad_request"
                                #  | "method_not_allowed" | "rate_limit"
                                #  | "server_error" | "network" | "unknown"
        "title": str,
        "detail": str,
        "action": str,          # suggested corrective action
        "raw_message": str | None,
    }
    """
    raw_msg: str | None = None
    if exception:
        raw_msg = str(exception)
    elif response:
        raw_msg = response.get("detail") or response.get("message")

    if status_code == 401:
        return _err(401, "auth",
                    "Unauthorized",
                    "JWT token missing or expired.",
                    "Re-authenticate with manager_username / manager_password.",
                    raw_msg)

    if status_code == 403:
        return _err(403, "permission",
                    "Permission denied",
                    "The API user lacks the required RBAC permission for this endpoint.",
                    "Check the Wazuh RBAC policy for the wazuh-wui user.",
                    raw_msg)

    if status_code == 404:
        return _err(404, "not_found",
                    "Not found",
                    "The requested resource or endpoint does not exist.",
                    "Verify the endpoint path against the API spec.",
                    raw_msg)

    if status_code == 400:
        return _err(400, "bad_request",
                    "Bad request",
                    "The API rejected the request parameters (e.g. invalid field name or query).",
                    "Check query parameters — use 'select=' not 'fields=', valid field names only.",
                    raw_msg)

    if status_code == 405:
        return _err(405, "method_not_allowed",
                    "Method not allowed",
                    "Wrong HTTP verb for this endpoint.",
                    "Check whether the endpoint requires GET, PUT, POST, or DELETE.",
                    raw_msg)

    if status_code == 429:
        return _err(429, "rate_limit",
                    "Rate limit exceeded",
                    "Too many requests to the Wazuh Manager API.",
                    "Reduce request frequency or increase the API rate limit in ossec.conf.",
                    raw_msg)

    if status_code and status_code >= 500:
        return _err(status_code, "server_error",
                    "Server error",
                    "The Wazuh Manager API returned a server-side error.",
                    "Check the Wazuh Manager logs (ossec.log / api.log).",
                    raw_msg)

    if exception:
        import httpx  # only import when needed
        if isinstance(exception, httpx.ConnectError):
            return _err(None, "network",
                        "Connection refused",
                        f"Cannot reach Wazuh Manager: {exception}",
                        "Check manager_url, network connectivity and port 55000.",
                        raw_msg)
        if isinstance(exception, httpx.TimeoutException):
            return _err(None, "network",
                        "Connection timeout",
                        f"Wazuh Manager did not respond in time: {exception}",
                        "Check server load or increase timeout in settings.",
                        raw_msg)

    return _err(status_code, "unknown",
                "Unknown error",
                raw_msg or "No additional information available.",
                "Check the backend logs.",
                raw_msg)


# ── internal helpers ──────────────────────────────────────────────────────────

def _empty(ok: bool = True, message: str = "OK") -> NormalizedResponse:
    return {
        "ok": ok,
        "error_code": None,
        "message": message,
        "affected_items": [],
        "total_affected_items": 0,
        "failed_items": [],
        "total_failed_items": 0,
        "raw": None,
        "warnings": [],
    }


def _err(
    status_code: int | None,
    category: str,
    title: str,
    detail: str,
    action: str,
    raw_message: str | None,
) -> dict:
    return {
        "status_code": status_code,
        "category": category,
        "title": title,
        "detail": detail,
        "action": action,
        "raw_message": raw_message,
    }
