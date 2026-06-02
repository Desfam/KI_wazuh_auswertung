"""
wazuh_api_capabilities.py
==========================
Load and parse the Wazuh Manager OpenAPI spec (spec-v4.14.5.yaml or similar)
and classify every endpoint as read_only / safe_test / controlled_action /
dangerous.

This lets the Trust Center and the UI show exactly which API endpoints are
available, which are implemented, and which remain disabled for safety.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

# ── safety classification ─────────────────────────────────────────────────────

# Paths/methods always classified as dangerous regardless of HTTP method
_DANGEROUS_PATHS: frozenset[str] = frozenset({
    "/active-response",
    "/manager/restart",
    "/manager/configuration",
    "/manager/configuration/validation",
    "/cluster/{node_id}/restart",
    "/cluster/{node_id}/configuration",
})

_DANGEROUS_PATH_PREFIXES: tuple[str, ...] = (
    "/rules/files",
    "/decoders/files",
    "/lists",
    "/manager/files",
    "/cluster/",
)

# DELETE is dangerous unless it's a logtest session
_SAFE_DELETE_PATHS: frozenset[str] = frozenset({
    "/logtest/sessions/{token}",
})

# Controlled actions: disruptive but not destructive
_CONTROLLED_PATHS: frozenset[str] = frozenset({
    "/syscheck",
    "/rootcheck",
    "/agents/{agent_id}/reconnect",
})
_CONTROLLED_PATH_PREFIXES: tuple[str, ...] = (
    "/agents/{agent_id}/restart",
    "/agents/restart",
    "/agents/{agent_id}/reconnect",
    "/syscheck",
    "/rootcheck",
)

# Implemented controlled-action paths (PUT/PATCH endpoints we actively expose)
_IMPLEMENTED_CONTROLLED_PATHS: frozenset[str] = frozenset({
    "/agents/{agent_id}/reconnect",  # PUT — reconnect single agent (permission-gated)
})

# Implemented read-only paths (mirrors routes_wazuh_manager.py)
_IMPLEMENTED_PATHS: frozenset[str] = frozenset({
    "/",
    "/manager/info",
    "/manager/status",
    "/agents",
    "/agents/summary/status",
    "/agents/summary/os",
    "/agents/{agent_id}",
    "/agents/{agent_id}/config/{component}/{configuration}",
    "/syscollector/{agent_id}/os",
    "/syscollector/{agent_id}/hardware",
    "/syscollector/{agent_id}/packages",
    "/syscollector/{agent_id}/ports",
    "/syscollector/{agent_id}/processes",
    "/syscollector/{agent_id}/services",
    "/syscollector/{agent_id}/users",
    "/syscollector/{agent_id}/groups",
    "/syscheck/{agent_id}",
    "/syscheck/{agent_id}/last_scan",
    "/sca/{agent_id}",
    "/sca/{agent_id}/checks/{policy_id}",
    "/rootcheck/{agent_id}",
    "/rootcheck/{agent_id}/last_scan",
    "/rules",
    "/decoders",
    "/mitre/techniques",
    "/mitre/tactics",
    "/logtest",
})


def _classify(method: str, path: str) -> str:
    method = method.upper()

    # Explicit dangerous paths
    if path in _DANGEROUS_PATHS:
        return "dangerous"
    for prefix in _DANGEROUS_PATH_PREFIXES:
        if path.startswith(prefix):
            return "dangerous"

    # DELETE
    if method == "DELETE":
        if path in _SAFE_DELETE_PATHS:
            return "read_only"
        return "dangerous"

    # Controlled (disruptive write)
    if method in ("PUT", "PATCH"):
        if path in _CONTROLLED_PATHS:
            return "controlled_action"
        for prefix in _CONTROLLED_PATH_PREFIXES:
            if path.startswith(prefix):
                return "controlled_action"
        return "dangerous"

    # POST
    if method == "POST":
        if "/logtest" in path:
            return "safe_test"
        if "/authenticate" in path:
            return "read_only"
        return "dangerous"

    # GET → always read-only
    return "read_only"


def _phase(safety: str) -> str:
    return {
        "read_only": "phase1_readonly",
        "safe_test": "phase1_readonly",
        "controlled_action": "phase2_controlled",
        "dangerous": "phase3_dangerous_disabled",
    }.get(safety, "phase3_dangerous_disabled")


# ── spec loading ──────────────────────────────────────────────────────────────

_SPEC_SEARCH_PATHS: list[str] = [
    # Alongside the backend dir
    str(Path(__file__).resolve().parents[2] / "spec-v4.14.5.yaml"),
    # Downloads folder (dev convenience)
    str(Path.home() / "Downloads" / "spec-v4.14.5.yaml"),
    # Configurable via env
    os.environ.get("WAZUH_API_SPEC_PATH", ""),
]


def load_wazuh_api_spec(path: str | None = None) -> dict | None:
    """
    Try to load the Wazuh OpenAPI YAML spec.
    Returns the parsed dict or None if not found.
    """
    search = [path] + _SPEC_SEARCH_PATHS if path else _SPEC_SEARCH_PATHS
    for p in search:
        if p and Path(p).is_file():
            try:
                import yaml  # type: ignore
                return yaml.safe_load(Path(p).read_text(encoding="utf-8"))
            except Exception:
                pass
    return None


def parse_wazuh_api_capabilities(spec: dict) -> list[dict]:
    """
    Extract every path+method from an OpenAPI spec dict and return a
    list of capability dicts.
    """
    capabilities: list[dict] = []
    paths: dict[str, Any] = spec.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head"):
                continue
            if not isinstance(operation, dict):
                continue

            tags = operation.get("tags", [])
            tag  = tags[0] if tags else "unknown"
            summary      = operation.get("summary", "")
            operation_id = operation.get("operationId", "")
            safety = _classify(method, path)
            m = method.upper()
            implemented = (
                (path in _IMPLEMENTED_PATHS and m in ("GET", "POST"))
                or (path in _IMPLEMENTED_CONTROLLED_PATHS and m in ("PUT", "PATCH"))
            )
            capabilities.append({
                "method":               m,
                "path":                 path,
                "tag":                  tag,
                "summary":              summary,
                "operation_id":         operation_id,
                "safety":               safety,
                "implemented":          implemented,
                "phase":                _phase(safety),
                "requires_action_policy": safety in ("controlled_action", "dangerous"),
            })

    return capabilities


def get_capabilities_summary(capabilities: list[dict]) -> dict:
    total        = len(capabilities)
    by_safety    = {}
    for c in capabilities:
        by_safety[c["safety"]] = by_safety.get(c["safety"], 0) + 1

    implemented  = sum(1 for c in capabilities if c["implemented"])
    return {
        "total":                  total,
        "read_only_total":        by_safety.get("read_only", 0) + by_safety.get("safe_test", 0),
        "read_only_implemented":  implemented,
        "controlled_disabled":    by_safety.get("controlled_action", 0),
        "dangerous_disabled":     by_safety.get("dangerous", 0),
        "by_safety":              by_safety,
    }


# ── module-level cached capabilities ─────────────────────────────────────────

_cached: list[dict] | None = None
_cached_summary: dict | None = None
_spec_loaded: bool | None = None  # None = not checked yet


def get_cached_capabilities() -> list[dict]:
    global _cached, _cached_summary, _spec_loaded
    if _cached is None:
        spec = load_wazuh_api_spec()
        if spec:
            _cached = parse_wazuh_api_capabilities(spec)
            _spec_loaded = True
        else:
            _cached = []
            _spec_loaded = False
        _cached_summary = get_capabilities_summary(_cached)
    return _cached


def get_cached_summary() -> dict:
    get_cached_capabilities()  # ensure loaded
    return _cached_summary or {}


def get_spec_status() -> dict:
    """Return whether the OpenAPI spec was found and the search paths tried."""
    get_cached_capabilities()  # ensure loaded
    # Filter out empty paths from the search list
    paths = [p for p in _SPEC_SEARCH_PATHS if p]
    return {
        "loaded": bool(_spec_loaded),
        "search_paths": paths,
    }
