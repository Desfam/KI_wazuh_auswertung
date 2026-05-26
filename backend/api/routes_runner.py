"""
Local Runner — safe backend-side utilities that run on the SOC server itself.

These are NOT remote host scripts. They have their own router (/runner/*)
so the safety validation test (which checks the scripts router for /run
and /exec routes) is not affected.

Current runners:
  POST /runner/fetch-wazuh-events   — pull N events from Wazuh Indexer and
                                      save them to <project_root>/Example JSON/
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from db.database import create_audit_entry, get_active_connection
from services.wazuh_indexer import build_auth, build_base_url, build_verify

router = APIRouter(prefix="/runner", tags=["runner"])

_PROJECT_ROOT  = Path(__file__).resolve().parent.parent.parent
_OUTPUT_DIR    = _PROJECT_ROOT / "Example JSON"
_PAGE_SIZE     = 10_000   # OpenSearch default max_result_window


# ── paginated fetch (search_after) ────────────────────────────────────────────

def _fetch_paginated(
    conn: dict[str, Any],
    lookback_hours: int,
    total_limit: int,
    host_filter: str | None,
) -> list[dict[str, Any]]:
    """
    Fetch up to `total_limit` events using search_after pagination.
    Falls back to a single request if limit <= _PAGE_SIZE.
    """
    now   = datetime.now(timezone.utc)
    start = now - timedelta(hours=lookback_hours)

    base_url      = build_base_url(conn)
    auth          = build_auth(conn)
    verify        = build_verify(conn)
    index_pattern = conn.get("indexer_index_pattern", "wazuh-alerts-*")

    filters: list[dict[str, Any]] = [
        {"range": {"timestamp": {
            "gte": start.isoformat(),
            "lte": now.isoformat(),
            "format": "strict_date_optional_time",
        }}},
    ]
    if host_filter:
        filters.append({"wildcard": {"agent.name": f"*{host_filter}*"}})

    sort = [{"timestamp": {"order": "desc", "unmapped_type": "boolean"}},
            {"_id":        {"order": "asc"}}]

    all_events: list[dict[str, Any]] = []
    search_after: list[Any] | None = None

    with httpx.Client(verify=verify, timeout=120.0, auth=auth) as client:
        while len(all_events) < total_limit:
            page_size = min(_PAGE_SIZE, total_limit - len(all_events))
            payload: dict[str, Any] = {
                "size": page_size,
                "sort": sort,
                "_source": {"excludes": ["@timestamp"]},
                "query": {"bool": {"filter": filters}},
            }
            if search_after is not None:
                payload["search_after"] = search_after

            resp = client.post(f"{base_url}/{index_pattern}/_search", json=payload)
            resp.raise_for_status()

            hits = resp.json().get("hits", {}).get("hits", [])
            if not hits:
                break

            for item in hits:
                src = item.get("_source") or {}
                if not isinstance(src, dict):
                    continue
                if not src.get("timestamp"):
                    ts = item.get("fields", {}).get("timestamp")
                    if isinstance(ts, list) and ts:
                        src["timestamp"] = ts[0]
                all_events.append(src)

            if len(hits) < page_size:
                break  # last page

            # next page anchor
            search_after = hits[-1].get("sort")
            if not search_after:
                break

    return all_events


# ── request / response models ─────────────────────────────────────────────────

class FetchWazuhEventsRequest(BaseModel):
    hours:       int   = Field(default=72,   ge=1,    le=8760,   description="Lookback window in hours")
    limit:       int   = Field(default=1000, ge=1,    le=100_000, description="Maximum events to fetch")
    host_filter: str | None = Field(default=None, description="Optional agent hostname filter (wildcard)")


class FetchWazuhEventsResponse(BaseModel):
    status:          str
    events_fetched:  int
    file_path:       str
    file_size_kb:    float
    agents:          list[str]
    agent_count:     int
    earliest:        str | None
    latest:          str | None
    parameters_used: dict[str, Any]


# ── endpoint ──────────────────────────────────────────────────────────────────

@router.post("/fetch-wazuh-events", response_model=FetchWazuhEventsResponse)
def run_fetch_wazuh_events(req: FetchWazuhEventsRequest) -> FetchWazuhEventsResponse:
    """
    Pull up to `limit` raw Wazuh alert events from the active Wazuh Indexer
    connection and save them as a JSON file in <project_root>/Example JSON/.

    Safe: read-only, local file write only, no remote command execution.
    """
    conn = get_active_connection()
    if not conn:
        raise HTTPException(
            status_code=503,
            detail="No active Wazuh connection configured. Add one in Settings → Connections.",
        )

    # Fetch (paginated — handles >10k events via search_after)
    try:
        events = _fetch_paginated(
            conn=conn,
            lookback_hours=req.hours,
            total_limit=req.limit,
            host_filter=req.host_filter or None,
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh Indexer error: {exc}") from exc

    # Save
    _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts        = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path  = _OUTPUT_DIR / f"events_{ts}.json"

    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(events, fh, ensure_ascii=False, indent=2, default=str)

    size_kb = out_path.stat().st_size / 1024

    # Build summary
    agents: list[str] = sorted({
        e.get("agent", {}).get("name", "?")
        for e in events
        if isinstance(e.get("agent"), dict)
    })
    timestamps = [e.get("timestamp", "") for e in events if e.get("timestamp")]
    earliest = min(timestamps) if timestamps else None
    latest   = max(timestamps) if timestamps else None

    # Audit
    try:
        create_audit_entry({
            "action_type":    "script_executed",
            "source_page":    "script_library",
            "details_json":   json.dumps({
                "script_id":      "fetch_wazuh_events",
                "script_name":    "Fetch Wazuh Events",
                "hours":          req.hours,
                "limit":          req.limit,
                "host_filter":    req.host_filter,
                "events_fetched": len(events),
                "file_path":      str(out_path.relative_to(_PROJECT_ROOT)),
                "file_size_kb":   round(size_kb, 1),
            }),
        })
    except Exception:
        pass  # audit failure must not break the response

    return FetchWazuhEventsResponse(
        status="ok",
        events_fetched=len(events),
        file_path=str(out_path.relative_to(_PROJECT_ROOT)),
        file_size_kb=round(size_kb, 1),
        agents=agents,
        agent_count=len(agents),
        earliest=earliest,
        latest=latest,
        parameters_used={"hours": req.hours, "limit": req.limit, "host_filter": req.host_filter},
    )


# ── download endpoint ─────────────────────────────────────────────────────────

@router.get("/download-events")
def download_events_file(
    filename: str = Query(..., description="Filename inside the 'Example JSON' folder"),
) -> FileResponse:
    """
    Serve a previously fetched events JSON file as a browser download.
    Only files inside <project_root>/Example JSON/ are accessible.
    """
    # Sanitise: strip any path components so callers can only reach this folder
    safe_name = Path(filename).name
    if not safe_name.endswith(".json"):
        raise HTTPException(status_code=400, detail="Only .json files are available for download.")

    target = _OUTPUT_DIR / safe_name
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {safe_name}")

    return FileResponse(
        path=str(target),
        media_type="application/json",
        filename=safe_name,
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


# ── per-host helpers ──────────────────────────────────────────────────────────

def _list_agents(
    conn: dict[str, Any],
    lookback_hours: int,
) -> list[str]:
    """Return all unique agent.name values seen in the last `lookback_hours`."""
    now   = datetime.now(timezone.utc)
    start = now - timedelta(hours=lookback_hours)

    base_url      = build_base_url(conn)
    auth          = build_auth(conn)
    verify        = build_verify(conn)
    index_pattern = conn.get("indexer_index_pattern", "wazuh-alerts-*")

    payload = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"timestamp": {
                "gte": start.isoformat(),
                "lte": now.isoformat(),
                "format": "strict_date_optional_time",
            }}}
        ]}},
        "aggs": {
            "agents": {
                "terms": {"field": "agent.name", "size": 2000}
            }
        },
    }

    with httpx.Client(verify=verify, timeout=60.0, auth=auth) as client:
        resp = client.post(f"{base_url}/{index_pattern}/_search", json=payload)
        resp.raise_for_status()

    buckets = (
        resp.json()
        .get("aggregations", {})
        .get("agents", {})
        .get("buckets", [])
    )
    return [b["key"] for b in buckets if b.get("key")]


def _safe_filename(name: str) -> str:
    """Replace characters not safe in filenames with underscores."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


# ── per-host request / response models ───────────────────────────────────────

class FetchEventsPerHostRequest(BaseModel):
    hours:          int = Field(default=72,   ge=1,    le=8760,    description="Lookback window in hours")
    limit_per_host: int = Field(default=1000, ge=1,    le=100_000, description="Max events per host")


class HostFetchResult(BaseModel):
    host:           str
    events_fetched: int
    file_path:      str
    file_size_kb:   float
    status:         str        # "ok" | "error"
    error:          str | None = None


class FetchEventsPerHostResponse(BaseModel):
    status:          str
    hosts_processed: int
    total_events:    int
    results:         list[HostFetchResult]
    output_folder:   str
    timestamp:       str


# ── per-host endpoint ─────────────────────────────────────────────────────────

@router.post("/fetch-events-per-host", response_model=FetchEventsPerHostResponse)
def run_fetch_events_per_host(req: FetchEventsPerHostRequest) -> FetchEventsPerHostResponse:
    """
    Discover every agent seen in the last `hours` and fetch up to `limit_per_host`
    events for each one. Each agent gets its own JSON file named after the host:
      <project_root>/Example JSON/<hostname>_events_<timestamp>.json
    """
    conn = get_active_connection()
    if not conn:
        raise HTTPException(
            status_code=503,
            detail="No active Wazuh connection configured. Add one in Settings → Connections.",
        )

    # Discover agents
    try:
        agents = _list_agents(conn, lookback_hours=req.hours)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not list agents: {exc}") from exc

    if not agents:
        raise HTTPException(status_code=404, detail="No agents found for the selected time window.")

    _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts      = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    results: list[HostFetchResult] = []
    total   = 0

    for agent_name in agents:
        try:
            events = _fetch_paginated(
                conn=conn,
                lookback_hours=req.hours,
                total_limit=req.limit_per_host,
                host_filter=agent_name,
            )
            safe = _safe_filename(agent_name)
            out_path = _OUTPUT_DIR / f"{safe}_events_{ts}.json"
            with out_path.open("w", encoding="utf-8") as fh:
                json.dump(events, fh, ensure_ascii=False, indent=2, default=str)
            size_kb = out_path.stat().st_size / 1024
            total += len(events)
            results.append(HostFetchResult(
                host=agent_name,
                events_fetched=len(events),
                file_path=str(out_path.relative_to(_PROJECT_ROOT)),
                file_size_kb=round(size_kb, 1),
                status="ok",
            ))
        except Exception as exc:
            results.append(HostFetchResult(
                host=agent_name,
                events_fetched=0,
                file_path="",
                file_size_kb=0.0,
                status="error",
                error=str(exc),
            ))

    # Audit
    try:
        create_audit_entry({
            "action_type":  "script_executed",
            "source_page":  "script_library",
            "details_json": json.dumps({
                "script_id":      "fetch_events_per_host",
                "script_name":    "Fetch Events per Host",
                "hours":          req.hours,
                "limit_per_host": req.limit_per_host,
                "hosts":          len(agents),
                "total_events":   total,
            }),
        })
    except Exception:
        pass

    return FetchEventsPerHostResponse(
        status="ok",
        hosts_processed=len(agents),
        total_events=total,
        results=results,
        output_folder=str(_OUTPUT_DIR.relative_to(_PROJECT_ROOT)),
        timestamp=ts,
    )
