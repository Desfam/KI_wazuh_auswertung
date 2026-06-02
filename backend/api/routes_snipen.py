"""Snipen – Host-centric Threat Hunting API routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from db.database import get_active_connection
from schemas.types import (
    SnipenAIQueryRequest,
    SnipenAIQueryResult,
    SnipenAnalysisResult,
    SnipenAnalyzeRequest,
    SnipenEvent,
    SnipenExplainContextRequest,
    SnipenExplainRequest,
    SnipenExplainResult,
    SnipenHostInfo,
    SnipenHostOverview,
    SnipenRelatedRequest,
    SnipenRemediateRequest,
)
from services.snipen_service import (
    ai_query_host,
    analyze_host,
    explain_event,
    explain_event_with_context,
    get_all_events,
    get_host_events,
    get_host_snipen_overview,
    get_related_events,
    get_snipen_hosts,
    remediate_event,
)

router = APIRouter(prefix="/snipen", tags=["snipen"])


def _get_active_connection_dict() -> dict[str, Any]:
    record = get_active_connection()
    if not record:
        raise HTTPException(status_code=503, detail="No active connection configured")
    return dict(record)


@router.get("/hosts")
def snipen_hosts(
    hours: int = Query(default=24, ge=1, le=168),
) -> list[SnipenHostInfo]:
    """Return all agent/host names with alert counts from the indexer."""
    conn = _get_active_connection_dict()
    try:
        return get_snipen_hosts(conn, hours=hours)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/host/{host}/events")
def snipen_host_events(
    host: str,
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=500, ge=10, le=100000),
    platform: str | None = Query(default=None, description="windows or linux"),
    min_rule_level: int | None = Query(default=None, ge=0, le=20),
    category: str | None = Query(default=None, description="auth|process|service|registry|powershell|network"),
    event_ids: str | None = Query(default=None, description="Comma-separated Windows event IDs"),
) -> list[SnipenEvent]:
    """Fetch recent events for a specific host."""
    conn = _get_active_connection_dict()
    ids_filter = [e.strip() for e in event_ids.split(",") if e.strip()] if event_ids else None
    try:
        return get_host_events(
            conn,
            host=host,
            hours=hours,
            limit=limit,
            platform_filter=platform,
            min_rule_level=min_rule_level,
            category_filter=category,
            event_ids_filter=ids_filter,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/events")
def snipen_all_events(
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=500, ge=10, le=100000),
    min_rule_level: int | None = Query(default=None, ge=0, le=20),
    category: str | None = Query(default=None, description="auth|process|service|registry|powershell|network"),
) -> list[SnipenEvent]:
    """Fetch recent events across ALL hosts for the given time window."""
    conn = _get_active_connection_dict()
    try:
        return get_all_events(
            conn,
            hours=hours,
            limit=limit,
            min_rule_level=min_rule_level,
            category_filter=category,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/host/{host}/overview")
def snipen_host_overview(
    host: str,
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=500, ge=10, le=2000),
    buckets: int = Query(default=24, ge=4, le=96),
) -> SnipenHostOverview:
    """
    Return a pre-computed host overview: severity distribution, top counters
    (event IDs, rule IDs, processes, users, IPs) and a bucketed event timeline.
    No AI – fast and lightweight.
    """
    conn = _get_active_connection_dict()
    try:
        return get_host_snipen_overview(
            conn,
            host=host,
            hours=hours,
            limit=limit,
            num_timeline_buckets=buckets,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/host/{host}/analyze")
def snipen_analyze_host(
    host: str,
    body: SnipenAnalyzeRequest,
) -> SnipenAnalysisResult:
    """Fetch events for a host and run an AI threat assessment."""
    conn = _get_active_connection_dict()
    try:
        return analyze_host(
            conn,
            host=host,
            hours=body.hours,
            limit=body.limit,
            windows_only=body.windows_only,
            linux_only=body.linux_only,
            include_noise=body.include_noise,
            run_ai=body.run_ai,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/event/explain")
def snipen_explain_event(body: SnipenExplainRequest) -> SnipenExplainResult:
    """Ask the AI to explain a single Wazuh event."""
    conn = _get_active_connection_dict()
    return explain_event(conn, body.event_raw)


@router.post("/event/remediate")
def snipen_remediate_event(body: SnipenRemediateRequest) -> SnipenExplainResult:
    """Ask the AI for remediation steps for a single Wazuh event."""
    conn = _get_active_connection_dict()
    return remediate_event(conn, body.event_raw)


@router.post("/event/explain-context")
def snipen_explain_event_with_context(body: SnipenExplainContextRequest) -> SnipenExplainResult:
    """Context-aware explain: fetches ±15-min surrounding events and enriches the AI analysis."""
    conn = _get_active_connection_dict()
    return explain_event_with_context(conn, body.event_raw)


@router.post("/event/related")
def snipen_related_events(body: SnipenRelatedRequest) -> list[SnipenEvent]:
    """Find events related to the given event (same host/rule/user/IP/process)."""
    conn = _get_active_connection_dict()
    try:
        return get_related_events(conn, body.event_raw, limit=body.limit, hours=body.hours)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc



@router.post("/host/{host}/ai-query")
def snipen_ai_query(host: str, body: SnipenAIQueryRequest) -> SnipenAIQueryResult:
    """Run a natural language threat hunting query over a host's events."""
    conn = _get_active_connection_dict()
    try:
        return ai_query_host(conn, host=host, query=body.query, hours=body.hours, limit=body.limit)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
