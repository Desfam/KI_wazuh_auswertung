"""Full Scan – API routes for deep host analysis."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services.baseline_service import get_baseline_diff, get_baseline_summary
from services.fullscan_service import (
    cancel_fullscan_job,
    fullscan_jobs,
    get_fullscan_result,
    get_fullscan_status,
    start_fullscan_job,
)
from services.snipen_profiles import build_profile_context_block, get_profile_for_host
from services.snipen_service import get_host_events
from db.database import get_active_connection

router = APIRouter(prefix="/fullscan", tags=["fullscan"])


class FullScanStartRequest(BaseModel):
    host: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)


@router.post("/start")
def start_fullscan(body: FullScanStartRequest):
    job_id = start_fullscan_job(body.host, body.params)
    return {"job_id": job_id}


@router.post("/cancel/{job_id}")
def fullscan_cancel(job_id: str):
    try:
        cancel_fullscan_job(job_id)
        return {"ok": True}
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")

@router.get("/status/{job_id}")
def fullscan_status(job_id: str):
    try:
        return get_fullscan_status(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")

@router.get("/result/{job_id}")
def fullscan_result(job_id: str):
    try:
        return get_fullscan_result(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Job not found")


@router.get("/debug/host/{host}/context")
def fullscan_debug_context(host: str):
    """Debug endpoint: show exactly what context the AI receives for a host."""
    try:
        profile = get_profile_for_host(host)
        profile_block = build_profile_context_block(profile)
    except Exception as exc:
        profile_block = f"Error loading profile: {exc}"

    baseline = None
    baseline_diff_block = ""
    try:
        summary = get_baseline_summary(host)
        if summary:
            baseline = {
                "computed_at": summary.computed_at,
                "window_hours": summary.window_hours,
                "total_events": summary.total_events,
                "daily_avg_events": summary.daily_avg_events,
                "high_alerts": summary.high_alerts,
                "critical_alerts": summary.critical_alerts,
                "open_deviations": summary.open_deviations,
                "top_processes": summary.top_processes[:8],
                "top_event_ids": summary.top_event_ids[:8],
                "top_users": summary.top_users[:6],
            }
            diff = get_baseline_diff(host)
            parts = []
            if diff.new_processes:
                parts.append(f"+ Neue Prozesse: {', '.join(diff.new_processes)}")
            if diff.new_services:
                parts.append(f"+ Neue Services: {', '.join(diff.new_services)}")
            if diff.new_users:
                parts.append(f"+ Neue Nutzer: {', '.join(diff.new_users)}")
            if diff.new_ips:
                parts.append(f"+ Neue IPs: {', '.join(diff.new_ips)}")
            if diff.new_event_ids:
                parts.append(f"+ Neue Event-IDs: {', '.join(diff.new_event_ids)}")
            if diff.volume_spike:
                parts.append(f"⚠ Volumen-Spike: {diff.volume_ratio:.1f}×")
            baseline_diff_block = "\n".join(parts) if parts else "Keine Abweichungen"
    except Exception as exc:
        baseline = {"error": str(exc)}

    event_count = 0
    try:
        connection = get_active_connection()
        if connection:
            events = get_host_events(connection, host=host, hours=24, limit=10, min_rule_level=0)
            event_count = len(events)
    except Exception:
        pass

    return {
        "host": host,
        "profile_assigned": profile is not None,
        "profile_name": profile.name if profile else None,
        "profile_context": profile_block,
        "baseline": baseline,
        "baseline_diff": baseline_diff_block,
        "events_last_24h_sample_count": event_count,
    }
