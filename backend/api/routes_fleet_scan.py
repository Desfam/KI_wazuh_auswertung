"""Fleet Scan – API routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services.fleet_scan_service import (
    cancel_fleet_scan,
    fleet_scan_jobs,
    get_fleet_scan_result,
    get_fleet_scan_status,
    start_fleet_scan,
)

router = APIRouter(prefix="/fleet-scan", tags=["fleet-scan"])


class FleetScanStartRequest(BaseModel):
    hosts: list[str] = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)


@router.post("/start")
def fleet_scan_start(body: FleetScanStartRequest):
    if not body.hosts:
        raise HTTPException(status_code=400, detail="No hosts provided")
    job_id = start_fleet_scan(body.hosts, body.params)
    return {"job_id": job_id, "total_hosts": len(body.hosts)}


@router.get("/status/{job_id}")
def fleet_scan_status(job_id: str):
    if job_id not in fleet_scan_jobs:
        raise HTTPException(status_code=404, detail="Fleet job not found")
    return get_fleet_scan_status(job_id)


@router.get("/result/{job_id}")
def fleet_scan_result(job_id: str):
    if job_id not in fleet_scan_jobs:
        raise HTTPException(status_code=404, detail="Fleet job not found")
    job = fleet_scan_jobs[job_id]
    if job.status not in ("finished", "failed"):
        raise HTTPException(status_code=409, detail="Job not finished yet")
    return get_fleet_scan_result(job_id)


@router.post("/cancel/{job_id}")
def fleet_scan_cancel(job_id: str):
    if job_id not in fleet_scan_jobs:
        raise HTTPException(status_code=404, detail="Fleet job not found")
    cancel_fleet_scan(job_id)
    return {"ok": True}
