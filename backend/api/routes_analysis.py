import threading

from fastapi import APIRouter, HTTPException

from db.database import (
    create_analysis_job,
    get_active_connection,
    get_analysis_job,
    get_findings_for_job,
    list_analysis_jobs,
    list_reports,
    update_analysis_job,
)
from schemas.types import AnalysisJobRecord, AnalysisRunRequest, FindingGroupRecord, ReportRecord
from services.app_config import load_analysis_profile_from_config
from services.analysis_engine import run_analysis_job
from services.remote_vm_script import run_remote_analysis_job

router = APIRouter(prefix="/analysis", tags=["analysis"])


def _execute_analysis(job_id: int, connection: dict, payload: AnalysisRunRequest) -> None:
    """Run analysis in a background thread; updates job record on completion or failure."""
    try:
        if payload.mode == "vm-script":
            summary = run_remote_analysis_job(job_id=job_id, connection=connection, request=payload)
        else:
            summary = run_analysis_job(job_id=job_id, connection=connection, request=payload)
        update_analysis_job(
            job_id,
            status="completed",
            completed_at=summary["completed_at"],
            total_alerts=summary["total_alerts"],
            relevant_alerts=summary["relevant_alerts"],
            report_markdown=summary["report_markdown"],
            report_json=summary["report_json"],
            error_message=None,
        )
    except Exception as exc:
        update_analysis_job(job_id, status="failed", error_message=str(exc))


@router.post("/run")
def run_analysis(payload: AnalysisRunRequest) -> AnalysisJobRecord:
    """Start an analysis job asynchronously. Returns the job record immediately
    with status='running'; poll GET /analysis/jobs/{job_id} for completion."""
    connection = get_active_connection()
    if not connection:
        raise HTTPException(status_code=404, detail="No active connection configured")

    profile = load_analysis_profile_from_config()
    if payload.event_ids is None and profile.event_ids:
        payload.event_ids = profile.event_ids
    if payload.min_rule_level is None:
        payload.min_rule_level = profile.min_rule_level
    if payload.max_findings is None:
        payload.max_findings = profile.max_findings
    if payload.max_events_per_host is None:
        payload.max_events_per_host = profile.max_events_per_host

    job_id = create_analysis_job(connection_id=connection["id"], lookback_hours=payload.lookback_hours)

    t = threading.Thread(target=_execute_analysis, args=(job_id, connection, payload), daemon=True)
    t.start()

    job = get_analysis_job(job_id)
    if not job:
        raise HTTPException(status_code=500, detail="Analysis job could not be created")
    return AnalysisJobRecord(**job)


@router.get("/jobs")
def get_jobs() -> list[AnalysisJobRecord]:
    return [AnalysisJobRecord(**item) for item in list_analysis_jobs()]


@router.get("/jobs/{job_id}")
def get_job(job_id: int) -> AnalysisJobRecord:
    job = get_analysis_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return AnalysisJobRecord(**job)


@router.get("/jobs/{job_id}/findings")
def get_job_findings(job_id: int) -> list[FindingGroupRecord]:
    return [FindingGroupRecord(**item) for item in get_findings_for_job(job_id)]


@router.get("/jobs/{job_id}/report")
def get_job_report(job_id: int) -> ReportRecord:
    job = get_analysis_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return ReportRecord(
        id=job["id"],
        job_id=job["id"],
        created_at=job["completed_at"] or job["started_at"],
        markdown=job.get("report_markdown") or "",
        report_json=job.get("report_json") or "{}",
    )


@router.get("/reports")
def get_analysis_reports() -> list[ReportRecord]:
    return [ReportRecord(**item) for item in list_reports()]
