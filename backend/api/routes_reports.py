from fastapi import APIRouter, HTTPException

from db.database import get_analysis_job, get_latest_job_id, list_reports
from schemas.types import ReportRecord

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/latest")
@router.get("")
def get_reports() -> list[ReportRecord]:
    return [ReportRecord(**item) for item in list_reports()]


@router.get("/latest")
def latest_report() -> ReportRecord:
    job_id = get_latest_job_id()
    if not job_id:
        raise HTTPException(status_code=404, detail="No reports available")
    job = get_analysis_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Latest report could not be loaded")
    return ReportRecord(
        id=job["id"],
        job_id=job["id"],
        created_at=job["completed_at"] or job["started_at"],
        markdown=job.get("report_markdown") or "",
        report_json=job.get("report_json") or "{}",
    )


@router.get("/{report_id}")
def get_report(report_id: int) -> ReportRecord:
    for report in list_reports():
        if report["id"] == report_id:
            return ReportRecord(**report)
    raise HTTPException(status_code=404, detail="Report not found")
