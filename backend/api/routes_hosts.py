from fastapi import APIRouter, HTTPException, Query

from db.database import get_host_findings, get_host_overview, get_host_trend, get_latest_job_id, get_ranked_hosts
from schemas.types import FindingGroupRecord, HostOverviewResponse, HostRankingRecord, HostTrendPoint

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("/ranking")
def hosts_ranking(job_id: int | None = Query(default=None)) -> list[HostRankingRecord]:
    resolved_job_id = job_id or get_latest_job_id()
    if not resolved_job_id:
        return []
    return [HostRankingRecord(**item) for item in get_ranked_hosts(resolved_job_id)]


@router.get("/{host}/findings")
def host_findings(host: str, job_id: int | None = Query(default=None)) -> list[FindingGroupRecord]:
    resolved_job_id = job_id or get_latest_job_id()
    if not resolved_job_id:
        raise HTTPException(status_code=404, detail="No analysis job available")
    return [FindingGroupRecord(**item) for item in get_host_findings(resolved_job_id, host)]


@router.get("/{host}/overview")
def host_overview(host: str, job_id: int | None = Query(default=None)) -> HostOverviewResponse:
    resolved_job_id = job_id or get_latest_job_id()
    if not resolved_job_id:
        raise HTTPException(status_code=404, detail="No analysis job available")
    payload = get_host_overview(resolved_job_id, host)
    if not payload:
        raise HTTPException(status_code=404, detail="No findings for host")
    return HostOverviewResponse(**payload)


@router.get("/{host}/trend")
def host_trend(host: str, limit: int = Query(default=14, ge=1, le=90)) -> list[HostTrendPoint]:
    return [HostTrendPoint(**item) for item in get_host_trend(host, limit=limit)]
