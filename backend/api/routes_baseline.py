"""Host Baseline API routes."""
from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, HTTPException

from db.database import get_active_connection
from schemas.types import (
    BaselineComputeRequest,
    BaselineDeviation,
    BaselineDiff,
    BaselineFeature,
    BaselineSnapshot,
    BaselineSummary,
)
from services.baseline_service import (
    compute_baseline,
    get_baseline_diff,
    get_baseline_summary,
    get_deviations,
    get_features,
    get_latest_snapshot,
    list_snapshots,
    resolve_deviation,
)

router = APIRouter(prefix="/baseline", tags=["baseline"])


def _require_connection() -> dict:
    conn = get_active_connection()
    if not conn:
        raise HTTPException(status_code=503, detail="No active Wazuh connection configured.")
    return conn


# ── Snapshot endpoints ────────────────────────────────────────────────────────

@router.post("/{host}/compute")
def baseline_compute(
    host: str,
    body: BaselineComputeRequest = BaselineComputeRequest(),
    background_tasks: BackgroundTasks = BackgroundTasks(),
) -> BaselineSnapshot:
    """
    Trigger a baseline computation for *host*.  Fetches events from Wazuh,
    aggregates Top-N counters, persists the snapshot, upserts features, and
    logs any newly detected deviations.
    """
    connection = _require_connection()
    try:
        return compute_baseline(host, connection, window_hours=body.window_hours)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/{host}/latest")
def baseline_latest(host: str) -> BaselineSnapshot:
    """Return the most recent baseline snapshot for *host*."""
    snap = get_latest_snapshot(host)
    if snap is None:
        raise HTTPException(status_code=404, detail="No baseline computed yet for this host.")
    return snap


@router.get("/{host}/history")
def baseline_history(host: str, limit: int = 10) -> list[BaselineSnapshot]:
    """Return the last *limit* baseline snapshots for *host*."""
    return list_snapshots(host, limit=min(limit, 50))


@router.get("/{host}/summary")
def baseline_summary(host: str) -> BaselineSummary:
    """Return a compact summary (for AI prompts / UI cards)."""
    summary = get_baseline_summary(host)
    if summary is None:
        raise HTTPException(status_code=404, detail="No baseline computed yet for this host.")
    return summary


# ── Feature endpoints ─────────────────────────────────────────────────────────

@router.get("/{host}/features")
def baseline_features(host: str, feature_type: str | None = None) -> list[BaselineFeature]:
    """
    Return all tracked baseline features for *host*.
    Optionally filter by *feature_type* (process, user, event_id, ip, service_name, event_family).
    """
    return get_features(host, feature_type=feature_type)


# ── Deviation endpoints ───────────────────────────────────────────────────────

@router.get("/{host}/deviations")
def baseline_deviations(host: str, unresolved_only: bool = True) -> list[BaselineDeviation]:
    """Return deviations detected for *host*."""
    return get_deviations(host, unresolved_only=unresolved_only)


@router.post("/deviations/{deviation_id}/resolve")
def baseline_resolve_deviation(deviation_id: int) -> dict[str, str]:
    """Mark a deviation as resolved."""
    ok = resolve_deviation(deviation_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Deviation not found.")
    return {"status": "resolved"}


# ── Diff endpoint ─────────────────────────────────────────────────────────────

@router.get("/{host}/diff")
def baseline_diff(host: str) -> BaselineDiff:
    """
    Return a structured diff of the host's current deviations vs baseline:
    new processes / users / services / IPs / event IDs, volume spike flag,
    and the top-risk open deviations.  Useful for AI summary prompts.
    """
    return get_baseline_diff(host)

