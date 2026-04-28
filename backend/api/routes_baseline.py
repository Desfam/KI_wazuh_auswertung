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
from db.database import get_connection

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


# ── Global deviation endpoints ────────────────────────────────────────────────

@router.get("/global/deviations")
def baseline_global_deviations(
    unresolved_only: bool = True,
    limit: int = 200,
    classification: str | None = None,
) -> list[BaselineDeviation]:
    """Return deviations across ALL hosts, optionally filtered by classification.

    Intended for the Server tab and global dashboards.
    Query params:
      - unresolved_only: default True
      - limit: max rows returned, default 200
      - classification: filter to a specific final_classification value
    """
    import json as _json
    from services.baseline_service import _row_to_deviation

    limit = max(1, min(limit, 1000))
    with get_connection() as conn:
        if unresolved_only:
            if classification:
                rows = conn.execute(
                    "SELECT * FROM host_baseline_deviations "
                    "WHERE resolved = 0 AND final_classification = ? "
                    "ORDER BY risk_score DESC, detected_at DESC LIMIT ?",
                    (classification, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM host_baseline_deviations "
                    "WHERE resolved = 0 "
                    "ORDER BY risk_score DESC, detected_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        else:
            if classification:
                rows = conn.execute(
                    "SELECT * FROM host_baseline_deviations "
                    "WHERE final_classification = ? "
                    "ORDER BY risk_score DESC, detected_at DESC LIMIT ?",
                    (classification, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM host_baseline_deviations "
                    "ORDER BY risk_score DESC, detected_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
    return [_row_to_deviation(r) for r in rows]


@router.get("/global/summary")
def baseline_global_summary() -> dict:
    """Cross-host baseline summary for Server tab widgets."""
    with get_connection() as conn:
        # Totals
        total_row = conn.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN resolved=0 THEN 1 ELSE 0 END) AS open, "
            "SUM(CASE WHEN resolved=0 AND risk_score>=75 THEN 1 ELSE 0 END) AS critical, "
            "SUM(CASE WHEN resolved=0 AND final_classification='known_but_suspicious' THEN 1 ELSE 0 END) AS suspicious, "
            "SUM(CASE WHEN resolved=0 AND final_classification='needs_investigation' THEN 1 ELSE 0 END) AS investigate, "
            "SUM(CASE WHEN resolved=0 AND final_classification='escalated' THEN 1 ELSE 0 END) AS escalated "
            "FROM host_baseline_deviations"
        ).fetchone()

        # Per-classification breakdown
        cls_rows = conn.execute(
            "SELECT final_classification, COUNT(*) AS cnt "
            "FROM host_baseline_deviations WHERE resolved=0 "
            "GROUP BY final_classification ORDER BY cnt DESC"
        ).fetchall()

        # Top affected hosts
        host_rows = conn.execute(
            "SELECT host, COUNT(*) AS open_devs, MAX(risk_score) AS top_score "
            "FROM host_baseline_deviations WHERE resolved=0 "
            "GROUP BY host ORDER BY top_score DESC, open_devs DESC LIMIT 10"
        ).fetchall()

        # Deviation type breakdown
        type_rows = conn.execute(
            "SELECT deviation_type, COUNT(*) AS cnt "
            "FROM host_baseline_deviations WHERE resolved=0 "
            "GROUP BY deviation_type ORDER BY cnt DESC"
        ).fetchall()

    return {
        "total": total_row["total"] or 0,
        "open": total_row["open"] or 0,
        "critical": total_row["critical"] or 0,
        "suspicious": total_row["suspicious"] or 0,
        "needs_investigation": total_row["investigate"] or 0,
        "escalated": total_row["escalated"] or 0,
        "by_classification": {r["final_classification"]: r["cnt"] for r in cls_rows},
        "top_hosts": [{"host": r["host"], "open_devs": r["open_devs"], "top_score": r["top_score"]} for r in host_rows],
        "by_type": {r["deviation_type"]: r["cnt"] for r in type_rows},
    }

