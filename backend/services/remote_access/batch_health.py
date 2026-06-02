"""
remote_access/batch_health.py
Batch Health Check service — Phase 1 read-only.

Runs concurrent ping / port-check / SSH health checks across a list of
server connections, respects policy per host, stores run + per-host results,
and returns a structured summary.

Rules:
- Read-only only (ping, port check, SSH health via ssh_service.health_check)
- Max concurrency default 5, hard-cap 20
- Per-host timeout: max 30 s for network tools, 45 s for SSH health
- Never hangs: all futures wrapped with timeout + exception guard
- Partial results returned if some hosts fail or are blocked
- Blocked hosts are marked status=blocked, not skipped silently
"""
from __future__ import annotations

import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from typing import Any

from db.database import get_connection, utc_now_iso
from services.remote_access.connection_store import get_connection_by_id
from services.remote_access.host_tools_service import ping_host, port_check
from services.remote_access.remote_policy import check_policy
from services.remote_access.ssh_service import health_check

_MAX_CONCURRENCY = 20
_NETWORK_TIMEOUT = 30   # seconds per future for ping/port
_SSH_TIMEOUT     = 45   # seconds per future for SSH health


# ── Single-host runner ─────────────────────────────────────────────────

def _check_single_host(
    conn: dict[str, Any],
    checks: list[str],
) -> dict[str, Any]:
    """Execute the requested checks for one connection dict.
    Returns a result dict: {status, duration_ms, result, error}
    """
    t0 = time.monotonic()
    result: dict[str, Any] = {}
    errors: list[str] = []

    target = conn.get("hostname") or conn.get("ip") or ""

    if "ping" in checks:
        try:
            pr = ping_host(target)
            result["ping"] = pr
        except Exception as exc:
            errors.append(f"ping: {exc}")

    if "port" in checks:
        default_ports: list[int] = []
        proto = (conn.get("protocol") or "ssh").lower()
        if proto == "ssh":
            default_ports = [int(conn.get("port") or 22), 22]
        elif proto == "rdp":
            default_ports = [int(conn.get("port") or 3389), 3389, 5985]
        else:
            default_ports = [int(conn.get("port") or 22)]
        check_ports = sorted(set(default_ports))[:5]
        try:
            pcr = port_check(target, check_ports)
            result["port"] = pcr
        except Exception as exc:
            errors.append(f"port: {exc}")

    if "ssh_health" in checks and (conn.get("protocol") or "ssh").lower() == "ssh":
        try:
            hr = health_check(conn)
            result["ssh_health"] = hr
        except Exception as exc:
            errors.append(f"ssh_health: {exc}")

    duration_ms = int((time.monotonic() - t0) * 1000)
    overall = "ok" if not errors else ("failed" if not result else "partial")
    return {
        "status": overall,
        "duration_ms": duration_ms,
        "result": result,
        "error": "; ".join(errors) if errors else None,
    }


# ── Store helpers ──────────────────────────────────────────────────────

def _create_run(
    group_id: str | None,
    action: str,
    created_by: str = "",
) -> str:
    run_id = str(uuid.uuid4())
    now = utc_now_iso()
    with get_connection() as db:
        db.execute(
            """
            INSERT INTO server_batch_runs (id, group_id, action, status, started_at, summary_json, created_by)
            VALUES (?, ?, ?, 'running', ?, '{}', ?)
            """,
            (run_id, group_id, action, now, created_by),
        )
    return run_id


def _finish_run(run_id: str, summary: dict[str, Any]) -> None:
    now = utc_now_iso()
    with get_connection() as db:
        db.execute(
            """
            UPDATE server_batch_runs
            SET status=?, finished_at=?, summary_json=?
            WHERE id=?
            """,
            (summary.get("status", "done"), now, json.dumps(summary), run_id),
        )


def _store_result(
    run_id: str,
    conn_id: str,
    host: str,
    status: str,
    duration_ms: int,
    result: dict[str, Any],
    error: str | None,
) -> None:
    with get_connection() as db:
        db.execute(
            """
            INSERT INTO server_batch_results
              (id, batch_run_id, connection_id, host, status, duration_ms, result_json, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()), run_id, conn_id, host,
                status, duration_ms, json.dumps(result), error,
            ),
        )


# ── Public API ─────────────────────────────────────────────────────────

def run_batch_health(
    connection_ids: list[str],
    checks: list[str] | None = None,
    concurrency: int = 5,
    group_id: str | None = None,
    created_by: str = "",
) -> dict[str, Any]:
    """
    Run health checks for a list of connection IDs.
    Returns the full run summary + per-host results.
    """
    if not checks:
        checks = ["ping", "port"]
    checks = [c for c in checks if c in ("ping", "port", "ssh_health")]
    concurrency = max(1, min(concurrency, _MAX_CONCURRENCY))

    action = "+".join(sorted(checks))
    run_id = _create_run(group_id, action, created_by)
    t0_global = time.monotonic()

    results_out: list[dict[str, Any]] = []
    ok_count = failed_count = blocked_count = 0

    # Collect connection objects first (fast, no network)
    conns_to_check: list[tuple[str, dict[str, Any] | None]] = []
    for cid in connection_ids:
        conn = get_connection_by_id(cid)
        conns_to_check.append((cid, conn))

    # Per-host policy check + run
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        future_map: dict[Any, tuple[str, dict[str, Any]]] = {}

        for cid, conn in conns_to_check:
            if conn is None:
                # Unknown connection → skip with error
                _store_result(run_id, cid, cid, "failed", 0, {}, "Connection not found")
                results_out.append({
                    "connection_id": cid, "host": cid,
                    "status": "failed", "duration_ms": 0,
                    "result": {}, "error": "Connection not found",
                })
                failed_count += 1
                continue

            target = conn.get("hostname") or conn.get("ip") or cid

            # Policy check — ping is always allowed; ssh_health needs review_required check
            if "ssh_health" in checks:
                pr = check_policy("health_check", conn)
            else:
                pr = check_policy("ping", conn)

            if pr.status == "blocked":
                _store_result(run_id, cid, target, "blocked", 0, {}, pr.policy_reason or pr.message)
                results_out.append({
                    "connection_id": cid, "host": target,
                    "status": "blocked", "duration_ms": 0,
                    "result": {}, "error": pr.policy_reason or pr.message,
                })
                blocked_count += 1
                continue

            fut = pool.submit(_check_single_host, conn, checks)
            future_map[fut] = (cid, conn)

        # Collect futures with per-future timeout
        per_fut_timeout = _SSH_TIMEOUT if "ssh_health" in checks else _NETWORK_TIMEOUT
        for fut in as_completed(future_map, timeout=per_fut_timeout * len(future_map) + 5):
            cid, conn = future_map[fut]
            target = conn.get("hostname") or conn.get("ip") or cid
            try:
                res = fut.result(timeout=per_fut_timeout)
                _store_result(run_id, cid, target, res["status"], res["duration_ms"], res["result"], res.get("error"))
                results_out.append({
                    "connection_id": cid, "host": target,
                    "status": res["status"],
                    "duration_ms": res["duration_ms"],
                    "result": res["result"],
                    "error": res.get("error"),
                })
                if res["status"] in ("ok", "partial"):
                    ok_count += 1
                else:
                    failed_count += 1
            except FuturesTimeout:
                _store_result(run_id, cid, target, "timeout", per_fut_timeout * 1000, {}, "Timed out")
                results_out.append({
                    "connection_id": cid, "host": target,
                    "status": "timeout", "duration_ms": per_fut_timeout * 1000,
                    "result": {}, "error": "Timed out",
                })
                failed_count += 1
            except Exception as exc:
                _store_result(run_id, cid, target, "failed", 0, {}, str(exc))
                results_out.append({
                    "connection_id": cid, "host": target,
                    "status": "failed", "duration_ms": 0,
                    "result": {}, "error": str(exc),
                })
                failed_count += 1

    total = ok_count + failed_count + blocked_count
    duration_ms = int((time.monotonic() - t0_global) * 1000)
    run_status = "done" if failed_count == 0 and blocked_count == 0 else "partial"
    if ok_count == 0 and total > 0:
        run_status = "failed"

    summary = {
        "status": run_status,
        "total": total,
        "ok": ok_count,
        "failed": failed_count,
        "blocked": blocked_count,
        "duration_ms": duration_ms,
    }
    _finish_run(run_id, summary)

    return {
        "status": "ok",
        "batch_run_id": run_id,
        "summary": summary,
        "results": results_out,
    }


def run_batch_health_for_group(
    group_id: str,
    checks: list[str] | None = None,
    concurrency: int = 5,
    created_by: str = "",
) -> dict[str, Any]:
    from services.remote_access.host_groups import get_group_connection_ids
    connection_ids = get_group_connection_ids(group_id)
    if not connection_ids:
        return {
            "status": "ok",
            "batch_run_id": None,
            "summary": {"status": "done", "total": 0, "ok": 0, "failed": 0, "blocked": 0, "duration_ms": 0},
            "results": [],
        }
    return run_batch_health(connection_ids, checks=checks, concurrency=concurrency, group_id=group_id, created_by=created_by)


# ── Query helpers ──────────────────────────────────────────────────────

def list_batch_runs(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as db:
        rows = db.execute(
            "SELECT * FROM server_batch_runs ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d["summary"] = json.loads(d.pop("summary_json", "{}") or "{}")
        result.append(d)
    return result


def get_batch_run(run_id: str) -> dict[str, Any] | None:
    with get_connection() as db:
        row = db.execute(
            "SELECT * FROM server_batch_runs WHERE id=?", (run_id,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    d["summary"] = json.loads(d.pop("summary_json", "{}") or "{}")
    return d


def get_batch_results(run_id: str) -> list[dict[str, Any]]:
    with get_connection() as db:
        rows = db.execute(
            "SELECT * FROM server_batch_results WHERE batch_run_id=? ORDER BY host ASC",
            (run_id,),
        ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d["result"] = json.loads(d.pop("result_json", "{}") or "{}")
        result.append(d)
    return result
