"""Fleet Scan – parallel multi-host scan with asyncio + Semaphore.

Architecture:
  Phase 1 (collect): all hosts queried in parallel (max MAX_CONCURRENT = 6)
  Phase 2 (analyze): risk-score aggregation + fleet-level correlation
  Result:  per-host summary + fleet stats
"""
from __future__ import annotations

import asyncio
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from db.database import get_active_connection
from services.fullscan_service import (
    FullScanJob,
    fullscan_jobs,
    run_fullscan_job,
)

# ─────────────────────────────────────────────────────────────────
MAX_CONCURRENT: int = 6
# ─────────────────────────────────────────────────────────────────

fleet_scan_jobs: dict[str, "FleetScanJob"] = {}


class FleetScanJob:
    def __init__(self, hosts: list[str], params: dict[str, Any]):
        self.id = str(uuid.uuid4())
        self.hosts = hosts
        self.params = params
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.started_at = datetime.utcnow().strftime("%H:%M:%S")
        self.status = "running"
        self.total_hosts = len(hosts)
        self.finished_hosts = 0
        self.failed_hosts = 0
        self.skipped_hosts = 0
        self.current_phase = "starting"
        self.active_hosts: list[str] = []
        self.log: list[str] = []
        self.host_results: dict[str, dict[str, Any]] = {}
        self.host_scan_job_ids: dict[str, str] = {}   # host → fullscan job_id (live)
        self.top_findings: list[dict[str, Any]] = []  # accumulated, deduplicated
        self.cancel_requested = False

    def add_log(self, msg: str) -> None:
        now = datetime.utcnow().strftime("%H:%M:%S")
        self.log.append(f"[{now}] {msg}")

    def get_host_statuses(self) -> dict[str, dict[str, Any]]:
        """Per-host live status, reads from individual FullScanJobs while running."""
        statuses: dict[str, dict[str, Any]] = {}
        for host in self.hosts:
            job_id = self.host_scan_job_ids.get(host)
            if job_id and job_id in fullscan_jobs:
                hj = fullscan_jobs[job_id]
                statuses[host] = {
                    "status": "scanning" if hj.status == "running" else hj.status,
                    "progress": round(hj.progress, 1),
                    "findings": hj.findings_count,
                    "high_findings": hj.high_findings,
                    "risk_score": round(hj.risk_score, 1) if hj.status != "running" else None,
                    "active_module": hj.active_module,
                    "ti_matches": hj.ti_matches,
                    "total_events": hj.total_events,
                }
            elif host in self.host_results:
                r = self.host_results[host]
                statuses[host] = {
                    "status": "done" if r.get("status") == "finished" else r.get("status", "done"),
                    "progress": 100.0,
                    "findings": r.get("findings_count", 0),
                    "high_findings": r.get("high_findings", 0),
                    "risk_score": r.get("risk_score", 0),
                    "active_module": None,
                    "ti_matches": r.get("ti_matches", 0),
                    "total_events": r.get("total_events", 0),
                }
            else:
                statuses[host] = {
                    "status": "queued",
                    "progress": 0.0,
                    "findings": 0,
                    "high_findings": 0,
                    "risk_score": None,
                    "active_module": None,
                    "ti_matches": 0,
                    "total_events": 0,
                }
        return statuses

    def to_status(self) -> dict[str, Any]:
        progress = (
            round((self.finished_hosts + self.failed_hosts + self.skipped_hosts) / max(1, self.total_hosts) * 100, 1)
            if self.total_hosts else 100.0
        )
        host_statuses = self.get_host_statuses()
        # live aggregates from per-host data
        live_findings = sum(v.get("findings", 0) for v in host_statuses.values())
        live_high = sum(v.get("high_findings", 0) for v in host_statuses.values())
        live_critical = sum(
            1 for v in host_statuses.values()
            if v.get("risk_score") is not None and v["risk_score"] >= 80
        )
        completed_scores = [v["risk_score"] for v in host_statuses.values() if v.get("risk_score") is not None]
        fleet_risk = round(sum(completed_scores) / len(completed_scores), 1) if completed_scores else 0.0
        return {
            "job_id": self.id,
            "status": self.status,
            "progress": progress,
            "total_hosts": self.total_hosts,
            "finished_hosts": self.finished_hosts,
            "failed_hosts": self.failed_hosts,
            "current_phase": self.current_phase,
            "active_hosts": self.active_hosts,
            "log": self.log[-50:],
            "host_statuses": host_statuses,
            "top_findings": self.top_findings[:20],
            "started_at": self.started_at,
            "params": self.params,
            "live_stats": {
                "total_findings": live_findings,
                "high_findings": live_high,
                "critical_hosts": live_critical,
                "fleet_risk_score": fleet_risk,
            },
        }

    def to_result(self) -> dict[str, Any]:
        """Build the final fleet result dict."""
        summaries = list(self.host_results.values())

        # fleet aggregations
        total_findings = sum(s.get("findings_count", 0) for s in summaries)
        total_high = sum(s.get("high_findings", 0) for s in summaries)
        total_events = sum(s.get("total_events", 0) for s in summaries)
        total_ti = sum(s.get("ti_matches", 0) for s in summaries)

        # risk distribution
        risk_critical = sum(1 for s in summaries if s.get("risk_score", 0) >= 80)
        risk_high = sum(1 for s in summaries if 60 <= s.get("risk_score", 0) < 80)
        risk_medium = sum(1 for s in summaries if 40 <= s.get("risk_score", 0) < 60)
        risk_low = sum(1 for s in summaries if s.get("risk_score", 0) < 40)

        # top risky hosts
        top_hosts = sorted(summaries, key=lambda s: s.get("risk_score", 0), reverse=True)[:10]

        avg_risk = (
            round(sum(s.get("risk_score", 0) for s in summaries) / len(summaries), 1)
            if summaries else 0.0
        )

        # unique IPs across all hosts (from threat intel matches)
        all_ioc_hosts = [s.get("host") for s in summaries if s.get("ti_matches", 0) > 0]

        return {
            "fleet_job_id": self.id,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "total_hosts": self.total_hosts,
            "finished_hosts": self.finished_hosts,
            "failed_hosts": self.failed_hosts,
            "params": self.params,
            "fleet_stats": {
                "total_findings": total_findings,
                "total_high_findings": total_high,
                "total_events": total_events,
                "total_ti_matches": total_ti,
                "avg_risk_score": avg_risk,
                "risk_critical": risk_critical,
                "risk_high": risk_high,
                "risk_medium": risk_medium,
                "risk_low": risk_low,
                "ioc_hosts": all_ioc_hosts,
            },
            "top_risk_hosts": top_hosts,
            "host_results": self.host_results,
        }


def start_fleet_scan(hosts: list[str], params: dict[str, Any]) -> str:
    job = FleetScanJob(hosts, params)
    fleet_scan_jobs[job.id] = job
    t = threading.Thread(target=_run_fleet_scan_sync, args=(job,), daemon=True)
    t.start()
    return job.id


def cancel_fleet_scan(job_id: str) -> None:
    job = fleet_scan_jobs[job_id]
    job.cancel_requested = True
    job.add_log("Abbruch angefordert")
    # also cancel any running host jobs
    for host_job_id in list(fullscan_jobs):
        hj = fullscan_jobs[host_job_id]
        if hj.status == "running" and hj.host in job.hosts:
            hj.cancel_requested = True


def get_fleet_scan_status(job_id: str) -> dict[str, Any]:
    return fleet_scan_jobs[job_id].to_status()


def get_fleet_scan_result(job_id: str) -> dict[str, Any]:
    return fleet_scan_jobs[job_id].to_result()


# ─────────────────────────── internals ───────────────────────────

def _run_fleet_scan_sync(fleet_job: FleetScanJob) -> None:
    """Entry point run in a background thread; bridges sync→async."""
    try:
        asyncio.run(_run_fleet_scan_async(fleet_job))
    except Exception as exc:
        fleet_job.status = "failed"
        fleet_job.add_log(f"Kritischer Fehler: {exc}")


async def _run_fleet_scan_async(fleet_job: FleetScanJob) -> None:
    fleet_job.current_phase = "collecting"
    fleet_job.add_log(
        f"Fleet-Scan gestartet: {fleet_job.total_hosts} Hosts, "
        f"Parallelität {MAX_CONCURRENT}, Modus {fleet_job.params.get('mode', 'quick')}"
    )

    sem = asyncio.Semaphore(MAX_CONCURRENT)

    async def scan_one(host: str) -> None:
        if fleet_job.cancel_requested:
            fleet_job.skipped_hosts += 1
            return

        async with sem:
            if fleet_job.cancel_requested:
                fleet_job.skipped_hosts += 1
                return

            fleet_job.active_hosts.append(host)
            fleet_job.add_log(f"→ Starte Scan: {host}")

            # Create the host job BEFORE running so its ID is visible in get_host_statuses()
            hj = FullScanJob(host, fleet_job.params)
            fullscan_jobs[hj.id] = hj
            fleet_job.host_scan_job_ids[host] = hj.id

            try:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, _run_host_job, hj
                )
                fleet_job.host_results[host] = result
                fleet_job.finished_hosts += 1
                fleet_job.add_log(
                    f"✓ {host}  Risk={result.get('risk_score', 0):.0f}  "
                    f"Findings={result.get('findings_count', 0)}  "
                    f"High={result.get('high_findings', 0)}"
                )
                # accumulate top findings (deduplicated by title)
                for f in result.get("top_findings", []):
                    title = f.get("title") or f.get("description", "")
                    existing = next((x for x in fleet_job.top_findings if x.get("title") == title), None)
                    if existing:
                        if host not in existing["hosts"]:
                            existing["hosts"].append(host)
                        existing["seen_on"] = len(existing["hosts"])
                    else:
                        fleet_job.top_findings.append({
                            **f,
                            "hosts": [host],
                            "seen_on": 1,
                        })
                # re-sort by severity
                sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                fleet_job.top_findings.sort(
                    key=lambda x: (sev_order.get(str(x.get("severity", "")).lower(), 5), -x.get("seen_on", 1))
                )
            except Exception as exc:
                fleet_job.failed_hosts += 1
                fleet_job.host_results[host] = {
                    "host": host,
                    "status": "failed",
                    "error": str(exc),
                    "risk_score": 0,
                    "findings_count": 0,
                    "high_findings": 0,
                    "total_events": 0,
                    "ti_matches": 0,
                }
                fleet_job.add_log(f"✗ {host}: {exc}")
            finally:
                if host in fleet_job.active_hosts:
                    fleet_job.active_hosts.remove(host)

    tasks = [scan_one(host) for host in fleet_job.hosts]
    await asyncio.gather(*tasks)

    fleet_job.current_phase = "analyzing"
    fleet_job.add_log("Alle Hosts abgeschlossen — berechne Fleet-Auswertung…")
    await asyncio.sleep(0.1)  # yield so status updates flush

    fleet_job.current_phase = "done"
    fleet_job.status = "finished"
    fleet_job.add_log(
        f"Fleet-Scan abgeschlossen: {fleet_job.finished_hosts} OK, "
        f"{fleet_job.failed_hosts} Fehler, {fleet_job.skipped_hosts} übersprungen"
    )


def _run_host_job(hj: FullScanJob) -> dict[str, Any]:
    """Run a pre-created FullScanJob (blocking) and return a compact summary."""
    run_fullscan_job(hj)
    return {
        "host": hj.host,
        "job_id": hj.id,
        "status": hj.status,
        "risk_score": round(hj.risk_score, 1),
        "findings_count": hj.findings_count,
        "high_findings": hj.high_findings,
        "ti_matches": hj.ti_matches,
        "total_events": hj.total_events,
        "relevant_events": hj.relevant_events,
        "suspicious_events": hj.suspicious_events,
        "profile_name": hj.profile_name,
        "ai_summary": hj.ai_final_summary,
        "top_findings": hj.findings[:8] if hj.findings else [],
        "log_tail": hj.log[-5:] if hj.log else [],
        "scan_time": hj.end_time.isoformat() if hj.end_time else None,
    }
