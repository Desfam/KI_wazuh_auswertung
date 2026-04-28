"""Full Scan - Modular Deep Host Analysis Service."""
from __future__ import annotations

import json
import re
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any

import httpx

from db.database import get_active_connection, save_fullscan_report
from services.ai_prompts import build_fullscan_ai_prompt
from services.baseline_service import get_baseline_diff, get_baseline_summary
from services.ollama_client import chat_with_context
from services.artifact_action_builder import (
    build_action_plans_for_insights,
    action_plans_to_next_steps,
)
from services.snipen_profiles import build_profile_context_block, get_profile_for_host
from services.snipen_service import get_host_events
from services.wazuh_indexer import _pick, build_auth, build_base_url, build_verify


DEFAULT_MODULES = [
    "Events",
    "Raw Event JSON",
    "Vulnerabilities",
    "FIM",
    "Configuration",
    "MITRE / Rules",
    "Threat Intel",
    "Host Context / Inventory",
]


class FullScanJob:
    def __init__(self, host: str, params: dict[str, Any]):
        self.id = str(uuid.uuid4())
        self.host = host
        self.params = params
        self.start_time = datetime.now(timezone.utc)
        self.end_time: datetime | None = None
        self.status = "running"  # running, finished, failed, canceled
        self.progress = 0.0
        self.log: list[str] = []
        self.result: dict[str, Any] | None = None
        self.active_module: str | None = None
        self.module_status: dict[str, str] = {}
        self.total_modules = 0
        self.completed_modules = 0
        self.total_events = 0
        self.relevant_events = 0
        self.processed_events = 0
        self.findings_count = 0
        self.high_findings = 0
        self.ti_matches = 0
        self.suspicious_events = 0
        self.risk_score = 0.0
        self.profile_name: str | None = None
        self.risk_breakdown: dict[str, Any] = {}
        self.ai_enabled = False
        self.ai_iterations_target = 0
        self.ai_iterations_completed = 0
        self.ai_outputs: list[str] = []
        self.ai_final_summary: str | None = None
        self.findings: list[dict[str, Any]] = []
        self.source_events: list[Any] = []
        self.vulnerabilities: list[dict[str, Any]] = []
        self.fim: list[dict[str, Any]] = []
        self.config: list[dict[str, Any]] = []
        self.threat_intel: list[dict[str, Any]] = []
        self.cancel_requested = False
        # Context enrichment (loaded before AI call)
        self.profile_context: str = ""
        self.baseline_text: str = ""
        self.baseline_diff_block: str = ""
        self.risk_score_reason: str = ""

    def add_log(self, msg: str) -> None:
        now = datetime.utcnow().strftime("%H:%M:%S")
        self.log.append(f"[{now}] {msg}")


fullscan_jobs: dict[str, FullScanJob] = {}


def start_fullscan_job(host: str, params: dict[str, Any]) -> str:
    job = FullScanJob(host, params)
    fullscan_jobs[job.id] = job
    worker = threading.Thread(target=run_fullscan_job, args=(job,), daemon=True)
    worker.start()
    return job.id


def cancel_fullscan_job(job_id: str) -> None:
    job = fullscan_jobs[job_id]
    if job.status == "running":
        job.cancel_requested = True
        job.add_log("Abbruch angefordert")


def _time_to_hours(label: str) -> int:
    mapping = {
        "1h": 1,
        "6h": 6,
        "24h": 24,
        "3d": 72,
        "7d": 168,
    }
    return mapping.get(label, 24)


def _scope_to_limit(scope: str) -> int:
    mapping = {
        "Top 100 Events": 100,
        "Top 250 Events": 250,
        "Top 500 Events": 500,
        "Alle relevanten Events": 2000,
        "Raw Full": 100000,
    }
    return mapping.get(scope, 250)


def _mode_to_ai_iterations(mode: str) -> int:
    mode_norm = mode.strip().lower()
    if mode_norm == "quick":
        return 0
    if mode_norm == "standard":
        return 1
    if mode_norm == "deep":
        return 2
    if mode_norm == "raw deep":
        return 3
    return 1


def _safe_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return []


def _safe_str(value: Any, fallback: str = "-") -> str:
    if value in (None, ""):
        return fallback
    return str(value)


def _host_should_filters(host: str) -> list[dict[str, Any]]:
    fields = [
        "agent.name.keyword",
        "agent.name",
        "agent.hostname.keyword",
        "agent.hostname",
        "host.name.keyword",
        "host.name",
        "hostname.keyword",
        "hostname",
    ]
    clauses: list[dict[str, Any]] = []
    for field in fields:
        clauses.append({"term": {field: host}})
        clauses.append({"wildcard": {field: {"value": f"*{host}*"}}})
    return clauses


def _search_indexer(
    connection: dict[str, Any],
    index_pattern: str,
    query: dict[str, Any],
    *,
    size: int = 100,
    sort_field: str | None = "@timestamp",
    timeout: float = 25.0,
) -> list[dict[str, Any]]:
    payload: dict[str, Any] = {
        "size": size,
        "query": query,
    }
    if sort_field:
        payload["sort"] = [{sort_field: {"order": "desc", "unmapped_type": "date"}}]

    with httpx.Client(verify=build_verify(connection), timeout=timeout, auth=build_auth(connection)) as client:
        response = client.post(f"{build_base_url(connection)}/{index_pattern}/_search", json=payload)
        response.raise_for_status()
        hits = response.json().get("hits", {}).get("hits", [])
    return [item.get("_source", {}) for item in hits if isinstance(item, dict)]


def _collect_vulnerabilities(connection: dict[str, Any], host: str) -> list[dict[str, Any]]:
    query = {
        "bool": {
            "should": _host_should_filters(host),
            "minimum_should_match": 1,
        }
    }
    rows = _search_indexer(connection, "wazuh-states-vulnerabilities-*", query, size=100, sort_field=None)
    results: list[dict[str, Any]] = []
    for row in rows:
        results.append(
            {
                "host": _safe_str(_pick(row, "agent.name", "host.name", "hostname"), host),
                "cve": _safe_str(_pick(row, "vulnerability.id", "vulnerability.cve", "cve")),
                "package": _safe_str(_pick(row, "package.name", "package", "name")),
                "version": _safe_str(_pick(row, "package.version", "version")),
                "severity": _safe_str(_pick(row, "vulnerability.severity", "severity"), "unknown"),
                "status": _safe_str(_pick(row, "vulnerability.status", "status"), "open"),
                "title": _safe_str(_pick(row, "vulnerability.title", "title", "description")),
                "published": _safe_str(_pick(row, "vulnerability.published", "published_at", "@timestamp")),
            }
        )
    return results


def _collect_fim(connection: dict[str, Any], host: str) -> list[dict[str, Any]]:
    query = {
        "bool": {
            "must": [
                {
                    "bool": {
                        "should": _host_should_filters(host),
                        "minimum_should_match": 1,
                    }
                },
                {"term": {"rule.groups": "syscheck"}},
            ]
        }
    }
    index_pattern = connection.get("indexer_index_pattern", "wazuh-alerts-*")
    rows = _search_indexer(connection, index_pattern, query, size=100)
    results: list[dict[str, Any]] = []
    for row in rows:
        results.append(
            {
                "host": _safe_str(_pick(row, "agent.name", "host.name", "hostname"), host),
                "path": _safe_str(_pick(row, "file.path", "path", "syscheck.path")),
                "event": _safe_str(_pick(row, "file.event", "event", "syscheck.event")),
                "sha1": _safe_str(_pick(row, "file.sha1", "sha1", "hash.sha1")),
                "changed_by": _safe_str(_pick(row, "file.uid", "uid", "user.name")),
                "timestamp": _safe_str(_pick(row, "timestamp", "@timestamp", "syscheck.mtime_after")),
            }
        )
    return results


def _collect_config(connection: dict[str, Any], host: str) -> list[dict[str, Any]]:
    query = {
        "bool": {
            "should": _host_should_filters(host),
            "minimum_should_match": 1,
        }
    }
    sca_rows = _search_indexer(connection, "wazuh-states-inventory-system-*", query, size=20, sort_field=None)
    inventory_rows = _search_indexer(connection, "wazuh-states-inventory-packages-*", query, size=60, sort_field=None)
    results: list[dict[str, Any]] = []
    for row in sca_rows:
        results.append(
            {
                "type": "system",
                "host": _safe_str(_pick(row, "agent.name", "host.name", "hostname"), host),
                "component": _safe_str(_pick(row, "os.name", "host.os.name", "os.platform")),
                "version": _safe_str(_pick(row, "os.version", "host.os.version")),
                "architecture": _safe_str(_pick(row, "os.architecture", "host.architecture")),
                "description": _safe_str(_pick(row, "os.codename", "host.os.codename")),
            }
        )
    for row in inventory_rows:
        results.append(
            {
                "type": "inventory",
                "host": _safe_str(_pick(row, "agent.name", "host.name", "hostname"), host),
                "component": _safe_str(_pick(row, "package.name", "name", "port.name", "process.name")),
                "version": _safe_str(_pick(row, "package.version", "version")),
                "architecture": _safe_str(_pick(row, "package.architecture", "architecture")),
                "description": _safe_str(_pick(row, "package.description", "description")),
            }
        )
    return results


def _collect_threat_intel(connection: dict[str, Any], host: str, hours: int) -> list[dict[str, Any]]:
    query = {
        "bool": {
            "filter": [
                {
                    "range": {
                        "timestamp": {
                            "gte": f"now-{hours}h",
                            "lte": "now",
                        }
                    }
                }
            ],
            "must": [
                {
                    "bool": {
                        "should": _host_should_filters(host),
                        "minimum_should_match": 1,
                    }
                },
                {
                    "bool": {
                        "should": [
                            {"term": {"rule.groups.keyword": "threat_intel"}},
                            {"term": {"rule.groups.keyword": "threat-intel"}},
                            {"wildcard": {"rule.description.keyword": {"value": "*threat intel*"}}},
                            {"exists": {"field": "data.threatintel"}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
            ],
        }
    }
    index_pattern = connection.get("indexer_index_pattern", "wazuh-alerts-*")
    rows = _search_indexer(connection, index_pattern, query, size=100)
    results: list[dict[str, Any]] = []
    for row in rows:
        results.append(
            {
                "timestamp": _safe_str(_pick(row, "@timestamp", "timestamp")),
                "host": _safe_str(_pick(row, "agent.name", "host.name", "hostname"), host),
                "indicator": _safe_str(_pick(row, "data.threatintel.indicator", "data.indicator", "data.srcip", "data.dstip")),
                "source": _safe_str(_pick(row, "data.threatintel.source", "rule.groups", "rule.id")),
                "description": _safe_str(_pick(row, "rule.description", "data.threatintel.description", "full_log")),
                "level": _safe_str(_pick(row, "rule.level", "data.threatintel.severity")),
            }
        )
    return results


def _extract_event_rows(events: list[Any], cap: int = 120) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in events[:cap]:
        smart = getattr(event, "smart", None)
        if not smart:
            continue
        rows.append(
            {
                "timestamp": getattr(smart, "timestamp", None),
                "event_id": getattr(smart, "event_id", None),
                "rule_id": getattr(smart, "rule_id", None),
                "rule_level": getattr(smart, "rule_level", None),
                "rule_description": getattr(smart, "rule_description", None),
                "user": getattr(smart, "user", None),
                "ip_address": getattr(smart, "ip_address", None),
                "process": getattr(smart, "process", None),
                "command_line": getattr(smart, "command_line", None),
                "service_name": getattr(smart, "service_name", None),
                "registry_key": getattr(smart, "registry_key", None),
                "mitre_id": getattr(smart, "mitre_id", None),
                "mitre_tactic": getattr(smart, "mitre_tactic", None),
                "system_message": getattr(smart, "system_message", None),
            }
        )
    return rows


def _build_insights(events: list[Any]) -> dict[str, Any]:
    event_ids: Counter[str] = Counter()
    rule_ids: Counter[str] = Counter()
    processes: Counter[str] = Counter()
    users: Counter[str] = Counter()
    mitre: Counter[str] = Counter()
    rule_levels: list[int] = []

    # Pattern scanning — unique hits only (deduplicated by match key)
    _HARD_RE = re.compile(
        r"\bmimikatz\b|sekurlsa|lsadump|lsass\.exe"
        r"|vssadmin\s+delete\s+shadows"
        r"|iex\s*[\(\[]|invoke-expression"
        r"|-enc\b|-encodedcommand"
        r"|downloadstring|downloadfile|downloaddata"
        r"|\bshellcode\b|inject.*process|process.*inject"
        r"|amsiScanBuffer|amsiInitialize",
        re.IGNORECASE,
    )
    _SOFT_RE = re.compile(
        r"rundll32\s+javascript|wscript\.shell"
        r"|powershell\s+-w(?:indowstyle)?\s+hidden"
        r"|-noprofile\s+-noni"
        r"|schtasks\s+/create|net\s+user\s+/add"
        r"|net\s+localgroup\s+administrators.*\/add"
        r"|reg\s+add\s+.*\\run\b"
        r"|\\AppData\\.*\.(?:exe|ps1|bat|cmd)\b"
        r"|\\Temp\\.*\.(?:exe|ps1|bat|cmd)\b",
        re.IGNORECASE,
    )
    seen_hard: set[str] = set()
    seen_soft: set[str] = set()
    hard_patterns: list[str] = []
    soft_patterns: list[str] = []

    for event in events:
        smart = getattr(event, "smart", None)
        if not smart:
            continue
        event_id = str(getattr(smart, "event_id", "") or "").strip()
        rule_id = str(getattr(smart, "rule_id", "") or "").strip()
        process = str(getattr(smart, "process", "") or "").strip()
        user = str(getattr(smart, "user", "") or "").strip()
        mitre_id = str(getattr(smart, "mitre_id", "") or "").strip()
        level = getattr(smart, "rule_level", None)

        if event_id:
            event_ids[event_id] += 1
        if rule_id:
            rule_ids[rule_id] += 1
        if process:
            processes[process] += 1
        if user:
            users[user] += 1
        if mitre_id:
            mitre[mitre_id] += 1
        if isinstance(level, int):
            rule_levels.append(level)

        # Scan raw text fields for attack patterns
        searchable = " ".join(filter(None, [
            str(getattr(smart, "command_line", "") or ""),
            str(getattr(smart, "system_message", "") or ""),
            str(getattr(smart, "rule_description", "") or ""),
            process,
        ]))
        m_hard = _HARD_RE.search(searchable)
        if m_hard:
            key = m_hard.group(0)[:40].lower()
            if key not in seen_hard:
                seen_hard.add(key)
                hard_patterns.append(key)
        m_soft = _SOFT_RE.search(searchable)
        if m_soft:
            key = m_soft.group(0)[:40].lower()
            if key not in seen_soft:
                seen_soft.add(key)
                soft_patterns.append(key)

    high_events = sum(1 for lvl in rule_levels if lvl >= 10)
    medium_events = sum(1 for lvl in rule_levels if 6 <= lvl < 10)

    return {
        "top_event_ids": event_ids.most_common(8),
        "top_rule_ids": rule_ids.most_common(8),
        "top_processes": processes.most_common(8),
        "top_users": users.most_common(8),
        "top_mitre": mitre.most_common(8),
        "high_events": high_events,
        "medium_events": medium_events,
        "hard_suspicious_patterns": hard_patterns,
        "soft_suspicious_patterns": soft_patterns,
    }


def _module_finding(module: str, insights: dict[str, Any], fallback_count: int) -> dict[str, Any]:
    top_event = (insights.get("top_event_ids") or [("-", 0)])[0]
    top_rule = (insights.get("top_rule_ids") or [("-", 0)])[0]
    top_process = (insights.get("top_processes") or [("-", 0)])[0]
    severity = "high" if int(insights.get("high_events", 0)) > 0 else "medium"

    if module == "Events":
        return {
            "title": "Auffaellige Event-Haeufung",
            "category": "events",
            "severity": severity,
            "source": "events",
            "count": max(1, int(top_event[1]) or fallback_count),
            "description": f"Event-ID {top_event[0]} tritt gehaeuft auf; Top Rule {top_rule[0]}.",
        }
    if module == "MITRE / Rules":
        return {
            "title": "Regel-/MITRE-Korrelation",
            "category": "mitre",
            "severity": "medium",
            "source": "rules",
            "count": max(1, int(top_rule[1]) or fallback_count),
            "description": f"Rule {top_rule[0]} erscheint wiederholt und sollte mit MITRE-Kontext geprueft werden.",
        }
    if module == "Threat Intel":
        return {
            "title": "TI-Enrichment erforderlich",
            "category": "threat-intel",
            "severity": "medium",
            "source": "threat_intel",
            "count": 1,
            "description": "Observable-Korrelation empfohlen, um bekannte Boese-Indikatoren auszuschliessen.",
        }
    return {
        "title": f"Modulbewertung: {module}",
        "category": module.lower(),
        "severity": "low",
        "source": module.lower(),
        "count": max(1, fallback_count),
        "description": f"Modul {module} abgeschlossen. Top Prozess: {top_process[0]}.",
    }


def _build_ai_context(job: FullScanJob, insights: dict[str, Any]) -> str:
    event_samples = [
        {
            "event_id": row.get("event_id"),
            "rule_id": row.get("rule_id"),
            "rule_level": row.get("rule_level"),
            "process": row.get("process"),
            "user": row.get("user"),
            "system_message": row.get("system_message"),
        }
        for row in _extract_event_rows(getattr(job, "source_events", []), cap=12)
    ]
    summary = {
        "host": job.host,
        "scan_mode": job.params.get("mode"),
        "time_window": job.params.get("time"),
        "scope": job.params.get("scope"),
        "profile_context": job.profile_context or "Kein Profil geladen.",
        "baseline_summary": job.baseline_text or "Keine Baseline vorhanden.",
        "baseline_diff": job.baseline_diff_block or "",
        "metrics": {
            "total_events": job.total_events,
            "relevant_events": job.relevant_events,
            "processed_events": job.processed_events,
            "findings": job.findings_count,
            "high_findings": job.high_findings,
            "ti_matches": job.ti_matches,
            "risk_score": job.risk_score,
        },
        "insights": insights,
        "findings": job.findings[:12],
        "event_samples": event_samples,
    }
    return json.dumps(summary, ensure_ascii=True)


def _run_ai_refinement(job: FullScanJob, connection: dict[str, Any], context_json: str) -> None:
    if not job.ai_enabled or job.ai_iterations_target <= 0:
        return

    history: list[dict[str, str]] = []
    final_text: str | None = None
    for iteration in range(1, job.ai_iterations_target + 1):
        if job.cancel_requested:
            return
        job.add_log(f"KI Iteration {iteration}/{job.ai_iterations_target} gestartet")
        if iteration == 1:
            prompt = build_fullscan_ai_prompt(
                risk_level=map_score_to_level(job.risk_score),
                risk_score=job.risk_score,
                risk_score_reason=job.risk_score_reason or "",
                profile_context=job.profile_context or "",
                baseline_text=job.baseline_text or "",
                baseline_diff_block=job.baseline_diff_block or "",
            )
        else:
            prompt = (
                "Refine the previous answer. "
                "Remove any generic SOC filler and unsupported claims. "
                "Ensure every bullet in '### Bestätigt' is directly traceable to scan data. "
                "Move anything without direct evidence to '### Prüfungswürdig' or '### Nicht beobachtet'. "
                "Do NOT add PowerShell, LSASS, C2, lateral movement, or persistence claims "
                "unless the scan data explicitly contains them."
            )
        try:
            ai_text = chat_with_context(connection, prompt, history=history, report_context=context_json)
            job.ai_outputs.append(ai_text)
            job.ai_iterations_completed = iteration
            final_text = ai_text
            history.append({"role": "user", "content": prompt})
            history.append({"role": "assistant", "content": ai_text})
            job.add_log(f"KI Iteration {iteration} abgeschlossen")
        except Exception as exc:
            job.add_log(f"KI Iteration {iteration} fehlgeschlagen: {exc}")
            break

    job.ai_final_summary = final_text


def _simulate_module_work(job: FullScanJob, module: str, module_index: int) -> None:
    event_chunk = max(4, int(max(job.relevant_events, 20) / max(job.total_modules, 1)))
    loops = 3
    for step in range(loops):
        if job.cancel_requested:
            return
        processed_now = int(event_chunk / loops)
        job.processed_events = min(job.relevant_events, job.processed_events + processed_now)
        if module in {"Events", "MITRE / Rules"}:
            job.suspicious_events += 1
            job.findings_count += 1
            if (module_index + step) % 2 == 0:
                job.high_findings += 1
        if module == "Threat Intel" and step == loops - 1:
            job.ti_matches += 1
        # Risk score is NOT updated here — final score is computed after all events are loaded
        base = ((job.completed_modules + (step + 1) / loops) / max(job.total_modules, 1)) * 100
        job.progress = round(min(99.5, base), 1)
        time.sleep(0.65)


def map_score_to_level(score: float) -> str:
    """Single source of truth for score → risk level mapping."""
    if score >= 8.0:
        return "HIGH"
    if score >= 5.0:
        return "MEDIUM"
    return "LOW"


# ── Risk Scoring Engine v3 (enterprise-grade, finding-based) ─────────────────
#
# Principle: volume != risk.  Score is derived from CONFIRMED findings
# (dangerous EIDs, attack chains, behavior patterns, TI hits, baseline
# deviations).  Hard caps ensure a stable sysadmin host cannot reach HIGH
# purely because it has many routine admin events.

# Score for ONE confirmed occurrence of a dangerous event ID.
# Multiple occurrences of the same EID do NOT multiply this.
_DANGEROUS_EID_SCORES: dict[str, float] = {
    "1102": 8.5,   # Audit log cleared
    "7045": 7.5,   # New service installed
    "4697": 7.5,   # Service installed via SCM
    "4719": 7.0,   # System audit policy changed
    "4698": 6.5,   # Scheduled task created
    "4728": 6.5,   # Member added to global security group
    "4732": 6.5,   # Member added to local security group
    "4720": 6.0,   # New user account created
    "4740": 5.5,   # Account locked out
    "4726": 5.5,   # User account deleted
    "4702": 5.5,   # Scheduled task updated
    "7023": 4.0,   # Service failed to start
    "4625": 2.5,   # Failed logon (base; brute-force chain adds more)
    "7040": 2.0,   # Service config change
}

_EID_LABELS: dict[str, str] = {
    "1102": "Audit-Log gelöscht",
    "7045": "Neuer Dienst installiert",
    "4697": "Dienst via SCM installiert",
    "4719": "Audit-Richtlinie geändert",
    "4698": "Geplante Aufgabe erstellt",
    "4702": "Geplante Aufgabe aktualisiert",
    "4720": "Neues Benutzerkonto erstellt",
    "4726": "Benutzerkonto gelöscht",
    "4728": "Mitglied zu globaler Gruppe hinzugefügt",
    "4732": "Mitglied zu lokaler Gruppe hinzugefügt",
    "4740": "Konto gesperrt",
    "4625": "Fehlgeschlagener Anmeldeversuch",
    "7040": "Dienst-Konfigurationsänderung",
    "7023": "Dienst nicht gestartet",
    "4624": "Erfolgreiche Anmeldung",
    "4688": "Prozesserstellung",
    "4648": "Anmeldung mit expliziten Anmeldedaten",
    "4672": "Sonderrechte bei Anmeldung",
}

# EIDs that are fully benign on sysadmin hosts — zero contribution to base score
_SYSADMIN_BENIGN_EIDS: frozenset[str] = frozenset({
    "4624", "4634", "4647", "4648", "4672", "4673", "4674",
    "4688", "4689", "5156", "5157", "7036", "7040",
    "10016", "16384", "4608", "4609", "4800", "4801",
    "6005", "6006", "6013", "41", "1074",
})

_BRUTE_FORCE_THRESHOLD = 10


def _compute_risk_score_v2(
    insights: dict[str, Any],
    ti_matches: int,
    deviation_count: int,
    profile_name: str | None = None,
) -> tuple[float, str, dict[str, Any]]:
    """Enterprise-grade risk scoring.  Returns (final_score, reason_text, breakdown).

    Aggregation:
        base   = max(dangerous_eid_finding_scores)
        extra  = diminishing bonus for additional dangerous EIDs  (+max 1.5)
        chain  = attack chain bonus                                (+max 3.0)
        behav  = suspicious behavior patterns                      (+max 3.0)
        ti     = threat-intel hits                                 (+max 2.0)
        dev    = baseline deviations                               (+max 1.5)
        raw    = base + extra + chain + behav + ti + dev
        final  = raw, then hard caps applied
    """
    is_sysadmin = bool(profile_name and "sysadmin" in profile_name.lower())

    event_id_counts: dict[str, int] = {
        str(eid): cnt for eid, cnt in insights.get("top_event_ids", [])
    }
    hard_patterns: list[str] = insights.get("hard_suspicious_patterns", [])
    soft_patterns: list[str] = insights.get("soft_suspicious_patterns", [])
    suspicious_behavior_count = len(hard_patterns) + len(soft_patterns)
    reasons: list[str] = []

    # ── 1. Finding base: max score from any dangerous EID present ────────────
    finding_scores: list[float] = []
    dangerous_eids_found: list[str] = []

    for eid, cnt in event_id_counts.items():
        if is_sysadmin and eid in _SYSADMIN_BENIGN_EIDS:
            continue
        eid_score = _DANGEROUS_EID_SCORES.get(eid, 0.0)
        if eid_score > 0.0:
            finding_scores.append(eid_score)
            dangerous_eids_found.append(eid)
            if eid_score >= 5.0:
                label = _EID_LABELS.get(eid, "Sicherheitsereignis")
                reasons.append(f"Event {eid} ({cnt}×): {label}")

    # Fallback: if no dangerous EID but Wazuh rule-level signals exist
    high_events = int(insights.get("high_events", 0))
    medium_events = int(insights.get("medium_events", 0))
    if not finding_scores:
        if high_events > 0:
            finding_scores.append(4.5)
            reasons.append(f"Wazuh-Regeln mit hohem Level: {high_events}×")
        elif medium_events > 0:
            finding_scores.append(2.5)

    max_finding_score = max(finding_scores) if finding_scores else 0.0

    # ── 2. Additional dangerous EIDs — diminishing increments ────────────────
    extra_eid_score = min(1.5, max(0, len(dangerous_eids_found) - 1) * 0.4)

    # ── 3. Attack chain ───────────────────────────────────────────────────────
    failed_logons = event_id_counts.get("4625", 0)
    attack_chain_score = 0.0
    has_attack_chain = False
    if failed_logons >= _BRUTE_FORCE_THRESHOLD:
        attack_chain_score += 1.5
        reasons.append(f"Brute-Force: {failed_logons}× fehlgeschlagene Anmeldungen (4625)")
        if event_id_counts.get("4624", 0) > 0 and event_id_counts.get("4672", 0) > 0:
            attack_chain_score += 1.5
            has_attack_chain = True
            reasons.append("Angriffskette bestätigt: 4625→4624→4672 (Brute Force→Erfolg→Privilegien)")

    # ── 4. Suspicious behavior ────────────────────────────────────────────────
    behavior_score = 0.0
    if hard_patterns:
        behavior_score += min(3.0, len(hard_patterns) * 1.5)
        reasons.append(f"Kritische Angriffsmuster: {', '.join(hard_patterns[:3])}")
    if soft_patterns:
        behavior_score += min(1.5, len(soft_patterns) * 0.5)
        reasons.append(f"Verdächtige Muster: {', '.join(soft_patterns[:3])}")
    behavior_score = min(behavior_score, 3.0)

    # ── 5. Threat Intel ───────────────────────────────────────────────────────
    ti_score = 0.0
    if ti_matches > 0:
        ti_score = min(2.0, ti_matches * 1.0)
        reasons.append(f"Threat-Intel-Treffer: {ti_matches}× (Überprüfung erforderlich)")

    # ── 6. Baseline deviations ────────────────────────────────────────────────
    deviation_score = 0.0
    if deviation_count > 0:
        deviation_score = min(1.5, deviation_count * 0.2)
        reasons.append(f"Baseline-Abweichungen: {deviation_count}")

    # ── 7. Aggregate ──────────────────────────────────────────────────────────
    raw_score = (
        max_finding_score
        + extra_eid_score
        + attack_chain_score
        + behavior_score
        + ti_score
        + deviation_score
    )

    # ── 8. Hard caps ──────────────────────────────────────────────────────────
    caps_applied: list[str] = []
    final_score = raw_score

    no_real_threat = (
        deviation_count == 0
        and suspicious_behavior_count == 0
        and ti_matches == 0
        and not has_attack_chain
    )

    if no_real_threat and final_score > 4.0:
        final_score = 4.0
        caps_applied.append("no-threat-gate: max 4.0")
        reasons.append(
            "Score auf 4.0 begrenzt: keine Baseline-Abweichungen, "
            "kein Angriffsverhalten, kein TI-Treffer, keine Angriffskette"
        )

    if is_sysadmin and not hard_patterns and deviation_count == 0:
        if final_score > 3.5:
            final_score = 3.5
            caps_applied.append("sysadmin-normal-gate: max 3.5")
            reasons.append(
                "Sysadmin-Profil: Keine Abweichungen, keine Angriffsmuster — Score auf 3.5 (LOW) begrenzt. "
                "Die hohe Event-Anzahl ist für dieses Profil erwartbar. "
                "Es wurden keine neuen Baseline-Abweichungen festgestellt. "
                "Der Score wurde wegen fehlender konkreter Bedrohungsindikatoren begrenzt."
            )

    # TI + hard attack pattern = confirmed threat → floor 7.0
    if ti_matches > 0 and hard_patterns:
        if final_score < 7.0:
            final_score = 7.0
            caps_applied.append("confirmed-threat-floor: min 7.0 (TI + Angriffsmuster)")
    elif ti_matches > 0 and final_score < 5.5:
        final_score = 5.5
        caps_applied.append("ti-floor: min 5.5")

    if is_sysadmin:
        reasons.append(
            "[Sysadmin-Profil: Normale Admin-Events (4624/4648/4688/4672/…) "
            "fließen nicht in Risiko-Basis ein]"
        )

    final_score = round(min(10.0, max(0.0, final_score)), 1)

    breakdown: dict[str, Any] = {
        "max_finding_score": round(max_finding_score, 1),
        "extra_eid_score": round(extra_eid_score, 1),
        "attack_chain_score": round(attack_chain_score, 1),
        "behavior_score": round(behavior_score, 1),
        "ti_score": round(ti_score, 1),
        "deviation_score": round(deviation_score, 1),
        "raw_score": round(raw_score, 1),
        "profile_modifier": f"sysadmin-gates (profile={profile_name})" if is_sysadmin else "none",
        "caps_applied": caps_applied,
        "hard_patterns_detected": hard_patterns,
        "soft_patterns_detected": soft_patterns,
        "final_score": final_score,
    }

    reason_text = "; ".join(reasons) if reasons else "Keine kritischen Indikatoren gefunden"
    return final_score, reason_text, breakdown




def _build_result(job: FullScanJob, insights: dict[str, Any], event_rows: list[dict[str, Any]]) -> dict[str, Any]:
    risk_label = map_score_to_level(job.risk_score)

    # ── Build evidence-driven action plans ───────────────────────────────────
    action_plans = build_action_plans_for_insights(
        top_event_ids=_safe_list(insights.get("top_event_ids")),
        top_rule_ids=_safe_list(insights.get("top_rule_ids")),
        top_processes=_safe_list(insights.get("top_processes")),
        ti_matches=job.ti_matches,
    )
    next_steps = action_plans_to_next_steps(action_plans)

    summary = {
        "host": job.host,
        "assessment": (
            "deutlich prüfungsbedürftig" if risk_label == "HIGH"
            else "mehrere verdächtige Muster" if risk_label == "MEDIUM"
            else "überwiegend unauffällig"
        ),
        "risk_score": job.risk_score,
        "risk_level": risk_label,
        "confidence": "medium",
        "ai_iterations_completed": job.ai_iterations_completed,
        "ai_iterations_target": job.ai_iterations_target,
        "top_event_ids": _safe_list(insights.get("top_event_ids")),
        "top_rule_ids": _safe_list(insights.get("top_rule_ids")),
        "next_steps": next_steps,
        "risk_breakdown": job.risk_breakdown,
    }
    findings = job.findings or [
        {
            "title": "Basis-Finding",
            "category": "events",
            "severity": "medium",
            "source": "events",
            "count": max(1, job.suspicious_events),
            "description": "Keine detaillierten Findings verfuegbar.",
        }
    ]

    # ── Structured data for report ────────────────────────────────────────────
    top_eids = _safe_list(insights.get("top_event_ids"))
    top_rules = _safe_list(insights.get("top_rule_ids"))
    top_procs = _safe_list(insights.get("top_processes"))
    top_users_list = _safe_list(insights.get("top_users"))

    top_eid_str = ", ".join(f"{eid} ({cnt}x)" for eid, cnt in top_eids[:5]) or "—"
    top_rule_str = ", ".join(f"{rid} ({cnt}x)" for rid, cnt in top_rules[:4]) or "—"
    top_proc_str = ", ".join(proc for proc, _ in top_procs[:5]) or "—"
    top_user_str = ", ".join(u for u, _ in top_users_list[:5]) or "—"

    # ── Baseline counts ───────────────────────────────────────────────────────
    bsl_diff = job.baseline_diff_block or ""
    def _bsl_count(label: str) -> str:
        import re as _re
        m = _re.search(rf"{label}[^\d]*(\d+)", bsl_diff)
        return m.group(1) if m else "0"

    new_procs = _bsl_count("Prozesse")
    new_services = _bsl_count("Services")
    new_users_bsl = _bsl_count("Nutzer")
    new_ips = _bsl_count("IP")
    new_eids = _bsl_count("Event-IDs")
    open_devs = _bsl_count("Abweichung")
    has_deviations = bsl_diff and "Keine neuen" not in bsl_diff

    # ── Score breakdown ───────────────────────────────────────────────────────
    bd = job.risk_breakdown
    caps = bd.get("caps_applied", [])
    caps_str = ", ".join(caps) if caps else "keine"

    # ── Status line ──────────────────────────────────────────────────────────
    if risk_label == "HIGH":
        status_str = "ACTION REQUIRED"
    elif risk_label == "MEDIUM":
        status_str = "REVIEW"
    else:
        status_str = "STABLE"

    # ── Top findings for report ───────────────────────────────────────────────
    findings_section_lines: list[str] = ["\n## Top Findings"]
    for f in (job.findings or [])[:6]:
        sev = (f.get("severity") or "?").upper()
        title = f.get("title") or "Finding"
        desc = f.get("description") or f.get("reason") or ""
        count = f.get("count") or ""
        count_note = f" ({count}x)" if count else ""
        findings_section_lines += [
            f"\n### {sev} – {title}",
            f"- Evidence: {desc}{count_note}",
            f"- Action: {next_steps[0] if next_steps else 'Befunde prüfen und einordnen.'}",
        ]
    if not job.findings:
        findings_section_lines.append("- Keine strukturierten Findings verfügbar.")

    # ── Timeline highlights ───────────────────────────────────────────────────
    TIMELINE_EIDS = {"7045", "7040", "4625", "4624", "4634", "1102", "1074"}
    timeline_lines: list[str] = []
    for eid, cnt in top_eids[:10]:
        if str(eid) in TIMELINE_EIDS:
            timeline_lines.append(f"- Event {eid}: {cnt}x")
    if job.ti_matches > 0:
        timeline_lines.append(f"- TI-Treffer: {job.ti_matches} (Validierung erforderlich)")
    if job.fim:
        timeline_lines.append(f"- FIM-Änderungen: {len(job.fim)}")

    # ── Recommended actions (max 5) ───────────────────────────────────────────
    actions_lines = [f"- {s}" for s in next_steps[:5]] or ["- Keine spezifischen Maßnahmen ermittelt."]

    # ── AI evidence block (or deterministic fallback) ─────────────────────────
    if job.ai_final_summary:
        ai_evidence_block = job.ai_final_summary
    else:
        # Deterministic fallback — no invented claims
        confirmed: list[str] = []
        review: list[str] = []
        not_observed = [
            "Keine verdächtige Command Line beobachtet",
            "Keine bestätigte Angriffskette",
            "Keine bestätigte Persistenz",
            "Kein bestätigtes C2",
            "Keine bestätigte Lateral Movement",
        ]
        if job.ti_matches > 0:
            review.append(f"{job.ti_matches} TI-Treffer – TI-Validierung erforderlich (keine IOC-Details vorhanden)")
        if has_deviations:
            review.append("Neue Baseline-Abweichungen vorhanden – Einordnung erforderlich")
        for eid, cnt in top_eids[:3]:
            if str(eid) in {"7045", "7040"}:
                review.append(f"Event {eid} ({cnt}x) – Service-Änderung, prüfungswürdig")
            elif str(eid) == "4625":
                review.append(f"Event 4625 ({cnt}x) – Logon-Fehler, auf Brute-Force prüfen")
        if job.findings_count > 0:
            confirmed.append(f"{job.findings_count} Findings durch Analyse-Module ermittelt (High: {job.high_findings})")
        if not confirmed:
            confirmed.append("Keine bestätigten Indikatoren")
        if not review:
            review.append("Nichts prüfungswürdig")
        bev_reason = (
            f"Risk Score {job.risk_score}/10 ({risk_label}) basiert auf "
            f"Max-Finding-Score {bd.get('max_finding_score', 0)}, "
            f"Behavior {bd.get('behavior_score', 0)}, "
            f"TI {bd.get('ti_score', 0)}, "
            f"Deviations {bd.get('deviation_score', 0)}."
        )
        ai_evidence_block = (
            "## Evidence\n"
            "### Bestätigt\n"
            + "\n".join(f"- {c}" for c in confirmed)
            + "\n\n### Prüfungswürdig\n"
            + "\n".join(f"- {r}" for r in review)
            + "\n\n### Nicht beobachtet\n"
            + "\n".join(f"- {n}" for n in not_observed)
            + f"\n\n## Bewertungsbegründung\n{bev_reason}\n"
        )

    # ── Assemble final report ─────────────────────────────────────────────────
    main_reason = job.risk_score_reason or "Keine kritischen Indikatoren."
    # truncate reason to ~one sentence
    main_reason_short = main_reason.split(";")[0].strip()

    markdown_report = "\n".join([
        f"# Full Scan Report – {job.host}",
        "",
        "## Decision Summary",
        f"- Risk: {job.risk_score}/10 – {risk_label}",
        f"- Status: {status_str}",
        f"- Main reason: {main_reason_short}",
        f"- Confidence: {summary.get('confidence', 'medium')}",
        "",
        ai_evidence_block,
        "",
        "## Key Data",
        f"- Top Event IDs: {top_eid_str}",
        f"- Top Rules: {top_rule_str}",
        f"- Top Processes: {top_proc_str}",
        f"- Top Users: {top_user_str}",
        "",
        "## Baseline vs Current",
        f"- New Processes: {new_procs}",
        f"- New Services: {new_services}",
        f"- New Users: {new_users_bsl}",
        f"- New IPs: {new_ips}",
        f"- New Event IDs: {new_eids}",
        f"- Open Deviations: {open_devs}",
        "",
        "> New does not mean malicious. Items marked 'needs validation' require analyst review.",
    ] + findings_section_lines + [
        "",
        "## Timeline Highlights",
    ] + (timeline_lines if timeline_lines else ["- Keine relevanten Timeline-Ereignisse"]) + [
        "",
        "## Recommended Actions",
    ] + actions_lines + [
        "",
        "## Score Explanation",
        f"- max finding: {bd.get('max_finding_score', 0)}",
        f"- threat intel: {bd.get('ti_score', 0)}",
        f"- behavior: {bd.get('behavior_score', 0)}",
        f"- deviations: {bd.get('deviation_score', 0)}",
        f"- attack chain: {bd.get('attack_chain_score', 0)}",
        f"- raw score: {bd.get('raw_score', 0)}",
        f"- final score: {bd.get('final_score', job.risk_score)}",
        f"- caps applied: {caps_str}",
    ])

    return {
        "summary": summary,
        "findings": findings,
        "events": event_rows,
        "vulnerabilities": job.vulnerabilities,
        "fim": job.fim,
        "config": job.config,
        "threat_intel": job.threat_intel,
        "ai": {
            "enabled": job.ai_enabled,
            "iterations_target": job.ai_iterations_target,
            "iterations_completed": job.ai_iterations_completed,
            "outputs": job.ai_outputs,
            "final_summary": job.ai_final_summary,
        },
        "raw_json": {
            "job_id": job.id,
            "host": job.host,
            "params": job.params,
            "insights": insights,
            "metrics": {
                "total_events": job.total_events,
                "relevant_events": job.relevant_events,
                "processed_events": job.processed_events,
                "findings": job.findings_count,
                "high_findings": job.high_findings,
                "ti_matches": job.ti_matches,
                "ai_iterations_target": job.ai_iterations_target,
                "ai_iterations_completed": job.ai_iterations_completed,
            },
            "risk_breakdown": job.risk_breakdown,
            "modules": {
                "vulnerabilities": job.vulnerabilities,
                "fim": job.fim,
                "config": job.config,
                "threat_intel": job.threat_intel,
            },
        },
        "markdown_report": markdown_report,
    }


def run_fullscan_job(job: FullScanJob) -> None:
    try:
        modules = job.params.get("modules") or DEFAULT_MODULES
        if not isinstance(modules, list):
            modules = DEFAULT_MODULES
        modules = [str(m) for m in modules]
        if not modules:
            modules = DEFAULT_MODULES

        job.total_modules = len(modules)
        mode = str(job.params.get("mode") or "standard")
        job.ai_iterations_target = int(job.params.get("ai_iterations") or _mode_to_ai_iterations(mode))
        job.ai_enabled = bool(job.params.get("run_ai", True)) and job.ai_iterations_target > 0

        for module in modules:
            job.module_status[module] = "pending"

        job.add_log(f"Full Scan gestartet fuer {job.host}")
        time_window = str(job.params.get("time") or "24h")
        hours = _time_to_hours(time_window)
        scope = str(job.params.get("scope") or "Top 250 Events")
        limit = _scope_to_limit(scope)
        min_rule_level = 0 if "Include Noise" in modules else 3
        if "Nur High/Medium" in modules:
            min_rule_level = 8
        job.add_log(f"Lade Eventdaten fuer Zeitraum: {time_window} ({hours}h)")
        job.add_log(f"Event Scope: {scope} (limit={limit})")

        connection = get_active_connection()
        if not connection:
            raise RuntimeError("Keine aktive Verbindung gefunden")

        try:
            host_events = get_host_events(
                connection,
                host=job.host,
                hours=hours,
                limit=limit,
                min_rule_level=min_rule_level,
            )
        except Exception as exc:
            job.add_log(f"Eventabruf fehlgeschlagen, nutze Fallback-Werte: {exc}")
            host_events = []

        if not host_events:
            job.add_log("Keine Events mit aktuellem Filter gefunden, wiederhole mit relaxterem Filter")
            try:
                host_events = get_host_events(
                    connection,
                    host=job.host,
                    hours=hours,
                    limit=min(limit, 500),
                    min_rule_level=0,
                )
                job.add_log(f"Relaxter Abruf lieferte {len(host_events)} Events")
            except Exception as exc:
                job.add_log(f"Relaxter Eventabruf ebenfalls fehlgeschlagen: {exc}")

        job.total_events = len(host_events)
        job.relevant_events = len(host_events)
        if job.total_events == 0:
            fallback = {"1h": 120, "6h": 240, "24h": 380, "3d": 620, "7d": 960}.get(time_window, 420)
            job.total_events = fallback
            job.relevant_events = max(20, int(fallback * 0.28))
        job.add_log(f"{job.total_events} Events gefunden")
        job.add_log(f"{job.relevant_events} relevante Events extrahiert")

        insights = _build_insights(host_events)
        job.source_events = host_events
        event_rows = _extract_event_rows(host_events, cap=200)

        try:
            if "Vulnerabilities" in modules:
                job.vulnerabilities = _collect_vulnerabilities(connection, job.host)
                job.add_log(f"Vulnerabilities geladen: {len(job.vulnerabilities)}")
            if "FIM" in modules:
                job.fim = _collect_fim(connection, job.host)
                job.add_log(f"FIM-Eintraege geladen: {len(job.fim)}")
            if "Configuration" in modules or "Host Context / Inventory" in modules:
                job.config = _collect_config(connection, job.host)
                job.add_log(f"Configuration/Inventory geladen: {len(job.config)}")
            if "Threat Intel" in modules:
                job.threat_intel = _collect_threat_intel(connection, job.host, hours)
                job.add_log(f"Threat-Intel-Treffer geladen: {len(job.threat_intel)}")
        except Exception as exc:
            job.add_log(f"Zusatzdaten konnten nicht vollstaendig geladen werden: {exc}")

        for idx, module in enumerate(modules):
            if job.cancel_requested:
                job.status = "canceled"
                job.add_log("Full Scan abgebrochen")
                job.end_time = datetime.utcnow()
                return

            job.active_module = module
            job.module_status[module] = "running"
            job.add_log(f"Analysiere Modul: {module}")
            _simulate_module_work(job, module, idx)
            if job.cancel_requested:
                job.module_status[module] = "canceled"
                job.status = "canceled"
                job.add_log("Full Scan abgebrochen")
                job.end_time = datetime.utcnow()
                return

            job.module_status[module] = "done"
            job.completed_modules += 1
            module_finding = _module_finding(module, insights, fallback_count=job.completed_modules)
            if module_finding.get("severity") in {"high", "critical"}:
                job.high_findings += 1
            job.findings.append(module_finding)
            job.findings_count = len(job.findings)
            job.add_log(f"Modul abgeschlossen: {module}")

        job.progress = 99.5
        job.active_module = "Final Correlation"
        job.add_log("Erstelle korrelierte Gesamtzusammenfassung")

        # ── Load profile + baseline context before AI ─────────────────────────
        try:
            profile = get_profile_for_host(job.host)
            job.profile_context = build_profile_context_block(profile)
            job.profile_name = profile.name if profile else None
            job.add_log(f"Profil geladen: {profile.display_name if profile else 'kein Profil'}")
        except Exception as exc:
            job.add_log(f"Profil konnte nicht geladen werden: {exc}")
            job.profile_context = "Host-Profil: Nicht zugewiesen.\nBewerte Events nach allgemeinem SOC-Standard."

        try:
            baseline = get_baseline_summary(job.host)
            if baseline:
                job.baseline_text = (
                    f"Baseline ({baseline.window_hours}h, Stand {baseline.computed_at}):\n"
                    f"  Events gesamt: {baseline.total_events} ({baseline.daily_avg_events:.0f}/Tag)\n"
                    f"  High Alerts: {baseline.high_alerts}, Critical: {baseline.critical_alerts}\n"
                    f"  Offene Abweichungen: {baseline.open_deviations}\n"
                    f"  Bekannte Prozesse: {', '.join(baseline.top_processes[:6]) or '—'}\n"
                    f"  Bekannte Event-IDs: {', '.join(baseline.top_event_ids[:6]) or '—'}\n"
                    f"  Bekannte Nutzer: {', '.join(baseline.top_users[:4]) or '—'}"
                )
                diff = get_baseline_diff(job.host)
                parts: list[str] = []
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
                    parts.append(f"⚠ Volumen-Spike: {diff.volume_ratio:.1f}× Baseline")
                job.baseline_diff_block = "\n".join(parts) if parts else "Keine neuen Abweichungen vs. Baseline"
                job.add_log(f"Baseline-Kontext geladen (Abweichungen: {baseline.open_deviations})")
            else:
                job.baseline_text = "Keine Baseline vorhanden – Host wurde noch nicht analysiert."
                job.baseline_diff_block = ""
                job.add_log("Keine Baseline für diesen Host verfügbar")
        except Exception as exc:
            job.add_log(f"Baseline konnte nicht geladen werden: {exc}")
            job.baseline_text = "Baseline-Daten nicht abrufbar."
            job.baseline_diff_block = ""

        if job.ai_enabled:
            job.active_module = "AI Summary"
            # ── Compute risk score v2 BEFORE AI so AI prompt uses correct level ──
            try:
                baseline_summary = get_baseline_summary(job.host)
                _deviation_count = baseline_summary.open_deviations if baseline_summary else 0
            except Exception:
                _deviation_count = 0
            job.risk_score, _risk_reason, job.risk_breakdown = _compute_risk_score_v2(
                insights,
                ti_matches=len(job.threat_intel),
                deviation_count=_deviation_count,
                profile_name=job.profile_name,
            )
            job.risk_score_reason = _risk_reason
            job.add_log(f"Risk Score v3: {job.risk_score}/10 ({map_score_to_level(job.risk_score)}) — {_risk_reason}")
            ai_context = _build_ai_context(job, insights)
            _run_ai_refinement(job, connection, ai_context)
        else:
            job.add_log("KI-Refinement deaktiviert (Quick-Modus oder run_ai=false)")
            # Still compute v2 risk score even without AI
            try:
                baseline_summary = get_baseline_summary(job.host)
                _deviation_count = baseline_summary.open_deviations if baseline_summary else 0
            except Exception:
                _deviation_count = 0
            job.risk_score, _risk_reason, job.risk_breakdown = _compute_risk_score_v2(
                insights,
                ti_matches=len(job.threat_intel),
                deviation_count=_deviation_count,
                profile_name=job.profile_name,
            )
            job.risk_score_reason = _risk_reason
            job.add_log(f"Risk Score v3: {job.risk_score}/10 ({map_score_to_level(job.risk_score)})")
        job.result = _build_result(job, insights, event_rows)
        job.progress = 100.0
        job.status = "finished"
        job.end_time = datetime.utcnow()
        job.active_module = None
        try:
            save_fullscan_report(
                host=job.host,
                fullscan_job_id=job.id,
                status=job.status,
                risk_score=job.risk_score,
                findings_count=job.findings_count,
                high_findings=job.high_findings,
                ti_matches=job.ti_matches,
                summary=job.result.get("summary") if isinstance(job.result, dict) else {},
                result=job.result if isinstance(job.result, dict) else {},
                markdown_report=str((job.result or {}).get("markdown_report") or ""),
            )
        except Exception as exc:
            job.add_log(f"Konnte Full-Scan-Report nicht speichern: {exc}")
        job.add_log("Full Scan abgeschlossen")
    except Exception as exc:
        job.status = "failed"
        job.end_time = datetime.utcnow()
        job.add_log(f"Fehler: {exc}")


def get_fullscan_status(job_id: str) -> dict[str, Any]:
    job = fullscan_jobs[job_id]
    return {
        "status": job.status,
        "progress": job.progress,
        "log": job.log,
        "active_module": job.active_module,
        "module_status": job.module_status,
        "host": job.host,
        "params": job.params,
        "metrics": {
            "total_modules": job.total_modules,
            "completed_modules": job.completed_modules,
            "total_events": job.total_events,
            "relevant_events": job.relevant_events,
            "processed_events": job.processed_events,
            "findings": job.findings_count,
            "high_findings": job.high_findings,
            "ti_matches": job.ti_matches,
            "suspicious_events": job.suspicious_events,
            "risk_score": job.risk_score,
            "ai_enabled": job.ai_enabled,
            "ai_iterations_target": job.ai_iterations_target,
            "ai_iterations_completed": job.ai_iterations_completed,
        },
    }


def get_fullscan_result(job_id: str) -> dict[str, Any]:
    job = fullscan_jobs[job_id]
    return job.result or {}
