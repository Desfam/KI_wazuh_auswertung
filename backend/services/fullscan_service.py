"""Full Scan - Modular Deep Host Analysis Service."""
from __future__ import annotations

import json
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any

import httpx

from db.database import get_active_connection, save_fullscan_report
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
            risk_level_now = map_score_to_level(job.risk_score)
            prompt = (
                "Erstelle einen operativen SOC-Report auf Deutsch.\n"
                "Der Report ersetzt ALLE anderen Sektionen – gib NUR diesen Text aus, keine Dopplungen.\n\n"
                "PFLICHT-SEKTIONEN (genau in dieser Reihenfolge, keine weiteren):\n"
                "## Executive Summary\n"
                "## Key Findings\n"
                "## Baseline-Bewertung\n"
                "## Risiko-Einschätzung\n"
                "## Maßnahmen\n"
                "## Confidence\n\n"
                "══════════ EISERNE REGELN ══════════\n"
                f"1. RISK LEVEL: Das vorberechnete Risk Level ist **{risk_level_now}** (Score {job.risk_score}/10).\n"
                "   Du MUSST dieses Level verwenden. Du darfst es begründen, aber NICHT ändern oder widersprechen.\n"
                f"   Risk Engine Begründung: {job.risk_score_reason or '—'}\n"
                f"   Verboten: irgendwo anders im Text ein anderes Niveau zu nennen (z.B. nicht 'MEDIUM' schreiben wenn '{risk_level_now}' = HIGH).\n"
                f"   Verboten: 'keine Bedrohungsindikatoren' oder 'keine Auffälligkeiten' schreiben wenn Risk Level {risk_level_now} ist HIGH oder MEDIUM.\n\n"
                "2. KEIN DUPLIKAT: Schreibe jeden Inhalt nur EINMAL. Kein Wiederholen von Summary in anderen Sektionen.\n\n"
                "3. PROFIL-KONTEXT (bekannt – NICHT 'Profil unbekannt' schreiben):\n"
                f"   {job.profile_context or 'Standardprofil'}\n\n"
                "4. BASELINE:\n"
                f"   {job.baseline_text or 'Keine Baseline vorhanden.'}\n"
                f"   Diff: {job.baseline_diff_block or 'Keine Abweichungen erkannt.'}\n"
                "   → Wenn KEINE neuen Abweichungen: Risiko relativieren, aber erklären warum Score trotzdem hoch ist falls zutreffend.\n"
                "   → NICHT schreiben 'keine ungewöhnlichen Entwicklungen' UND gleichzeitig auffällige Events aufführen.\n\n"
                "5. EVENT-IDs ERKLÄREN: Wenn du Event-IDs nennst, erkläre kurz was sie bedeuten.\n"
                "   Bekannte IDs: 4624=Logon, 4625=Logon Failure, 4634=Logoff, 4688=Process Creation,\n"
                "   4697=Service Install, 4720=Account Created, 4732=Group Change, 7040=Service Config Change,\n"
                "   7045=New Service, 1102=Audit Log Cleared, 4698/4702=Task Create/Update,\n"
                "   16384=oft WinRM/PowerShell Execution-Policy oder Subscription-Events – Kontext prüfen.\n\n"
                "6. PROFIL-NORMALISIERUNG: Für einen Entwicklungs-Host (DEV-Profil) sind\n"
                "   powershell.exe, cmd.exe, 4624/4634 (Logon/Logoff) grundsätzlich erklärbar.\n"
                "   Trotzdem: Frequenz und Kontext prüfen. Wenn baseline-konform → explizit sagen.\n\n"
                "7. MASSNAHMEN: mindestens 3, host- und evidenzspezifisch. Format: 'Prüfe X → warum → womit'.\n"
                "   Keine generischen Ratschläge wie 'prüfe Prozesse'.\n\n"
                "8. STATUS-FELD: Nicht selbst ausgeben – Status wird vom System gesetzt.\n"
            )
        else:
            prompt = (
                "Verfeinere die letzte Antwort. Entferne generische Aussagen, priorisiere Top-3 Risiken, "
                "nenne konkrete Checks und markiere moeglich harmlose Muster klar getrennt. "
                "Bevorzuge technische Details aus Eventdaten gegenueber allgemeinen SOC-Floskeln."
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


# ── Risk Scoring Engine v2 ────────────────────────────────────────────────────

# Weighted risk contribution per Event ID (per occurrence, capped internally)
_EVENT_RISK_WEIGHTS: dict[str, float] = {
    # Persistence / Critical
    "7045": 2.5,   # New service installed
    "1102": 3.0,   # Audit log cleared — high suspicion
    "4697": 2.5,   # Service installed via SCM
    "4719": 2.0,   # System audit policy changed
    "4698": 1.8,   # Scheduled task created
    "4702": 1.5,   # Scheduled task updated
    "4720": 1.8,   # New user account created
    "4726": 1.5,   # User account deleted
    "4732": 1.2,   # Member added to security group
    "4728": 1.2,   # Member added to global group
    "4740": 1.5,   # Account locked out
    # Lateral movement / credential
    "4625": 0.4,   # Failed logon (many = brute force)
    "4648": 1.0,   # Explicit credential use
    "4672": 0.8,   # Special privileges assigned at logon
    # Low risk operational
    "4624": 0.05,  # Successful logon — very common
    "4634": 0.02,  # Logoff
    "4688": 0.1,   # Process creation
    "4689": 0.02,  # Process exit
    "7023": 0.2,   # Service failed — operational, not threat
    "7040": 0.5,   # Service config change — moderate
    "7036": 0.0,   # Service state change — noise
    # Noise / ignore
    "10016": 0.0,
    "16384": 0.0,
    "4608":  0.0,
    "4609":  0.0,
    "4800":  0.0,
    "4801":  0.0,
    "6005":  0.0,
    "6006":  0.0,
    "6013":  0.0,
    "41":    0.0,
    "1074":  0.0,
}

# Persistence event IDs — any single occurrence sets a risk floor
_PERSISTENCE_EVENT_IDS: frozenset[str] = frozenset({"7045", "1102", "4697", "4719", "4698", "4702", "4720"})

# Brute force: if 4625 occurs many times then 4624 + 4672 follow → attack chain
_BRUTE_FORCE_THRESHOLD = 10  # 4625 occurrences needed to flag brute force


def _compute_risk_score_v2(insights: dict[str, Any], ti_matches: int, deviation_count: int) -> tuple[float, str]:
    """
    Compute a weighted risk score (0.0–10.0) and human-readable reason.
    Returns (score, reason_text).
    """
    top_event_ids: list[tuple[str, int]] = insights.get("top_event_ids", [])
    event_id_counts: dict[str, int] = {eid: cnt for eid, cnt in top_event_ids}

    score = 0.0
    reasons: list[str] = []
    persistence_hit = False

    for eid, cnt in event_id_counts.items():
        weight = _EVENT_RISK_WEIGHTS.get(str(eid), 0.15)  # unknown event IDs get small weight
        if weight == 0.0:
            continue
        # Cap contribution per event type to avoid single noisy event dominating
        contribution = min(weight * cnt, weight * 20)
        score += contribution

        if str(eid) in _PERSISTENCE_EVENT_IDS:
            persistence_hit = True
            reasons.append(f"Event {eid} ({cnt}x) — Persistenz-/Konfigurationsänderung")

    # Brute force chain: high 4625 count
    failed_logons = event_id_counts.get("4625", 0)
    if failed_logons >= _BRUTE_FORCE_THRESHOLD:
        bonus = min(2.0, failed_logons / 20.0)
        score += bonus
        reasons.append(f"Brute-Force-Indikator: {failed_logons}× Login-Failure (4625)")
        # Check if followed by successful logon + privilege — escalation chain
        if event_id_counts.get("4624", 0) > 0 and event_id_counts.get("4672", 0) > 0:
            score += 1.5
            reasons.append("Eskalations-Kette: 4625 → 4624 → 4672 (mögliche Kompromittierung)")

    # Threat Intel matches — always high signal
    if ti_matches > 0:
        score += min(3.0, ti_matches * 1.5)
        reasons.append(f"Threat-Intel-Treffer: {ti_matches}x")

    # Baseline deviations
    if deviation_count > 0:
        score += min(1.5, deviation_count * 0.3)
        reasons.append(f"Baseline-Abweichungen: {deviation_count}")

    # Persistence floor: if any persistence event found, minimum score is 5.0
    if persistence_hit and score < 5.0:
        score = 5.0

    score = round(min(10.0, score), 1)
    reason_text = "; ".join(reasons) if reasons else "Keine kritischen Indikatoren gefunden"
    return score, reason_text




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

    # ── Build key findings line ───────────────────────────────────────────────
    top_eid_str = ", ".join(f"Event-ID {eid} ({cnt}x)" for eid, cnt in _safe_list(insights.get("top_event_ids"))[:4]) or "—"
    top_rule_str = ", ".join(f"Regel {rid} ({cnt}x)" for rid, cnt in _safe_list(insights.get("top_rule_ids"))[:3]) or "—"
    top_proc_str = ", ".join(proc for proc, _ in _safe_list(insights.get("top_processes"))[:4]) or "—"
    top_user_str = ", ".join(u for u, _ in _safe_list(insights.get("top_users"))[:4]) or "—"

    # ── Baseline vs Current block ─────────────────────────────────────────────
    baseline_vs_lines: list[str] = []
    if job.baseline_diff_block and "Keine neuen" not in job.baseline_diff_block:
        baseline_vs_lines = ["", "## Baseline vs. Aktuell", job.baseline_diff_block]
    elif job.baseline_text and "keine Baseline" not in job.baseline_text.lower():
        baseline_vs_lines = ["", "## Baseline", job.baseline_text]

    # ── Structured header (Status + Key Data) ────────────────────────────────
    header_lines = [
        f"# Full Scan Report – {job.host}",
        "",
        "## Status",
        f"- **Risk Score:** {job.risk_score}/10",
        f"- **Risk Level:** {risk_label}",
        f"- **Scan:** completed",
        f"- **Findings:** {job.findings_count}  |  High: {job.high_findings}  |  TI-Treffer: {job.ti_matches}",
        f"- **Profil:** {(job.profile_context.splitlines()[0] if job.profile_context else '—')}",
        "",
        "## Key Data",
        f"- Top Event-IDs: {top_eid_str}",
        f"- Top Regeln: {top_rule_str}",
        f"- Top Prozesse: {top_proc_str}",
        f"- Top Nutzer: {top_user_str}",
    ]

    # ── AI block (single, no duplication) ────────────────────────────────────
    ai_block = job.ai_final_summary or (
        "## Executive Summary\n"
        "Keine KI-Zusammenfassung verfügbar (Quick-Modus oder KI deaktiviert).\n\n"
        "## Risiko-Einschätzung\n"
        f"Risk Level: {risk_label} (Score {job.risk_score}/10)\n\n"
        "## Maßnahmen\n"
        + "\n".join(f"- {s}" for s in next_steps)
    )

    markdown_report = "\n".join(header_lines + baseline_vs_lines + ["", "---", ""] + [ai_block])

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
            job.risk_score, _risk_reason = _compute_risk_score_v2(
                insights,
                ti_matches=len(job.threat_intel),
                deviation_count=_deviation_count,
            )
            job.risk_score_reason = _risk_reason
            job.add_log(f"Risk Score v2: {job.risk_score}/10 ({map_score_to_level(job.risk_score)}) — {_risk_reason}")
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
            job.risk_score, _risk_reason = _compute_risk_score_v2(
                insights,
                ti_matches=len(job.threat_intel),
                deviation_count=_deviation_count,
            )
            job.risk_score_reason = _risk_reason
            job.add_log(f"Risk Score v2: {job.risk_score}/10 ({map_score_to_level(job.risk_score)})")
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
