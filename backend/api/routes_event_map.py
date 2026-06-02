"""Event Map — live cluster API.

GET /event-map/live  →  list[LiveEventCluster]

Groups raw Wazuh alerts into event clusters by eventId + ruleId so the
frontend can render a SOC live radar instead of a raw node-graph.
"""
from __future__ import annotations

import hashlib
from typing import Any

from fastapi import APIRouter, Query

from db.database import get_active_connection
from services.wazuh_indexer import fetch_alerts
from services.wazuh_field_mapper import get_field as _wf_get

# ── Knowledge / Evidence / Playbook enrichment (optional — graceful fallback) ─
try:
    from knowledge.event_knowledge_resolver import resolve_event_knowledge as _resolve_knowledge
    from knowledge.investigation_playbooks import get_playbooks_for_event_knowledge as _resolve_playbooks
    from services.event_evidence_extractor import extract_event_evidence, build_evidence_summary
    _ENRICHMENT_AVAILABLE = True
except ImportError:
    _ENRICHMENT_AVAILABLE = False

    def _resolve_knowledge(event: Any) -> dict:  # type: ignore[misc]
        return {}

    def _resolve_playbooks(k: Any, e: Any = None) -> list:  # type: ignore[misc]
        return []

    def extract_event_evidence(e: Any) -> dict:  # type: ignore[misc]
        return {}

    def build_evidence_summary(e: Any) -> dict:  # type: ignore[misc]
        return {}

# ── Baseline-aware evaluation (optional — graceful fallback) ──────────────────
try:
    from services.final_event_evaluator import evaluate_event_with_baseline as _evaluate_event
    _EVALUATION_AVAILABLE = True
except ImportError:
    _EVALUATION_AVAILABLE = False

    def _evaluate_event(event: Any) -> dict | None:  # type: ignore[misc]
        return None

# ── Unified pipeline (Phase 3+) ───────────────────────────────────────────────
try:
    from services.unified_event_evaluator import evaluate_unified_event as _evaluate_unified  # type: ignore[import]
    _UNIFIED_EVAL_AVAILABLE = True
except ImportError:
    _UNIFIED_EVAL_AVAILABLE = False

    def _evaluate_unified(event: Any) -> dict:  # type: ignore[misc]
        return {}

# ── Agent enrichment (optional — graceful fallback) ──────────────────────────
try:
    from services.wazuh_agent_enrichment import (
        enrich_agent_context as _enrich_agent,
        enrich_agent_contexts as _enrich_agents_batch,
        _cache_primary_key as _agent_cache_key,
    )
    _AGENT_ENRICHMENT_AVAILABLE = True
except ImportError:
    _AGENT_ENRICHMENT_AVAILABLE = False

    def _enrich_agent(*a: Any, **kw: Any) -> dict:  # type: ignore[misc]
        return {}

    def _enrich_agents_batch(agents: Any, conn: Any = None) -> dict:  # type: ignore[misc]
        return {}

    def _agent_cache_key(aid: Any, name: Any, ip: Any) -> str:  # type: ignore[misc]
        return "unknown"

router = APIRouter(prefix="/event-map", tags=["event-map"])

# ─── Known Windows Event ID names ─────────────────────────────────────────────

WIN_EVENT_NAMES: dict[str, str] = {
    "1102": "1102 Audit Log Cleared",
    "4103": "4103 PowerShell Pipe",
    "4104": "4104 PowerShell Script",
    "4624": "4624 Successful Logon",
    "4625": "4625 Login Failure",
    "4634": "4634 Logoff",
    "4648": "4648 Explicit Credential Logon",
    "4657": "4657 Registry Modified",
    "4663": "4663 Object Access",
    "4672": "4672 Special Privileges",
    "4688": "4688 Process Created",
    "4697": "4697 Service Installed",
    "4698": "4698 Scheduled Task Created",
    "4699": "4699 Scheduled Task Deleted",
    "4700": "4700 Scheduled Task Enabled",
    "4720": "4720 Account Created",
    "4726": "4726 Account Deleted",
    "4728": "4728 Group Member Added",
    "4732": "4732 Local Group Member Added",
    "7045": "7045 New Service",
}

SHORT_EXPLANATIONS: dict[str, str] = {
    "1102": "Audit log cleared — high-priority anti-forensics indicator. Preserve remaining logs immediately.",
    "4104": "PowerShell script block logging triggered. Review content for obfuscation or suspicious commands.",
    "4624": "Successful logons observed. Correlate with failed attempts and subsequent privilege events.",
    "4625": "Repeated failed logons detected. May indicate stale credentials, misconfiguration or password spraying.",
    "4648": "Logon using explicit credentials observed. May indicate lateral movement or credential reuse.",
    "4672": "Special privileges assigned to a logon. Verify this is expected for the affected user.",
    "4688": "Process creation events detected. Review process names, command lines and parent process context.",
    "4697": "New Windows service installed via SCM. Verify installer source, path and signer.",
    "4698": "Scheduled task created. Review binary path, trigger conditions and creating account.",
    "4720": "New user account created. Verify this is an authorized action.",
    "7045": "New Windows service installed. May be legitimate admin work or malware persistence.",
}

RECOMMENDED_ACTIONS: dict[str, list[str]] = {
    "1102": [
        "Treat as high priority — possible anti-forensics activity",
        "Preserve any remaining logs from affected host",
        "Correlate with other activity on the same host",
    ],
    "4625": [
        "Check source IPs and logon frequency",
        "Verify whether successful 4624 logons follow the failures",
        "Review affected user account status and lockout policy",
        "Check logon type and workstation name fields",
    ],
    "4648": [
        "Identify which process used explicit credentials",
        "Check whether target host is expected for this account",
        "Correlate with lateral movement indicators",
    ],
    "4672": [
        "Review whether privileged logon is expected for this user",
        "Correlate with subsequent process creation events",
        "Check admin action timeline for this session",
    ],
    "4688": [
        "Inspect process command line and parent process",
        "Check process hash against known malware repositories",
        "Review user context and initiating application",
    ],
    "4697": [
        "Validate service binary path and digital signer",
        "Check whether service name appeared on other hosts",
        "Review service startup type and configured account",
    ],
    "7045": [
        "Validate service binary path and digital signer",
        "Check whether service name appeared on other hosts",
        "Review service startup type and configured account",
    ],
    "4698": [
        "Review scheduled task binary path and trigger",
        "Validate creating account and timestamp",
        "Check whether task appeared on other hosts",
    ],
}

GENERAL_ACTIONS: dict[str, list[str]] = {
    "critical": ["Isolate host immediately", "Collect forensic artifacts", "Escalate to incident response team"],
    "high":     ["Open investigation timeline", "Check lateral movement indicators", "Review full host context"],
    "medium":   ["Correlate with baseline", "Check nearby events on same host", "Review user and process context"],
    "low":      ["Monitor for escalation or repeated pattern", "Validate against host baseline"],
    "info":     ["Monitor for recurrence or escalation"],
}

SEV_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ─── Raw preview helper ───────────────────────────────────────────────────────

def _raw_preview(hit: dict[str, Any]) -> dict[str, Any]:
    """Return a safe, trimmed raw event preview for the Investigation Workbench."""
    full_log = hit.get("full_log") or hit.get("message") or ""
    if len(full_log) > 1000:
        full_log = full_log[:1000] + "\u2026"
    return {
        "agent": hit.get("agent"),
        "rule": hit.get("rule"),
        "data": hit.get("data"),
        "syscheck": hit.get("syscheck") or None,
        "decoder": hit.get("decoder"),
        "location": hit.get("location"),
        "full_log": full_log or None,
        "timestamp": hit.get("timestamp") or hit.get("@timestamp"),
    }


# ─── Extraction helpers ────────────────────────────────────────────────────────

def _safe(v: Any) -> str:
    return str(v).strip() if v is not None else ""


def _first(*values: Any) -> str | None:
    for v in values:
        s = _safe(v)
        if s and s not in ("-", "?", "null", "None"):
            return s
    return None


def _basename(p: str | None) -> str | None:
    if not p:
        return None
    p = p.strip().replace("/", "\\")
    return (p.rsplit("\\", 1)[-1] if "\\" in p else p) or None


def _extract(hit: dict[str, Any]) -> dict[str, Any] | None:
    agent = hit.get("agent") or {}
    rule = hit.get("rule") or {}
    data = hit.get("data") or {}
    win = data.get("win") if isinstance(data.get("win"), dict) else {}
    # Handle both lowercase 'eventdata' and camelCase 'eventData'
    evtdata_raw = win.get("eventdata") or win.get("eventData")
    evtdata = evtdata_raw if isinstance(evtdata_raw, dict) else {}
    system = win.get("system") if isinstance(win.get("system"), dict) else {}
    mitre = rule.get("mitre") or {}

    agent_name = _first(agent.get("name"))
    rule_id = _first(rule.get("id"))
    if not agent_name or not rule_id:
        return None

    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0

    if level >= 12:
        sev = "critical"
    elif level >= 10:
        sev = "high"
    elif level >= 7:
        sev = "medium"
    elif level >= 4:
        sev = "low"
    else:
        sev = "info"

    event_id = _first(
        _wf_get(hit, "data.win.system.eventID"),
        _wf_get(hit, "data.win.system.eventId"),
        data.get("eventid"), data.get("event_id"),
    )

    tactics = mitre.get("tactic") or []
    if isinstance(tactics, str):
        tactics = [tactics]
    tactic = tactics[0] if tactics else None

    ids = mitre.get("id") or []
    if isinstance(ids, str):
        ids = [ids]
    mitre_id = ids[0] if ids else None

    src_ip = _first(
        data.get("srcip"), data.get("src_ip"),
        evtdata.get("ipAddress"), evtdata.get("sourceNetworkAddress"),
    )
    if src_ip in ("::1", "127.0.0.1", "-"):
        src_ip = None

    user = _first(
        data.get("dstuser"), data.get("srcuser"), data.get("user"),
        evtdata.get("targetUserName"), evtdata.get("subjectUserName"),
    )
    if user in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"):
        user = None

    process = _basename(_first(
        evtdata.get("processName"), evtdata.get("newProcessName"),
        evtdata.get("image"), data.get("process"), data.get("command"),
    ))

    timestamp = _first(hit.get("timestamp"), hit.get("@timestamp")) or ""

    return {
        "agentName": agent_name,
        "agentId": _first(agent.get("id")) or "",
        "agentIp": _first(agent.get("ip")),
        "ruleId": rule_id,
        "ruleDesc": _safe(rule.get("description")),
        "severity": sev,
        "eventId": event_id,
        "tactic": tactic,
        "mitreId": mitre_id,
        "srcIp": src_ip,
        "user": user,
        "process": process,
        "timestamp": timestamp,
    }


def _cluster_title(event_id: str | None, rule_desc: str, tactic: str | None) -> str:
    if event_id and event_id in WIN_EVENT_NAMES:
        return WIN_EVENT_NAMES[event_id]
    if event_id:
        return f"EID {event_id}"
    if rule_desc:
        return rule_desc[:60]
    if tactic:
        return tactic
    return "Security Alert"


# ─── Route ────────────────────────────────────────────────────────────────────

@router.get("/live")
def get_live_clusters(
    lookback_hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=50, ge=1, le=200),
    host: str | None = Query(default=None),
) -> list[dict[str, Any]]:
    """Aggregate Wazuh alerts into LiveEventCluster objects for the Event Map."""

    record = get_active_connection()
    if not record:
        return []

    conn = dict(record)
    raw = fetch_alerts(
        conn,
        lookback_hours=lookback_hours,
        query_size=min(limit * 25, 5000),
        host_filter=host or None,
    )

    buckets: dict[str, dict[str, Any]] = {}

    for hit in raw:
        ex = _extract(hit)
        if not ex:
            continue

        # Cluster key: prefer eventId+ruleId, fall back to tactic+ruleId, then ruleId alone
        if ex["eventId"]:
            key = f"eid:{ex['eventId']}:{ex['ruleId']}"
            kind = "event_id"
        elif ex["tactic"]:
            key = f"tac:{ex['tactic']}:{ex['ruleId']}"
            kind = "mitre_tactic"
        else:
            key = f"rule:{ex['ruleId']}"
            kind = "rule"

        if key not in buckets:
            uid = hashlib.md5(key.encode()).hexdigest()[:16]
            buckets[key] = {
                "id": f"cluster:{uid}",
                "kind": kind,
                "title": _cluster_title(ex["eventId"], ex["ruleDesc"], ex["tactic"]),
                "severity": ex["severity"],
                "alertCount": 0,
                "_hostCounts": {},
                "_hostIps": {},
                "_hostAgentIds": {},
                "_userCounts": {},
                "_processCounts": {},
                "_ipCounts": {},
                "ruleIds": set(),
                "eventIds": set(),
                "mitreTactics": set(),
                "mitreIds": set(),
                "firstSeen": ex["timestamp"],
                "lastSeen": ex["timestamp"],
                "_raw_first": hit,
                "_raw_highest_sev": hit,
            }

        b = buckets[key]
        b["alertCount"] += 1

        if SEV_RANK.get(ex["severity"], 0) > SEV_RANK.get(b["severity"], 0):
            b["severity"] = ex["severity"]

        h = ex["agentName"]
        b["_hostCounts"][h] = b["_hostCounts"].get(h, 0) + 1
        if ex["agentIp"]:
            b["_hostIps"][h] = ex["agentIp"]
        if ex["agentId"]:
            b["_hostAgentIds"][h] = ex["agentId"]

        if ex["user"]:
            b["_userCounts"][ex["user"]] = b["_userCounts"].get(ex["user"], 0) + 1
        if ex["process"]:
            b["_processCounts"][ex["process"]] = b["_processCounts"].get(ex["process"], 0) + 1
        if ex["srcIp"]:
            b["_ipCounts"][ex["srcIp"]] = b["_ipCounts"].get(ex["srcIp"], 0) + 1

        b["ruleIds"].add(ex["ruleId"])
        if ex["eventId"]:
            b["eventIds"].add(ex["eventId"])
        if ex["tactic"]:
            b["mitreTactics"].add(ex["tactic"])
        if ex["mitreId"]:
            b["mitreIds"].add(ex["mitreId"])

        ts = ex["timestamp"]
        if ts:
            if not b["firstSeen"] or ts < b["firstSeen"]:
                b["firstSeen"] = ts
            if not b["lastSeen"] or ts > b["lastSeen"]:
                b["lastSeen"] = ts

        # Track highest-severity representative event
        if SEV_RANK.get(ex["severity"], 0) >= SEV_RANK.get(
            _safe((b.get("_raw_highest_sev") or {}).get("rule", {}) or {}).get("level") or "info", 0  # type: ignore[arg-type]
        ):
            b["_raw_highest_sev"] = hit

    result = []

    # ── Batch-enrich agent contexts once before the result loop ───────────────
    agent_context_map: dict = {}
    if _AGENT_ENRICHMENT_AVAILABLE and buckets:
        try:
            agent_descriptors = []
            for b in buckets.values():
                hc = sorted(b["_hostCounts"].items(), key=lambda x: -x[1])
                top_host = hc[0][0] if hc else None
                if top_host:
                    agent_descriptors.append({
                        "agent_id":   b["_hostAgentIds"].get(top_host),
                        "agent_name": top_host,
                        "agent_ip":   b["_hostIps"].get(top_host),
                    })
            agent_context_map = _enrich_agents_batch(agent_descriptors, conn=conn)  # type: ignore[call-arg]
        except Exception:
            agent_context_map = {}

    for b in buckets.values():
        host_counts = sorted(b["_hostCounts"].items(), key=lambda x: -x[1])
        eids = list(b["eventIds"])
        primary_eid = eids[0] if eids else None
        sev = b["severity"]

        # ── Knowledge / Evidence / Playbook enrichment ────────────────────────
        raw_event: dict[str, Any] | None = b.get("_raw_first")
        knowledge: dict[str, Any] = {}
        evidence_smry: dict[str, Any] = {}
        cluster_playbooks: list[dict[str, Any]] = []
        raw_preview: dict[str, Any] | None = None
        evaluation: dict[str, Any] | None = None

        if raw_event:
            raw_preview = _raw_preview(raw_event)
            if _ENRICHMENT_AVAILABLE:
                try:
                    knowledge = _resolve_knowledge(raw_event) or {}  # type: ignore[call-arg]
                except Exception:
                    knowledge = {}
                if knowledge:
                    try:
                        cluster_playbooks = _resolve_playbooks(knowledge, raw_event) or []  # type: ignore[call-arg]
                    except Exception:
                        cluster_playbooks = []
                try:
                    ev = extract_event_evidence(raw_event)  # type: ignore[call-arg]
                    evidence_smry = build_evidence_summary(ev)  # type: ignore[call-arg]
                except Exception:
                    evidence_smry = {}
            if _EVALUATION_AVAILABLE:
                try:
                    evaluation = _evaluate_event(raw_event)  # type: ignore[call-arg]
                except Exception:
                    evaluation = None

            # ── Unified pipeline (explanation + deterministic evaluation) ──────
            unified_evaluation: dict | None = None
            explanation_obj:    dict | None = None
            if raw_event and _UNIFIED_EVAL_AVAILABLE:
                try:
                    unified_evaluation = _evaluate_unified(raw_event)  # type: ignore[call-arg]
                    explanation_obj    = unified_evaluation.get("explanation")
                except Exception:
                    pass

        # ── Wazuh Agent Context — lookup from pre-built batch map ────────────
        wazuh_agent_context: dict | None = None
        if _AGENT_ENRICHMENT_AVAILABLE:
            try:
                top_host = host_counts[0][0] if host_counts else None
                if top_host:
                    top_agent_id = b["_hostAgentIds"].get(top_host)
                    top_agent_ip = b["_hostIps"].get(top_host)
                    cache_key = _agent_cache_key(top_agent_id, top_host, top_agent_ip)  # type: ignore[call-arg]
                    wazuh_agent_context = agent_context_map.get(cache_key)
            except Exception:
                wazuh_agent_context = None

        # ── Title: prefer knowledge title ─────────────────────────────────────
        kb_title: str = knowledge.get("title") or ""
        display_title = b["title"]
        if kb_title and kb_title not in ("Unknown Event", "Wazuh Event", ""):
            display_title = kb_title

        # ── Short explanation: prefer knowledge summary ────────────────────────
        explanation: str = SHORT_EXPLANATIONS.get(primary_eid or "", "")
        if not explanation and knowledge:
            explanation = knowledge.get("summary") or ""
        if not explanation:
            n_hosts = len(host_counts)
            if sev in ("critical", "high"):
                explanation = (
                    f"{display_title} was detected on {n_hosts} host(s). "
                    "This severity level requires prompt investigation."
                )
            else:
                explanation = f"{display_title} was detected on {n_hosts} host(s)."

        # ── Recommended actions: prefer playbook checks ────────────────────────
        if cluster_playbooks:
            actions: list[str] = (cluster_playbooks[0].get("recommended_checks") or [])[:6]
        else:
            actions = list(RECOMMENDED_ACTIONS.get(primary_eid or "", []))
            if not actions:
                actions = list(GENERAL_ACTIONS.get(sev, GENERAL_ACTIONS["info"]))

        # ── Slim playbook payload (top 5) ──────────────────────────────────────
        slim_playbooks = [
            {
                "playbook_id": p.get("playbook_id"),
                "title": p.get("title"),
                "description": p.get("description"),
                "recommended_checks": (p.get("recommended_checks") or [])[:5],
                "recommended_readonly_scripts": p.get("recommended_readonly_scripts") or [],
                "dangerous_actions": p.get("dangerous_actions") or [],
                "blocked_actions_reason": p.get("blocked_actions_reason"),
                "escalation_conditions": p.get("escalation_conditions") or [],
                "false_positive_notes": p.get("false_positive_notes") or [],
            }
            for p in cluster_playbooks[:5]
        ]

        result.append({
            "id": b["id"],
            "kind": b["kind"],
            "title": display_title,
            "severity": sev,
            "alertCount": b["alertCount"],
            "affectedHostCount": len(host_counts),
            "affectedHosts": [
                {
                    "hostname": hn,
                    "agentId": b["_hostAgentIds"].get(hn),
                    "ip": b["_hostIps"].get(hn),
                    "count": cnt,
                }
                for hn, cnt in host_counts[:15]
            ],
            "users": [
                {"name": u, "count": c}
                for u, c in sorted(b["_userCounts"].items(), key=lambda x: -x[1])[:10]
            ],
            "processes": [
                {"name": p, "count": c}
                for p, c in sorted(b["_processCounts"].items(), key=lambda x: -x[1])[:8]
            ],
            "sourceIps": [
                {"ip": ip, "count": c}
                for ip, c in sorted(b["_ipCounts"].items(), key=lambda x: -x[1])[:8]
            ],
            "ruleIds": sorted(b["ruleIds"]),
            "eventIds": sorted(b["eventIds"]),
            "mitreTactics": sorted(b["mitreTactics"]),
            "mitreIds": sorted(b["mitreIds"]),
            "firstSeen": b["firstSeen"],
            "lastSeen": b["lastSeen"],
            "shortExplanation": explanation,
            "recommendedActions": actions,
            # ── New enrichment fields ─────────────────────────────────────────
            "knowledge": knowledge or None,
            "evidence_summary": evidence_smry,
            "playbooks": slim_playbooks,
            "rawPreview": raw_preview,
            "evaluation": evaluation,
            # ── Phase 3: unified pipeline ─────────────────────────────────────
            "explanation": explanation_obj,
            "unified_evaluation": unified_evaluation,            # ── Wazuh Agent Context ───────────────────────────────────────
            "wazuh_agent_context": wazuh_agent_context,        })

    result.sort(key=lambda x: (-SEV_RANK.get(x["severity"], 0), -x["alertCount"]))
    return result[:limit]
