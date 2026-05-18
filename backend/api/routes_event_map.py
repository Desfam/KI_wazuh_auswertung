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
    evtdata = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
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
        system.get("eventID"), system.get("eventId"),
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

    result = []
    for b in buckets.values():
        host_counts = sorted(b["_hostCounts"].items(), key=lambda x: -x[1])
        eids = list(b["eventIds"])
        primary_eid = eids[0] if eids else None
        sev = b["severity"]

        explanation = SHORT_EXPLANATIONS.get(primary_eid or "", "")
        if not explanation:
            n_hosts = len(host_counts)
            if sev in ("critical", "high"):
                explanation = f"{b['title']} was detected on {n_hosts} host(s). This severity level requires prompt investigation."
            else:
                explanation = f"{b['title']} was detected on {n_hosts} host(s)."

        actions = list(RECOMMENDED_ACTIONS.get(primary_eid or "", []))
        if not actions:
            actions = list(GENERAL_ACTIONS.get(sev, GENERAL_ACTIONS["info"]))

        result.append({
            "id": b["id"],
            "kind": b["kind"],
            "title": b["title"],
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
        })

    result.sort(key=lambda x: (-SEV_RANK.get(x["severity"], 0), -x["alertCount"]))
    return result[:limit]
