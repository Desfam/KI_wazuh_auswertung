"""Constellation / Event Map API.

Supplies aggregated Wazuh alerts for the force-directed Event Map in the frontend.
The endpoint intentionally returns a compact, UI-friendly event format instead of
raw Wazuh alerts.
"""
from __future__ import annotations

import hashlib
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from db.database import get_active_connection
from services.wazuh_indexer import fetch_alerts
from services.wazuh_field_mapper import get_field as _wf_get

router = APIRouter(prefix="/constellation", tags=["constellation"])


SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _conn() -> dict[str, Any]:
    record = get_active_connection()
    if not record:
        raise HTTPException(status_code=503, detail="No active connection configured")
    return dict(record)


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _level_to_severity(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "info"


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _first_non_empty(*values: Any) -> str | None:
    for value in values:
        text = _safe_str(value)
        if text and text not in ("-", "?", "null", "None"):
            return text
    return None


def _basename(path_or_name: str | None) -> str | None:
    if not path_or_name:
        return None

    value = path_or_name.strip()
    if not value or value == "-":
        return None

    value = value.replace("/", "\\")
    if "\\" in value:
        value = value.rsplit("\\", 1)[-1]

    return value or None


def _extract_mitre(rule: dict[str, Any]) -> tuple[str | None, str | None]:
    mitre = rule.get("mitre") or {}

    tactics = _as_list(mitre.get("tactic"))
    ids = _as_list(mitre.get("id"))

    tactic = _first_non_empty(*tactics)
    mitre_id = _first_non_empty(*ids)

    return tactic, mitre_id


def _explain_event(
    *,
    event_id: str | None,
    rule_desc: str,
    user: str | None,
    process: str | None,
    src_ip: str | None,
    service_name: str | None,
    rule_level: int,
) -> str:
    """Create a short deterministic explanation for the Event Map tooltip."""

    if event_id == "4625":
        return (
            f"Failed logon detected for user '{user or 'unknown'}'. "
            f"Check logon type, failure status, source context and whether successful "
            f"4624 logons happened afterwards."
        )

    if event_id == "4624":
        return (
            f"Successful logon observed for user '{user or 'unknown'}'. "
            f"Correlate with previous failures, source host/IP and privilege events."
        )

    if event_id == "4672":
        return (
            f"Special privileges were assigned to a new logon. "
            f"Verify whether user '{user or 'unknown'}' should receive elevated rights."
        )

    if event_id == "4688":
        return (
            f"Process execution detected: '{process or 'unknown process'}'. "
            f"Review command line, parent process and user context."
        )

    if event_id == "7045":
        return (
            f"New Windows service created: '{service_name or 'unknown service'}'. "
            f"New services can be legitimate administration or persistence."
        )

    if src_ip:
        return (
            f"{rule_desc or 'Security event detected.'} Source IP '{src_ip}' is involved. "
            f"Validate whether this IP is expected for the affected host."
        )

    if rule_level >= 10:
        return (
            f"{rule_desc or 'High severity Wazuh alert detected.'} "
            f"Prioritize validation and correlate nearby host activity."
        )

    return rule_desc or "Wazuh alert detected. Correlate with host context and baseline."


def _next_step(
    *,
    event_id: str | None,
    severity: str,
    src_ip: str | None,
    process: str | None,
    service_name: str | None,
) -> str:
    if event_id == "4625":
        return "Check failed-logon burst count, source IP/host, target account status and following 4624 events."

    if event_id == "4624":
        return "Verify whether this successful logon followed failed attempts or used unusual source context."

    if event_id == "4672":
        return "Review privileged account usage and correlate with process creation and admin actions."

    if event_id == "4688":
        return f"Inspect parent process, command line and hash for '{process or 'the process'}'."

    if event_id == "7045":
        return f"Validate service path, signer, installer source and whether '{service_name or 'this service'}' appears on other hosts."

    if src_ip:
        return "Run threat-intel lookup and check whether the IP appears on multiple hosts."

    if severity in ("critical", "high"):
        return "Open investigation timeline, validate evidence and consider containment if activity is confirmed."

    if severity == "medium":
        return "Correlate with baseline, nearby events and affected user/process context."

    return "Monitor for recurrence or escalation."


def _map_alert(hit: dict[str, Any], idx: int) -> dict[str, Any] | None:
    """Map one raw Wazuh alert to a compact ConstellationEvent object."""

    agent = hit.get("agent") or {}
    rule = hit.get("rule") or {}
    data = hit.get("data") or {}
    syscheck = hit.get("syscheck") or {}

    win = data.get("win") if isinstance(data.get("win"), dict) else {}
    # Handle both lowercase 'eventdata' and camelCase 'eventData'
    win_evtdata_raw = win.get("eventdata") or win.get("eventData")
    win_evtdata = win_evtdata_raw if isinstance(win_evtdata_raw, dict) else {}
    win_system = win.get("system") if isinstance(win.get("system"), dict) else {}

    agent_name = _first_non_empty(agent.get("name"), hit.get("agent_name"))
    agent_id = _first_non_empty(agent.get("id"), hit.get("agent_id")) or ""
    agent_ip = _first_non_empty(agent.get("ip"), hit.get("agent_ip"))

    rule_id = _first_non_empty(rule.get("id"), hit.get("rule_id"))
    rule_desc = _safe_str(rule.get("description"))

    if not agent_name or not rule_id:
        return None

    try:
        rule_level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        rule_level = 0

    severity = _level_to_severity(rule_level)

    mitre_tactic, mitre_id = _extract_mitre(rule)

    event_id = _first_non_empty(
        _wf_get(hit, "data.win.system.eventID"),
        _wf_get(hit, "data.win.system.eventId"),
        data.get("eventid"),
        data.get("event_id"),
    )

    src_ip = _first_non_empty(
        data.get("srcip"),
        data.get("src_ip"),
        data.get("source_ip"),
        hit.get("srcip"),
        win_evtdata.get("ipAddress"),
        win_evtdata.get("sourceNetworkAddress"),
    )

    if src_ip in ("::1", "127.0.0.1", "-"):
        src_ip = None

    user = _first_non_empty(
        data.get("dstuser"),
        data.get("srcuser"),
        data.get("user"),
        win_evtdata.get("targetUserName"),
        win_evtdata.get("subjectUserName"),
        win_evtdata.get("accountName"),
    )

    if user in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"):
        user = None

    process_raw = _first_non_empty(
        win_evtdata.get("processName"),
        win_evtdata.get("newProcessName"),
        win_evtdata.get("image"),
        win_evtdata.get("parentImage"),
        data.get("process"),
        data.get("command"),
    )
    process = _basename(process_raw)

    service_name = _first_non_empty(
        win_evtdata.get("serviceName"),
        win_evtdata.get("service"),
        data.get("service"),
    )

    file_path = _first_non_empty(
        syscheck.get("path"),
        win_evtdata.get("targetFilename"),
        win_evtdata.get("objectName"),
    )

    timestamp = _first_non_empty(
        hit.get("timestamp"),
        hit.get("@timestamp"),
    ) or ""

    uid = hashlib.md5(
        f"{agent_id}:{agent_name}:{rule_id}:{event_id or ''}:{timestamp}:{idx}".encode("utf-8")
    ).hexdigest()[:16]

    explanation = _explain_event(
        event_id=event_id,
        rule_desc=rule_desc,
        user=user,
        process=process,
        src_ip=src_ip,
        service_name=service_name,
        rule_level=rule_level,
    )

    next_step = _next_step(
        event_id=event_id,
        severity=severity,
        src_ip=src_ip,
        process=process,
        service_name=service_name,
    )

    return {
        "id": uid,
        "timestamp": timestamp,
        "agentName": agent_name,
        "agentId": agent_id,
        "agentIp": agent_ip,
        "ruleId": str(rule_id),
        "ruleLevel": rule_level,
        "ruleDescription": rule_desc,
        "severity": severity,
        "eventId": str(event_id) if event_id else None,
        "mitreTactic": mitre_tactic,
        "mitreId": mitre_id,
        "srcIp": src_ip,
        "user": user,
        "process": process,
        "serviceName": service_name,
        "filePath": file_path,
        "count": 1,
        "explanation": explanation,
        "nextStep": next_step,
    }


def _aggregate(events: list[dict[str, Any]], max_nodes: int = 300) -> list[dict[str, Any]]:
    """Aggregate repeated alert contexts.

    Grouping by host + rule + event id + user + process + source ip keeps the map useful:
    repeated noise becomes thicker links instead of hundreds of duplicate nodes.
    """

    buckets: dict[str, dict[str, Any]] = {}

    for ev in events:
        key = "|".join(
            [
                ev.get("agentName") or "",
                ev.get("ruleId") or "",
                ev.get("eventId") or "",
                ev.get("user") or "",
                ev.get("process") or "",
                ev.get("srcIp") or "",
                ev.get("serviceName") or "",
            ]
        )

        if key not in buckets:
            buckets[key] = dict(ev)
            continue

        existing = buckets[key]
        existing["count"] = int(existing.get("count") or 1) + int(ev.get("count") or 1)

        if SEVERITY_RANK.get(ev["severity"], 0) > SEVERITY_RANK.get(existing["severity"], 0):
            existing["severity"] = ev["severity"]
            existing["ruleLevel"] = ev["ruleLevel"]

        if not existing.get("timestamp") or ev.get("timestamp", "") > existing.get("timestamp", ""):
            existing["timestamp"] = ev.get("timestamp")

    result = list(buckets.values())
    result.sort(
        key=lambda e: (
            SEVERITY_RANK.get(e.get("severity", "info"), 0),
            int(e.get("count") or 1),
            int(e.get("ruleLevel") or 0),
        ),
        reverse=True,
    )

    return result[:max_nodes]


@router.get("/events")
def get_constellation_events(
    lookback_hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=300, ge=1, le=1000),
    host: str | None = Query(default=None),
) -> list[dict[str, Any]]:
    """Return aggregated Wazuh alerts formatted for the Event Map."""

    conn = _conn()

    raw = fetch_alerts(
        conn,
        lookback_hours=lookback_hours,
        query_size=min(limit * 5, 2500),
        host_filter=host or None,
    )

    mapped: list[dict[str, Any]] = []
    for idx, hit in enumerate(raw):
        ev = _map_alert(hit, idx)
        if ev:
            mapped.append(ev)

    return _aggregate(mapped, max_nodes=limit)