from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx


def build_auth(connection: dict[str, Any] | Any) -> tuple[str, str]:
    return connection["indexer_username"], connection["indexer_password"]


def build_verify(connection: dict[str, Any] | Any) -> bool:
    return bool(connection["verify_ssl"]) if isinstance(connection, dict) else bool(connection.verify_ssl)


def build_base_url(connection: dict[str, Any] | Any) -> str:
    return connection["indexer_url"].rstrip("/") if isinstance(connection, dict) else connection.indexer_url.rstrip("/")


def ping_indexer(connection: dict[str, Any] | Any) -> tuple[bool, str]:
    try:
        with httpx.Client(verify=build_verify(connection), timeout=10.0, auth=build_auth(connection)) as client:
            response = client.get(f"{build_base_url(connection)}/")
            response.raise_for_status()
        return True, "Indexer reachable"
    except Exception as exc:
        return False, str(exc)


def fetch_alerts(connection: dict[str, Any], lookback_hours: int, query_size: int, host_filter: str | None = None) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=lookback_hours)
    payload: dict[str, Any] = {
        "size": query_size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start.isoformat(),
                                "lte": now.isoformat(),
                            }
                        }
                    }
                ]
            }
        },
    }
    if host_filter:
        payload["query"]["bool"]["filter"].append(
            {"wildcard": {"agent.name": f"*{host_filter}*"}}
        )

    index_pattern = connection.get("indexer_index_pattern", "wazuh-alerts-*")
    with httpx.Client(verify=build_verify(connection), timeout=45.0, auth=build_auth(connection)) as client:
        response = client.post(f"{build_base_url(connection)}/{index_pattern}/_search", json=payload)
        response.raise_for_status()
        hits = response.json().get("hits", {}).get("hits", [])
    return [item.get("_source", {}) for item in hits]


def _pick(source: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        current: Any = source
        found = True
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                found = False
                break
        if found and current not in (None, ""):
            return current
    return None


def normalize_alert(raw: dict[str, Any]) -> dict[str, Any]:
    event_id = _pick(raw, "data.win.system.eventID", "data.win.system.eventId", "win.system.eventID")
    host = _pick(raw, "agent.name", "agent.hostname", "host.name", "manager.name") or "unknown-host"
    rule_id = _pick(raw, "rule.id")
    rule_description = _pick(raw, "rule.description", "rule.firedtimes")
    groups = _pick(raw, "rule.groups") or []
    if isinstance(groups, str):
        groups = [groups]
    decoder = _pick(raw, "decoder.name")
    location = _pick(raw, "location") or "unknown-location"
    user = _pick(
        raw,
        "data.win.eventdata.targetUserName",
        "data.win.eventdata.subjectUserName",
        "data.srcuser",
        "data.user",
    )
    logon_type = _pick(raw, "data.win.eventdata.logonType")
    process = _pick(raw, "data.win.eventdata.processName", "data.process.name")
    timestamp = _pick(raw, "@timestamp", "timestamp")
    platform = detect_platform(raw, groups, decoder, event_id)
    linux_type = _pick(raw, "data.program", "syslog.program", "data.audit.exe", "decoder.name")
    return {
        "timestamp": timestamp,
        "host": host,
        "platform": platform,
        "event_id": str(event_id) if event_id is not None else None,
        "rule_id": str(rule_id) if rule_id is not None else None,
        "rule_description": str(rule_description) if rule_description is not None else None,
        "groups": groups,
        "decoder": decoder,
        "location": location,
        "target_user": user,
        "logon_type": str(logon_type) if logon_type is not None else None,
        "process": process,
        "linux_type": linux_type,
        "raw": raw,
    }


def detect_platform(raw: dict[str, Any], groups: list[str], decoder: Any, event_id: Any) -> str:
    groups_joined = " ".join(str(item).lower() for item in groups)
    decoder_text = str(decoder or "").lower()
    if event_id or "windows" in groups_joined or "win" in decoder_text:
        return "windows"
    if any(keyword in groups_joined for keyword in ("linux", "syslog", "sshd", "pam", "audit")):
        return "linux"
    if "sshd" in decoder_text or "pam" in decoder_text or _pick(raw, "data.srcip"):
        return "linux"
    return "other"
