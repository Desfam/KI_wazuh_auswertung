"""Timeline / Correlation API route.

GET /timeline/events
  Query params:
    host            - agent name filter
    agent_id        - Wazuh agent ID filter
    user            - username filter
    source_ip       - source IP filter
    event_id        - Windows event ID filter
    rule_id         - Wazuh rule ID filter
    from_time       - ISO timestamp lower bound (default: now - minutes_before)
    to_time         - ISO timestamp upper bound (default: now + minutes_after)
    minutes_before  - default 15
    minutes_after   - default 15
    limit           - default 200, max 500

Returns normalised timeline items enriched with knowledge key + playbook IDs.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Query

from db.database import get_active_connection
from services.wazuh_indexer import build_auth, build_base_url, build_verify

router = APIRouter(prefix="/timeline", tags=["timeline"])

# ── Optional knowledge enrichment ─────────────────────────────────────────────
try:
    from knowledge.event_knowledge_resolver import resolve_event_knowledge as _resolve_knowledge
    from knowledge.investigation_playbooks import get_playbooks_for_event_knowledge as _resolve_playbooks
    _ENRICH = True
except ImportError:
    _ENRICH = False

    def _resolve_knowledge(e: Any) -> dict:  # type: ignore[misc]
        return {}

    def _resolve_playbooks(k: Any, e: Any = None) -> list:  # type: ignore[misc]
        return []


SEV_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _level_to_sev(level: Any) -> str:
    try:
        lvl = int(level)
    except (TypeError, ValueError):
        return "info"
    if lvl >= 12:
        return "critical"
    if lvl >= 10:
        return "high"
    if lvl >= 7:
        return "medium"
    if lvl >= 4:
        return "low"
    return "info"


def _safe(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s if s and s not in ("-", "?", "null", "None", "") else None


def _first(*vals: Any) -> str | None:
    for v in vals:
        s = _safe(v)
        if s:
            return s
    return None


@router.get("/events")
def get_timeline_events(
    host: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    user: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    event_id: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    from_time: str | None = Query(default=None),
    to_time: str | None = Query(default=None),
    minutes_before: int = Query(default=15, ge=1, le=1440),
    minutes_after: int = Query(default=15, ge=0, le=1440),
    limit: int = Query(default=200, ge=1, le=500),
) -> list[dict[str, Any]]:
    """Return normalised timeline events around a specific time window."""

    record = get_active_connection()
    if not record:
        return []

    conn = dict(record)
    now = datetime.now(timezone.utc)

    # Resolve time bounds
    try:
        ts_from = datetime.fromisoformat(from_time).replace(tzinfo=timezone.utc) if from_time else now - timedelta(minutes=minutes_before)
    except (ValueError, TypeError):
        ts_from = now - timedelta(minutes=minutes_before)

    try:
        ts_to = datetime.fromisoformat(to_time).replace(tzinfo=timezone.utc) if to_time else now + timedelta(minutes=minutes_after)
    except (ValueError, TypeError):
        ts_to = now + timedelta(minutes=minutes_after)

    # Build ES query filters
    must_filters: list[dict[str, Any]] = [
        {
            "range": {
                "timestamp": {
                    "gte": ts_from.isoformat(),
                    "lte": ts_to.isoformat(),
                    "format": "strict_date_optional_time",
                }
            }
        }
    ]

    if host:
        must_filters.append({"wildcard": {"agent.name": f"*{host}*"}})
    if agent_id:
        must_filters.append({"term": {"agent.id": agent_id}})
    if user:
        must_filters.append({
            "bool": {
                "should": [
                    {"wildcard": {"data.dstuser": f"*{user}*"}},
                    {"wildcard": {"data.srcuser": f"*{user}*"}},
                    {"wildcard": {"data.win.eventdata.targetUserName": f"*{user}*"}},
                ],
                "minimum_should_match": 1,
            }
        })
    if source_ip:
        must_filters.append({
            "bool": {
                "should": [
                    {"term": {"data.srcip": source_ip}},
                    {"term": {"data.win.eventdata.ipAddress": source_ip}},
                ],
                "minimum_should_match": 1,
            }
        })
    if event_id:
        must_filters.append({
            "bool": {
                "should": [
                    {"term": {"data.win.system.eventID": event_id}},
                    {"term": {"data.id": event_id}},
                ],
                "minimum_should_match": 1,
            }
        })
    if rule_id:
        must_filters.append({"term": {"rule.id": rule_id}})

    payload: dict[str, Any] = {
        "sort": [{"timestamp": {"order": "asc", "unmapped_type": "boolean"}}],
        "size": limit,
        "_source": {"excludes": ["@timestamp"]},
        "query": {
            "bool": {
                "must": [],
                "filter": must_filters,
                "should": [],
                "must_not": [],
            }
        },
    }

    index_pattern = conn.get("indexer_index_pattern", "wazuh-alerts-*")
    try:
        with httpx.Client(
            verify=build_verify(conn), timeout=30.0, auth=build_auth(conn)
        ) as client:
            resp = client.post(
                f"{build_base_url(conn)}/{index_pattern}/_search", json=payload
            )
            resp.raise_for_status()
            raw_hits = resp.json().get("hits", {}).get("hits", [])
    except Exception:
        return []

    items: list[dict[str, Any]] = []
    for h in raw_hits:
        src: dict[str, Any] = h.get("_source") or {}
        agent: dict = src.get("agent") or {}
        rule: dict = src.get("rule") or {}
        data: dict = src.get("data") or {}
        win_raw = data.get("win")
        win: dict = win_raw if isinstance(win_raw, dict) else {}
        evtdata: dict = win.get("eventdata") or {} if isinstance(win.get("eventdata"), dict) else {}
        system: dict = win.get("system") or {} if isinstance(win.get("system"), dict) else {}
        mitre: dict = rule.get("mitre") or {}

        eid = _first(
            system.get("eventID"), system.get("eventId"),
            data.get("eventid"), data.get("event_id"),
        )

        sev = _level_to_sev(rule.get("level"))

        src_ip = _first(
            data.get("srcip"), data.get("src_ip"),
            evtdata.get("ipAddress"), evtdata.get("sourceNetworkAddress"),
        )
        if src_ip in ("::1", "127.0.0.1", "-"):
            src_ip = None

        usr = _first(
            data.get("dstuser"), data.get("srcuser"), data.get("user"),
            evtdata.get("targetUserName"), evtdata.get("subjectUserName"),
        )

        proc_raw = _first(
            evtdata.get("processName"), evtdata.get("newProcessName"),
            evtdata.get("image"), data.get("process"),
        )
        process = (proc_raw.rsplit("\\", 1)[-1] if proc_raw and "\\" in proc_raw else proc_raw)

        fp = _first(
            src.get("syscheck", {}).get("path") if src.get("syscheck") else None,
            evtdata.get("objectName"),
        )

        cmd = _first(evtdata.get("commandLine"), data.get("command_line"))

        tactics = mitre.get("tactic") or []
        if isinstance(tactics, str):
            tactics = [tactics]
        tactic = tactics[0] if tactics else None

        ts = _first(src.get("timestamp"), src.get("@timestamp")) or ""

        # Knowledge + playbook enrichment
        knowledge_key: str | None = None
        playbook_ids: list[str] = []
        kb_title: str | None = None

        if _ENRICH:
            try:
                kb = _resolve_knowledge(src)
                if kb:
                    knowledge_key = kb.get("key")
                    kb_title = kb.get("title")
                    pbs = _resolve_playbooks(kb, src)
                    playbook_ids = [p["playbook_id"] for p in (pbs or []) if p.get("playbook_id")]
            except Exception:
                pass

        category = None
        if _ENRICH and knowledge_key:
            try:
                from knowledge.event_id_knowledge import EVENT_ID_KNOWLEDGE
                if eid and eid in EVENT_ID_KNOWLEDGE:
                    category = EVENT_ID_KNOWLEDGE[eid].get("category")
            except Exception:
                pass

        items.append({
            "timestamp": ts,
            "host": _first(agent.get("name")),
            "agent_id": _first(agent.get("id")),
            "severity": sev,
            "rule_id": _first(rule.get("id")),
            "rule_description": _first(rule.get("description")),
            "event_id": eid,
            "category": category,
            "title": kb_title or _first(rule.get("description")) or (f"EID {eid}" if eid else "Security Alert"),
            "user": usr,
            "source_ip": src_ip,
            "process": process,
            "file_path": fp,
            "command_line": cmd,
            "mitre_tactic": tactic,
            "knowledge_key": knowledge_key,
            "playbook_ids": playbook_ids,
            "raw_preview": {
                "agent": src.get("agent"),
                "rule": src.get("rule"),
                "data": src.get("data"),
                "timestamp": ts,
            },
        })

    return items
