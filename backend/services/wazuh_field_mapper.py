"""
wazuh_field_mapper.py
=====================
Normalise both nested Wazuh-JSON (from Indexer) and flat escaped CSV/export
field names (e.g. ``data\\.win\\.system\\.eventID``) into a consistent dict.

Usage::

    from services.wazuh_field_mapper import normalize_wazuh_event, get_field

    norm = normalize_wazuh_event(raw_event)
    print(norm["event_id"], norm["target_user"])
"""
from __future__ import annotations

import re
from typing import Any


# ── helpers ───────────────────────────────────────────────────────────────────

def _safe_str(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, list):
        v = v[0] if v else None
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _safe_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _safe_list_str(v: Any) -> list[str]:
    """Turn a string, list, or None into a list[str]."""
    if not v:
        return []
    if isinstance(v, list):
        return [str(i).strip() for i in v if i]
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return []
        # Sometimes Wazuh exports lists as JSON-like: ["T1078"]
        if s.startswith("[") and s.endswith("]"):
            try:
                import json
                parsed = json.loads(s)
                return [str(i).strip() for i in parsed if i]
            except Exception:
                pass
        return [s]
    return [str(v)]


# ── flat (CSV) path resolver ───────────────────────────────────────────────────

# Pre-compiled: split flat escaped path like "data\.win\.system\.eventID"
# into ["data", "win", "system", "eventID"]
_FLAT_SPLIT = re.compile(r"(?<!\\)\.")  # split on unescaped dot

def _unescape_key(k: str) -> str:
    return k.replace("\\.", ".")


def get_field(event: dict, *paths: str) -> Any:
    """
    Try each path in order; return the first non-None/non-empty value.

    Each path can be:
    - Nested JSON dotpath:      "data.win.eventdata.targetUserName"
    - Flat escaped CSV path:    "data\\.win\\.eventdata\\.targetUserName"
    - Single key:               "targetUserName"

    Also handles alternative casing automatically for the last key step.
    """
    for path in paths:
        val = _resolve_path(event, path)
        if val is not None and val != "":
            return val
    return None


def _resolve_path(obj: Any, path: str) -> Any:
    if not isinstance(obj, dict):
        return None

    # Flat escaped path — try it as a literal top-level key first
    if "\\." in path:
        if path in obj:
            return obj[path]
        # Split on escaped dot and walk
        parts = [_unescape_key(p) for p in path.split("\\.")]
        return _walk(obj, parts)

    # Nested dotpath — check if literal key exists first
    if path in obj:
        return obj[path]
    parts = path.split(".")
    return _walk(obj, parts)


def _walk(obj: Any, parts: list[str]) -> Any:
    cur = obj
    for part in parts:
        if not isinstance(cur, dict):
            return None
        # Try exact key, then alternative casing variants
        if part in cur:
            cur = cur[part]
        else:
            # Try case-insensitive match for common eventdata casing issue
            found = False
            part_lower = part.lower()
            for k, v in cur.items():
                if k.lower() == part_lower:
                    cur = v
                    found = True
                    break
            if not found:
                return None
    return cur


# ── main normaliser ───────────────────────────────────────────────────────────

def normalize_wazuh_event(event: dict) -> dict:
    """
    Convert a raw Wazuh alert (from Indexer hit or CSV row) into a flat,
    consistently named dict.  Returns a superset — unknown fields still
    accessible via ``norm["raw"]``.
    """
    # ── agent ──────────────────────────────────────────────────────────────
    agent_name = _safe_str(get_field(event,
        "agent.name", "agent\\.name"))
    agent_id   = _safe_str(get_field(event,
        "agent.id", "agent\\.id"))
    agent_ip   = _safe_str(get_field(event,
        "agent.ip", "agent\\.ip"))
    manager_name = _safe_str(get_field(event,
        "manager.name", "manager\\.name"))
    index = _safe_str(get_field(event,
        "_index", "index"))
    timestamp = _safe_str(get_field(event,
        "timestamp", "@timestamp",
        "data\\.win\\.system\\.systemTime"))

    # ── rule / decoder ─────────────────────────────────────────────────────
    rule_id   = _safe_str(get_field(event, "rule.id", "rule\\.id"))
    rule_level = _safe_int(get_field(event, "rule.level", "rule\\.level"))
    rule_desc  = _safe_str(get_field(event,
        "rule.description", "rule\\.description"))
    rule_groups = _safe_list_str(get_field(event,
        "rule.groups", "rule\\.groups"))

    mitre_ids        = _safe_list_str(get_field(event,
        "rule.mitre.id", "rule\\.mitre\\.id"))
    mitre_tactics    = _safe_list_str(get_field(event,
        "rule.mitre.tactic", "rule\\.mitre\\.tactic"))
    mitre_techniques = _safe_list_str(get_field(event,
        "rule.mitre.technique", "rule\\.mitre\\.technique"))

    decoder_name = _safe_str(get_field(event,
        "decoder.name", "decoder\\.name"))
    location = _safe_str(get_field(event, "location"))

    # ── Windows system block ───────────────────────────────────────────────
    event_id = _safe_str(get_field(event,
        "data.win.system.eventID",
        "data\\.win\\.system\\.eventID"))
    provider = _safe_str(get_field(event,
        "data.win.system.providerName",
        "data\\.win\\.system\\.providerName"))
    channel  = _safe_str(get_field(event,
        "data.win.system.channel",
        "data\\.win\\.system\\.channel"))
    computer = _safe_str(get_field(event,
        "data.win.system.computer",
        "data\\.win\\.system\\.computer"))
    event_record_id = _safe_str(get_field(event,
        "data.win.system.eventRecordID",
        "data\\.win\\.system\\.eventRecordID"))
    system_message = _safe_str(get_field(event,
        "data.win.system.message",
        "data\\.win\\.system\\.message"))

    # ── Windows eventdata block ────────────────────────────────────────────
    # The eventdata key can be lowercase ("eventdata") or camelCase ("eventData")
    # get_field handles this via case-insensitive matching.

    target_user  = _safe_str(get_field(event,
        "data.win.eventdata.targetUserName",
        "data\\.win\\.eventdata\\.targetUserName"))
    subject_user = _safe_str(get_field(event,
        "data.win.eventdata.subjectUserName",
        "data\\.win\\.eventdata\\.subjectUserName"))
    # Combine for a generic "user" field: prefer target, fall back to subject
    user = target_user or subject_user

    source_ip    = _safe_str(get_field(event,
        "data.win.eventdata.ipAddress",
        "data\\.win\\.eventdata\\.ipAddress"))
    source_port  = _safe_str(get_field(event,
        "data.win.eventdata.ipPort",
        "data\\.win\\.eventdata\\.ipPort"))
    workstation  = _safe_str(get_field(event,
        "data.win.eventdata.workstationName",
        "data\\.win\\.eventdata\\.workstationName"))
    logon_type   = _safe_str(get_field(event,
        "data.win.eventdata.logonType",
        "data\\.win\\.eventdata\\.logonType"))

    process_name = _safe_str(get_field(event,
        "data.win.eventdata.newProcessName",
        "data\\.win\\.eventdata\\.newProcessName",
        "data.win.eventdata.processName",
        "data\\.win\\.eventdata\\.processName"))
    process_id   = _safe_str(get_field(event,
        "data.win.eventdata.newProcessId",
        "data\\.win\\.eventdata\\.newProcessId",
        "data.win.eventdata.processId",
        "data\\.win\\.eventdata\\.processId"))
    command_line = _safe_str(get_field(event,
        "data.win.eventdata.commandLine",
        "data\\.win\\.eventdata\\.commandLine"))
    parent_process = _safe_str(get_field(event,
        "data.win.eventdata.parentProcessName",
        "data\\.win\\.eventdata\\.parentProcessName"))

    service_name = _safe_str(get_field(event,
        "data.win.eventdata.serviceName",
        "data\\.win\\.eventdata\\.serviceName",
        # Service Control Manager uses param1 for service name
        "data.win.eventdata.param1",
        "data\\.win\\.eventdata\\.param1"))
    service_path = _safe_str(get_field(event,
        "data.win.eventdata.imagePath",
        "data\\.win\\.eventdata\\.imagePath"))

    # ── FIM / syscheck ────────────────────────────────────────────────────
    file_path   = _safe_str(get_field(event, "syscheck.path"))
    file_action = _safe_str(get_field(event, "syscheck.event"))

    # ── Linux / generic ───────────────────────────────────────────────────
    full_log = _safe_str(get_field(event, "full_log", "message"))

    return {
        # agent
        "agent_name":    agent_name,
        "agent_id":      agent_id,
        "agent_ip":      agent_ip,
        "manager_name":  manager_name,
        "index":         index,
        "timestamp":     timestamp,
        # rule
        "rule_id":       rule_id,
        "rule_level":    rule_level,
        "rule_description": rule_desc,
        "rule_groups":   rule_groups,
        "mitre_ids":     mitre_ids,
        "mitre_tactics": mitre_tactics,
        "mitre_techniques": mitre_techniques,
        # decoder / location
        "decoder_name":  decoder_name,
        "location":      location,
        # Windows system
        "event_id":      event_id,
        "provider":      provider,
        "channel":       channel,
        "computer":      computer,
        "event_record_id": event_record_id,
        "system_message": system_message,
        # Windows eventdata
        "target_user":   target_user,
        "subject_user":  subject_user,
        "user":          user,
        "source_ip":     source_ip,
        "source_port":   source_port,
        "workstation":   workstation,
        "logon_type":    logon_type,
        "process_name":  process_name,
        "process_id":    process_id,
        "command_line":  command_line,
        "parent_process": parent_process,
        "service_name":  service_name,
        "service_path":  service_path,
        # FIM
        "file_path":     file_path,
        "file_action":   file_action,
        # generic
        "full_log":      full_log,
        # original
        "raw":           event,
    }
