"""Event Evidence Extractor (backend)
=====================================
Python port of frontend/src/services/eventEvidenceExtractor.ts

Extracts structured evidence fields from a raw Wazuh event dict.
Used by Event Map cluster enrichment and investigation workbench.
"""
from __future__ import annotations

import re
from typing import Any

# ── Sensitive path patterns: (regex, reason) ──────────────────────────────────
_SENSITIVE_PATTERNS: list[tuple[str, str]] = [
    (r"/etc/shadow", "Contains hashed credentials"),
    (r"/etc/passwd", "Contains user account data"),
    (r"/etc/sudoers", "Defines sudo privileges"),
    (r"\.ssh/", "SSH keys or config"),
    (r"(?i)(\\sam|ntds\.dit)", "Windows credential store"),
    (r"(?i)lsass", "Windows credential process"),
]

_SYSTEM_USERS: frozenset[str] = frozenset({
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON",
})


def _safe(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s if s and s not in ("-", "?", "null", "None", "N/A", "") else None


def _first(*values: Any) -> str | None:
    for v in values:
        s = _safe(v)
        if s:
            return s
    return None


def _basename(p: str | None) -> str | None:
    if not p:
        return None
    p = p.strip().replace("/", "\\")
    return (p.rsplit("\\", 1)[-1] if "\\" in p else p) or None


def extract_event_evidence(event: dict) -> dict:
    """Extract structured evidence from a raw Wazuh event dict.

    Handles both wrapped (``_source``) and unwrapped event formats.
    Returns a dict with only non-None values.
    """
    if not isinstance(event, dict):
        return {}

    # Unwrap _source if present (Elasticsearch/OpenSearch format)
    src = event.get("_source", event)

    agent: dict = src.get("agent") or {}
    rule: dict = src.get("rule") or {}
    data: dict = src.get("data") or {}
    win_raw = data.get("win")
    win: dict = win_raw if isinstance(win_raw, dict) else {}
    evtdata_raw = win.get("eventdata")
    evtdata: dict = evtdata_raw if isinstance(evtdata_raw, dict) else {}
    system_raw = win.get("system")
    system: dict = system_raw if isinstance(system_raw, dict) else {}
    syscheck: dict = src.get("syscheck") or {}
    decoder_raw = src.get("decoder")
    decoder: dict = decoder_raw if isinstance(decoder_raw, dict) else {}
    mitre: dict = rule.get("mitre") or {}

    out: dict[str, Any] = {}

    # ── Host ──────────────────────────────────────────────────────────────────
    out["host"] = _first(agent.get("name"))
    out["host_ip"] = _first(agent.get("ip"))

    # ── User / Identity ───────────────────────────────────────────────────────
    user = _first(
        data.get("dstuser"), data.get("srcuser"), data.get("user"),
        evtdata.get("targetUserName"), evtdata.get("subjectUserName"),
    )
    if user and user not in _SYSTEM_USERS:
        out["user"] = user

    target_user = _first(evtdata.get("targetUserName"))
    if target_user and target_user != out.get("user"):
        out["target_user"] = target_user

    # ── Network ───────────────────────────────────────────────────────────────
    src_ip = _first(
        data.get("srcip"), data.get("src_ip"),
        evtdata.get("ipAddress"), evtdata.get("sourceNetworkAddress"),
    )
    if src_ip and src_ip not in ("::1", "127.0.0.1", "-"):
        out["source_ip"] = src_ip

    out["source_port"] = _first(evtdata.get("ipPort"), data.get("srcport"))
    out["destination_ip"] = _first(evtdata.get("destinationAddress"), data.get("dstip"))
    out["destination_port"] = _first(evtdata.get("destinationPort"), data.get("dstport"))

    # ── Process ───────────────────────────────────────────────────────────────
    out["process"] = _basename(_first(
        evtdata.get("processName"), evtdata.get("newProcessName"),
        evtdata.get("image"), data.get("process"), data.get("command"),
    ))
    out["parent_process"] = _basename(_first(
        evtdata.get("parentProcessName"), evtdata.get("parentImage"),
    ))
    out["command_line"] = _first(
        evtdata.get("commandLine"), evtdata.get("processCommandLine"),
        data.get("command_line"),
    )

    # ── File / Syscheck ───────────────────────────────────────────────────────
    out["file_path"] = _first(
        syscheck.get("path"),
        evtdata.get("objectName"), evtdata.get("targetFilename"),
    )
    out["file_action"] = _first(
        syscheck.get("event"),
        evtdata.get("accessList"), evtdata.get("objectType"),
    )
    out["old_hash"] = _first(syscheck.get("md5_before"), syscheck.get("sha256_before"))
    out["new_hash"] = _first(syscheck.get("md5_after"), syscheck.get("sha256_after"))

    # ── Service ───────────────────────────────────────────────────────────────
    out["service_name"] = _first(evtdata.get("serviceName"), data.get("service"))
    out["service_path"] = _first(evtdata.get("imagePath"), evtdata.get("serviceFileName"))
    out["service_start_type"] = _first(evtdata.get("startType"))

    # ── Package ───────────────────────────────────────────────────────────────
    out["package_name"] = _first(
        data.get("package"), data.get("deb_package"), data.get("rpm_package"),
    )
    out["package_version"] = _first(data.get("version"), data.get("package_version"))

    # ── Logon ─────────────────────────────────────────────────────────────────
    out["logon_type"] = _first(evtdata.get("logonType"))
    out["status"] = _first(evtdata.get("status"), data.get("status"))
    out["sub_status"] = _first(evtdata.get("subStatus"), evtdata.get("substatus"))

    # ── Rule / MITRE ──────────────────────────────────────────────────────────
    out["rule_id"] = _first(rule.get("id"))
    out["rule_description"] = _first(rule.get("description"))

    tactics = mitre.get("tactic") or []
    if isinstance(tactics, str):
        tactics = [tactics]
    if tactics:
        out["mitre_tactics"] = tactics

    ids = mitre.get("id") or []
    if isinstance(ids, str):
        ids = [ids]
    if ids:
        out["mitre_techniques"] = ids

    # ── Windows system metadata ────────────────────────────────────────────────
    out["provider"] = _first(system.get("providerName"))
    out["channel"] = _first(system.get("channel"))
    out["computer"] = _first(system.get("computer"))
    out["event_record_id"] = _first(system.get("eventRecordID"))
    out["level"] = _first(system.get("level"))
    out["task"] = _first(system.get("task"))
    out["opcode"] = _first(system.get("opcode"))

    # ── Location / Decoder ────────────────────────────────────────────────────
    out["location"] = _first(src.get("location"))
    out["decoder"] = _first(decoder.get("name") if isinstance(decoder, dict) else None)

    # ── Sensitive path detection ───────────────────────────────────────────────
    fp = (out.get("file_path") or "").lower()
    pr = (out.get("process") or "").lower()
    check_str = fp + " " + pr
    for pattern, reason in _SENSITIVE_PATTERNS:
        if re.search(pattern, check_str, re.IGNORECASE):
            out["sensitive_path"] = out.get("file_path") or out.get("process")
            out["sensitive_reason"] = reason
            break

    # ── Raw message ───────────────────────────────────────────────────────────
    raw_msg = _first(src.get("full_log"), src.get("message"))
    if raw_msg:
        out["raw_message"] = raw_msg[:500] + ("…" if len(raw_msg) > 500 else "")

    # Remove None values
    return {k: v for k, v in out.items() if v is not None}


def build_evidence_summary(evidence: dict) -> dict:
    """Return a compact evidence summary suitable for cluster-level display."""
    return {k: v for k, v in {
        "top_user": evidence.get("user"),
        "top_source_ip": evidence.get("source_ip"),
        "top_process": evidence.get("process"),
        "file_path": evidence.get("file_path"),
        "file_action": evidence.get("file_action"),
        "service_name": evidence.get("service_name"),
        "command_line": evidence.get("command_line"),
        "sensitive_path": evidence.get("sensitive_path"),
        "sensitive_reason": evidence.get("sensitive_reason"),
        "logon_type": evidence.get("logon_type"),
        "status": evidence.get("status"),
        "sub_status": evidence.get("sub_status"),
    }.items() if v is not None}
