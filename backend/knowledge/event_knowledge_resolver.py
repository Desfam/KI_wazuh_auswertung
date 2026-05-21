"""
Event Knowledge Resolver
========================
Top-level router that dispatches an incoming Wazuh event to the correct
knowledge base — Windows Event ID KB or Linux Event KB — and returns a
normalised knowledge response.

Usage::

    from backend.knowledge.event_knowledge_resolver import resolve_event_knowledge

    knowledge = resolve_event_knowledge(wazuh_event_dict)
    print(knowledge["title"], knowledge["default_severity"])

Response shape
--------------
The returned dict always contains at minimum:

    key               str    — canonical knowledge key
    title             str    — human-readable event title
    category          str    — event category string
    default_severity  str    — info | low | medium | high | critical
    summary           str    — one-line description
    knowledge_level   str    — deep | pattern | basic | generic | unknown
    platform          str    — "windows" | "linux" | "unknown"

Deep entries also carry the full analyst fields from the underlying KB.
"""

from __future__ import annotations

from backend.knowledge.linux_event_knowledge import resolve_linux_event_from_log

# Import lazily or at module level — Windows KB is a plain dict lookup
from backend.knowledge.event_id_knowledge import EVENT_ID_KNOWLEDGE

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Programs that strongly indicate a Linux origin
_LINUX_PROGRAMS: frozenset[str] = frozenset({
    "sshd", "sudo", "su", "login", "cron", "crond",
    "systemd", "kernel", "dmesg", "auditd",
    "dpkg", "apt", "apt-get", "yum", "dnf", "rpm",
    "ossec-syscheckd", "wazuh-syscheckd",
})

# Wazuh decoder names that indicate Linux origin
_LINUX_DECODERS: frozenset[str] = frozenset({
    "sshd", "sudo", "pam", "syslog", "auditd",
    "systemd", "kernel", "dpkg",
})


def _is_linux_event(event: dict) -> bool:
    """Heuristically determine whether an event originates from a Linux host."""
    # 1. Agent OS platform
    try:
        platform: str = event["agent"]["os"]["platform"] or ""
        if "linux" in platform.lower():
            return True
        if "windows" in platform.lower():
            return False
    except (KeyError, TypeError):
        pass

    # 2. Wazuh decoder name
    try:
        decoder_name: str = (event.get("decoder") or {}).get("name") or ""
        if decoder_name.lower() in _LINUX_DECODERS:
            return True
    except (KeyError, TypeError):
        pass

    # 3. Program name / process name
    try:
        prog: str = (
            event.get("program_name")
            or (event.get("data") or {}).get("program_name")
            or (event.get("predecoder") or {}).get("program_name")
            or ""
        )
        if prog.lower() in _LINUX_PROGRAMS:
            return True
    except (KeyError, TypeError):
        pass

    return False


def _extract_windows_event_id(event: dict) -> str | None:
    """Return the Windows Event ID as a string, or None."""
    try:
        # Wazuh normalised field
        eid = event.get("data", {}).get("win", {}).get("system", {}).get("eventID")
        if eid:
            return str(eid)
    except (KeyError, TypeError, AttributeError):
        pass
    try:
        eid = event.get("data", {}).get("id")
        if eid:
            return str(eid)
    except (KeyError, TypeError):
        pass
    return None


def _extract_linux_fields(event: dict) -> tuple[str | None, str | None, str | None, str | None]:
    """Extract (program, message, source, wazuh_rule_description) from a Wazuh event."""
    program: str | None = None
    message: str | None = None
    source: str | None = None
    rule_desc: str | None = None

    try:
        program = (
            event.get("program_name")
            or (event.get("predecoder") or {}).get("program_name")
            or (event.get("data") or {}).get("program_name")
        )
    except (KeyError, TypeError):
        pass

    try:
        message = (
            event.get("full_log")
            or event.get("message")
            or (event.get("data") or {}).get("log")
        )
    except (KeyError, TypeError):
        pass

    try:
        source = (
            event.get("location")
            or (event.get("data") or {}).get("srcip")
        )
    except (KeyError, TypeError):
        pass

    try:
        rule_desc = (event.get("rule") or {}).get("description")
    except (KeyError, TypeError):
        pass

    return program, message, source, rule_desc


def _unknown_fallback(event: dict) -> dict:
    """Return a minimal unknown response."""
    rule_desc: str = ""
    try:
        rule_desc = (event.get("rule") or {}).get("description") or ""
    except (KeyError, TypeError):
        pass

    return {
        "key": "unknown",
        "title": "Unknown Event",
        "category": "unknown",
        "default_severity": "info",
        "summary": rule_desc or "No matching event knowledge found.",
        "knowledge_level": "unknown",
        "platform": "unknown",
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_event_knowledge(event: dict) -> dict:
    """
    Resolve analyst knowledge for a Wazuh event.

    Routing logic
    -------------
    1. If a Windows Event ID is present → Windows KB lookup
    2. If Linux indicators are present → Linux resolver
    3. Wazuh rule description basic fallback
    4. Unknown fallback

    Parameters
    ----------
    event:
        A Wazuh event document (dict).  Must have at least a ``data``
        or ``rule`` sub-key for useful resolution.

    Returns
    -------
    dict
        Normalised knowledge response.  Always contains:
        ``key``, ``title``, ``category``, ``default_severity``,
        ``summary``, ``knowledge_level``, ``platform``.
    """
    if not isinstance(event, dict):
        return _unknown_fallback({})

    # ------------------------------------------------------------------
    # Route 1 — Windows Event ID
    # ------------------------------------------------------------------
    win_event_id = _extract_windows_event_id(event)
    if win_event_id and win_event_id in EVENT_ID_KNOWLEDGE:
        entry = dict(EVENT_ID_KNOWLEDGE[win_event_id])
        entry.setdefault("key", f"windows.event.{win_event_id}")
        entry.setdefault("knowledge_level", "deep")
        entry["platform"] = "windows"
        return entry

    # ------------------------------------------------------------------
    # Route 2 — Linux event
    # ------------------------------------------------------------------
    if _is_linux_event(event):
        program, message, source, rule_desc = _extract_linux_fields(event)
        result = resolve_linux_event_from_log(
            program=program,
            message=message,
            source=source,
            wazuh_rule_description=rule_desc,
        )
        result["platform"] = "linux"
        return result

    # ------------------------------------------------------------------
    # Route 3 — Wazuh rule description basic fallback
    # ------------------------------------------------------------------
    rule_desc: str = ""
    try:
        rule_desc = (event.get("rule") or {}).get("description") or ""
    except (KeyError, TypeError):
        pass

    if rule_desc:
        return {
            "key": "generic",
            "title": "Wazuh Event",
            "category": "unknown",
            "default_severity": "info",
            "summary": rule_desc,
            "knowledge_level": "generic",
            "platform": "unknown",
        }

    # ------------------------------------------------------------------
    # Route 4 — Unknown
    # ------------------------------------------------------------------
    return _unknown_fallback(event)
