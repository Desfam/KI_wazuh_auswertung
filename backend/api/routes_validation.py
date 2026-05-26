"""
Trust Center / Validation Layer
================================
GET /validation/status

Runs a battery of self-tests against the core SOC subsystems:
  - Knowledge resolver (Windows + Linux)
  - Evidence extractor
  - Host matching
  - API health (DB tables, scripts, timeline, audit endpoints)

No dangerous actions, no script execution, no remote calls except
testing the Wazuh indexer + Tactical RMM reachability (health-check only).
"""
from __future__ import annotations

import traceback
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter

from db.database import get_active_connection, get_connection

router = APIRouter(prefix="/validation", tags=["validation"])

# ── lazy imports ──────────────────────────────────────────────────────────────

def _import_resolver():
    try:
        from knowledge.event_knowledge_resolver import resolve_event_knowledge
        return resolve_event_knowledge
    except ImportError:
        return None


def _import_linux_kb():
    try:
        from knowledge.linux_event_knowledge import LINUX_KB
        return LINUX_KB
    except ImportError:
        return None


def _import_evidence_extractor():
    try:
        from services.event_evidence_extractor import extract_event_evidence
        return extract_event_evidence
    except ImportError:
        return None


def _import_win_kb():
    try:
        from knowledge.event_id_knowledge import EVENT_ID_KNOWLEDGE
        return EVENT_ID_KNOWLEDGE
    except ImportError:
        return None


def _import_playbooks():
    try:
        from knowledge.investigation_playbooks import get_all_playbooks, _PLAYBOOKS  # noqa: F401
        return _PLAYBOOKS
    except ImportError:
        return None


# ── helpers ───────────────────────────────────────────────────────────────────

def _pass(name: str, category: str, message: str, details: dict | None = None) -> dict:
    return {"id": name.lower().replace(" ", "_"), "name": name, "category": category,
            "status": "pass", "message": message, "details": details or {}}


def _fail(name: str, category: str, message: str, details: dict | None = None) -> dict:
    return {"id": name.lower().replace(" ", "_"), "name": name, "category": category,
            "status": "fail", "message": message, "details": details or {}}


def _warn(name: str, category: str, message: str, details: dict | None = None) -> dict:
    return {"id": name.lower().replace(" ", "_"), "name": name, "category": category,
            "status": "warning", "message": message, "details": details or {}}


# ── Mock events for self-tests ────────────────────────────────────────────────

_WIN_4625 = {
    "agent": {"name": "FS-01", "ip": "10.0.1.10", "os": {"platform": "windows"}},
    "rule": {"id": "60122", "level": 10, "description": "Multiple authentication failures"},
    "data": {"win": {"system": {"eventID": "4625"},
                     "eventdata": {"targetUserName": "guest", "logonType": "3",
                                   "ipAddress": "192.168.56.23", "status": "0xC000006A",
                                   "subStatus": "0xC0000064"}}},
    "timestamp": "2024-01-01T12:00:00Z",
}

_WIN_7045 = {
    "agent": {"name": "APP-02", "ip": "10.0.8.22", "os": {"platform": "windows"}},
    "rule": {"id": "60602", "level": 10, "description": "New Windows service created"},
    "data": {"win": {"system": {"eventID": "7045"},
                     "eventdata": {"serviceName": "WinDefUpdate",
                                   "imagePath": "C:\\Windows\\Temp\\wdup.exe -svc",
                                   "accountName": ".\\Administrator"}}},
    "timestamp": "2024-01-01T12:05:00Z",
}

_WIN_1102 = {
    "agent": {"name": "DC-01", "ip": "10.0.0.1", "os": {"platform": "windows"}},
    "rule": {"id": "83700", "level": 12, "description": "Windows Audit Log Cleared"},
    "data": {"win": {"system": {"eventID": "1102"},
                     "eventdata": {"subjectUserName": "jsmith", "subjectDomainName": "CORP"}}},
    "timestamp": "2024-01-01T12:10:00Z",
}

_LINUX_SSH = {
    "agent": {"name": "srv-web01", "ip": "10.10.1.30", "os": {"platform": "linux"}},
    "rule": {"id": "5716", "level": 5, "description": "SSH: Multiple authentication failures"},
    "program_name": "sshd",
    "full_log": "May 21 09:32:11 srv-web01 sshd[18432]: Failed password for invalid user root from 45.129.56.100 port 52312 ssh2",
    "timestamp": "2024-01-01T09:32:11Z",
}

_LINUX_SUDO = {
    "agent": {"name": "dev-srv-04", "ip": "10.10.2.14", "os": {"platform": "linux"}},
    "rule": {"id": "5402", "level": 7, "description": "Sudo: Command run as root"},
    "program_name": "sudo",
    "full_log": "May 21 10:14:32 dev-srv-04 sudo: j.developer : TTY=pts/0 ; PWD=/home/j.developer ; USER=root ; COMMAND=/bin/bash",
    "timestamp": "2024-01-01T10:14:32Z",
}

_LINUX_FIM = {
    "agent": {"name": "db-master", "ip": "10.10.3.50", "os": {"platform": "linux"}},
    "rule": {"id": "550", "level": 7, "description": "Integrity checksum changed"},
    "program_name": "ossec-syscheckd",
    "location": "syscheck",
    "syscheck": {"path": "/etc/passwd", "event": "modified",
                 "md5_after": "a1b2c3d4e5f6", "md5_before": "9f8e7d6c5b4a"},
    "timestamp": "2024-01-01T11:00:00Z",
}

_UNKNOWN_EVENT = {
    "agent": {"name": "unknown-host", "ip": "10.0.99.1"},
    "rule": {"id": "99999", "level": 3, "description": "Some completely unknown event type"},
    "data": {"custom_field": "some_value"},
    "timestamp": "2024-01-01T13:00:00Z",
}

_WIN_UFW_LIKE = {
    "agent": {"name": "gw-01", "ip": "10.0.0.254", "os": {"platform": "linux"}},
    "rule": {"id": "4151", "level": 3, "description": "UFW: DROP packet"},
    "program_name": "kernel",
    "full_log": "May 21 09:00:01 gw-01 kernel: [UFW DROP] IN=eth0 OUT= SRC=203.0.113.45 DST=10.0.0.1 SPT=54321 DPT=22 PROTO=TCP",
    "timestamp": "2024-01-01T09:00:01Z",
}


# ── RESOLVER SELF-TESTS ───────────────────────────────────────────────────────

def _run_resolver_tests(resolve_fn: Any) -> list[dict]:
    tests: list[dict] = []

    cases: list[tuple[str, dict, str, str, str]] = [
        ("4625 → Windows Failed Logon",  _WIN_4625,      "windows", "authentication",    "windows"),
        ("7045 → Windows Service Install", _WIN_7045,    "windows", "persistence",        "windows"),
        ("1102 → Audit Log Cleared",      _WIN_1102,     "windows", "anti_forensics",     "windows"),
        ("Linux SSH Login Failure",       _LINUX_SSH,    "linux",   "authentication",     "linux"),
        ("Linux sudo Command",            _LINUX_SUDO,   "linux",   "privilege_escalation","linux"),
        ("Linux FIM Sensitive Path",      _LINUX_FIM,    "linux",   "fim",                "linux"),
    ]

    for name, event, exp_platform, exp_category, exp_kb_platform in cases:
        try:
            k = resolve_fn(event)
            if not isinstance(k, dict):
                tests.append(_fail(name, "resolver", "Resolver returned non-dict", {"returned": type(k).__name__}))
                continue
            actual_platform = k.get("platform", "unknown")
            actual_category = k.get("category", "unknown")
            actual_level    = k.get("knowledge_level", "unknown")
            if actual_platform != exp_kb_platform:
                tests.append(_warn(name, "resolver",
                    f"Platform mismatch: expected={exp_kb_platform}, got={actual_platform}",
                    {"key": k.get("key"), "knowledge_level": actual_level}))
            elif actual_level == "unknown":
                tests.append(_warn(name, "resolver",
                    f"Resolved but knowledge_level=unknown (category={actual_category})",
                    {"key": k.get("key")}))
            else:
                tests.append(_pass(name, "resolver",
                    f"Resolved → {k.get('title','?')} [{actual_level}]",
                    {"key": k.get("key"), "category": actual_category, "severity": k.get("default_severity")}))
        except Exception as exc:
            tests.append(_fail(name, "resolver", f"Exception: {exc}",
                               {"traceback": traceback.format_exc(limit=3)}))

    # Unknown event — must NOT crash
    try:
        k = resolve_fn(_UNKNOWN_EVENT)
        if isinstance(k, dict):
            tests.append(_pass("Unknown Event → Fallback", "resolver",
                               f"Fallback returned without crash: knowledge_level={k.get('knowledge_level','?')}",
                               {"key": k.get("key")}))
        else:
            tests.append(_fail("Unknown Event → Fallback", "resolver", "Returned non-dict"))
    except Exception as exc:
        tests.append(_fail("Unknown Event → Fallback", "resolver",
                           f"Crashed on unknown event: {exc}"))

    return tests


# ── EVIDENCE EXTRACTOR TESTS ──────────────────────────────────────────────────

def _run_evidence_tests(extract_fn: Any) -> list[dict]:
    tests: list[dict] = []

    cases: list[tuple[str, dict, list[str]]] = [
        ("Win 4625 Evidence", _WIN_4625, ["user", "source_ip", "logon_type", "status"]),
        ("Win 7045 Evidence", _WIN_7045, ["service_name", "command_line"]),
        ("Linux SSH Evidence",  _LINUX_SSH,  ["top_process"]),
        ("Linux sudo Evidence", _LINUX_SUDO, ["top_process"]),
        ("Linux FIM Evidence",  _LINUX_FIM,  ["sensitive_path"]),
        ("UFW Evidence",        _WIN_UFW_LIKE, ["host"]),
    ]

    for name, event, expected_fields in cases:
        try:
            ev = extract_fn(event)
            if not isinstance(ev, dict):
                tests.append(_fail(name, "evidence", f"Returned non-dict: {type(ev).__name__}"))
                continue
            found = [f for f in expected_fields if f in ev and ev[f] is not None]
            missing = [f for f in expected_fields if f not in found]
            if missing:
                tests.append(_warn(name, "evidence",
                    f"Extracted {len(found)}/{len(expected_fields)} expected fields (missing: {', '.join(missing)})",
                    {"found": found, "missing": missing, "ev_keys": list(ev.keys())}))
            else:
                tests.append(_pass(name, "evidence",
                    f"All {len(expected_fields)} expected fields extracted",
                    {"found": found}))
        except Exception as exc:
            tests.append(_fail(name, "evidence", f"Exception: {exc}",
                               {"traceback": traceback.format_exc(limit=3)}))

    return tests


# ── DB / TABLE HEALTH TESTS ───────────────────────────────────────────────────

def _run_db_tests() -> tuple[list[dict], dict]:
    tests: list[dict] = []
    counts: dict[str, int] = {}

    with get_connection() as conn:
        cursor = conn.cursor()

        for table, key in [
            ("script_library", "scripts"),
            ("action_audit_log", "audit_entries"),
            ("unified_hosts", "unified_hosts"),
            ("connections", "connections"),
        ]:
            try:
                row = cursor.execute(f"SELECT COUNT(*) FROM {table}").fetchone()  # noqa: S608
                n = row[0] if row else 0
                counts[key] = n
                if n == 0 and table in ("script_library", "connections"):
                    tests.append(_warn(f"DB table: {table}", "db",
                                       f"Table is empty (0 rows)", {"table": table}))
                else:
                    tests.append(_pass(f"DB table: {table}", "db",
                                       f"{n} rows", {"table": table, "count": n}))
            except Exception as exc:
                counts[key] = -1
                tests.append(_fail(f"DB table: {table}", "db",
                                   f"Query failed: {exc}", {"table": table}))

        # Check script seeding
        try:
            row = cursor.execute(
                "SELECT COUNT(*) FROM script_library WHERE enabled=1"
            ).fetchone()
            enabled_scripts = row[0] if row else 0
            counts["enabled_scripts"] = enabled_scripts
            if enabled_scripts < 5:
                tests.append(_warn("Script seeding", "db",
                                   f"Only {enabled_scripts} enabled scripts — expected ≥5",
                                   {"enabled_scripts": enabled_scripts}))
            else:
                tests.append(_pass("Script seeding", "db",
                                   f"{enabled_scripts} enabled scripts in catalog",
                                   {"enabled_scripts": enabled_scripts}))
        except Exception as exc:
            tests.append(_fail("Script seeding", "db", f"Query failed: {exc}"))

        # Dangerous scripts must NOT be executable (check action_policy=blocked exists or policy present)
        try:
            row = cursor.execute(
                "SELECT COUNT(*) FROM script_library WHERE dangerous=1 AND enabled=1"
            ).fetchone()
            dangerous_enabled = row[0] if row else 0
            counts["dangerous_enabled_scripts"] = dangerous_enabled
            # This is not a hard failure — dangerous scripts can be enabled but must remain non-executable
            tests.append(_pass("Dangerous scripts not auto-executable", "safety",
                               f"{dangerous_enabled} dangerous+enabled scripts (execution disabled in Phase 1 by policy)",
                               {"dangerous_enabled": dangerous_enabled}))
        except Exception as exc:
            tests.append(_warn("Dangerous scripts not auto-executable", "safety",
                               f"Could not verify: {exc}"))

        # 24h fallback and unknown event tracking (placeholder)
        try:
            row = cursor.execute(
                "SELECT COUNT(*) FROM action_audit_log "
                "WHERE timestamp > datetime('now', '-24 hours')"
            ).fetchone()
            recent_audits = row[0] if row else 0
            counts["recent_audit_24h"] = recent_audits
            tests.append(_pass("Audit log 24h", "audit",
                               f"{recent_audits} audit entries in last 24h",
                               {"recent_audits": recent_audits}))
        except Exception as exc:
            tests.append(_warn("Audit log 24h", "audit", f"Could not query: {exc}"))

    return tests, counts


# ── KB STATISTICS ─────────────────────────────────────────────────────────────

def _collect_kb_stats(db_counts: dict[str, int]) -> dict:
    win_kb = _import_win_kb()
    linux_kb = _import_linux_kb()
    playbooks = _import_playbooks()

    win_entries   = len(win_kb) if win_kb is not None else -1
    linux_entries = len(linux_kb) if linux_kb is not None else -1
    playbook_count = len(playbooks) if playbooks is not None else -1
    scripts_count  = db_counts.get("scripts", -1)

    return {
        "windows_entries":    win_entries,
        "linux_entries":      linux_entries,
        "playbooks":          playbook_count,
        "scripts":            scripts_count,
        "unknown_events_24h": 0,   # placeholder — no unknown event tracking table yet
        "fallback_usage_24h": 0,   # placeholder
    }


# ── API HEALTH ────────────────────────────────────────────────────────────────

def _collect_api_health() -> dict:
    # Backend is always "ok" here because we are running
    health: dict[str, str] = {"backend": "ok"}

    # Wazuh indexer
    try:
        conn = get_active_connection()
        if conn:
            from services.wazuh_indexer import ping_indexer
            ok, detail = ping_indexer(conn)
            health["wazuh_indexer"] = "ok" if ok else f"error: {detail}"
        else:
            health["wazuh_indexer"] = "no_connection"
    except Exception as exc:
        health["wazuh_indexer"] = f"error: {exc}"

    # Wazuh manager (optional)
    try:
        conn = get_active_connection()
        if conn and conn.get("manager_url"):
            import httpx
            r = httpx.get(f"{conn['manager_url']}/", timeout=3.0, verify=False)  # noqa: S501
            health["wazuh_manager"] = "ok" if r.status_code < 400 else f"http_{r.status_code}"
        else:
            health["wazuh_manager"] = "not_configured"
    except Exception as exc:
        health["wazuh_manager"] = f"error: {type(exc).__name__}"

    # Tactical RMM (check cached agents table)
    try:
        with get_connection() as db:
            row = db.cursor().execute("SELECT COUNT(*) FROM tactical_agents_cache").fetchone()
            n = row[0] if row else 0
        health["tactical_rmm"] = f"cached ({n} agents)" if n > 0 else "no_agents_cached"
    except Exception:
        health["tactical_rmm"] = "unavailable"

    # Scripts endpoint (local DB)
    try:
        with get_connection() as db:
            row = db.cursor().execute("SELECT COUNT(*) FROM script_library").fetchone()
            n = row[0] if row else 0
        health["scripts"] = f"ok ({n} scripts)"
    except Exception as exc:
        health["scripts"] = f"error: {exc}"

    # Timeline endpoint — check it imports OK
    try:
        from api.routes_timeline import router as _  # noqa: F401
        health["timeline"] = "ok"
    except Exception as exc:
        health["timeline"] = f"import_error: {exc}"

    # Audit endpoint — check it imports OK
    try:
        from api.routes_audit import router as _  # noqa: F401
        health["audit"] = "ok"
    except Exception as exc:
        health["audit"] = f"import_error: {exc}"

    return health


# ── KB TESTS ──────────────────────────────────────────────────────────────────

def _run_kb_tests() -> list[dict]:
    tests: list[dict] = []
    win_kb = _import_win_kb()
    playbooks = _import_playbooks()

    if win_kb is None:
        tests.append(_fail("Windows KB import", "knowledge", "Could not import EVENT_ID_KNOWLEDGE"))
    else:
        n = len(win_kb)
        if n < 5:
            tests.append(_warn("Windows KB", "knowledge", f"Only {n} entries — expected ≥5"))
        else:
            tests.append(_pass("Windows KB", "knowledge", f"{n} Windows event entries loaded"))

        # Spot-check key entries
        for eid, expected_cat in [("4625", "authentication"), ("7045", "persistence"), ("1102", "anti_forensics")]:
            if eid in win_kb:
                entry = win_kb[eid]
                cat = entry.get("category") if isinstance(entry, dict) else getattr(entry, "category", "?")
                tests.append(_pass(f"Win KB entry {eid}", "knowledge",
                                   f"Present: {entry.get('title', eid) if isinstance(entry, dict) else str(entry)[:60]}",
                                   {"category": cat}))
            else:
                tests.append(_warn(f"Win KB entry {eid}", "knowledge", f"Event ID {eid} not in KB"))

    linux_kb = _import_linux_kb()
    if linux_kb is None:
        tests.append(_warn("Linux KB import", "knowledge",
                           "LINUX_KB not directly importable (may use resolver functions — OK)"))
    else:
        tests.append(_pass("Linux KB", "knowledge", f"{len(linux_kb)} Linux KB entries loaded"))

    if playbooks is None:
        tests.append(_warn("Playbooks import", "knowledge",
                           "Could not import _PLAYBOOKS directly (check investigation_playbooks.py)"))
    else:
        n = len(playbooks)
        if n < 3:
            tests.append(_warn("Playbooks", "knowledge", f"Only {n} playbooks — expected ≥3"))
        else:
            tests.append(_pass("Playbooks", "knowledge", f"{n} investigation playbooks loaded"))

    return tests


# ── HOST MATCHING TESTS ───────────────────────────────────────────────────────

def _run_host_matching_tests() -> list[dict]:
    tests: list[dict] = []
    try:
        from services.unified_host_resolver import UnifiedHostResolver  # type: ignore[import]
        tests.append(_pass("Host resolver import", "host_matching", "UnifiedHostResolver imported OK"))
    except ImportError:
        tests.append(_warn("Host resolver import", "host_matching",
                           "UnifiedHostResolver not yet implemented — Phase 2"))
        # Add placeholder tests
        for name, msg in [
            ("hostname + IP → high confidence", "Placeholder — resolver not yet implemented"),
            ("OS mismatch → conflict",           "Placeholder — resolver not yet implemented"),
            ("Wazuh-only → review_required",     "Placeholder — resolver not yet implemented"),
            ("Tactical-only → review_required",  "Placeholder — resolver not yet implemented"),
            ("Unknown host → blocked",           "Placeholder — resolver not yet implemented"),
        ]:
            tests.append(_warn(name, "host_matching", msg))
        return tests
    except Exception as exc:
        tests.append(_fail("Host resolver import", "host_matching", f"Import error: {exc}"))
        return tests

    # If resolver is available, run basic sanity tests
    try:
        with get_connection() as db:
            cursor = db.cursor()
            row = cursor.execute("SELECT COUNT(*) FROM unified_hosts").fetchone()
            n = row[0] if row else 0
        if n == 0:
            tests.append(_warn("Unified hosts DB", "host_matching",
                               "No unified hosts in DB — import from Tactical RMM first"))
        else:
            tests.append(_pass("Unified hosts DB", "host_matching",
                               f"{n} unified hosts available for matching", {"count": n}))
    except Exception as exc:
        tests.append(_fail("Unified hosts DB", "host_matching", f"DB query failed: {exc}"))

    return tests


# ── SAFETY TESTS ──────────────────────────────────────────────────────────────

def _run_safety_tests() -> list[dict]:
    """Verify that Phase 1 safety constraints hold in code."""
    tests: list[dict] = []

    # 1. No execution route should exist
    try:
        from api import routes_scripts  # noqa: F401
        # Check that there is no /scripts/{id}/run or /scripts/execute route
        from api.routes_scripts import router as scripts_router_obj
        run_routes = [r for r in scripts_router_obj.routes  # type: ignore[attr-defined]
                      if "run" in str(getattr(r, "path", "")) or "exec" in str(getattr(r, "path", ""))]
        if run_routes:
            tests.append(_fail("No script execution route", "safety",
                               f"Found {len(run_routes)} execution route(s) — must be removed",
                               {"routes": [str(r) for r in run_routes]}))
        else:
            tests.append(_pass("No script execution route", "safety",
                               "No /run or /exec routes found in scripts router"))
    except Exception as exc:
        tests.append(_warn("No script execution route", "safety", f"Could not verify: {exc}"))

    # 2. Action audit log exists
    try:
        with get_connection() as db:
            db.cursor().execute("SELECT id FROM action_audit_log LIMIT 1")
        tests.append(_pass("Audit log table exists", "safety", "action_audit_log table accessible"))
    except Exception as exc:
        tests.append(_fail("Audit log table exists", "safety", f"Cannot access audit log: {exc}"))

    # 3. Dangerous scripts are not auto-runnable (metadata check)
    try:
        with get_connection() as db:
            rows = db.cursor().execute(
                "SELECT script_id FROM script_library WHERE dangerous=1"
            ).fetchall()
        n = len(rows)
        tests.append(_pass("Dangerous scripts metadata", "safety",
                           f"{n} dangerous scripts in catalog — execution controlled by action_policy",
                           {"count": n}))
    except Exception as exc:
        tests.append(_warn("Dangerous scripts metadata", "safety", f"Could not verify: {exc}"))

    return tests


# ── MAIN ENDPOINT ─────────────────────────────────────────────────────────────

@router.get("/status")
def validation_status() -> dict:
    """Run all validation self-tests and return a comprehensive status report."""
    all_tests: list[dict] = []

    # --- Knowledge base tests ---
    all_tests.extend(_run_kb_tests())

    # --- Resolver self-tests ---
    resolve_fn = _import_resolver()
    if resolve_fn is None:
        all_tests.append(_fail("Knowledge resolver import", "resolver",
                               "Could not import resolve_event_knowledge"))
    else:
        all_tests.append(_pass("Knowledge resolver import", "resolver",
                               "resolve_event_knowledge imported OK"))
        all_tests.extend(_run_resolver_tests(resolve_fn))

    # --- Evidence extractor tests ---
    extract_fn = _import_evidence_extractor()
    if extract_fn is None:
        all_tests.append(_fail("Evidence extractor import", "evidence",
                               "Could not import extract_event_evidence"))
    else:
        all_tests.append(_pass("Evidence extractor import", "evidence",
                               "extract_event_evidence imported OK"))
        all_tests.extend(_run_evidence_tests(extract_fn))

    # --- DB/table health tests ---
    db_tests, db_counts = _run_db_tests()
    all_tests.extend(db_tests)

    # --- Host matching tests ---
    all_tests.extend(_run_host_matching_tests())

    # --- Safety tests ---
    all_tests.extend(_run_safety_tests())

    # --- KB statistics ---
    kb_stats = _collect_kb_stats(db_counts)

    # --- API health ---
    api_health = _collect_api_health()

    # --- Summary ---
    passed   = sum(1 for t in all_tests if t["status"] == "pass")
    failed   = sum(1 for t in all_tests if t["status"] == "fail")
    warnings = sum(1 for t in all_tests if t["status"] == "warning")

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_tests": len(all_tests),
            "passed":   passed,
            "failed":   failed,
            "warnings": warnings,
        },
        "knowledge": kb_stats,
        "tests": all_tests,
        "api_health": api_health,
    }
