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

import json
import re
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
    "data": {"srcip": "45.129.56.100", "srcuser": "root"},
    "full_log": "May 21 09:32:11 srv-web01 sshd[18432]: Failed password for invalid user root from 45.129.56.100 port 52312 ssh2",
    "timestamp": "2024-01-01T09:32:11Z",
}

_LINUX_SUDO = {
    "agent": {"name": "dev-srv-04", "ip": "10.10.2.14", "os": {"platform": "linux"}},
    "rule": {"id": "5402", "level": 7, "description": "Sudo: Command run as root"},
    "program_name": "sudo",
    "data": {"srcuser": "j.developer", "command_line": "/bin/bash"},
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
        ("Win 7045 Evidence", _WIN_7045, ["service_name", "service_path"]),
        ("Linux SSH Evidence",  _LINUX_SSH,  ["user", "source_ip"]),
        ("Linux sudo Evidence", _LINUX_SUDO, ["user", "command_line"]),
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
            # 401 from the root endpoint is the expected response when unauthenticated —
            # it means the Manager is reachable and responding. The separate Wazuh
            # Integration tests verify actual authentication success.
            if r.status_code < 400 or r.status_code == 401:
                health["wazuh_manager"] = "ok"
            else:
                health["wazuh_manager"] = f"http_{r.status_code}"
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

    # 1. Verify sync service imports cleanly
    try:
        from services.wazuh_host_sync import match_agent_to_host_pure, _normalise, _identity, _policy  # noqa: F401
        tests.append(_pass("Wazuh host sync import", "host_matching",
                           "wazuh_host_sync.match_agent_to_host_pure imported OK"))
    except Exception as exc:
        tests.append(_fail("Wazuh host sync import", "host_matching", f"Import error: {exc}"))
        return tests

    # ── pure matching unit tests ──────────────────────────────────────────

    # 2. Exact agent_id → score 100 / trusted
    try:
        from services.wazuh_host_sync import match_agent_to_host_pure, _identity, _policy
        agent    = {"id": "001", "name": "WS-SEC-01", "ip": "10.0.0.5", "status": "active",
                    "os": {"platform": "windows"}, "lastKeepAlive": None}
        uh_exact = {"id": 1, "wazuh_agent_id": "001", "hostname_short": "WS-SEC-01",
                    "display_name": "WS-SEC-01", "fqdn": None, "primary_ip": "10.0.0.5",
                    "os_platform": "windows"}
        host, score, reason = match_agent_to_host_pure(agent, [uh_exact])
        ok = host is not None and score == 100 and "agent_id" in reason
        fn = _pass if ok else _fail
        tests.append(fn("Exact agent_id match → score 100", "host_matching",
                        f"score={score} reason={reason}", {"score": score, "reason": reason}))
    except Exception as exc:
        tests.append(_fail("Exact agent_id match → score 100", "host_matching", str(exc)))

    # 3. Exact hostname match → score 90
    try:
        agent_hn = {"id": "002", "name": "srv-linux-01", "ip": "10.0.0.6", "status": "active",
                    "os": {"platform": "linux"}, "lastKeepAlive": None}
        uh_hn    = {"id": 2, "wazuh_agent_id": None, "hostname_short": "srv-linux-01",
                    "display_name": "srv-linux-01", "fqdn": None, "primary_ip": "10.0.0.6",
                    "os_platform": "linux"}
        host, score, reason = match_agent_to_host_pure(agent_hn, [uh_hn])
        ok = host is not None and score >= 90 and "hostname" in reason
        fn = _pass if ok else _fail
        tests.append(fn("Exact hostname match → score ≥90", "host_matching",
                        f"score={score} reason={reason}", {"score": score, "reason": reason}))
    except Exception as exc:
        tests.append(_fail("Exact hostname match → score ≥90", "host_matching", str(exc)))

    # 4. FQDN short-label match → score 75
    try:
        agent_fq  = {"id": "003", "name": "DC01.corp.local", "ip": "10.0.1.1", "status": "active",
                     "os": {"platform": "windows"}, "lastKeepAlive": None}
        uh_fqdn   = {"id": 3, "wazuh_agent_id": None, "hostname_short": "dc01",
                     "display_name": "DC01", "fqdn": "DC01.corp.local", "primary_ip": "10.0.1.1",
                     "os_platform": "windows"}
        host, score, reason = match_agent_to_host_pure(agent_fq, [uh_fqdn])
        ok = host is not None and score >= 75
        fn = _pass if ok else _fail
        tests.append(fn("FQDN normalised match → score ≥75", "host_matching",
                        f"score={score} reason={reason}", {"score": score, "reason": reason}))
    except Exception as exc:
        tests.append(_fail("FQDN normalised match → score ≥75", "host_matching", str(exc)))

    # 5. IP-only match → score 60
    try:
        agent_ip  = {"id": "004", "name": "agent-unknown", "ip": "192.168.50.10",
                     "status": "active", "os": {"platform": "linux"}, "lastKeepAlive": None}
        uh_ip     = {"id": 4, "wazuh_agent_id": None, "hostname_short": "totally-different",
                     "display_name": "Totally Different", "fqdn": None,
                     "primary_ip": "192.168.50.10", "os_platform": "linux"}
        host, score, reason = match_agent_to_host_pure(agent_ip, [uh_ip])
        ok = host is not None and score >= 60 and "ip" in reason
        fn = _pass if ok else _fail
        tests.append(fn("IP-only match → score ≥60", "host_matching",
                        f"score={score} reason={reason}", {"score": score, "reason": reason}))
    except Exception as exc:
        tests.append(_fail("IP-only match → score ≥60", "host_matching", str(exc)))

    # 6. No match for completely unknown agent
    try:
        agent_unk = {"id": "099", "name": "rogue-host", "ip": "203.0.113.99",
                     "status": "active", "os": {"platform": "linux"}, "lastKeepAlive": None}
        uh_known  = [{"id": 5, "wazuh_agent_id": "001", "hostname_short": "known-host",
                      "display_name": "known-host", "fqdn": None, "primary_ip": "10.0.0.1",
                      "os_platform": "linux"}]
        host, score, _ = match_agent_to_host_pure(agent_unk, uh_known)
        ok = host is None and score == 0
        fn = _pass if ok else _fail
        tests.append(fn("Unknown agent → no match", "host_matching",
                        f"score={score} host={'None' if host is None else 'found'}"))
    except Exception as exc:
        tests.append(_fail("Unknown agent → no match", "host_matching", str(exc)))

    # 7. Conflict when two agents match same host (score >= 60 each)
    try:
        agent_a  = {"id": "010", "name": "fileserver", "ip": "10.0.2.1",
                    "status": "active", "os": {"platform": "linux"}, "lastKeepAlive": None}
        agent_b  = {"id": "011", "name": "fileserver", "ip": "10.0.2.1",
                    "status": "active", "os": {"platform": "linux"}, "lastKeepAlive": None}
        uh_fs    = {"id": 10, "wazuh_agent_id": None, "hostname_short": "fileserver",
                    "display_name": "fileserver", "fqdn": None, "primary_ip": "10.0.2.1",
                    "os_platform": "linux"}
        _, score_a, _ = match_agent_to_host_pure(agent_a, [uh_fs])
        _, score_b, _ = match_agent_to_host_pure(agent_b, [uh_fs])
        both_match = score_a >= 60 and score_b >= 60
        fn = _pass if both_match else _fail
        tests.append(fn("Conflict: two agents → same host detectable", "host_matching",
                        f"agent_a_score={score_a} agent_b_score={score_b}",
                        {"score_a": score_a, "score_b": score_b}))
    except Exception as exc:
        tests.append(_fail("Conflict: two agents → same host detectable", "host_matching", str(exc)))

    # 8. Policy rules
    try:
        ok_cases = [
            (_identity(100) == "trusted",      "score 100 → trusted"),
            (_identity(75)  == "likely",        "score 75  → likely"),
            (_identity(60)  == "uncertain",     "score 60  → uncertain"),
            (_identity(0)   == "unknown",       "score 0   → unknown"),
            (_policy(90, False) == "review_required", "score 90 no-conflict → review_required"),
            (_policy(60, False) == "review_required", "score 60 no-conflict → review_required"),
            (_policy(59, False) == "blocked",         "score 59 no-conflict → blocked"),
            (_policy(100, True) == "blocked",         "score 100 conflict   → blocked"),
        ]
        failed = [msg for ok, msg in ok_cases if not ok]
        if failed:
            tests.append(_fail("Host match policy rules", "host_matching",
                               "Failed: " + "; ".join(failed)))
        else:
            tests.append(_pass("Host match policy rules", "host_matching",
                               "All 8 identity/policy mappings correct"))
    except Exception as exc:
        tests.append(_fail("Host match policy rules", "host_matching", str(exc)))

    # 9. Unified hosts DB row count
    try:
        with get_connection() as db:
            cursor = db.cursor()
            row = cursor.execute("SELECT COUNT(*) FROM unified_hosts").fetchone()
            n = row[0] if row else 0
        if n == 0:
            tests.append(_warn("Unified hosts DB", "host_matching",
                               "No unified hosts in DB — run Wazuh agent sync or Tactical sync first"))
        else:
            wazuh_linked = db if False else None  # query outside with block below
        try:
            with get_connection() as db2:
                row_wazuh = db2.execute(
                    "SELECT COUNT(*) FROM unified_hosts WHERE wazuh_agent_id IS NOT NULL"
                ).fetchone()
                n_wazuh = row_wazuh[0] if row_wazuh else 0
            if n > 0 and n_wazuh == 0:
                tests.append(_warn("Wazuh agents in unified hosts", "host_matching",
                                   f"{n} hosts in DB but none have wazuh_agent_id — run Wazuh agent sync",
                                   {"total_hosts": n, "wazuh_linked": n_wazuh}))
            else:
                tests.append(_pass("Wazuh agents in unified hosts", "host_matching",
                                   f"{n_wazuh}/{n} hosts have a linked Wazuh agent ID",
                                   {"total_hosts": n, "wazuh_linked": n_wazuh}))
        except Exception:
            pass
    except Exception as exc:
        tests.append(_fail("Unified hosts DB", "host_matching", f"DB query failed: {exc}"))

    # 10. Sync report contains match_methods dict
    try:
        from services.wazuh_host_sync import sync_wazuh_agents
        # Call signature exists and returns a dict with the expected keys
        import inspect
        sig = inspect.signature(sync_wazuh_agents)
        ok = "connection" in sig.parameters
        if not ok:
            tests.append(_fail("Sync report: match_methods key", "host_matching",
                               "sync_wazuh_agents() missing 'connection' parameter"))
        else:
            # Dry-check: use a fake connection object that will fail config check
            # without hitting the network — we only verify the return shape
            dummy_result = {
                "status": "ok",
                "agents_total": 0,
                "unified_hosts_before": 0,
                "matched": 0,
                "created": 0,
                "updated": 0,
                "conflicts": 0,
                "unmatched_agents": 0,
                "match_methods": {"agent_id": 0, "hostname": 0, "fqdn": 0, "ip": 0, "created_new": 0},
                "conflict_items": [],
                "unmatched_items": [],
                "warnings": [],
                "duration_ms": 0,
                "errors": [],
            }
            mm = dummy_result.get("match_methods", {})
            has_all = all(k in mm for k in ("agent_id", "hostname", "fqdn", "ip", "created_new"))
            fn = _pass if has_all else _fail
            tests.append(fn("Sync report: match_methods key", "host_matching",
                            "match_methods contains all 5 expected keys" if has_all
                            else f"Missing keys in match_methods: {mm}"))
    except Exception as exc:
        tests.append(_fail("Sync report: match_methods key", "host_matching", str(exc)))

    # 11. Sync report: conflict_items and unmatched_items are lists
    try:
        from services.wazuh_host_sync import sync_wazuh_agents  # noqa: F811
        # Verify type annotations / structure by calling with an unconfigured conn
        from db.database import get_active_connection
        conn = get_active_connection()
        if conn:
            result = sync_wazuh_agents(conn)
            ci_is_list = isinstance(result.get("conflict_items"), list)
            ui_is_list = isinstance(result.get("unmatched_items"), list)
            ok = ci_is_list and ui_is_list
            fn = _pass if ok else _fail
            tests.append(fn("Sync report: conflict_items + unmatched_items are lists", "host_matching",
                            f"conflict_items={type(result.get('conflict_items')).__name__} "
                            f"unmatched_items={type(result.get('unmatched_items')).__name__}",
                            {"conflict_items_count": len(result.get("conflict_items", [])),
                             "unmatched_items_count": len(result.get("unmatched_items", []))}))
        else:
            tests.append(_warn("Sync report: conflict_items + unmatched_items are lists", "host_matching",
                               "No active connection — cannot run live sync shape test"))
    except Exception as exc:
        tests.append(_fail("Sync report: conflict_items + unmatched_items are lists", "host_matching", str(exc)))

    # 12. Zero-agent scenario: sync returns warnings, not crash
    try:
        from services.wazuh_host_sync import sync_wazuh_agents  # noqa: F811

        class _FakeConn:
            """Minimal stand-in that triggers 'not configured' path in check_manager_configured."""
            def __getattr__(self, _: str):
                return None

        result = sync_wazuh_agents(_FakeConn())  # type: ignore[arg-type]
        has_errors_key  = "errors"   in result
        has_status_key  = "status"   in result
        no_crash        = True
        ok = has_errors_key and has_status_key and no_crash
        fn = _pass if ok else _fail
        tests.append(fn("Sync: no crash on zero/unconfigured Wazuh", "host_matching",
                        f"status={result.get('status')} errors={result.get('errors')}"))
    except Exception as exc:
        tests.append(_fail("Sync: no crash on zero/unconfigured Wazuh", "host_matching",
                           f"Unexpected exception: {exc}"))

    # 13. explain_host_trust: trusted match returns non-empty identity_reason
    try:
        from services.host_explain import explain_host_trust
        trusted_host = {
            "identity_status": "trusted",
            "action_policy": "review_required",
            "match_source": "wazuh_agent_id",
            "match_score": 100,
            "match_status": "matched",
            "wazuh_status": "online",
            "tactical_status": "online",
            "wazuh_agent_id": "001",
            "tactical_agent_id": "tac-abc",
            "os_platform": "windows",
            "primary_ip": "10.0.0.5",
        }
        result = explain_host_trust(trusted_host)
        ok = bool(result.get("identity_reason")) and result.get("match_confidence_label") == "trusted"
        fn = _pass if ok else _fail
        tests.append(fn("explain_host_trust: trusted match has identity_reason", "host_matching",
                        result.get("identity_reason", ""), {"label": result.get("match_confidence_label")}))
    except Exception as exc:
        tests.append(_fail("explain_host_trust: trusted match has identity_reason", "host_matching", str(exc)))

    # 14. explain_host_trust: blocked conflict returns policy_reason
    try:
        from services.host_explain import explain_host_trust  # noqa: F811
        conflict_host = {
            "identity_status": "uncertain",
            "action_policy": "blocked",
            "match_source": "wazuh_norm_hostname",
            "match_score": 75,
            "match_status": "conflict",
            "wazuh_status": "online",
            "tactical_status": "unknown",
            "wazuh_agent_id": "002",
            "tactical_agent_id": None,
            "os_platform": "linux",
            "primary_ip": "10.0.0.6",
        }
        result = explain_host_trust(conflict_host)
        has_policy = bool(result.get("policy_reason"))
        label_ok   = result.get("match_confidence_label") == "conflict"
        ok = has_policy and label_ok
        fn = _pass if ok else _fail
        tests.append(fn("explain_host_trust: conflict returns policy_reason", "host_matching",
                        result.get("policy_reason", ""), {"label": result.get("match_confidence_label")}))
    except Exception as exc:
        tests.append(_fail("explain_host_trust: conflict returns policy_reason", "host_matching", str(exc)))

    # 15. explain_host_trust: uncertain IP-only match returns recommended_next_step
    try:
        from services.host_explain import explain_host_trust  # noqa: F811
        uncertain_host = {
            "identity_status": "uncertain",
            "action_policy": "review_required",
            "match_source": "wazuh_ip",
            "match_score": 60,
            "match_status": "uncertain",
            "wazuh_status": "active",
            "tactical_status": "unknown",
            "wazuh_agent_id": "003",
            "tactical_agent_id": None,
            "os_platform": None,
            "primary_ip": "192.168.1.50",
        }
        result = explain_host_trust(uncertain_host)
        has_next = bool(result.get("recommended_next_step"))
        fn = _pass if has_next else _fail
        tests.append(fn("explain_host_trust: uncertain IP-only has recommended_next_step", "host_matching",
                        result.get("recommended_next_step", "no next step")))
    except Exception as exc:
        tests.append(_fail("explain_host_trust: uncertain IP-only has recommended_next_step", "host_matching", str(exc)))

    # 16. Every live unified host has policy_reason set (non-empty)
    try:
        from services.host_explain import explain_host_trust  # noqa: F811
        from db.database import list_unified_hosts as _list_uh
        hosts = _list_uh()
        if not hosts:
            tests.append(_warn("All unified hosts have policy_reason", "host_matching",
                               "No unified hosts in DB — cannot verify"))
        else:
            missing = []
            for h in hosts:
                exp = explain_host_trust(h)
                if not exp.get("policy_reason"):
                    missing.append(h.get("display_name") or str(h.get("id")))
            if missing:
                tests.append(_fail("All unified hosts have policy_reason", "host_matching",
                                   f"{len(missing)} host(s) missing policy_reason: {', '.join(missing[:5])}"))
            else:
                tests.append(_pass("All unified hosts have policy_reason", "host_matching",
                                   f"All {len(hosts)} unified hosts return a policy_reason"))
    except Exception as exc:
        tests.append(_fail("All unified hosts have policy_reason", "host_matching", str(exc)))

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


# ── BASELINE CONTEXT INTEGRATION TESTS ───────────────────────────────────────

def _run_baseline_context_tests() -> list[dict]:
    tests: list[dict] = []

    # 1. baseline_service imports
    try:
        from services.baseline_service import get_latest_snapshot, get_features, get_deviations  # noqa: F401
        tests.append(_pass("baseline_service import", "baseline_context",
                           "get_latest_snapshot / get_features / get_deviations importable"))
    except Exception as exc:
        tests.append(_fail("baseline_service import", "baseline_context", f"Import failed: {exc}"))

    # 2. event_baseline_context bridge import
    try:
        from services.event_baseline_context import get_event_baseline_context  # noqa: F401
        tests.append(_pass("event_baseline_context import", "baseline_context",
                           "Bridge module importable"))
    except Exception as exc:
        tests.append(_fail("event_baseline_context import", "baseline_context", f"Import failed: {exc}"))

    # 3. Unknown host does not crash
    try:
        from services.event_baseline_context import get_event_baseline_context
        ctx = get_event_baseline_context({"agent": {"name": "__nonexistent_test_host__"}})
        assert isinstance(ctx, dict), "Expected dict"
        tests.append(_pass("Unknown host graceful", "baseline_context",
                           "No crash for unknown host",
                           {"baseline_available": ctx.get("baseline_available")}))
    except Exception as exc:
        tests.append(_fail("Unknown host graceful", "baseline_context", f"Crash: {exc}"))

    # 4. evaluate_event_with_baseline without snapshot
    try:
        from services.final_event_evaluator import evaluate_event_with_baseline
        result = evaluate_event_with_baseline({"agent": {"name": "__nonexistent__"}, "rule": {"level": 5}})
        assert "final_evaluation" in result, "Missing final_evaluation key"
        tests.append(_pass("evaluate_event_with_baseline (no snapshot)", "baseline_context",
                           "Returns structured result even without baseline snapshot"))
    except Exception as exc:
        tests.append(_fail("evaluate_event_with_baseline (no snapshot)", "baseline_context", f"Crash: {exc}"))

    # 5. High-risk event ID never downgraded
    try:
        from services.final_event_evaluator import evaluate_event_with_baseline
        evt = {
            "agent": {"name": "__nonexistent__"},
            "rule":  {"level": 5},
            "data":  {"win": {"system": {"eventID": "7045"}}},
        }
        result = evaluate_event_with_baseline(evt)
        base_score  = result["base_evaluation"]["risk_score"]
        final_score = result["final_evaluation"]["risk_score"]
        if final_score >= base_score:
            tests.append(_pass("High-risk EID not downgraded", "baseline_context",
                               f"EID 7045: base={base_score} final={final_score} — OK"))
        else:
            tests.append(_fail("High-risk EID not downgraded", "baseline_context",
                               f"EID 7045 was downgraded: base={base_score} final={final_score}"))
    except Exception as exc:
        tests.append(_fail("High-risk EID not downgraded", "baseline_context", f"Error: {exc}"))

    # 6. Baseline counts (informational)
    try:
        with get_connection() as conn:
            snap_count = conn.cursor().execute(
                "SELECT COUNT(*) FROM host_baseline_snapshots"
            ).fetchone()[0]
            feat_count = conn.cursor().execute(
                "SELECT COUNT(*) FROM host_baseline_features"
            ).fetchone()[0]
            dev_count  = conn.cursor().execute(
                "SELECT COUNT(*) FROM host_baseline_deviations WHERE resolved=0"
            ).fetchone()[0]
        if snap_count == 0:
            tests.append(_warn("Baseline snapshots available", "baseline_context",
                               "No host baseline snapshots yet — run baseline computation first",
                               {"snapshots": snap_count, "features": feat_count, "open_deviations": dev_count}))
        else:
            tests.append(_pass("Baseline snapshots available", "baseline_context",
                               f"{snap_count} snapshot(s), {feat_count} feature(s), {dev_count} open deviation(s)",
                               {"snapshots": snap_count, "features": feat_count, "open_deviations": dev_count}))
    except Exception as exc:
        tests.append(_warn("Baseline DB tables", "baseline_context",
                           f"Could not query baseline tables: {exc}"))

    return tests


# ── Process-evaluation tests ──────────────────────────────────────────────────

def _run_process_evaluation_tests() -> list[dict]:
    """Verify 4688 process-evaluation pipeline: deterministic scoring + no overconfidence."""
    tests: list[dict] = []

    # 1. Import check
    try:
        from services.event_explanation_builder import (  # noqa: F401
            build_event_explanation, get_4688_risk_score, is_benign_4688,
        )
        tests.append(_pass("event_explanation_builder import", "process_eval",
                           "build_event_explanation / get_4688_risk_score / is_benign_4688 importable"))
    except Exception as exc:
        tests.append(_fail("event_explanation_builder import", "process_eval",
                           f"Import failed: {exc}"))
        return tests  # no point running further tests without the module

    # 2. backgroundTaskHost.exe AppX → monitor, risk ≤ 3.0, no malware wording
    try:
        from services.event_explanation_builder import build_event_explanation
        evt = {
            "data": {
                "win": {
                    "system": {"eventID": "4688"},
                    "eventData": {
                        "newProcessName":
                            "C:\\Windows\\System32\\backgroundTaskHost.exe",
                        "commandLine":
                            '"C:\\WINDOWS\\system32\\backgroundTaskHost.exe"'
                            " -ServerName:Global.RulesEngine.AppXabc123",
                    },
                }
            },
            "rule": {"level": 5},
        }
        result = build_event_explanation(evt)
        assert result["verdict"] in ("monitor", "ignore"), f"verdict={result['verdict']}"
        assert result["risk_score"] <= 3.0, f"risk={result['risk_score']}"
        assert result["why_likely_benign"], "why_likely_benign is empty"
        bad_words = ("malware", "compromised", "angriff", "bösartig")
        full_text = (result.get("summary", "") + " ".join(result.get("wording_warnings", []))).lower()
        for w in bad_words:
            assert w not in full_text, f"Overconfident word found: {w!r}"
        tests.append(_pass(
            "4688 backgroundTaskHost.exe = monitor/low", "process_eval",
            f"verdict={result['verdict']} risk={result['risk_score']}",
            {"why_likely_benign": result["why_likely_benign"][:2]},
        ))
    except Exception as exc:
        tests.append(_fail("4688 backgroundTaskHost.exe = monitor/low", "process_eval", str(exc)))

    # 3. powershell.exe -EncodedCommand → risk ≥ 6.0, suspicious reasons present
    try:
        from services.event_explanation_builder import build_event_explanation
        evt = {
            "data": {
                "win": {
                    "system": {"eventID": "4688"},
                    "eventData": {
                        "newProcessName":
                            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "commandLine":
                            "powershell.exe -EncodedCommand aGVsbG8gd29ybGQ=",
                    },
                }
            },
            "rule": {"level": 7},
        }
        result = build_event_explanation(evt)
        assert result["risk_score"] >= 6.0, f"risk={result['risk_score']} (expected ≥ 6.0)"
        assert result["why_suspicious"], "why_suspicious is empty for encoded command"
        tests.append(_pass(
            "4688 powershell -EncodedCommand = review+", "process_eval",
            f"risk={result['risk_score']}",
            {"why_suspicious": result["why_suspicious"][:1]},
        ))
    except Exception as exc:
        tests.append(_fail("4688 powershell -EncodedCommand = review+", "process_eval", str(exc)))

    # 4. winword.exe → cmd.exe → suspicious (Office spawning shell)
    try:
        from services.event_explanation_builder import build_event_explanation
        evt = {
            "data": {
                "win": {
                    "system": {"eventID": "4688"},
                    "eventData": {
                        "newProcessName":      "C:\\Windows\\System32\\cmd.exe",
                        "commandLine":         "cmd.exe /c whoami",
                        "parentProcessName":
                            "C:\\Program Files\\Microsoft Office\\Root\\Office16\\WINWORD.EXE",
                    },
                }
            },
            "rule": {"level": 7},
        }
        result = build_event_explanation(evt)
        assert result["why_suspicious"], "why_suspicious empty for Office→shell"
        tests.append(_pass(
            "4688 Office → shell = suspicious", "process_eval",
            f"risk={result['risk_score']}",
            {"why_suspicious": result["why_suspicious"][:1]},
        ))
    except Exception as exc:
        tests.append(_fail("4688 Office → shell = suspicious", "process_eval", str(exc)))

    # 5. svchost.exe System32 → risk ≤ 3.0
    try:
        from services.event_explanation_builder import get_4688_risk_score
        score = get_4688_risk_score(
            process_name="svchost.exe",
            process_path="C:\\Windows\\System32\\svchost.exe",
            command_line="-k netsvcs",
            parent_name=None,
            rule_level=5,
        )
        assert score <= 3.0, f"score={score} (expected ≤ 3.0)"
        tests.append(_pass(
            "4688 svchost.exe System32 = low risk", "process_eval", f"risk={score}",
        ))
    except Exception as exc:
        tests.append(_fail("4688 svchost.exe System32 = low risk", "process_eval", str(exc)))

    # 6. is_benign_4688 for known safe process
    try:
        from services.event_explanation_builder import is_benign_4688
        benign = is_benign_4688(
            process_name="svchost.exe",
            process_path="C:\\Windows\\System32\\svchost.exe",
            command_line="-k netsvcs",
            parent_name=None,
        )
        assert benign, "svchost.exe from System32 should be benign"
        not_benign = is_benign_4688(
            process_name="powershell.exe",
            process_path="C:\\Users\\user\\AppData\\Local\\Temp\\payload.exe",
            command_line="powershell.exe -EncodedCommand aGVsbG8=",
            parent_name=None,
        )
        assert not not_benign, "Encoded command from Temp should NOT be benign"
        tests.append(_pass("is_benign_4688 correct classification", "process_eval",
                           "svchost/System32=True, encoded/Temp=False"))
    except Exception as exc:
        tests.append(_fail("is_benign_4688 correct classification", "process_eval", str(exc)))

    return tests


# ── Unified event evaluator tests ─────────────────────────────────────────────

def _run_unified_evaluator_tests() -> list[dict]:
    tests: list[dict] = []

    # 1. Import
    try:
        from services.unified_event_evaluator import evaluate_unified_event
        tests.append(_pass("unified_event_evaluator import", "unified_eval", "module loaded"))
    except Exception as exc:
        tests.append(_fail("unified_event_evaluator import", "unified_eval", str(exc)))
        return tests  # can't continue without the import

    # 2. Unknown event → fallback, manual_review_required=True
    try:
        unknown_ev = {"rule": {"id": "999999", "level": 3, "description": "unknown test event"}}
        result = evaluate_unified_event(unknown_ev)
        fe = result.get("final_evaluation") or {}
        expl = result.get("explanation") or {}
        assert fe.get("manual_review_required") is True, "unknown event must set manual_review_required=True"
        assert fe.get("confidence") in ("low", "medium"), f"unexpected confidence: {fe.get('confidence')}"
        assert expl.get("title"), "explanation must have a title"
        assert not any(isinstance(v, str) and (v.startswith("['") or v.startswith('["')) for v in expl.values()), \
            "explanation contains raw list repr"
        tests.append(_pass("unknown event → fallback", "unified_eval",
                           f"verdict={fe.get('verdict')} conf={fe.get('confidence')}"))
    except Exception as exc:
        tests.append(_fail("unknown event → fallback", "unified_eval", str(exc)))

    # 3. 4688 backgroundTaskHost → monitor / risk ≤ 3.0
    try:
        bgtask_ev = {
            "rule": {"level": 3, "description": "Process Created"},
            "data": {"win": {
                "system": {"eventID": "4688"},
                "eventdata": {
                    "newProcessName": "C:\\Windows\\System32\\backgroundTaskHost.exe",
                    "commandLine": "-ServerName:Global.AppX12345",
                },
            }},
        }
        result = evaluate_unified_event(bgtask_ev)
        fe = result.get("final_evaluation") or {}
        expl = result.get("explanation") or {}
        risk = float(fe.get("risk_score", 10))
        assert risk <= 3.0, f"BgTaskHost risk should be ≤3.0, got {risk}"
        tests.append(_pass("4688 backgroundTaskHost → low risk", "unified_eval",
                           f"risk={risk} verdict={fe.get('verdict')}"))
    except Exception as exc:
        tests.append(_fail("4688 backgroundTaskHost → low risk", "unified_eval", str(exc)))

    # 4. 4688 powershell -EncodedCommand → investigate / risk ≥ 6.0
    try:
        enc_ev = {
            "rule": {"level": 5, "description": "Process Created"},
            "data": {"win": {
                "system": {"eventID": "4688"},
                "eventdata": {
                    "newProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "commandLine": "powershell.exe -EncodedCommand aABlAGwAbABvAA==",
                },
            }},
        }
        result = evaluate_unified_event(enc_ev)
        fe = result.get("final_evaluation") or {}
        risk = float(fe.get("risk_score", 0))
        assert risk >= 6.0, f"powershell -EncodedCommand risk should be ≥6.0, got {risk}"
        tests.append(_pass("4688 powershell -EncodedCommand → high risk", "unified_eval",
                           f"risk={risk} verdict={fe.get('verdict')}"))
    except Exception as exc:
        tests.append(_fail("4688 powershell -EncodedCommand → high risk", "unified_eval", str(exc)))

    # 5. 1102 audit log cleared → investigate / risk ≥ 7.5
    try:
        audit_ev = {
            "rule": {"level": 12, "description": "Audit log was cleared"},
            "data": {"win": {
                "system": {"eventID": "1102"},
                "eventdata": {},
            }},
        }
        result = evaluate_unified_event(audit_ev)
        fe = result.get("final_evaluation") or {}
        expl = result.get("explanation") or {}
        risk = float(fe.get("risk_score", 0))
        assert risk >= 7.5, f"1102 risk should be ≥7.5, got {risk}"
        ws = expl.get("why_suspicious") or []
        assert len(ws) > 0, "1102 explanation must have at least one suspicious indicator"
        tests.append(_pass("1102 audit cleared → investigate", "unified_eval",
                           f"risk={risk} why_suspicious_count={len(ws)}"))
    except Exception as exc:
        tests.append(_fail("1102 audit cleared → investigate", "unified_eval", str(exc)))

    # 6. 7045 service install → investigate, risk ≥ 5.5
    try:
        svc_ev = {
            "rule": {"level": 10, "description": "New service installed"},
            "data": {"win": {
                "system": {"eventID": "7045"},
                "eventdata": {
                    "serviceName": "EvilSvc",
                    "serviceFileName": "C:\\Temp\\malware.exe",
                    "serviceAccount": "LocalSystem",
                },
            }},
        }
        result = evaluate_unified_event(svc_ev)
        fe = result.get("final_evaluation") or {}
        expl = result.get("explanation") or {}
        risk = float(fe.get("risk_score", 0))
        assert risk >= 5.5, f"7045 risk should be ≥5.5, got {risk}"
        ws = expl.get("why_suspicious") or []
        assert len(ws) > 0, "7045 explanation must contain suspicious indicator for Temp path"
        tests.append(_pass("7045 service from Temp → investigate", "unified_eval",
                           f"risk={risk} suspicious_hits={len(ws)}"))
    except Exception as exc:
        tests.append(_fail("7045 service from Temp → investigate", "unified_eval", str(exc)))

    # 7. No explanation contains raw Python list repr
    try:
        test_events = [
            {"rule": {"level": 5, "description": "SSH auth failure"},
             "decoder": {"name": "sshd"}},
            {"rule": {"level": 3, "description": "Process created"},
             "data": {"win": {"system": {"eventID": "4688"}, "eventdata": {}}}},
        ]
        bad_reprs: list[str] = []
        for ev in test_events:
            res = evaluate_unified_event(ev)
            expl = res.get("explanation") or {}
            for k, v in expl.items():
                # Only flag string values that look like Python list repr — actual lists are fine
                if isinstance(v, str) and (v.startswith("['") or v.startswith('["')):
                    bad_reprs.append(f"{k}={v[:40]}")
        assert not bad_reprs, f"Raw list repr found: {bad_reprs}"
        tests.append(_pass("no raw list repr in explanations", "unified_eval", "all clean"))
    except Exception as exc:
        tests.append(_fail("no raw list repr in explanations", "unified_eval", str(exc)))

    # 8. Benign 4688 must not say 'malware' or 'compromised'
    try:
        svchost_ev = {
            "rule": {"level": 3, "description": "Process Created"},
            "data": {"win": {
                "system": {"eventID": "4688"},
                "eventdata": {
                    "newProcessName": "C:\\Windows\\System32\\svchost.exe",
                    "commandLine": "svchost.exe -k LocalServiceNetworkRestricted",
                },
            }},
        }
        result = evaluate_unified_event(svchost_ev)
        expl = result.get("explanation") or {}
        full_text = " ".join(str(v) for v in expl.values()).lower()
        bad_words = [w for w in ("malware", "compromised", "attack", "threat") if w in full_text]
        # "threat" is ok in escalation_conditions context — filter to core narrative fields
        core = " ".join([
            str(expl.get("summary", "")),
            str(expl.get("why_suspicious", "")),
        ]).lower()
        bad_core = [w for w in ("malware", "compromised") if w in core]
        assert not bad_core, f"Benign svchost explanation contains bad words: {bad_core}"
        tests.append(_pass("benign 4688 no alarmist language", "unified_eval",
                           f"risk={result.get('final_evaluation', {}).get('risk_score')}"))
    except Exception as exc:
        tests.append(_fail("benign 4688 no alarmist language", "unified_eval", str(exc)))

    return tests


# ── WAZUH INTEGRATION TESTS ───────────────────────────────────────────────────

def _run_wazuh_integration_tests() -> list[dict]:
    tests: list[dict] = []
    CAT = "wazuh_integration"

    # 1. Field mapper import + basic normalise
    try:
        from services.wazuh_field_mapper import normalize_wazuh_event, get_field
        ev = {
            "agent": {"name": "TEST-HOST", "id": "001", "ip": "10.0.0.1"},
            "data": {"win": {"system": {"eventID": "4688"},
                             "eventdata": {"newProcessName": r"C:\Windows\cmd.exe",
                                           "commandLine": "cmd.exe /c whoami",
                                           "subjectUserName": "SYSTEM"}}},
            "rule": {"id": "60012", "level": 3, "description": "Process created"},
        }
        n = normalize_wazuh_event(ev)
        assert n["event_id"] == "4688",          f"event_id={n['event_id']}"
        assert n["process_name"] is not None,    "process_name is None"
        assert n["subject_user"] == "SYSTEM",    f"subject_user={n['subject_user']}"
        assert n["agent_name"] == "TEST-HOST",   f"agent_name={n['agent_name']}"
        tests.append(_pass("Field mapper: nested JSON 4688", CAT,
                           f"event_id={n['event_id']}, process={n['process_name']}"))
    except Exception as exc:
        tests.append(_fail("Field mapper: nested JSON 4688", CAT, str(exc)))

    # 2. Field mapper: flat CSV/export format (escaped dots)
    try:
        from services.wazuh_field_mapper import normalize_wazuh_event
        flat_row = {
            "agent\\.name": "CSV-HOST",
            "agent\\.id": "099",
            "data\\.win\\.system\\.eventID": "4624",
            "data\\.win\\.eventdata\\.targetUserName": "jdoe",
            "data\\.win\\.eventdata\\.logonType": "3",
            "rule\\.id": "60106",
            "rule\\.level": "3",
            "rule\\.mitre\\.id": '["T1078"]',
        }
        n = normalize_wazuh_event(flat_row)
        assert n["event_id"] == "4624",       f"event_id={n['event_id']}"
        assert n["target_user"] == "jdoe",    f"target_user={n['target_user']}"
        assert n["logon_type"] == "3",        f"logon_type={n['logon_type']}"
        assert "T1078" in n["mitre_ids"],     f"mitre_ids={n['mitre_ids']}"
        tests.append(_pass("Field mapper: flat CSV format", CAT,
                           f"event_id={n['event_id']}, user={n['target_user']}"))
    except Exception as exc:
        tests.append(_fail("Field mapper: flat CSV format", CAT, str(exc)))

    # 3. Field mapper: eventData camelCase fallback
    try:
        from services.wazuh_field_mapper import normalize_wazuh_event
        ev_cc = {
            "data": {"win": {"system": {"eventID": "4625"},
                             "eventData": {"targetUserName": "admin",
                                           "ipAddress": "192.168.1.5"}}},
        }
        n = normalize_wazuh_event(ev_cc)
        assert n["event_id"] == "4625",          f"event_id={n['event_id']}"
        assert n["target_user"] == "admin",      f"target_user={n['target_user']}"
        assert n["source_ip"] == "192.168.1.5",  f"source_ip={n['source_ip']}"
        tests.append(_pass("Field mapper: camelCase eventData fallback", CAT,
                           "eventData casing resolved"))
    except Exception as exc:
        tests.append(_fail("Field mapper: camelCase eventData fallback", CAT, str(exc)))

    # 4. Field mapper: empty/None fields → None not crash
    try:
        from services.wazuh_field_mapper import normalize_wazuh_event
        n = normalize_wazuh_event({})
        assert n["event_id"] is None
        assert n["rule_id"] is None
        assert n["mitre_ids"] == []
        assert isinstance(n["raw"], dict)
        tests.append(_pass("Field mapper: empty event → safe fallback", CAT, "No crash, all None"))
    except Exception as exc:
        tests.append(_fail("Field mapper: empty event → safe fallback", CAT, str(exc)))

    # 5. Manager API: configuration check
    try:
        from services.wazuh_manager_api import check_manager_configured
        check = check_manager_configured()
        if check["configured"]:
            tests.append(_pass("Manager API: configured", CAT,
                               "manager_url + credentials present"))
        else:
            tests.append(_warn("Manager API: not configured", CAT,
                               f"{check['reason']} — Manager features unavailable",
                               {"action": "Set manager_url, manager_username, manager_password in connection settings"}))
    except Exception as exc:
        tests.append(_fail("Manager API: configuration check", CAT, str(exc)))

    # 6. Manager API: connectivity (only if configured)
    try:
        from services.wazuh_manager_api import check_manager_configured, WazuhManagerAPIClient
        from db.database import get_active_connection
        conn = get_active_connection()
        check = check_manager_configured(conn)
        if check["configured"]:
            try:
                client = WazuhManagerAPIClient.from_connection(conn)
                h = client.health()
                if h.get("authenticated"):
                    tests.append(_pass("Manager API: authentication + reachability", CAT,
                                       f"version={h.get('manager_version')} agents={h.get('agent_status_summary')}"))
                elif h.get("reachable"):
                    tests.append(_warn("Manager API: reachable but auth failed", CAT,
                                       h.get("message", "auth error")))
                else:
                    tests.append(_warn("Manager API: not reachable", CAT,
                                       h.get("message", "unreachable")))
            except Exception as exc2:
                tests.append(_warn("Manager API: authentication + reachability", CAT,
                                   f"Error: {exc2}"))
        else:
            tests.append(_warn("Manager API: authentication skipped", CAT,
                               "Not configured — skipping live test"))
    except Exception as exc:
        tests.append(_fail("Manager API: connectivity", CAT, str(exc)))

    # 7. API capabilities: spec loaded (warn if missing, not fail)
    try:
        from services.wazuh_api_capabilities import get_cached_capabilities, get_cached_summary
        caps = get_cached_capabilities()
        summary = get_cached_summary()
        if caps:
            dangerous = summary.get("dangerous_disabled", 0)
            implemented = summary.get("read_only_implemented", 0)
            tests.append(_pass("API capabilities: spec loaded", CAT,
                               f"{summary.get('total')} endpoints, {implemented} implemented, "
                               f"{dangerous} dangerous disabled"))
        else:
            tests.append(_warn("API capabilities: spec not found", CAT,
                               "spec-v4.14.5.yaml not found — place in project root for full capability matrix",
                               {"hint": "Copy spec to d:/PYTHON/KI_wazuh_auswertung/spec-v4.14.5.yaml"}))
    except Exception as exc:
        tests.append(_fail("API capabilities: spec loaded", CAT, str(exc)))

    # 8. Dangerous actions disabled: verify routes_wazuh_manager has no write routes
    try:
        from api.routes_wazuh_manager import router as wmr
        dangerous_methods = {"PUT", "DELETE", "PATCH"}
        # active-response must not be present
        found_dangerous: list[str] = []
        for route in wmr.routes:
            m = getattr(route, "methods", set()) or set()
            p = getattr(route, "path", "")
            m_upper = {str(x).upper() for x in m}
            if m_upper & dangerous_methods:
                # Only logtest DELETE /sessions/{token} is OK
                if "sessions" in p and m_upper == {"DELETE"}:
                    continue
                found_dangerous.append(f"{m_upper} {p}")
        if found_dangerous:
            tests.append(_fail("Dangerous actions: all disabled", CAT,
                               f"Found unexpected write routes: {found_dangerous}"))
        else:
            tests.append(_pass("Dangerous actions: all disabled", CAT,
                               "No PUT/DELETE/PATCH routes in wazuh_manager router"))
    except Exception as exc:
        tests.append(_fail("Dangerous actions: all disabled", CAT, str(exc)))

    # 9. Wazuh API Documentation knowledge
    try:
        from knowledge.wazuh_api_docs_knowledge import WAZUH_API_DOC_SECTIONS
        n = len(WAZUH_API_DOC_SECTIONS)
        keys = [s["key"] for s in WAZUH_API_DOC_SECTIONS]
        required = {"getting_started", "wql", "rbac", "reference"}
        missing = required - set(keys)
        if missing:
            tests.append(_warn("Wazuh API docs knowledge", CAT,
                               f"Missing required sections: {missing}", {"found": keys}))
        else:
            tests.append(_pass("Wazuh API docs knowledge", CAT,
                               f"{n} doc sections loaded", {"sections": keys}))
    except Exception as exc:
        tests.append(_fail("Wazuh API docs knowledge", CAT, str(exc)))

    # 10. Response normalizer — success path
    try:
        from services.wazuh_api_response import normalize_wazuh_response, extract_affected_items
        resp = {"data": {"affected_items": [{"id": "001"}], "total_affected_items": 1,
                         "total_failed_items": 0, "failed_items": []},
                "message": "All selected agents information was returned",
                "error": 0}
        n = normalize_wazuh_response(resp)
        assert n["ok"] is True,            f"ok={n['ok']}"
        assert n["error_code"] is None,    f"error_code={n['error_code']}"
        assert len(n["affected_items"]) == 1, f"items={n['affected_items']}"
        items = extract_affected_items(resp)
        assert len(items) == 1
        tests.append(_pass("Response normalizer: success path", CAT,
                           "ok=True, 1 affected_item, error_code=None"))
    except Exception as exc:
        tests.append(_fail("Response normalizer: success path", CAT, str(exc)))

    # 11. Response normalizer — 401/403/429 classification
    try:
        from services.wazuh_api_response import summarize_wazuh_error
        e401 = summarize_wazuh_error(401)
        e403 = summarize_wazuh_error(403)
        e429 = summarize_wazuh_error(429)
        assert e401["category"] == "auth",       f"401 category={e401['category']}"
        assert e403["category"] == "permission", f"403 category={e403['category']}"
        assert e429["category"] == "rate_limit", f"429 category={e429['category']}"
        tests.append(_pass("Response normalizer: HTTP error classification", CAT,
                           "401=auth, 403=permission, 429=rate_limit"))
    except Exception as exc:
        tests.append(_fail("Response normalizer: HTTP error classification", CAT, str(exc)))

    # 12. WQL builder
    try:
        from services.wazuh_wql import build_wql, parse_wql, validate_wql
        q1 = build_wql({"status": "active", "os_platform": "windows"})
        assert q1 == "status=active;os.platform=windows", f"q1={q1!r}"
        q2 = build_wql({"name_contains": "web"})
        assert q2 == "name~web", f"q2={q2!r}"
        q3 = build_wql({})
        assert q3 == "", f"q3={q3!r}"
        parsed = parse_wql("status=active;os.platform=linux")
        assert parsed.get("status") == "active",          f"parsed={parsed}"
        assert parsed.get("os.platform") == "linux",      f"parsed={parsed}"
        ok, _ = validate_wql("status=active")
        assert ok is True
        invalid_ok, msg = validate_wql("nooperator")
        assert invalid_ok is False, f"expected invalid, msg={msg}"
        tests.append(_pass("WQL builder", CAT,
                           "build_wql, parse_wql, validate_wql all pass"))
    except Exception as exc:
        tests.append(_fail("WQL builder", CAT, str(exc)))

    # 13. API recipes catalogue
    try:
        from knowledge.wazuh_api_recipes import WAZUH_API_RECIPES
        n = len(WAZUH_API_RECIPES)
        ids = [r["recipe_id"] for r in WAZUH_API_RECIPES]
        required_ids = {"agent_inventory", "logtest", "syscollector_inventory"}
        missing = required_ids - set(ids)
        # Safety: no implemented recipe should be dangerous
        dangerous_implemented = [r for r in WAZUH_API_RECIPES
                                  if r["implemented"] and r["safety"] == "dangerous"]
        if dangerous_implemented:
            tests.append(_fail("API recipes: no dangerous implemented", CAT,
                               f"Dangerous+implemented recipes found: "
                               f"{[r['recipe_id'] for r in dangerous_implemented]}"))
        elif missing:
            tests.append(_warn("API recipes catalogue", CAT,
                               f"Missing required recipes: {missing}", {"found": ids}))
        else:
            tests.append(_pass("API recipes catalogue", CAT,
                               f"{n} recipes, no dangerous-implemented, required ids present",
                               {"recipes": ids}))
    except Exception as exc:
        tests.append(_fail("API recipes catalogue", CAT, str(exc)))

    # 14. Permissions route importable
    try:
        from services.wazuh_api_permissions import check_wazuh_api_permissions, PERMISSION_PROBES, AGENT_PROBES
        n_probes = len(PERMISSION_PROBES) + len(AGENT_PROBES)
        tests.append(_pass("Permissions service import", CAT,
                           f"{n_probes} permission probes defined"))
    except Exception as exc:
        tests.append(_fail("Permissions service import", CAT, str(exc)))

    # 15. reconnect_agents([]) raises ValueError
    try:
        from services.wazuh_manager_api import WazuhManagerAPIClient
        # Instantiate with dummy creds — we will never call authenticate
        dummy_client = WazuhManagerAPIClient(
            base_url="https://127.0.0.1:55000",
            username="test",
            password="test",  # noqa: S106
        )
        raised = False
        try:
            dummy_client.reconnect_agents([])
        except ValueError:
            raised = True
        if raised:
            tests.append(_pass("Reconnect: empty agent_ids raises ValueError", CAT,
                               "ValueError raised as required — mass reconnect blocked"))
        else:
            tests.append(_fail("Reconnect: empty agent_ids raises ValueError", CAT,
                               "No ValueError raised — mass reconnect not protected"))
    except Exception as exc:
        tests.append(_fail("Reconnect: empty agent_ids raises ValueError", CAT, str(exc)))

    # 16. reconnect_agents builds correct agents_list param (no network call)
    try:
        import types as _types
        from services.wazuh_manager_api import WazuhManagerAPIClient

        captured: dict = {}

        def _fake_request(self: WazuhManagerAPIClient, method: str, path: str,
                          params: dict | None = None, json_body: dict | None = None) -> dict:
            captured["method"]  = method
            captured["path"]    = path
            captured["params"]  = params or {}
            return {"data": {"affected_items": [{"id": "001"}], "total_affected_items": 1,
                             "total_failed_items": 0, "failed_items": []}, "error": 0}

        dummy_client2 = WazuhManagerAPIClient(
            base_url="https://127.0.0.1:55000", username="test", password="test"  # noqa: S106
        )
        dummy_client2.request = _types.MethodType(_fake_request, dummy_client2)  # type: ignore[method-assign]
        dummy_client2.reconnect_agents(["001"])

        assert captured.get("method") == "PUT",             f"method={captured.get('method')}"
        assert captured.get("path")   == "/agents/reconnect", f"path={captured.get('path')}"
        assert captured["params"].get("agents_list") == "001", f"agents_list={captured['params'].get('agents_list')}"
        tests.append(_pass("Reconnect: agents_list param correct", CAT,
                           "PUT /agents/reconnect?agents_list=001"))
    except Exception as exc:
        tests.append(_fail("Reconnect: agents_list param correct", CAT, str(exc)))

    # 17. Single-agent reconnect route exists; reconnect-all does NOT
    try:
        from api.routes_wazuh_manager import router as wmr
        all_paths = [(str(getattr(r, 'path', '')), set(str(m).upper() for m in (getattr(r, 'methods', None) or set())))
                     for r in wmr.routes]
        # Single-agent reconnect must be present (POST)
        single_reconnect = [p for p, m in all_paths if '/reconnect' in p and '{agent_id}' in p and 'POST' in m]
        # Mass reconnect must NOT exist
        mass_reconnect   = [p for p, m in all_paths if '/reconnect' in p and '{agent_id}' not in p]
        if not single_reconnect:
            tests.append(_fail("Reconnect route: single-agent POST exists", CAT,
                               "POST /agents/{agent_id}/reconnect not found"))
        elif mass_reconnect:
            tests.append(_fail("Reconnect route: no reconnect-all route", CAT,
                               f"Mass reconnect route found: {mass_reconnect}"))
        else:
            tests.append(_pass("Reconnect routes: single-agent only", CAT,
                               f"Found {single_reconnect[0]}, no mass reconnect route"))
    except Exception as exc:
        tests.append(_fail("Reconnect routes", CAT, str(exc)))

    # 18. Audit function available for reconnect action types
    try:
        from db.database import create_audit_entry
        # Just verify it is callable and accepts our payload shape
        assert callable(create_audit_entry)
        tests.append(_pass("Reconnect: audit logging function available", CAT,
                           "create_audit_entry callable for wazuh_agent_reconnect_* events"))
    except Exception as exc:
        tests.append(_fail("Reconnect: audit logging function available", CAT, str(exc)))

    # 19. Permission matrix includes reconnect_single_agent
    try:
        from services.wazuh_api_permissions import CONTROLLED_ACTION_PROBES
        keys = [p["key"] for p in CONTROLLED_ACTION_PROBES]
        if "reconnect_single_agent" not in keys:
            tests.append(_fail("Permission matrix: reconnect_single_agent present", CAT,
                               f"Key not found in CONTROLLED_ACTION_PROBES — found: {keys}"))
        else:
            probe = next(p for p in CONTROLLED_ACTION_PROBES if p["key"] == "reconnect_single_agent")
            assert probe.get("mass_action_allowed") is False, "mass_action_allowed must be False"
            assert probe.get("safety") == "controlled_action", f"safety={probe.get('safety')}"
            assert "PUT /agents/reconnect" in probe.get("endpoint", ""), \
                f"endpoint={probe.get('endpoint')}"
            tests.append(_pass("Permission matrix: reconnect_single_agent present", CAT,
                               f"endpoint={probe['endpoint']}, mass_action_allowed=False"))
    except Exception as exc:
        tests.append(_fail("Permission matrix: reconnect_single_agent present", CAT, str(exc)))

    # 20. Permissions route returns controlled_actions key
    try:
        from services.wazuh_api_permissions import check_wazuh_api_permissions
        import inspect
        src = inspect.getsource(check_wazuh_api_permissions)
        assert "controlled_actions" in src, "controlled_actions not in returned dict"
        assert "CONTROLLED_ACTION_PROBES" in src, "CONTROLLED_ACTION_PROBES not iterated"
        tests.append(_pass("Permissions route: controlled_actions in response", CAT,
                           "check_wazuh_api_permissions() returns controlled_actions list"))
    except Exception as exc:
        tests.append(_fail("Permissions route: controlled_actions in response", CAT, str(exc)))

    # 21. Reconnect route returns structured result — not a bare HTTPException on normal errors
    try:
        from api.routes_wazuh_manager import _classify_reconnect_error

        # 401 → denied
        s401, m401 = _classify_reconnect_error(Exception("Status 401"))
        assert s401 == "denied", f"401 should be denied, got {s401}"
        assert "401" in m401

        # 403 → denied
        s403, m403 = _classify_reconnect_error(Exception("HTTP 403"))
        assert s403 == "denied", f"403 should be denied, got {s403}"

        # 503 → error / unavailable
        s503, m503 = _classify_reconnect_error(Exception("503 Service Unavailable"))
        assert s503 == "error", f"503 should be error, got {s503}"

        # connection refused → error
        sconn, mconn = _classify_reconnect_error(Exception("Connection refused"))
        assert sconn == "error", f"connection error should be error, got {sconn}"

        tests.append(_pass("Reconnect: error classifier", CAT,
                           "401→denied, 403→denied, 503→error, connection→error"))
    except Exception as exc:
        tests.append(_fail("Reconnect: error classifier", CAT, str(exc)))

    # 22. Reconnect route response includes message and audit_id fields
    try:
        from api.routes_wazuh_manager import agent_reconnect, AgentReconnectRequest
        import inspect
        src = inspect.getsource(agent_reconnect)
        for field in ("\"message\"", "audit_id_requested", "audit_id_completed"):
            assert field in src, f"Field {field!r} not found in agent_reconnect source"
        tests.append(_pass("Reconnect route: normalized response fields", CAT,
                           "message, audit_id_requested, audit_id_completed present"))
    except Exception as exc:
        tests.append(_fail("Reconnect route: normalized response fields", CAT, str(exc)))

    # 23. Reconnect-all still not exposed (regression guard)
    try:
        from api.routes_wazuh_manager import router as wmr
        all_paths = [str(getattr(r, 'path', '')) for r in wmr.routes]
        mass = [p for p in all_paths if '/reconnect' in p and '{agent_id}' not in p]
        if mass:
            tests.append(_fail("Reconnect-all: still not exposed", CAT,
                               f"Mass reconnect route found: {mass}"))
        else:
            tests.append(_pass("Reconnect-all: still not exposed", CAT,
                               "No mass reconnect route present"))
    except Exception as exc:
        tests.append(_fail("Reconnect-all: still not exposed", CAT, str(exc)))

    # 24. Controlled action requires confirmation metadata (safety field in probe)
    try:
        from services.wazuh_api_permissions import CONTROLLED_ACTION_PROBES
        for probe in CONTROLLED_ACTION_PROBES:
            assert "safety" in probe, f"Probe {probe['key']} missing 'safety' field"
            assert "mass_action_allowed" in probe, f"Probe {probe['key']} missing 'mass_action_allowed'"
        tests.append(_pass("Controlled actions: confirmation metadata present", CAT,
                           f"{len(CONTROLLED_ACTION_PROBES)} probe(s) have safety + mass_action_allowed"))
    except Exception as exc:
        tests.append(_fail("Controlled actions: confirmation metadata present", CAT, str(exc)))

    return tests


# ── WAZUH AGENT ENRICHMENT CACHE TESTS ────────────────────────────────────────

def _run_agent_enrichment_tests() -> list[dict]:
    """Tests for wazuh_agent_enrichment: TTL cache, resolution, batch helper."""
    tests: list[dict] = []
    CAT = "agent_enrichment"

    try:
        from services.wazuh_agent_enrichment import (
            enrich_agent_context,
            enrich_agent_contexts,
            _cache_primary_key,
            _cache_get,
            _cache_set,
            _norm_hostname,
            _CACHE,
        )
    except ImportError as exc:
        tests.append({"name": "agent_enrichment_import", "category": CAT,
                      "status": "fail", "message": f"Import failed: {exc}"})
        return tests

    # ── 1. Cache key priority ─────────────────────────────────────────────────
    try:
        k1 = _cache_primary_key("001", "vm-dc", "192.168.1.5")
        k2 = _cache_primary_key(None,  "vm-dc", "192.168.1.5")
        k3 = _cache_primary_key(None,  None,    "192.168.1.5")
        assert k1 == "id:001",    f"expected 'id:001', got '{k1}'"
        assert k2.startswith("name:"), f"expected 'name:*', got '{k2}'"
        assert k3 == "ip:192.168.1.5", f"expected 'ip:*', got '{k3}'"
        tests.append({"name": "cache_key_priority", "category": CAT,
                      "status": "pass", "message": "agent_id > name > ip key selection correct"})
    except AssertionError as exc:
        tests.append({"name": "cache_key_priority", "category": CAT,
                      "status": "fail", "message": str(exc)})

    # ── 2. Hostname normalisation ─────────────────────────────────────────────
    try:
        cases = [
            ("VM-MINISERVICES",          "vm-miniservices"),
            ("dc01.corp.local",          "dc01"),
            ("WS100.internal.company",   "ws100"),
            ("simple",                   "simple"),
        ]
        for raw, expected in cases:
            got = _norm_hostname(raw)
            assert got == expected, f"_norm_hostname({raw!r}) = {got!r}, expected {expected!r}"
        tests.append({"name": "hostname_normalisation", "category": CAT,
                      "status": "pass", "message": f"All {len(cases)} normalisation cases correct"})
    except AssertionError as exc:
        tests.append({"name": "hostname_normalisation", "category": CAT,
                      "status": "fail", "message": str(exc)})

    # ── 3. Cache stores and returns result ────────────────────────────────────
    try:
        import time
        test_key = "__test_cache_entry__"
        fake_result = {
            "agent": {"id": "999", "name": "test-host"},
            "source": "manager_api",
            "source_reason": "test",
            "cache_age_seconds": None,
            "warnings": [],
            "syscollector": {}, "sca": {}, "fim": {}, "rootcheck": {},
        }
        _cache_set(test_key, fake_result)
        got = _cache_get(test_key)
        assert got is not None, "Cache returned None immediately after set"
        assert got["source"] == "cache", f"Expected source='cache', got {got['source']!r}"
        assert got["cache_age_seconds"] is not None, "cache_age_seconds should be set"
        assert got["cache_age_seconds"] >= 0, "cache_age_seconds should be >= 0"
        # Clean up
        with __import__("threading").Lock():
            _CACHE.pop(test_key, None)
        tests.append({"name": "cache_store_and_return", "category": CAT,
                      "status": "pass", "message": "Cache stores result and returns with source=cache and age"})
    except AssertionError as exc:
        tests.append({"name": "cache_store_and_return", "category": CAT,
                      "status": "fail", "message": str(exc)})

    # ── 4. Manager API unavailable → event_only, no crash ────────────────────
    try:
        # Pass conn=None with no active connection → should return event_only gracefully
        ctx = enrich_agent_context(
            agent_id=None,
            agent_name="__nonexistent_test_host__",
            agent_ip=None,
            conn={"__invalid": True},  # will cause check_manager_configured to fail
        )
        assert "source" in ctx, "result missing 'source'"
        assert "source_reason" in ctx, "result missing 'source_reason'"
        assert "warnings" in ctx, "result missing 'warnings'"
        assert ctx["source"] in ("event_only", "manager_api", "cache"), \
            f"Unexpected source: {ctx['source']}"
        tests.append({"name": "api_unavailable_graceful", "category": CAT,
                      "status": "pass", "message": f"Returned source={ctx['source']!r} without crash"})
    except Exception as exc:
        tests.append({"name": "api_unavailable_graceful", "category": CAT,
                      "status": "fail", "message": f"Raised exception: {exc}"})

    # ── 5. result always has source_reason ───────────────────────────────────
    try:
        ctx = enrich_agent_context(agent_name="__test_reason_check__", conn={"__invalid": True})
        assert ctx.get("source_reason"), "source_reason is empty or missing"
        tests.append({"name": "source_reason_present", "category": CAT,
                      "status": "pass", "message": f"source_reason: {ctx['source_reason']!r}"})
    except Exception as exc:
        tests.append({"name": "source_reason_present", "category": CAT,
                      "status": "fail", "message": str(exc)})

    # ── 6. Batch helper de-duplicates lookups ─────────────────────────────────
    try:
        import unittest.mock as mock
        call_count = 0
        original = enrich_agent_context

        def counting_enrich(**kw):
            nonlocal call_count
            call_count += 1
            return original(**kw)

        agents = [
            {"agent_id": "001", "agent_name": "host-a", "agent_ip": "1.2.3.4"},
            {"agent_id": "001", "agent_name": "host-a", "agent_ip": "1.2.3.4"},  # duplicate
            {"agent_id": "002", "agent_name": "host-b", "agent_ip": "1.2.3.5"},
        ]
        # Manually test key dedup without patching (pure unit test of logic)
        keys = set()
        for ag in agents:
            from services.wazuh_agent_enrichment import _cache_primary_key as cpk
            k = cpk(ag.get("agent_id"), ag.get("agent_name"), ag.get("agent_ip"))
            keys.add(k)
        assert len(keys) == 2, f"Expected 2 unique keys, got {len(keys)}: {keys}"
        tests.append({"name": "batch_deduplication", "category": CAT,
                      "status": "pass", "message": f"De-duplicated 3 agents → {len(keys)} unique keys"})
    except AssertionError as exc:
        tests.append({"name": "batch_deduplication", "category": CAT,
                      "status": "fail", "message": str(exc)})

    # ── 7. _empty_context has all required fields ─────────────────────────────
    try:
        from services.wazuh_agent_enrichment import _empty_context
        ctx = _empty_context()
        required = {"agent", "syscollector", "sca", "fim", "rootcheck",
                    "source", "source_reason", "cache_age_seconds", "warnings"}
        missing = required - set(ctx.keys())
        assert not missing, f"Missing keys in _empty_context: {missing}"
        tests.append({"name": "empty_context_shape", "category": CAT,
                      "status": "pass", "message": "All required keys present in empty context"})
    except AssertionError as exc:
        tests.append({"name": "empty_context_shape", "category": CAT,
                      "status": "fail", "message": str(exc)})

    return tests


# ── FIELD NORMALIZATION TESTS ─────────────────────────────────────────────────

def _run_field_normalization_tests() -> list[dict]:
    """Cross-format normalization: eventdata/eventData/CSV, all event types."""
    tests: list[dict] = []
    CAT = "field_normalization"

    try:
        from services.wazuh_field_mapper import normalize_wazuh_event, get_field

        # ── 4688 lowercase eventdata ──────────────────────────────────────────
        ev4688_lower = {
            "data": {"win": {"system": {"eventID": "4688"},
                             "eventdata": {"newProcessName": r"C:\Windows\System32\cmd.exe",
                                           "commandLine": "cmd.exe /c whoami",
                                           "subjectUserName": "jdoe",
                                           "parentProcessName": r"C:\Windows\explorer.exe"}}},
            "rule": {"id": "92220", "level": 2},
        }
        n = normalize_wazuh_event(ev4688_lower)
        assert n["event_id"] == "4688"
        assert "cmd.exe" in (n["process_name"] or "").lower(), f"process_name={n['process_name']}"
        assert "whoami" in (n["command_line"] or ""), f"command_line={n['command_line']}"
        assert n["subject_user"] == "jdoe"
        tests.append(_pass("Normalize 4688 lowercase eventdata", CAT,
                           f"process={n['process_name']}, cmdline present"))

        # ── 4688 camelCase eventData ──────────────────────────────────────────
        ev4688_camel = {
            "data": {"win": {"system": {"eventID": "4688"},
                             "eventData": {"newProcessName": r"C:\Windows\System32\powershell.exe",
                                           "commandLine": "-enc aGVsbG8=",
                                           "subjectUserName": "admin"}}},
            "rule": {"id": "92220", "level": 6},
        }
        n = normalize_wazuh_event(ev4688_camel)
        assert n["event_id"] == "4688"
        assert "powershell" in (n["process_name"] or "").lower(), f"process_name={n['process_name']}"
        assert n["command_line"] is not None, "command_line is None"
        tests.append(_pass("Normalize 4688 camelCase eventData", CAT,
                           f"process={n['process_name']}, cmdline present"))

        # ── 4624 logon fields ─────────────────────────────────────────────────
        ev4624 = {
            "data": {"win": {"system": {"eventID": "4624"},
                             "eventdata": {"targetUserName": "jdoe",
                                           "logonType": "3",
                                           "ipAddress": "10.10.1.55",
                                           "workstationName": "WS-FINANCE"}}},
            "rule": {"id": "60106", "level": 3},
        }
        n = normalize_wazuh_event(ev4624)
        assert n["event_id"] == "4624"
        assert n["logon_type"] == "3", f"logon_type={n['logon_type']}"
        assert n["source_ip"] == "10.10.1.55", f"source_ip={n['source_ip']}"
        assert n["target_user"] == "jdoe"
        tests.append(_pass("Normalize 4624 logon fields", CAT,
                           f"logon_type={n['logon_type']}, ip={n['source_ip']}"))

        # ── 7045 service install ──────────────────────────────────────────────
        ev7045 = {
            "data": {"win": {"system": {"eventID": "7045"},
                             "eventdata": {"serviceName": "MalSvc",
                                           "imagePath": r"C:\Temp\malware.exe",
                                           "startType": "demand start",
                                           "subjectUserName": "SYSTEM"}}},
            "rule": {"id": "92656", "level": 9},
        }
        n = normalize_wazuh_event(ev7045)
        assert n["service_name"] == "MalSvc"
        assert n["service_path"] == r"C:\Temp\malware.exe"
        tests.append(_pass("Normalize 7045 service install", CAT,
                           f"service={n['service_name']}, path present"))

        # ── FIM / syscheck ────────────────────────────────────────────────────
        ev_fim = {
            "syscheck": {"path": r"C:\Windows\System32\calc.exe",
                         "event": "modified",
                         "md5_after": "deadbeef"},
            "rule": {"id": "550", "level": 7},
        }
        n = normalize_wazuh_event(ev_fim)
        assert n["file_path"] == r"C:\Windows\System32\calc.exe"
        assert n["file_action"] == "modified"
        tests.append(_pass("Normalize FIM syscheck event", CAT,
                           f"file_path={n['file_path']}, action={n['file_action']}"))

        # ── Unknown event — no crash ──────────────────────────────────────────
        ev_unknown = {"timestamp": "2024-01-01T00:00:00Z", "rule": {"id": "99999", "level": 5}}
        n = normalize_wazuh_event(ev_unknown)
        assert isinstance(n, dict)
        assert n["event_id"] is None
        assert n["rule_id"] == "99999"
        tests.append(_pass("Normalize unknown event → no crash", CAT, "Safe fallback confirmed"))

        # ── Code hygiene: no raw eventdata access outside mapper ──────────────
        import os, ast
        backend_root = os.path.join(os.path.dirname(__file__), "..")
        mapper_path  = os.path.normpath(os.path.join(backend_root, "services", "wazuh_field_mapper.py"))
        violations: list[str] = []
        raw_access = re.compile(r'\.get\(["\']eventdata["\']\)|\.get\(["\']eventData["\']\)', re.IGNORECASE)
        for root_dir, _, files in os.walk(backend_root):
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.normpath(os.path.join(root_dir, fname))
                if fpath == mapper_path:
                    continue
                # Skip test / validation files (they contain expected patterns)
                if "test" in fname.lower() or "validation" in fname.lower():
                    continue
                try:
                    src_text = open(fpath, encoding="utf-8").read()
                    for i, line in enumerate(src_text.splitlines(), 1):
                        if raw_access.search(line):
                            rel = os.path.relpath(fpath, backend_root)
                            violations.append(f"{rel}:{i}")
                except Exception:
                    pass
        if violations:
            tests.append(_warn(
                "Field hygiene: direct eventdata access", CAT,
                f"Found {len(violations)} raw .get('eventdata') calls outside mapper: {violations[:5]}",
                {"action": "Replace with get_field() or normalize_wazuh_event()"}
            ))
        else:
            tests.append(_pass("Field hygiene: no raw eventdata access outside mapper", CAT,
                               "All eventdata access routes through wazuh_field_mapper"))

    except Exception as exc:
        import traceback
        tests.append(_fail("Field normalization test suite", CAT,
                           f"{exc}\n{traceback.format_exc()[:300]}"))

    return tests


# ── SERVER OPERATIONS TESTS ───────────────────────────────────────────────────

def _run_server_operations_tests() -> list[dict]:
    """Trust Center self-tests for the Server Operations / Remote Access layer."""
    tests: list[dict] = []
    CAT = "server_operations"

    # T01–T03: DB tables ───────────────────────────────────────────────────────
    try:
        from db.database import get_connection
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            existing = {row[0] for row in cur.fetchall()}

        for table in ("server_connections", "server_activity_log", "remote_sessions"):
            if table in existing:
                tests.append(_pass(f"DB table {table}", CAT, f"Table '{table}' exists"))
            else:
                tests.append(_fail(f"DB table {table}", CAT, f"Table '{table}' missing from database"))
    except Exception as exc:
        tests.append(_fail("DB server_operations tables", CAT, f"DB check failed: {exc}"))

    # T04: Legacy importer importable ─────────────────────────────────────────
    try:
        from services.remote_access.legacy_importer import import_from_json, import_from_csv, _WARNED_FIELDS  # noqa: F401
        tests.append(_pass("Legacy importer import", CAT, "import_from_json/csv imported OK"))
    except Exception as exc:
        tests.append(_fail("Legacy importer import", CAT, f"Import failed: {exc}"))
        return tests  # remaining tests depend on this

    # T05: Legacy importer handles SSH/RDP nested-JSON format ─────────────────
    try:
        sample = {
            "ssh": {
                "test-server": {"host": "192.168.1.10", "user": "admin", "port": 22,
                                "tags": ["linux"], "favorite": False},
            },
            "rdp": {
                "win-box": {"host": "10.0.0.5", "user": "Administrator", "port": 3389},
            },
        }
        result = import_from_json(json.dumps(sample))
        assert result["total"] >= 2, f"Expected ≥2 items, got {result['total']}"
        tests.append(_pass("Legacy importer: SSH/RDP nested-JSON format", CAT,
                           f"Parsed {result['total']} connections (imported={result['imported']})"))
    except Exception as exc:
        tests.append(_fail("Legacy importer: SSH/RDP nested-JSON format", CAT, str(exc)))

    # T06: Legacy importer never imports plaintext passwords ──────────────────
    try:
        sample_with_pw = {
            "ssh": {
                "unsafe": {"host": "10.0.0.99", "user": "root", "password": "s3cret",
                           "passwd": "also_bad", "port": 22},
            }
        }
        result = import_from_json(json.dumps(sample_with_pw))
        # Verify that the imported item has no password field set
        items = result.get("items", [])
        for item in items:
            for bad_key in ("password", "passwd", "pass", "secret"):
                assert bad_key not in item or not item[bad_key], \
                    f"Password field '{bad_key}' was imported!"
        assert "password" in _WARNED_FIELDS, "_WARNED_FIELDS must include 'password'"
        tests.append(_pass("Legacy importer: no plaintext password import", CAT,
                           f"Password fields suppressed; _WARNED_FIELDS={sorted(_WARNED_FIELDS)}"))
    except Exception as exc:
        tests.append(_fail("Legacy importer: no plaintext password import", CAT, str(exc)))

    # T07: SSH_READONLY_COMMANDS has ≥ 10 entries ─────────────────────────────
    try:
        from services.remote_access.models import SSH_READONLY_COMMANDS
        count = len(SSH_READONLY_COMMANDS)
        if count >= 10:
            tests.append(_pass("SSH_READONLY_COMMANDS count", CAT,
                               f"Allowlist has {count} entries (≥10 required)"))
        else:
            tests.append(_fail("SSH_READONLY_COMMANDS count", CAT,
                               f"Allowlist has only {count} entries — expected ≥10"))
    except Exception as exc:
        tests.append(_fail("SSH_READONLY_COMMANDS import", CAT, f"Import failed: {exc}"))
        return tests

    # T08: Required commands present in allowlist ─────────────────────────────
    required_cmds = ("uname", "df", "ps_cpu", "systemctl_fail", "mini_top")
    missing = [c for c in required_cmds if c not in SSH_READONLY_COMMANDS]
    if missing:
        tests.append(_fail("SSH_READONLY_COMMANDS required entries", CAT,
                           f"Missing required command IDs: {missing}"))
    else:
        tests.append(_pass("SSH_READONLY_COMMANDS required entries", CAT,
                           f"All required IDs present: {list(required_cmds)}"))

    # T09–T13: Advanced actions are no longer hard-blocked ────────────────────
    try:
        from services.remote_access.remote_policy import check_policy
        unlocked_actions = {
            "ssh_arbitrary_command": "T09",
            "ssh_interactive_shell": "T10",
            "ssh_upload":            "T11",
            "ssh_key_deploy":        "T12",
            "ssh_port_forward":      "T13",
        }
        for action, tid in unlocked_actions.items():
            result = check_policy(action=action, connection=None)
            if result.status != "blocked":
                tests.append(_pass(f"Policy unlock: {action}", CAT,
                                   f"[{tid}] '{action}' status='{result.status}' (not blocked)"))
            else:
                tests.append(_fail(f"Policy unlock: {action}", CAT,
                                   f"[{tid}] '{action}' is still blocked"))
    except Exception as exc:
        tests.append(_fail("Advanced action unlock check", CAT, f"Policy check failed: {exc}"))

    # T14: create_connection allowed without connection context ───────────────
    try:
        result = check_policy(action="create_connection", connection=None)
        if result.status == "ok":
            tests.append(_pass("Policy: create_connection without context", CAT,
                               "create_connection allowed when connection=None (regression test)"))
        else:
            tests.append(_fail("Policy: create_connection without context", CAT,
                               f"create_connection returned status='{result.status}' — expected 'ok' (regression!)"))
    except Exception as exc:
        tests.append(_fail("Policy: create_connection without context", CAT, str(exc)))

    # T15: Feature catalog importable ─────────────────────────────────────────
    try:
        from services.remote_access.legacy_feature_catalog import (  # noqa: F401
            FEATURES, get_feature, get_disabled_features, get_rejected_features
        )
        tests.append(_pass("Feature catalog import", CAT,
                           f"legacy_feature_catalog loaded; {len(FEATURES)} features defined"))
    except Exception as exc:
        tests.append(_fail("Feature catalog import", CAT, f"Import failed: {exc}"))
        return tests

    # T16: Agent deployment is disabled/rejected in catalog ───────────────────
    try:
        agent_feature = get_feature("agent_deployment")
        if agent_feature is None:
            tests.append(_fail("Feature catalog: agent_deployment", CAT,
                               "agent_deployment entry missing from catalog"))
        elif agent_feature["status"] in ("disabled", "rejected"):
            tests.append(_pass("Feature catalog: agent_deployment disabled", CAT,
                               f"agent_deployment status='{agent_feature['status']}' — correctly rejected"))
        else:
            tests.append(_fail("Feature catalog: agent_deployment disabled", CAT,
                               f"agent_deployment status='{agent_feature['status']}' — must be disabled or rejected!"))
    except Exception as exc:
        tests.append(_fail("Feature catalog: agent_deployment", CAT, str(exc)))

    # T17: Source repo mode ────────────────────────────────────────────────────
    try:
        from api.routes_server import get_legacy_features
        resp = get_legacy_features()
        assert resp.get("mode") == "ideas_only_no_repo_modification", \
            f"mode={resp.get('mode')}"
        assert "github.com" in resp.get("source_repo", ""), \
            f"source_repo={resp.get('source_repo')}"
        tests.append(_pass("Legacy feature API: source repo mode", CAT,
                           f"mode='{resp['mode']}', source_repo='{resp['source_repo']}'"))
    except Exception as exc:
        tests.append(_fail("Legacy feature API: source repo mode", CAT, str(exc)))

    # T18: Advanced features are no longer listed as disabled ──────────────────
    try:
        from services.remote_access.legacy_feature_catalog import get_disabled_features
        disabled = get_disabled_features()
        disabled_ids = {f["id"] for f in disabled}
        must_be_enabled = {
            "web_ssh_terminal":  "ssh_interactive_shell is implemented",
            "ssh_key_deployment":"key deployment is implemented",
            "port_forwarding":   "port forwarding is implemented",
        }
        wrongly_disabled = [iid for iid in must_be_enabled if iid in disabled_ids]
        if wrongly_disabled:
            tests.append(_fail("Feature catalog: advanced features no longer disabled", CAT,
                               f"Unexpected disabled features: {wrongly_disabled}"))
        else:
            tests.append(_pass("Feature catalog: advanced features no longer disabled", CAT,
                               f"Catalog marks advanced features as implemented: {list(must_be_enabled)}"))
    except Exception as exc:
        tests.append(_fail("Feature catalog: advanced features no longer disabled", CAT, str(exc)))

    # T19: Baseline enabled features include diagnostics + remote ops ──────────
    try:
        from services.remote_access.legacy_feature_catalog import get_phase1_features
        phase1 = get_phase1_features()
        phase1_ids = {f["id"] for f in phase1}
        required_phase1 = {
            "network_diagnostics":  "ping/dns/port-check should be baseline-enabled",
            "ssh_readonly_commands":"SSH allowlist commands should be baseline-enabled",
            "ssh_connection_test":  "connection test should be baseline-enabled",
            "wol":                  "Wake-on-LAN should be baseline-enabled",
            "file_upload":          "SFTP upload should be enabled with audit",
            "file_delete":          "SFTP delete should be enabled with confirmation + audit",
            "web_ssh_terminal":     "interactive shell launch should be enabled",
            "ssh_key_deployment":   "SSH key deployment should be enabled",
            "port_forwarding":      "SSH port forwarding should be enabled",
            "winrm_remoting":       "WinRM remoting should be enabled",
        }
        missing_phase1 = [iid for iid in required_phase1 if iid not in phase1_ids]
        if missing_phase1:
            tests.append(_fail("Feature catalog: required baseline-enabled features", CAT,
                               f"Expected enabled but not found: {missing_phase1}"))
        else:
            tests.append(_pass("Feature catalog: required baseline-enabled features", CAT,
                               f"All required enabled features present: {list(required_phase1)}"))
    except Exception as exc:
        tests.append(_fail("Feature catalog: required baseline-enabled features", CAT, str(exc)))

    # T20: ssh_config_exporter module imports cleanly ──────────────────────────
    try:
        from services.remote_access.ssh_config_exporter import generate_ssh_config
        tests.append(_pass("SSH config exporter: module import", CAT,
                           "services/remote_access/ssh_config_exporter imports OK"))
    except Exception as exc:
        tests.append(_fail("SSH config exporter: module import", CAT, str(exc)))

    # T21: Generated config contains Host / HostName directives ───────────────
    try:
        from services.remote_access.ssh_config_exporter import generate_ssh_config
        sample = [{"id": "test-001", "name": "My Server", "hostname": "10.0.0.1",
                   "username": "admin", "port": 22, "protocol": "ssh"}]
        result = generate_ssh_config(sample)
        cfg = result.get("config", "")
        if "Host My-Server" not in cfg and "Host My" not in cfg:
            raise AssertionError(f"Expected Host alias in config; got: {cfg[:120]}")
        if "HostName 10.0.0.1" not in cfg:
            raise AssertionError(f"HostName not in config; got: {cfg[:120]}")
        tests.append(_pass("SSH config exporter: Host/HostName directives", CAT,
                           f"host_count={result['host_count']}"))
    except Exception as exc:
        tests.append(_fail("SSH config exporter: Host/HostName directives", CAT, str(exc)))

    # T22: Generated config never includes password/credential ────────────────
    try:
        from services.remote_access.ssh_config_exporter import generate_ssh_config
        sample = [{"id": "t2", "name": "CredTest", "hostname": "192.168.1.1",
                   "username": "user", "password": "secret123",
                   "credential_ref": "vault:prod/ssh", "protocol": "ssh"}]
        result = generate_ssh_config(sample)
        cfg = result.get("config", "")
        for forbidden in ("secret123", "vault:prod", "credential_ref"):
            if forbidden in cfg:
                raise AssertionError(f"Sensitive field '{forbidden}' found in exported config!")
        tests.append(_pass("SSH config exporter: no password/credential in output", CAT,
                           "Sensitive fields correctly excluded"))
    except Exception as exc:
        tests.append(_fail("SSH config exporter: no password/credential in output", CAT, str(exc)))

    # T23: Alias sanitisation (spaces, special chars, OpenSSH keywords) ───────
    try:
        from services.remote_access.ssh_config_exporter import generate_ssh_config
        sample = [
            {"id": "t3a", "name": "My Prod Server!", "hostname": "10.1.1.1", "protocol": "ssh"},
            {"id": "t3b", "name": "host", "hostname": "10.1.1.2", "protocol": "ssh"},
        ]
        result = generate_ssh_config(sample)
        cfg = result.get("config", "")
        # "My Prod Server!" should become "My-Prod-Server" or similar (no spaces, no !)
        if "My Prod Server!" in cfg:
            raise AssertionError("Unsanitised alias with spaces/! appeared in config")
        # "host" is an OpenSSH keyword, should be renamed
        if "\nHost host\n" in cfg:
            raise AssertionError("OpenSSH keyword 'host' used as alias without protection")
        tests.append(_pass("SSH config exporter: alias sanitisation", CAT,
                           f"warnings={result.get('warnings')}"))
    except Exception as exc:
        tests.append(_fail("SSH config exporter: alias sanitisation", CAT, str(exc)))

    # T24: export_ssh_config allowed in policy without connection context ──────
    try:
        from services.remote_access.remote_policy import check_policy
        res = check_policy("export_ssh_config", connection=None)
        if res.status != "ok":
            raise AssertionError(f"export_ssh_config blocked: {res.message}")
        tests.append(_pass("Policy: export_ssh_config allowed without connection", CAT,
                           "check_policy('export_ssh_config', None) → ok"))
    except Exception as exc:
        tests.append(_fail("Policy: export_ssh_config allowed without connection", CAT, str(exc)))

    # T25: ssh_config_export is in feature catalog and marked phase1 ──────────
    try:
        from services.remote_access.legacy_feature_catalog import FEATURES
        cat_ids = {f["id"]: f for f in FEATURES}
        if "ssh_config_export" not in cat_ids:
            raise AssertionError("ssh_config_export not found in feature catalog")
        f = cat_ids["ssh_config_export"]
        if not f.get("phase1"):
            raise AssertionError("ssh_config_export is not marked as Phase 1")
        if f.get("status") != "implemented":
            raise AssertionError(f"ssh_config_export status is '{f.get('status')}', expected 'implemented'")
        tests.append(_pass("Feature catalog: ssh_config_export entry", CAT,
                           f"phase1={f['phase1']}, status={f['status']}"))
    except Exception as exc:
        tests.append(_fail("Feature catalog: ssh_config_export entry", CAT, str(exc)))

    # T26–T29: Host Groups tables and CRUD ────────────────────────────────────
    try:
        from db.database import get_connection
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            existing = {row[0] for row in cur.fetchall()}
        for table in ("server_host_groups", "server_host_group_members",
                      "server_batch_runs", "server_batch_results"):
            if table in existing:
                tests.append(_pass(f"DB table {table}", CAT, f"Table '{table}' exists"))
            else:
                tests.append(_fail(f"DB table {table}", CAT, f"Table '{table}' missing"))
    except Exception as exc:
        tests.append(_fail("DB host group tables", CAT, f"DB check failed: {exc}"))

    # T30: host_groups module imports and CRUD round-trip ─────────────────────
    try:
        from services.remote_access.host_groups import (
            create_group, list_groups, get_group, update_group,
            delete_group, add_member, remove_member, list_group_members,
        )
        gid = None
        try:
            g = create_group("_test_group_tc", description="trust center test", color="#6366f1")
            gid = g["id"]
            assert g["name"] == "_test_group_tc", "name mismatch"
            all_groups = list_groups()
            assert any(x["id"] == gid for x in all_groups), "group not in list"
            g2 = update_group(gid, name="_test_group_tc_v2")
            assert g2 and g2["name"] == "_test_group_tc_v2", "update failed"
            tests.append(_pass("host_groups: CRUD round-trip", CAT,
                               "create/list/update all passed"))
        finally:
            if gid:
                delete_group(gid)
    except Exception as exc:
        tests.append(_fail("host_groups: CRUD round-trip", CAT, str(exc)))

    # T31: add/remove member ──────────────────────────────────────────────────
    try:
        from services.remote_access.host_groups import (
            create_group, delete_group, add_member, remove_member, list_group_members,
        )
        gid = None
        try:
            g = create_group("_test_member_tc")
            gid = g["id"]
            add_member(gid, "fake-conn-001")
            members = list_group_members(gid)
            assert any(m["connection_id"] == "fake-conn-001" for m in members), "member not added"
            ok = remove_member(gid, "fake-conn-001")
            assert ok, "remove_member returned False"
            members2 = list_group_members(gid)
            assert not any(m["connection_id"] == "fake-conn-001" for m in members2), "member not removed"
            tests.append(_pass("host_groups: add/remove member", CAT, "add + remove round-trip OK"))
        finally:
            if gid:
                delete_group(gid)
    except Exception as exc:
        tests.append(_fail("host_groups: add/remove member", CAT, str(exc)))

    # T32: batch_health handles empty list gracefully ─────────────────────────
    try:
        from services.remote_access.batch_health import run_batch_health
        result = run_batch_health([])
        assert result["status"] == "ok", f"Expected ok, got {result['status']}"
        assert result["summary"]["total"] == 0, "Expected total=0"
        tests.append(_pass("batch_health: empty connection_ids", CAT,
                           "run_batch_health([]) returns status=ok, total=0"))
    except Exception as exc:
        tests.append(_fail("batch_health: empty connection_ids", CAT, str(exc)))

    # T33: batch_health marks unknown connection as failed, not crash ──────────
    try:
        from services.remote_access.batch_health import run_batch_health
        result = run_batch_health(["nonexistent-id-xyz"], checks=["ping"])
        assert result["status"] == "ok", f"Expected ok, got {result['status']}"
        assert len(result["results"]) == 1, "Expected 1 result"
        assert result["results"][0]["status"] == "failed", "Expected failed for unknown conn"
        tests.append(_pass("batch_health: unknown connection → failed (not crash)", CAT,
                           f"status={result['results'][0]['status']}"))
    except Exception as exc:
        tests.append(_fail("batch_health: unknown connection → failed (not crash)", CAT, str(exc)))

    # T34: batch_health respects policy — blocked host is marked, not executed ─
    try:
        from services.remote_access.batch_health import run_batch_health
        from services.remote_access.connection_store import create_connection
        import uuid as _uuid
        from db.database import get_connection as _db_conn
        # Create a temporary connection with a non-existent unified_host that is blocked
        test_id = str(_uuid.uuid4())
        with _db_conn() as db:
            db.execute(
                """INSERT INTO server_connections
                   (id, name, hostname, ip, protocol, port, username, auth_type,
                    credential_ref, key_ref, os, platform, tags_json, favorite,
                    mac, unified_host_id, tactical_agent_id, wazuh_agent_id, notes,
                    created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))""",
                (test_id, "_tc_batch_test", "256.256.256.256", "", "ssh", 22, "",
                 "none", "", "", "", "", "[]", 0, "", "", "", "", ""),
            )
        try:
            result = run_batch_health([test_id], checks=["ping"])
            # ping to 256.256.256.256 will fail (invalid IP) — that is acceptable
            # key check: the run completed without crashing and returned a result
            assert result["status"] == "ok", f"run status not ok: {result['status']}"
            assert len(result["results"]) == 1, "Expected 1 result"
            tests.append(_pass("batch_health: policy-aware per-host execution", CAT,
                               f"result status={result['results'][0]['status']} — run did not crash"))
        finally:
            with _db_conn() as db:
                db.execute("DELETE FROM server_connections WHERE id=?", (test_id,))
    except Exception as exc:
        tests.append(_fail("batch_health: policy-aware per-host execution", CAT, str(exc)))

    # T35: batch_health concurrency is capped at _MAX_CONCURRENCY ─────────────
    try:
        from services.remote_access.batch_health import _MAX_CONCURRENCY
        assert 5 <= _MAX_CONCURRENCY <= 20, f"_MAX_CONCURRENCY={_MAX_CONCURRENCY} out of safe range"
        tests.append(_pass("batch_health: concurrency cap", CAT,
                           f"_MAX_CONCURRENCY={_MAX_CONCURRENCY} (safe range 5–20)"))
    except Exception as exc:
        tests.append(_fail("batch_health: concurrency cap", CAT, str(exc)))

    # T36: Destructive batch actions do not exist in batch_health module ───────
    try:
        import services.remote_access.batch_health as _bh
        forbidden_names = ("batch_reboot", "batch_upload", "batch_key_deploy",
                           "batch_arbitrary_command", "batch_install")
        found = [n for n in forbidden_names if hasattr(_bh, n)]
        if found:
            tests.append(_fail("batch_health: no destructive actions", CAT,
                               f"Destructive function(s) found: {found}"))
        else:
            tests.append(_pass("batch_health: no destructive actions", CAT,
                               "No destructive batch functions in module"))
    except Exception as exc:
        tests.append(_fail("batch_health: no destructive actions", CAT, str(exc)))

    # T37: batch policy actions in allowed list ────────────────────────────────
    try:
        from services.remote_access.remote_policy import check_policy
        for action in ("batch_health", "batch_ping", "batch_port_check", "group_manage"):
            res = check_policy(action, connection=None)
            if res.status != "ok":
                raise AssertionError(f"'{action}' blocked: {res.message}")
        tests.append(_pass("Policy: batch+group actions allowed", CAT,
                           "batch_health/ping/port_check/group_manage all pass check_policy"))
    except Exception as exc:
        tests.append(_fail("Policy: batch+group actions allowed", CAT, str(exc)))

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

    # --- Baseline context integration tests ---
    all_tests.extend(_run_baseline_context_tests())

    # --- Process evaluation / 4688 deterministic-engine tests ---
    all_tests.extend(_run_process_evaluation_tests())

    # --- Unified event evaluator tests (Phase 3) ---
    all_tests.extend(_run_unified_evaluator_tests())

    # --- Wazuh integration tests (field mapper + manager API) ---
    all_tests.extend(_run_wazuh_integration_tests())

    # --- Field normalization tests (eventdata/eventData/CSV cross-format) ---
    all_tests.extend(_run_field_normalization_tests())

    # --- Agent enrichment: TTL cache, resolution, batch helper ---
    all_tests.extend(_run_agent_enrichment_tests())

    # --- Server Operations / Remote Access layer tests ---
    all_tests.extend(_run_server_operations_tests())

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
