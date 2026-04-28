"""Host Profile service – CRUD + profile-aware context helpers."""
from __future__ import annotations

import json
from typing import Any

from db.database import get_connection, utc_now_iso
from schemas.types import HostProfile, HostProfileAssignment, HostProfileCreate


# ── Conversion helpers ────────────────────────────────────────────────────────

def _row_to_profile(row: Any) -> HostProfile:
    return HostProfile(
        id=row["id"],
        name=row["name"],
        display_name=row["display_name"],
        description=row["description"],
        risk_tolerance=row["risk_tolerance"],
        expected_behaviors=json.loads(row["expected_behaviors_json"] or "{}"),
        allowed_process_patterns=json.loads(row["allowed_process_patterns_json"] or "[]"),
        suspicious_patterns=json.loads(row["suspicious_patterns_json"] or "[]"),
        always_critical_event_ids=json.loads(row["always_critical_event_ids_json"] or "[]"),
        notes=json.loads(row["notes_json"] or "[]"),
        is_builtin=bool(row["is_builtin"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


# ── Profile CRUD ──────────────────────────────────────────────────────────────

def list_profiles() -> list[HostProfile]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM host_profiles ORDER BY is_builtin DESC, name"
        ).fetchall()
    return [_row_to_profile(r) for r in rows]


def get_profile_by_id(profile_id: int) -> HostProfile | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM host_profiles WHERE id = ?", (profile_id,)
        ).fetchone()
    return _row_to_profile(row) if row else None


def get_profile_by_name(name: str) -> HostProfile | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM host_profiles WHERE name = ?", (name,)
        ).fetchone()
    return _row_to_profile(row) if row else None


def create_profile(payload: HostProfileCreate) -> HostProfile:
    now = utc_now_iso()
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO host_profiles (
                name, display_name, description, risk_tolerance,
                expected_behaviors_json, allowed_process_patterns_json,
                suspicious_patterns_json, always_critical_event_ids_json,
                notes_json, is_builtin, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
            """,
            (
                payload.name,
                payload.display_name,
                payload.description,
                payload.risk_tolerance,
                json.dumps(payload.expected_behaviors, ensure_ascii=False),
                json.dumps(payload.allowed_process_patterns, ensure_ascii=False),
                json.dumps(payload.suspicious_patterns, ensure_ascii=False),
                json.dumps(payload.always_critical_event_ids, ensure_ascii=False),
                json.dumps(payload.notes, ensure_ascii=False),
                now,
                now,
            ),
        )
        profile_id = cursor.lastrowid
    result = get_profile_by_id(profile_id)
    if result is None:
        raise RuntimeError("Profile creation failed")
    return result


def update_profile(profile_id: int, payload: HostProfileCreate) -> HostProfile | None:
    now = utc_now_iso()
    with get_connection() as conn:
        # Don't allow overwriting built-in flag
        conn.execute(
            """
            UPDATE host_profiles SET
                display_name = ?,
                description = ?,
                risk_tolerance = ?,
                expected_behaviors_json = ?,
                allowed_process_patterns_json = ?,
                suspicious_patterns_json = ?,
                always_critical_event_ids_json = ?,
                notes_json = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                payload.display_name,
                payload.description,
                payload.risk_tolerance,
                json.dumps(payload.expected_behaviors, ensure_ascii=False),
                json.dumps(payload.allowed_process_patterns, ensure_ascii=False),
                json.dumps(payload.suspicious_patterns, ensure_ascii=False),
                json.dumps(payload.always_critical_event_ids, ensure_ascii=False),
                json.dumps(payload.notes, ensure_ascii=False),
                now,
                profile_id,
            ),
        )
    return get_profile_by_id(profile_id)


def delete_profile(profile_id: int) -> bool:
    """Delete a custom profile. Built-in profiles cannot be deleted."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT is_builtin FROM host_profiles WHERE id = ?", (profile_id,)
        ).fetchone()
        if not row or row["is_builtin"]:
            return False
        conn.execute("DELETE FROM host_profiles WHERE id = ?", (profile_id,))
        conn.execute(
            "DELETE FROM host_profile_assignments WHERE profile_id = ?", (profile_id,)
        )
    return True


# ── Assignment CRUD ───────────────────────────────────────────────────────────

def assign_profile_to_host(
    host: str,
    profile_id: int,
    assigned_by: str = "manual",
    notes: str | None = None,
) -> HostProfileAssignment:
    now = utc_now_iso()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO host_profile_assignments
                (host, profile_id, assigned_by, notes, assigned_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(host) DO UPDATE SET
                profile_id = excluded.profile_id,
                assigned_by = excluded.assigned_by,
                notes = excluded.notes,
                updated_at = excluded.updated_at
            """,
            (host, profile_id, assigned_by, notes, now, now),
        )
    return get_host_assignment(host)  # type: ignore[return-value]


def remove_host_assignment(host: str) -> bool:
    with get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM host_profile_assignments WHERE host = ?", (host,)
        )
    return cursor.rowcount > 0


def get_host_assignment(host: str) -> HostProfileAssignment | None:
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT a.host, a.profile_id, a.assigned_by, a.notes,
                   a.assigned_at, a.updated_at,
                   p.name AS profile_name, p.display_name AS profile_display_name
            FROM host_profile_assignments a
            JOIN host_profiles p ON p.id = a.profile_id
            WHERE a.host = ?
            """,
            (host,),
        ).fetchone()
    if not row:
        return None
    return HostProfileAssignment(
        host=row["host"],
        profile_id=row["profile_id"],
        profile_name=row["profile_name"],
        profile_display_name=row["profile_display_name"],
        assigned_by=row["assigned_by"],
        notes=row["notes"],
        assigned_at=row["assigned_at"],
        updated_at=row["updated_at"],
    )


def list_all_assignments() -> list[HostProfileAssignment]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT a.host, a.profile_id, a.assigned_by, a.notes,
                   a.assigned_at, a.updated_at,
                   p.name AS profile_name, p.display_name AS profile_display_name,
                   p.risk_tolerance AS risk_tolerance
            FROM host_profile_assignments a
            JOIN host_profiles p ON p.id = a.profile_id
            ORDER BY a.host
            """
        ).fetchall()
    return [
        HostProfileAssignment(
            host=r["host"],
            profile_id=r["profile_id"],
            profile_name=r["profile_name"],
            profile_display_name=r["profile_display_name"],
            risk_tolerance=r["risk_tolerance"],
            assigned_by=r["assigned_by"],
            notes=r["notes"],
            assigned_at=r["assigned_at"],
            updated_at=r["updated_at"],
        )
        for r in rows
    ]


# ── Profile-aware context for AI ─────────────────────────────────────────────

def get_profile_for_host(host: str) -> HostProfile | None:
    """Return the assigned profile for a host, or None if unassigned."""
    assignment = get_host_assignment(host)
    if not assignment:
        return None
    return get_profile_by_id(assignment.profile_id)


def build_profile_context_block(profile: HostProfile | None) -> str:
    """
    Build a compact text block that can be injected into AI prompts to give
    the model profile-aware context about the host.
    """
    if profile is None:
        return (
            "Host-Profil: Nicht zugewiesen (kein Profil bekannt).\n"
            "Bewerte Events nach allgemeinem SOC-Standard."
        )

    tolerance_labels = {
        "low": "streng – jede Abweichung ist relevant",
        "medium": "mittel – auffällige Muster sind relevant",
        "high": "tolerant – nur klare Angriffsmuster sind relevant",
    }

    expected_on: list[str] = [
        k.replace("_", " ")
        for k, v in profile.expected_behaviors.items()
        if v
    ]
    expected_off: list[str] = [
        k.replace("_", " ")
        for k, v in profile.expected_behaviors.items()
        if not v
    ]

    lines: list[str] = [
        f"Host-Profil: {profile.display_name} ({profile.name})",
        f"Beschreibung: {profile.description}",
        f"Risiko-Toleranz: {tolerance_labels.get(profile.risk_tolerance, profile.risk_tolerance)}",
    ]
    if expected_on:
        lines.append(f"Normal auf diesem Host: {', '.join(expected_on)}")
    if expected_off:
        lines.append(f"Untypisch auf diesem Host: {', '.join(expected_off)}")
    if profile.allowed_process_patterns:
        lines.append(
            f"Erlaubte/erwartete Prozesse: {', '.join(profile.allowed_process_patterns[:12])}"
        )
    if profile.suspicious_patterns:
        lines.append(
            f"Immer auffällig auf diesem Profil: {', '.join(profile.suspicious_patterns[:10])}"
        )
    if profile.always_critical_event_ids:
        lines.append(
            f"Immer kritisch (unabhängig vom Profil): Event-IDs {', '.join(profile.always_critical_event_ids)}"
        )
    if profile.notes:
        lines.append("Hinweise:")
        for note in profile.notes:
            lines.append(f"  - {note}")

    return "\n".join(lines)


def adjust_severity_for_profile(
    base_severity: str,
    event_family: str | None,
    process: str | None,
    event_id: str | None,
    profile: HostProfile | None,
) -> str:
    """
    Adjust a base severity string (critical/high/medium/low/info) by one step
    based on profile risk tolerance and whether the activity is expected.
    Hard events (log clearing, known-bad patterns) are never downgraded.
    """
    if profile is None:
        return base_severity

    severity_order = ["info", "low", "medium", "high", "critical"]
    idx = severity_order.index(base_severity) if base_severity in severity_order else 2

    # Never downgrade always-critical event IDs
    if event_id and event_id in profile.always_critical_event_ids:
        return base_severity

    # Never downgrade known hard patterns
    hard_patterns = {"log_cleared", "credential_dumping", "mimikatz", "lsass_dump"}
    if event_family and event_family in hard_patterns:
        return base_severity

    proc_lower = (process or "").lower()
    is_expected_process = any(
        pat.lower().rstrip("*") in proc_lower
        for pat in profile.allowed_process_patterns
        if pat
    )

    expected_behaviors = profile.expected_behaviors

    # Map event family → expected_behaviors key
    family_to_behavior: dict[str, str] = {
        "process_create": "many_process_creations",
        "process_terminate": "many_process_creations",
        "service_install": "software_changes",
        "scheduled_task": "software_changes",
        "privilege_use": "admin_actions",
        "logon_explicit": "admin_actions",
    }
    behavior_key_from_process: dict[str, str] = {
        "powershell": "powershell_usage",
        "pwsh": "powershell_usage",
        "cmd": "cmd_usage",
        "ssh": "ssh_usage",
    }

    is_expected_behavior = False

    # Check process-based expectations
    for token, bkey in behavior_key_from_process.items():
        if token in proc_lower and expected_behaviors.get(bkey, False):
            is_expected_behavior = True
            break

    # Check event-family-based expectations
    if not is_expected_behavior and event_family:
        bkey = family_to_behavior.get(event_family)
        if bkey and expected_behaviors.get(bkey, False):
            is_expected_behavior = True

    if is_expected_process or is_expected_behavior:
        if profile.risk_tolerance == "high" and idx > 0:
            # Downgrade by one step for tolerant profiles on expected activity
            idx = max(0, idx - 1)
    elif profile.risk_tolerance == "low" and idx < len(severity_order) - 1:
        # Upgrade by one step for strict profiles on unexpected activity
        idx = min(len(severity_order) - 1, idx + 1)

    return severity_order[idx]


# ── Built-in profile seeding ──────────────────────────────────────────────────

_BUILTIN_PROFILES: list[dict] = [
    {
        "name": "sysadmin_workstation",
        "display_name": "SysAdmin Workstation",
        "description": (
            "System-Administrator-Host mit erwartetem hohem Aktivitätsniveau. "
            "PowerShell, Admin-Logins, Dienst-Änderungen, RDP und Remote-Management "
            "sind normal. Nur echte Angriffsmuster und Baseline-Abweichungen zählen."
        ),
        "risk_tolerance": "high",
        "expected_behaviors": {
            "many_process_creations": True,
            "many_logins": True,
            "admin_actions": True,
            "remote_management": True,
            "powershell_usage": True,
            "cmd_usage": True,
            "ssh_usage": True,
            "rdp_usage": True,
            "service_changes": True,
            "script_execution": True,
            "software_changes": True,
            "network_activity": True,
        },
        "allowed_process_patterns": [
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "mmc.exe",
            "mstsc.exe",
            "ssh.exe",
            "code.exe",
            "services.exe",
            "taskmgr.exe",
            "regedit.exe",
            "eventvwr.exe",
            "compmgmt.exe",
            "sc.exe",
            "net.exe",
        ],
        "suspicious_patterns": [
            "powershell -enc",
            "powershell -encodedcommand",
            "IEX(",
            "Invoke-Expression",
            "DownloadString",
            "DownloadFile",
            "New-Object Net.WebClient",
            "rundll32 javascript",
            "mimikatz",
            "sekurlsa",
            "lsass dump",
            "vssadmin delete shadows",
            "schtasks /create",
            "reg add.*\\Run",
            "net user /add",
            "net localgroup administrators",
        ],
        "always_critical_event_ids": ["1102", "517", "4728", "4732", "4756", "4720", "4726"],
        "notes": [
            "Hohes Aktivitätsniveau ist für SysAdmins normal — nicht als Angriff werten.",
            "Score-Deckelung auf LOW für erwartete Events (4624, 4688, 4672, …).",
            "Baseline-Abweichungen bei bekannten Events → max MEDIUM.",
            "Encoding, LSASS-Zugriff, Mimikatz → immer CRITICAL unabhängig vom Profil.",
        ],
    },
    {
        "name": "developer",
        "display_name": "Developer Workstation",
        "description": (
            "Entwickler-Workstation mit erhöhter Prozess- und Build-Aktivität. "
            "Compiler, IDEs, npm/pip, Git und PowerShell sind normal. "
            "Netzwerkverbindungen zu bekannten Dev-Repos sind erwartet."
        ),
        "risk_tolerance": "medium",
        "expected_behaviors": {
            "many_process_creations": True,
            "powershell_usage": True,
            "cmd_usage": True,
            "ssh_usage": True,
            "software_changes": True,
            "network_activity": True,
            "script_execution": True,
        },
        "allowed_process_patterns": [
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "code.exe",
            "node.exe",
            "python.exe",
            "git.exe",
            "npm.cmd",
            "msbuild.exe",
            "devenv.exe",
            "dotnet.exe",
        ],
        "suspicious_patterns": [
            "powershell -enc",
            "IEX(",
            "mimikatz",
            "lsass",
            "vssadmin delete",
        ],
        "always_critical_event_ids": ["1102", "4728", "4732", "4756", "4720"],
        "notes": [
            "Build-Prozesse und IDEs erzeugen viele Process-Create-Events — normal.",
            "SSH/Git zu bekannten Repositories ist erwartet.",
        ],
    },
    {
        "name": "server",
        "display_name": "Application Server",
        "description": (
            "Produktionsserver mit definierten Diensten. "
            "Wenig interaktive Logins erwartet. "
            "Neue Prozesse oder Logins von unbekannten Accounts sind auffällig."
        ),
        "risk_tolerance": "low",
        "expected_behaviors": {
            "network_activity": True,
            "service_changes": False,
            "many_logins": False,
            "admin_actions": False,
            "powershell_usage": False,
            "software_changes": False,
        },
        "allowed_process_patterns": [
            "svchost.exe",
            "services.exe",
            "lsass.exe",
            "spoolsv.exe",
        ],
        "suspicious_patterns": [
            "powershell",
            "cmd.exe",
            "mstsc",
            "IEX(",
            "mimikatz",
            "lsass",
        ],
        "always_critical_event_ids": ["1102", "4720", "4728", "4732", "7045", "4697"],
        "notes": [
            "Interaktive Logins und neue Prozesse sind auf diesem Host ungewöhnlich.",
            "Powershell-Nutzung gilt als verdächtig.",
        ],
    },
]


def seed_builtin_profiles() -> None:
    """Ensure built-in profiles exist in the database.

    Safe to call on every startup — skips profiles that already exist by name.
    """
    now = utc_now_iso()
    with get_connection() as conn:
        for p in _BUILTIN_PROFILES:
            existing = conn.execute(
                "SELECT id FROM host_profiles WHERE name = ?", (p["name"],)
            ).fetchone()
            if existing:
                continue
            conn.execute(
                """
                INSERT INTO host_profiles (
                    name, display_name, description, risk_tolerance,
                    expected_behaviors_json, allowed_process_patterns_json,
                    suspicious_patterns_json, always_critical_event_ids_json,
                    notes_json, is_builtin, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    p["name"],
                    p["display_name"],
                    p["description"],
                    p["risk_tolerance"],
                    json.dumps(p["expected_behaviors"], ensure_ascii=False),
                    json.dumps(p["allowed_process_patterns"], ensure_ascii=False),
                    json.dumps(p["suspicious_patterns"], ensure_ascii=False),
                    json.dumps(p["always_critical_event_ids"], ensure_ascii=False),
                    json.dumps(p["notes"], ensure_ascii=False),
                    now,
                    now,
                ),
            )
