from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from schemas.types import ConnectionCreate

DB_PATH = Path(__file__).resolve().parent.parent / "app.db"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_db() -> None:
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                indexer_url TEXT NOT NULL,
                indexer_username TEXT NOT NULL,
                indexer_password TEXT NOT NULL,
                indexer_index_pattern TEXT NOT NULL,
                manager_url TEXT,
                manager_username TEXT,
                manager_password TEXT,
                ollama_url TEXT NOT NULL,
                ollama_model TEXT NOT NULL,
                verify_ssl INTEGER NOT NULL DEFAULT 0,
                lookback_hours INTEGER NOT NULL DEFAULT 24,
                vm_enabled INTEGER NOT NULL DEFAULT 0,
                vm_host TEXT,
                vm_port INTEGER NOT NULL DEFAULT 22,
                vm_username TEXT,
                vm_password TEXT,
                vm_script_path TEXT NOT NULL DEFAULT '/home/ai_wazuh_24h_v2.py',
                vm_python_path TEXT NOT NULL DEFAULT 'python3',
                vm_report_txt_path TEXT NOT NULL DEFAULT '/tmp/ai_wazuh_24h_report.txt',
                vm_report_json_path TEXT NOT NULL DEFAULT '/tmp/ai_wazuh_24h_report.json',
                default_analysis_mode TEXT NOT NULL DEFAULT 'local',
                default_query_size INTEGER NOT NULL DEFAULT 1000,
                default_only_windows INTEGER NOT NULL DEFAULT 0,
                default_only_linux INTEGER NOT NULL DEFAULT 0,
                default_include_noise INTEGER NOT NULL DEFAULT 0,
                default_run_ai INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connection_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                lookback_hours INTEGER NOT NULL,
                total_alerts INTEGER NOT NULL DEFAULT 0,
                relevant_alerts INTEGER NOT NULL DEFAULT 0,
                report_markdown TEXT,
                report_json TEXT,
                error_message TEXT,
                FOREIGN KEY(connection_id) REFERENCES connections(id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS finding_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                platform TEXT NOT NULL,
                event_id TEXT,
                rule_id TEXT,
                rule_description TEXT,
                count INTEGER NOT NULL,
                group_key TEXT NOT NULL,
                local_severity TEXT NOT NULL,
                local_score INTEGER NOT NULL,
                confidence INTEGER NOT NULL,
                suspicious INTEGER NOT NULL,
                ai_severity TEXT,
                reason TEXT,
                recommended_checks TEXT,
                first_seen TEXT,
                last_seen TEXT,
                raw_summary_json TEXT NOT NULL,
                FOREIGN KEY(job_id) REFERENCES analysis_jobs(id)
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS fullscan_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fullscan_job_id TEXT NOT NULL,
                host TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'finished',
                risk_score REAL NOT NULL DEFAULT 0.0,
                findings_count INTEGER NOT NULL DEFAULT 0,
                high_findings INTEGER NOT NULL DEFAULT 0,
                ti_matches INTEGER NOT NULL DEFAULT 0,
                summary_json TEXT,
                result_json TEXT,
                markdown_report TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        # ── Tactical RMM integration tables ──────────────────────────────────
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS tactical_agents_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tactical_agent_id TEXT NOT NULL UNIQUE,
                hostname TEXT NOT NULL,
                fqdn TEXT,
                description TEXT,
                client_name TEXT,
                site_name TEXT,
                os_platform TEXT,
                os_full TEXT,
                local_ips TEXT,
                public_ip TEXT,
                last_checkin TEXT,
                status TEXT,
                agent_version TEXT,
                logged_user TEXT,
                mesh_node_id TEXT,
                checks_failing INTEGER NOT NULL DEFAULT 0,
                needs_reboot INTEGER NOT NULL DEFAULT 0,
                raw_json TEXT,
                synced_at TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS unified_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                display_name TEXT NOT NULL,
                hostname_short TEXT,
                fqdn TEXT,
                tactical_agent_id TEXT,
                wazuh_agent_id TEXT,
                mesh_node_id TEXT,
                match_score INTEGER NOT NULL DEFAULT 0,
                match_status TEXT NOT NULL DEFAULT 'unmatched',
                match_source TEXT NOT NULL DEFAULT 'auto',
                identity_status TEXT NOT NULL DEFAULT 'unknown',
                tactical_status TEXT NOT NULL DEFAULT 'unknown',
                wazuh_status TEXT NOT NULL DEFAULT 'unknown',
                mesh_status TEXT NOT NULL DEFAULT 'unknown',
                action_policy TEXT NOT NULL DEFAULT 'read_only',
                primary_ip TEXT,
                os_platform TEXT,
                os_full TEXT,
                last_seen_tactical TEXT,
                last_seen_wazuh TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS host_conflicts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                unified_host_id INTEGER NOT NULL,
                conflict_type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'warning',
                field_name TEXT,
                tactical_value TEXT,
                wazuh_value TEXT,
                description TEXT NOT NULL,
                resolved INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                detected_at TEXT NOT NULL,
                FOREIGN KEY(unified_host_id) REFERENCES unified_hosts(id)
            )
            """
        )
        # ── Script Library ────────────────────────────────────────────────────
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS script_library (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                script_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                description TEXT,
                platform TEXT NOT NULL DEFAULT 'both',
                category TEXT NOT NULL DEFAULT 'triage',
                executor TEXT NOT NULL DEFAULT 'powershell',
                script_body TEXT,
                parameters_json TEXT,
                requires_admin INTEGER NOT NULL DEFAULT 0,
                risk_level TEXT NOT NULL DEFAULT 'low',
                dangerous INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                readonly INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        # ── Audit Log ─────────────────────────────────────────────────────────
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS action_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user TEXT,
                action_type TEXT NOT NULL,
                action_id TEXT,
                source_page TEXT,
                source_event_id TEXT,
                source_rule_id TEXT,
                host TEXT,
                unified_host_id INTEGER,
                wazuh_agent_id TEXT,
                tactical_agent_id TEXT,
                action_policy TEXT,
                policy_reason TEXT,
                status TEXT NOT NULL DEFAULT 'logged',
                details_json TEXT,
                result_json TEXT
            )
            """
        )
        ensure_connection_columns(connection)
        _seed_script_library(connection)
        _ensure_server_tables(connection)


def _ensure_server_tables(connection: sqlite3.Connection) -> None:
    """Create server/remote-access tables if they do not exist."""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS server_connections (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            hostname TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL DEFAULT '',
            protocol TEXT NOT NULL DEFAULT 'ssh',
            port INTEGER NOT NULL DEFAULT 22,
            username TEXT NOT NULL DEFAULT '',
            auth_type TEXT NOT NULL DEFAULT 'none',
            credential_ref TEXT NOT NULL DEFAULT '',
            key_ref TEXT NOT NULL DEFAULT '',
            os TEXT NOT NULL DEFAULT '',
            platform TEXT NOT NULL DEFAULT '',
            tags_json TEXT NOT NULL DEFAULT '[]',
            favorite INTEGER NOT NULL DEFAULT 0,
            mac TEXT NOT NULL DEFAULT '',
            unified_host_id TEXT NOT NULL DEFAULT '',
            tactical_agent_id TEXT NOT NULL DEFAULT '',
            wazuh_agent_id TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT ''
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS server_activity_log (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            connection_id TEXT NOT NULL DEFAULT '',
            host TEXT NOT NULL DEFAULT '',
            protocol TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'ok',
            message TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}'
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS remote_sessions (
            id TEXT PRIMARY KEY,
            connection_id TEXT NOT NULL DEFAULT '',
            protocol TEXT NOT NULL DEFAULT '',
            host TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL DEFAULT '',
            ended_at TEXT,
            status TEXT NOT NULL DEFAULT 'started',
            audit_json TEXT NOT NULL DEFAULT '{}'
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS server_host_groups (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            color TEXT NOT NULL DEFAULT '#6366f1',
            tags_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT ''
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS server_host_group_members (
            id TEXT PRIMARY KEY,
            group_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            added_at TEXT NOT NULL DEFAULT '',
            UNIQUE(group_id, connection_id)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS server_batch_runs (
            id TEXT PRIMARY KEY,
            group_id TEXT,
            action TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'running',
            started_at TEXT NOT NULL DEFAULT '',
            finished_at TEXT,
            summary_json TEXT NOT NULL DEFAULT '{}',
            created_by TEXT NOT NULL DEFAULT ''
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS server_batch_results (
            id TEXT PRIMARY KEY,
            batch_run_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            host TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            duration_ms INTEGER NOT NULL DEFAULT 0,
            result_json TEXT NOT NULL DEFAULT '{}',
            error TEXT
        )
        """
    )


def ensure_connection_columns(connection: sqlite3.Connection) -> None:
    existing_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(connections)").fetchall()
    }
    expected_columns = {
        "vm_enabled": "INTEGER NOT NULL DEFAULT 0",
        "vm_host": "TEXT",
        "vm_port": "INTEGER NOT NULL DEFAULT 22",
        "vm_username": "TEXT",
        "vm_password": "TEXT",
        "vm_script_path": "TEXT NOT NULL DEFAULT '/home/ai_wazuh_24h_v2.py'",
        "vm_python_path": "TEXT NOT NULL DEFAULT 'python3'",
        "vm_report_txt_path": "TEXT NOT NULL DEFAULT '/tmp/ai_wazuh_24h_report.txt'",
        "vm_report_json_path": "TEXT NOT NULL DEFAULT '/tmp/ai_wazuh_24h_report.json'",
        "default_analysis_mode": "TEXT NOT NULL DEFAULT 'local'",
        "default_query_size": "INTEGER NOT NULL DEFAULT 1000",
        "default_only_windows": "INTEGER NOT NULL DEFAULT 0",
        "default_only_linux": "INTEGER NOT NULL DEFAULT 0",
        "default_include_noise": "INTEGER NOT NULL DEFAULT 0",
        "default_run_ai": "INTEGER NOT NULL DEFAULT 1",
    }
    for column_name, ddl in expected_columns.items():
        if column_name not in existing_columns:
            connection.execute(f"ALTER TABLE connections ADD COLUMN {column_name} {ddl}")


def ensure_default_connection() -> None:
    """Ensure a default connection exists in the database."""
    with get_connection() as conn:
        # Check if any active connection exists
        row = conn.execute("SELECT id FROM connections WHERE is_active = 1 LIMIT 1").fetchone()
        if row:
            return  # Already has an active connection

        # Check if a default connection exists
        row = conn.execute("SELECT id FROM connections WHERE name = 'Default Wazuh Connection' LIMIT 1").fetchone()
        if row:
            conn.execute("UPDATE connections SET is_active = 1 WHERE id = ?", (row["id"],))
            return

        # Create default connection
        conn.execute(
            """
            INSERT INTO connections (
                name, indexer_url, indexer_username, indexer_password, indexer_index_pattern,
                manager_url, manager_username, manager_password,
                ollama_url, ollama_model, verify_ssl, lookback_hours,
                vm_enabled, vm_host, vm_port, vm_username, vm_password,
                vm_script_path, vm_python_path, vm_report_txt_path, vm_report_json_path,
                default_analysis_mode, default_query_size, default_only_windows,
                default_only_linux, default_include_noise, default_run_ai,
                created_at, updated_at, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                "Default Wazuh Connection",
                "https://172.21.5.91:9200",
                "admin",
                "",
                "wazuh-alerts-*",
                "https://wazuh.manager:55000",
                "",
                "",
                "http://127.0.0.1:11434",
                "llama3",
                0,
                24,
                1,  # vm_enabled=true
                "172.21.5.91",
                22,
                "",
                "",
                "/home/ai_wazuh_24h_v2.py",
                "python3",
                "/home/ai_wazuh_24h_report.txt",
                "/home/ai_wazuh_24h_report.json",
                "vm-script",
                1000,
                0,
                0,
                0,
                1,
                utc_now_iso(),
                utc_now_iso(),
            ),
        )


def upsert_active_connection(payload: ConnectionCreate) -> int:
    existing = get_active_connection()
    if existing:
        update_connection(int(existing["id"]), payload)
        return int(existing["id"])
    return save_connection(payload)


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return dict(row)


def rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def save_connection(payload: ConnectionCreate) -> int:
    with get_connection() as connection:
        connection.execute("UPDATE connections SET is_active = 0")
        cursor = connection.execute(
            """
            INSERT INTO connections (
                name, indexer_url, indexer_username, indexer_password, indexer_index_pattern,
                manager_url, manager_username, manager_password,
                ollama_url, ollama_model, verify_ssl, lookback_hours,
                vm_enabled, vm_host, vm_port, vm_username, vm_password,
                vm_script_path, vm_python_path, vm_report_txt_path, vm_report_json_path,
                default_analysis_mode, default_query_size, default_only_windows,
                default_only_linux, default_include_noise, default_run_ai,
                created_at, updated_at, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                payload.name,
                payload.indexer_url,
                payload.indexer_username,
                payload.indexer_password,
                payload.indexer_index_pattern,
                payload.manager_url,
                payload.manager_username,
                payload.manager_password,
                payload.ollama_url,
                payload.ollama_model,
                1 if payload.verify_ssl else 0,
                payload.lookback_hours,
                1 if payload.vm_enabled else 0,
                payload.vm_host,
                payload.vm_port,
                payload.vm_username,
                payload.vm_password,
                payload.vm_script_path,
                payload.vm_python_path,
                payload.vm_report_txt_path,
                payload.vm_report_json_path,
                payload.default_analysis_mode,
                payload.default_query_size,
                1 if payload.default_only_windows else 0,
                1 if payload.default_only_linux else 0,
                1 if payload.default_include_noise else 0,
                1 if payload.default_run_ai else 0,
                utc_now_iso(),
                utc_now_iso(),
            ),
        )
        return int(cursor.lastrowid)


def update_connection(connection_id: int, payload: ConnectionCreate) -> bool:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE connections SET
                name = ?,
                indexer_url = ?,
                indexer_username = ?,
                indexer_password = ?,
                indexer_index_pattern = ?,
                manager_url = ?,
                manager_username = ?,
                manager_password = ?,
                ollama_url = ?,
                ollama_model = ?,
                verify_ssl = ?,
                lookback_hours = ?,
                vm_enabled = ?,
                vm_host = ?,
                vm_port = ?,
                vm_username = ?,
                vm_password = ?,
                vm_script_path = ?,
                vm_python_path = ?,
                vm_report_txt_path = ?,
                vm_report_json_path = ?,
                default_analysis_mode = ?,
                default_query_size = ?,
                default_only_windows = ?,
                default_only_linux = ?,
                default_include_noise = ?,
                default_run_ai = ?,
                updated_at = ?,
                is_active = 1
            WHERE id = ?
            """,
            (
                payload.name,
                payload.indexer_url,
                payload.indexer_username,
                payload.indexer_password,
                payload.indexer_index_pattern,
                payload.manager_url,
                payload.manager_username,
                payload.manager_password,
                payload.ollama_url,
                payload.ollama_model,
                1 if payload.verify_ssl else 0,
                payload.lookback_hours,
                1 if payload.vm_enabled else 0,
                payload.vm_host,
                payload.vm_port,
                payload.vm_username,
                payload.vm_password,
                payload.vm_script_path,
                payload.vm_python_path,
                payload.vm_report_txt_path,
                payload.vm_report_json_path,
                payload.default_analysis_mode,
                payload.default_query_size,
                1 if payload.default_only_windows else 0,
                1 if payload.default_only_linux else 0,
                1 if payload.default_include_noise else 0,
                1 if payload.default_run_ai else 0,
                utc_now_iso(),
                connection_id,
            ),
        )
        if cursor.rowcount:
            connection.execute("UPDATE connections SET is_active = 0 WHERE id != ?", (connection_id,))
            return True
        return False


def list_connections() -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute("SELECT * FROM connections ORDER BY updated_at DESC").fetchall()
    return rows_to_dicts(rows)


def get_connection_by_id(connection_id: int) -> dict[str, Any] | None:
    with get_connection() as connection:
        row = connection.execute("SELECT * FROM connections WHERE id = ?", (connection_id,)).fetchone()
    return row_to_dict(row)


def get_active_connection() -> dict[str, Any] | None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM connections WHERE is_active = 1 ORDER BY updated_at DESC LIMIT 1"
        ).fetchone()
    return row_to_dict(row)


def create_analysis_job(connection_id: int, lookback_hours: int) -> int:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO analysis_jobs (connection_id, status, started_at, lookback_hours)
            VALUES (?, 'running', ?, ?)
            """,
            (connection_id, utc_now_iso(), lookback_hours),
        )
        return int(cursor.lastrowid)


def update_analysis_job(
    job_id: int,
    status: str,
    completed_at: str | None = None,
    total_alerts: int | None = None,
    relevant_alerts: int | None = None,
    report_markdown: str | None = None,
    report_json: str | None = None,
    error_message: str | None = None,
) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE analysis_jobs
            SET status = ?,
                completed_at = COALESCE(?, completed_at),
                total_alerts = COALESCE(?, total_alerts),
                relevant_alerts = COALESCE(?, relevant_alerts),
                report_markdown = COALESCE(?, report_markdown),
                report_json = COALESCE(?, report_json),
                error_message = ?
            WHERE id = ?
            """,
            (status, completed_at, total_alerts, relevant_alerts, report_markdown, report_json, error_message, job_id),
        )


def save_finding_groups(job_id: int, findings: list[dict[str, Any]]) -> None:
    with get_connection() as connection:
        connection.execute("DELETE FROM finding_groups WHERE job_id = ?", (job_id,))
        connection.executemany(
            """
            INSERT INTO finding_groups (
                job_id, host, platform, event_id, rule_id, rule_description, count, group_key,
                local_severity, local_score, confidence, suspicious, ai_severity, reason,
                recommended_checks, first_seen, last_seen, raw_summary_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    job_id,
                    finding["host"],
                    finding["platform"],
                    finding.get("event_id"),
                    finding.get("rule_id"),
                    finding.get("rule_description"),
                    finding["count"],
                    finding["group_key"],
                    finding["local_severity"],
                    finding["local_score"],
                    finding["confidence"],
                    1 if finding["suspicious"] else 0,
                    finding.get("ai_severity"),
                    finding.get("reason"),
                    json.dumps(finding.get("recommended_checks", [])),
                    finding.get("first_seen"),
                    finding.get("last_seen"),
                    json.dumps(finding),
                )
                for finding in findings
            ],
        )


def list_analysis_jobs() -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute("SELECT * FROM analysis_jobs ORDER BY id DESC").fetchall()
    return rows_to_dicts(rows)


def get_analysis_job(job_id: int) -> dict[str, Any] | None:
    with get_connection() as connection:
        row = connection.execute("SELECT * FROM analysis_jobs WHERE id = ?", (job_id,)).fetchone()
    return row_to_dict(row)


def get_findings_for_job(job_id: int) -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM finding_groups WHERE job_id = ? ORDER BY local_score DESC, count DESC", (job_id,)
        ).fetchall()
    findings = rows_to_dicts(rows)
    for finding in findings:
        finding["recommended_checks"] = json.loads(finding["recommended_checks"] or "[]")
    return findings


def get_latest_job_id() -> int | None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT id FROM analysis_jobs WHERE status = 'completed' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if not row:
        return None
    return int(row["id"])


def get_ranked_hosts(job_id: int) -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                host,
                COUNT(*) AS findings_count,
                SUM(count) AS alert_count,
                ROUND(AVG(local_score), 1) AS avg_score,
                MAX(local_score) AS top_score,
                GROUP_CONCAT(DISTINCT platform) AS platforms
            FROM finding_groups
            WHERE job_id = ?
            GROUP BY host
            ORDER BY top_score DESC, alert_count DESC
            """,
            (job_id,),
        ).fetchall()
    results = rows_to_dicts(rows)
    for item in results:
        item["platforms"] = (item["platforms"] or "").split(",") if item.get("platforms") else []
    return results


def get_host_findings(job_id: int, host: str) -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM finding_groups
            WHERE job_id = ? AND host = ?
            ORDER BY local_score DESC, count DESC
            """,
            (job_id, host),
        ).fetchall()
    findings = rows_to_dicts(rows)
    for finding in findings:
        finding["recommended_checks"] = json.loads(finding["recommended_checks"] or "[]")
    return findings


def get_host_overview(job_id: int, host: str) -> dict[str, Any] | None:
    findings = get_host_findings(job_id, host)
    if not findings:
        return None

    severity_counts: dict[str, int] = {}
    suspicious_groups = 0
    top_local_score = 0
    top_ai_severity = "low"
    top_findings = sorted(findings, key=lambda item: (int(item.get("local_score") or 0), int(item.get("count") or 0)), reverse=True)[:8]
    total_grouped_events = 0
    ai_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    top_rank = 0

    for item in findings:
        total_grouped_events += int(item.get("count") or 0)
        sev = str(item.get("ai_severity") or item.get("local_severity") or "low").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if int(item.get("suspicious") or 0) == 1:
            suspicious_groups += 1
        local_score = int(item.get("local_score") or 0)
        if local_score > top_local_score:
            top_local_score = local_score
        rank = ai_rank.get(sev, 0)
        if rank > top_rank:
            top_rank = rank
            top_ai_severity = sev

    return {
        "host": host,
        "job_id": job_id,
        "total_grouped_events": total_grouped_events,
        "finding_groups": len(findings),
        "top_local_score": top_local_score,
        "top_ai_severity": top_ai_severity,
        "suspicious_groups": suspicious_groups,
        "severity_counts": severity_counts,
        "top_findings": top_findings,
    }


def get_host_trend(host: str, limit: int = 14) -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                aj.id AS job_id,
                COALESCE(aj.completed_at, aj.started_at) AS completed_at,
                COALESCE(SUM(fg.count), 0) AS total_grouped_events,
                COUNT(fg.id) AS finding_groups,
                COALESCE(SUM(CASE WHEN fg.suspicious = 1 THEN 1 ELSE 0 END), 0) AS suspicious_groups,
                COALESCE(MAX(fg.local_score), 0) AS max_local_score
            FROM analysis_jobs aj
            LEFT JOIN finding_groups fg ON fg.job_id = aj.id AND fg.host = ?
            WHERE aj.status = 'completed'
            GROUP BY aj.id
            HAVING COUNT(fg.id) > 0
            ORDER BY aj.id DESC
            LIMIT ?
            """,
            (host, int(limit)),
        ).fetchall()
    return rows_to_dicts(rows)


def list_reports() -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, id AS job_id, COALESCE(completed_at, started_at) AS created_at,
                   COALESCE(report_markdown, '') AS markdown,
                   COALESCE(report_json, '{}') AS report_json
            FROM analysis_jobs
            WHERE report_markdown IS NOT NULL OR report_json IS NOT NULL
            ORDER BY id DESC
            """
        ).fetchall()
    return rows_to_dicts(rows)


def get_latest_fullscan_report(host: str) -> dict[str, Any] | None:
    """Return the latest fullscan report for a host, or None if no scan exists yet."""
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, fullscan_job_id, host, status, risk_score, findings_count,
                   high_findings, ti_matches,
                   summary_json AS summary, result_json AS result,
                   markdown_report, created_at
            FROM fullscan_reports
            WHERE host = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (host,),
        ).fetchone()
    if row is None:
        return None
    d = dict(row)
    # Deserialize JSON fields
    for field in ("summary", "result"):
        raw = d.get(field)
        if raw and isinstance(raw, str):
            try:
                d[field] = json.loads(raw)
            except Exception:
                pass
    return d


def list_fullscan_reports(host: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    """List fullscan reports, optionally filtered by host."""
    with get_connection() as connection:
        if host:
            rows = connection.execute(
                """
                SELECT id, fullscan_job_id, host, status, risk_score, findings_count,
                       high_findings, ti_matches, created_at, markdown_report
                FROM fullscan_reports
                WHERE host = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (host, limit),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT id, fullscan_job_id, host, status, risk_score, findings_count,
                       high_findings, ti_matches, created_at, markdown_report
                FROM fullscan_reports
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    return rows_to_dicts(rows)


def save_fullscan_report(
    host: str,
    fullscan_job_id: str,
    status: str = "finished",
    risk_score: float = 0.0,
    findings_count: int = 0,
    high_findings: int = 0,
    ti_matches: int = 0,
    summary: dict[str, Any] | None = None,
    result: dict[str, Any] | None = None,
    markdown_report: str = "",
) -> int:
    """Persist a fullscan report and return its row id."""
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO fullscan_reports (
                fullscan_job_id, host, status, risk_score, findings_count,
                high_findings, ti_matches, summary_json, result_json, markdown_report, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fullscan_job_id,
                host,
                status,
                risk_score,
                findings_count,
                high_findings,
                ti_matches,
                json.dumps(summary or {}),
                json.dumps(result or {}),
                markdown_report,
                utc_now_iso(),
            ),
        )
        return cursor.lastrowid or 0


# ── Tactical RMM Cache DB functions ──────────────────────────────────────────

def upsert_tactical_agent(agent: dict[str, Any]) -> None:
    """Insert or update a tactical agent cache row."""
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO tactical_agents_cache (
                tactical_agent_id, hostname, fqdn, description,
                client_name, site_name, os_platform, os_full,
                local_ips, public_ip, last_checkin, status,
                agent_version, logged_user, mesh_node_id,
                checks_failing, needs_reboot, raw_json, synced_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(tactical_agent_id) DO UPDATE SET
                hostname=excluded.hostname,
                fqdn=excluded.fqdn,
                description=excluded.description,
                client_name=excluded.client_name,
                site_name=excluded.site_name,
                os_platform=excluded.os_platform,
                os_full=excluded.os_full,
                local_ips=excluded.local_ips,
                public_ip=excluded.public_ip,
                last_checkin=excluded.last_checkin,
                status=excluded.status,
                agent_version=excluded.agent_version,
                logged_user=excluded.logged_user,
                mesh_node_id=excluded.mesh_node_id,
                checks_failing=excluded.checks_failing,
                needs_reboot=excluded.needs_reboot,
                raw_json=excluded.raw_json,
                synced_at=excluded.synced_at
            """,
            (
                agent.get("tactical_agent_id", ""),
                agent.get("hostname", ""),
                agent.get("fqdn"),
                agent.get("description"),
                agent.get("client_name"),
                agent.get("site_name"),
                agent.get("os_platform"),
                agent.get("os_full"),
                agent.get("local_ips"),
                agent.get("public_ip"),
                agent.get("last_checkin"),
                agent.get("status"),
                agent.get("agent_version"),
                agent.get("logged_user"),
                agent.get("mesh_node_id"),
                int(agent.get("checks_failing", 0)),
                int(agent.get("needs_reboot", 0)),
                agent.get("raw_json"),
                utc_now_iso(),
            ),
        )


def list_tactical_agents() -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM tactical_agents_cache ORDER BY hostname"
        ).fetchall()
    return rows_to_dicts(rows)


def get_tactical_agent(tactical_agent_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM tactical_agents_cache WHERE tactical_agent_id = ?",
            (tactical_agent_id,),
        ).fetchone()
    return row_to_dict(row)


def clear_tactical_agents() -> int:
    with get_connection() as conn:
        cursor = conn.execute("DELETE FROM tactical_agents_cache")
        return cursor.rowcount or 0


# ── UnifiedHost DB functions ──────────────────────────────────────────────────

def upsert_unified_host(host: dict[str, Any]) -> int:
    """Insert or update a unified host row. Returns the row id."""
    with get_connection() as conn:
        existing = conn.execute(
            """
            SELECT id FROM unified_hosts
            WHERE (tactical_agent_id IS NOT NULL AND tactical_agent_id = ?)
               OR (wazuh_agent_id    IS NOT NULL AND wazuh_agent_id    = ?)
               OR (hostname_short    IS NOT NULL AND hostname_short     = ?)
            LIMIT 1
            """,
            (
                host.get("tactical_agent_id"),
                host.get("wazuh_agent_id"),
                host.get("hostname_short"),
            ),
        ).fetchone()

        now = utc_now_iso()
        if existing:
            host_id = existing["id"]
            conn.execute(
                """
                UPDATE unified_hosts SET
                    display_name=?, hostname_short=?, fqdn=?,
                    tactical_agent_id=?, wazuh_agent_id=?, mesh_node_id=?,
                    match_score=?, match_status=?, match_source=?,
                    identity_status=?, tactical_status=?, wazuh_status=?,
                    mesh_status=?, action_policy=?, primary_ip=?,
                    os_platform=?, os_full=?,
                    last_seen_tactical=?, last_seen_wazuh=?,
                    notes=?, updated_at=?
                WHERE id=?
                """,
                (
                    host.get("display_name", ""),
                    host.get("hostname_short"),
                    host.get("fqdn"),
                    host.get("tactical_agent_id"),
                    host.get("wazuh_agent_id"),
                    host.get("mesh_node_id"),
                    host.get("match_score", 0),
                    host.get("match_status", "unmatched"),
                    host.get("match_source", "auto"),
                    host.get("identity_status", "unknown"),
                    host.get("tactical_status", "unknown"),
                    host.get("wazuh_status", "unknown"),
                    host.get("mesh_status", "unknown"),
                    host.get("action_policy", "read_only"),
                    host.get("primary_ip"),
                    host.get("os_platform"),
                    host.get("os_full"),
                    host.get("last_seen_tactical"),
                    host.get("last_seen_wazuh"),
                    host.get("notes"),
                    now,
                    host_id,
                ),
            )
        else:
            cursor = conn.execute(
                """
                INSERT INTO unified_hosts (
                    display_name, hostname_short, fqdn,
                    tactical_agent_id, wazuh_agent_id, mesh_node_id,
                    match_score, match_status, match_source,
                    identity_status, tactical_status, wazuh_status,
                    mesh_status, action_policy, primary_ip,
                    os_platform, os_full,
                    last_seen_tactical, last_seen_wazuh,
                    notes, created_at, updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    host.get("display_name", ""),
                    host.get("hostname_short"),
                    host.get("fqdn"),
                    host.get("tactical_agent_id"),
                    host.get("wazuh_agent_id"),
                    host.get("mesh_node_id"),
                    host.get("match_score", 0),
                    host.get("match_status", "unmatched"),
                    host.get("match_source", "auto"),
                    host.get("identity_status", "unknown"),
                    host.get("tactical_status", "unknown"),
                    host.get("wazuh_status", "unknown"),
                    host.get("mesh_status", "unknown"),
                    host.get("action_policy", "read_only"),
                    host.get("primary_ip"),
                    host.get("os_platform"),
                    host.get("os_full"),
                    host.get("last_seen_tactical"),
                    host.get("last_seen_wazuh"),
                    host.get("notes"),
                    now,
                    now,
                ),
            )
            host_id = cursor.lastrowid or 0
    return host_id


def list_unified_hosts() -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM unified_hosts ORDER BY display_name"
        ).fetchall()
    return rows_to_dicts(rows)


def get_unified_host(host_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM unified_hosts WHERE id = ?", (host_id,)
        ).fetchone()
    return row_to_dict(row)


# ── HostConflict DB functions ─────────────────────────────────────────────────

def add_host_conflict(conflict: dict[str, Any]) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO host_conflicts (
                unified_host_id, conflict_type, severity, field_name,
                tactical_value, wazuh_value, description,
                resolved, is_active, detected_at
            ) VALUES (?,?,?,?,?,?,?,0,1,?)
            """,
            (
                conflict["unified_host_id"],
                conflict["conflict_type"],
                conflict.get("severity", "warning"),
                conflict.get("field_name"),
                conflict.get("tactical_value"),
                conflict.get("wazuh_value"),
                conflict.get("description", ""),
                utc_now_iso(),
            ),
        )
        return cursor.lastrowid or 0


def clear_host_conflicts(unified_host_id: int) -> None:
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM host_conflicts WHERE unified_host_id = ?",
            (unified_host_id,),
        )


def list_host_conflicts(unified_host_id: int) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM host_conflicts WHERE unified_host_id = ? AND is_active = 1 ORDER BY detected_at DESC",
            (unified_host_id,),
        ).fetchall()
    return rows_to_dicts(rows)


# ── Script Library DB functions ───────────────────────────────────────────────

def list_scripts(
    platform: str | None = None,
    category: str | None = None,
    dangerous: bool | None = None,
    enabled: bool | None = None,
    search: str | None = None,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if platform:
        clauses.append("(platform = ? OR platform = 'both')")
        params.append(platform)
    if category:
        clauses.append("category = ?")
        params.append(category)
    if dangerous is not None:
        clauses.append("dangerous = ?")
        params.append(1 if dangerous else 0)
    if enabled is not None:
        clauses.append("enabled = ?")
        params.append(1 if enabled else 0)
    if search:
        clauses.append("(name LIKE ? OR description LIKE ? OR script_id LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT * FROM script_library {where} ORDER BY category, name", params
        ).fetchall()
    return rows_to_dicts(rows)


def get_script(script_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM script_library WHERE script_id = ?", (script_id,)
        ).fetchone()
    return row_to_dict(row)


def create_script(payload: dict[str, Any]) -> str:
    now = utc_now_iso()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO script_library (
                script_id, name, description, platform, category, executor,
                script_body, parameters_json, requires_admin, risk_level,
                dangerous, enabled, readonly, created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                payload["script_id"],
                payload["name"],
                payload.get("description"),
                payload.get("platform", "both"),
                payload.get("category", "triage"),
                payload.get("executor", "powershell"),
                payload.get("script_body"),
                json.dumps(payload["parameters_json"]) if payload.get("parameters_json") else None,
                1 if payload.get("requires_admin") else 0,
                payload.get("risk_level", "low"),
                1 if payload.get("dangerous") else 0,
                1 if payload.get("enabled", True) else 0,
                1 if payload.get("readonly", True) else 0,
                now,
                now,
            ),
        )
    return payload["script_id"]


def update_script(script_id: str, payload: dict[str, Any]) -> None:
    now = utc_now_iso()
    allowed = {
        "name", "description", "platform", "category", "executor",
        "script_body", "parameters_json", "requires_admin", "risk_level",
        "dangerous", "enabled", "readonly",
    }
    updates = {k: v for k, v in payload.items() if k in allowed}
    if not updates:
        return
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [now, script_id]
    with get_connection() as conn:
        conn.execute(
            f"UPDATE script_library SET {set_clause}, updated_at = ? WHERE script_id = ?",
            values,
        )


def delete_script(script_id: str) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM script_library WHERE script_id = ?", (script_id,))


# ── Audit Log DB functions ────────────────────────────────────────────────────

def create_audit_entry(payload: dict[str, Any]) -> int:
    now = utc_now_iso()
    details = payload.get("details_json")
    if details and not isinstance(details, str):
        details = json.dumps(details)
    result = payload.get("result_json")
    if result and not isinstance(result, str):
        result = json.dumps(result)
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO action_audit_log (
                timestamp, user, action_type, action_id, source_page,
                source_event_id, source_rule_id, host, unified_host_id,
                wazuh_agent_id, tactical_agent_id, action_policy, policy_reason,
                status, details_json, result_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                now,
                payload.get("user"),
                payload.get("action_type", "unknown"),
                payload.get("action_id"),
                payload.get("source_page"),
                payload.get("source_event_id"),
                payload.get("source_rule_id"),
                payload.get("host"),
                payload.get("unified_host_id"),
                payload.get("wazuh_agent_id"),
                payload.get("tactical_agent_id"),
                payload.get("action_policy"),
                payload.get("policy_reason"),
                payload.get("status", "logged"),
                details,
                result,
            ),
        )
        return cursor.lastrowid or 0


def list_audit_entries(
    action_type: str | None = None,
    host: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if action_type:
        clauses.append("action_type = ?")
        params.append(action_type)
    if host:
        clauses.append("host = ?")
        params.append(host)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT * FROM action_audit_log {where} ORDER BY timestamp DESC LIMIT ?",
            params,
        ).fetchall()
    return rows_to_dicts(rows)


# ── Script Library seed ───────────────────────────────────────────────────────

_SEED_SCRIPTS: list[dict[str, Any]] = [
    # Windows read-only triage scripts
    {"script_id": "collect_windows_event_context", "name": "Collect Windows Event Context",
     "description": "Collect recent Windows Security events around the alert timestamp.", "platform": "windows",
     "category": "triage", "executor": "powershell", "risk_level": "low"},
    {"script_id": "collect_windows_processes", "name": "Collect Windows Processes",
     "description": "List all running processes with parent PID, user and command line.", "platform": "windows",
     "category": "triage", "executor": "powershell", "risk_level": "low"},
    {"script_id": "collect_windows_services", "name": "Collect Windows Services",
     "description": "List all installed and running Windows services with binary paths.", "platform": "windows",
     "category": "triage", "executor": "powershell", "risk_level": "low"},
    {"script_id": "collect_windows_scheduled_tasks", "name": "Collect Windows Scheduled Tasks",
     "description": "List all scheduled tasks with executable paths and triggers.", "platform": "windows",
     "category": "persistence", "executor": "powershell", "risk_level": "low"},
    {"script_id": "collect_windows_local_admins", "name": "Collect Windows Local Admins",
     "description": "List members of the local Administrators group.", "platform": "windows",
     "category": "users", "executor": "powershell", "risk_level": "low"},
    {"script_id": "collect_windows_defender_status", "name": "Collect Windows Defender Status",
     "description": "Check Windows Defender real-time protection and signature status.", "platform": "windows",
     "category": "triage", "executor": "powershell", "risk_level": "low"},
    {"script_id": "collect_windows_network_connections", "name": "Collect Windows Network Connections",
     "description": "List all active TCP/UDP connections with process names.", "platform": "windows",
     "category": "network", "executor": "powershell", "risk_level": "low"},
    {"script_id": "collect_windows_firewall_rules", "name": "Collect Windows Firewall Rules",
     "description": "List all enabled Windows Firewall rules (inbound and outbound).", "platform": "windows",
     "category": "firewall", "executor": "powershell", "risk_level": "low"},
    # Linux read-only triage scripts
    {"script_id": "collect_linux_auth_context", "name": "Collect Linux Auth Context",
     "description": "Show recent auth.log / secure entries around the alert timestamp.", "platform": "linux",
     "category": "triage", "executor": "bash", "risk_level": "low"},
    {"script_id": "collect_linux_recent_logins", "name": "Collect Linux Recent Logins",
     "description": "Show recent logins via last, lastb and who.", "platform": "linux",
     "category": "users", "executor": "bash", "risk_level": "low"},
    {"script_id": "collect_linux_sudo_activity", "name": "Collect Linux Sudo Activity",
     "description": "Show recent sudo commands from auth.log.", "platform": "linux",
     "category": "users", "executor": "bash", "risk_level": "low"},
    {"script_id": "collect_linux_processes", "name": "Collect Linux Processes",
     "description": "List all running processes with user, PID, parent and command.", "platform": "linux",
     "category": "triage", "executor": "bash", "risk_level": "low"},
    {"script_id": "collect_linux_services", "name": "Collect Linux Services",
     "description": "List all systemd services and their state.", "platform": "linux",
     "category": "triage", "executor": "bash", "risk_level": "low"},
    {"script_id": "collect_linux_cron_jobs", "name": "Collect Linux Cron Jobs",
     "description": "List all user and system crontabs.", "platform": "linux",
     "category": "persistence", "executor": "bash", "risk_level": "low"},
    {"script_id": "collect_linux_systemd_units", "name": "Collect Linux Systemd Units",
     "description": "List all enabled systemd units including timers.", "platform": "linux",
     "category": "persistence", "executor": "bash", "risk_level": "low"},
    {"script_id": "collect_linux_listening_ports", "name": "Collect Linux Listening Ports",
     "description": "List all listening TCP/UDP ports with process names.", "platform": "linux",
     "category": "network", "executor": "bash", "risk_level": "low"},
    {"script_id": "collect_linux_package_history", "name": "Collect Linux Package History",
     "description": "Show recent package install/remove history (dpkg/rpm).", "platform": "linux",
     "category": "triage", "executor": "bash", "risk_level": "low"},
    {"script_id": "collect_linux_sensitive_files", "name": "Collect Linux Sensitive File Hashes",
     "description": "Hash key sensitive files (/etc/passwd, /etc/shadow, sudoers, SSH keys).", "platform": "linux",
     "category": "fim", "executor": "bash", "risk_level": "low"},
    {"script_id": "collect_linux_firewall_status", "name": "Collect Linux Firewall Status",
     "description": "Show UFW / iptables / nftables active rules.", "platform": "linux",
     "category": "firewall", "executor": "bash", "risk_level": "low"},
    # Network / cross-platform
    {"script_id": "check_dns_resolution", "name": "Check DNS Resolution",
     "description": "Resolve a hostname and check against known-bad lists (read-only).", "platform": "network",
     "category": "network", "executor": "python", "risk_level": "low"},
    {"script_id": "check_ip_reputation_placeholder", "name": "Check IP Reputation (Placeholder)",
     "description": "Placeholder: query IP reputation feeds for a given IP.", "platform": "network",
     "category": "network", "executor": "python", "risk_level": "low"},
    {"script_id": "check_open_ports_readonly", "name": "Check Open Ports (Read-only)",
     "description": "Passive TCP port scan against a known baseline (read-only).", "platform": "network",
     "category": "network", "executor": "python", "risk_level": "low"},
    {"script_id": "check_tls_certificate", "name": "Check TLS Certificate",
     "description": "Retrieve and display TLS certificate chain for a given host:port.", "platform": "network",
     "category": "network", "executor": "python", "risk_level": "low"},
]


def _seed_script_library(conn: sqlite3.Connection) -> None:
    """Insert seed scripts if the table is empty."""
    count = conn.execute("SELECT COUNT(*) FROM script_library").fetchone()[0]
    if count > 0:
        return
    now = utc_now_iso()
    for s in _SEED_SCRIPTS:
        conn.execute(
            """
            INSERT OR IGNORE INTO script_library (
                script_id, name, description, platform, category, executor,
                script_body, parameters_json, requires_admin, risk_level,
                dangerous, enabled, readonly, created_at, updated_at
            ) VALUES (?,?,?,?,?,?,NULL,NULL,0,?,0,1,1,?,?)
            """,
            (
                s["script_id"], s["name"], s.get("description"),
                s.get("platform", "both"), s.get("category", "triage"),
                s.get("executor", "powershell"), s.get("risk_level", "low"),
                now, now,
            ),
        )


# ── Runner scripts (always ensure, regardless of seed count) ──────────────────

_RUNNER_SCRIPT_BODY = '''\
"""
Fetch Wazuh Events — Local Runner Script
=========================================
This script runs on the SOC backend server.
It queries the active Wazuh Indexer connection and saves
the results to <project_root>/Example JSON/.

Parameters:
  hours       — lookback window (default 72)
  limit       — max events to fetch (default 1000, max 5000)
  host_filter — optional agent hostname filter (wildcard)

Execution is handled by the backend runner endpoint:
  POST /runner/fetch-wazuh-events
"""
# This is a metadata-only entry. Execution is handled server-side.
# Body shown for documentation purposes only.
pass
'''

_RUNNER_SCRIPT_PARAMS = json.dumps([
    {"name": "hours",       "type": "integer", "default": 72,   "min": 1,  "max": 8760,
     "description": "Lookback window in hours"},
    {"name": "limit",       "type": "integer", "default": 1000, "min": 1,  "max": 100000,
     "description": "Maximum number of events to fetch"},
    {"name": "host_filter", "type": "string",  "default": None,
     "description": "Optional: filter by agent hostname (wildcard, leave blank for all)"},
])


def ensure_runner_scripts() -> None:
    """Insert or update the local runner scripts into the script library.

    Called at server startup (regardless of total script count).
    Uses INSERT OR IGNORE so it is idempotent on subsequent restarts.
    """
    now = utc_now_iso()

    # ── per-all-hosts script ───────────────────────────────────────────────────
    _per_host_body = '''\
"""
Fetch Events per Host — Local Runner Script
============================================
Discovers every Wazuh agent active in the chosen time window and
fetches up to limit_per_host events for each one, saving a separate
JSON file per agent named:
  <hostname>_events_<timestamp>.json

Parameters:
  hours          — lookback window (default 72)
  limit_per_host — max events per host (default 1000, max 100 000)

Execution is handled by the backend runner endpoint:
  POST /runner/fetch-events-per-host
"""
pass
'''

    _per_host_params = json.dumps([
        {"name": "hours",          "type": "integer", "default": 72,   "min": 1, "max": 8760,
         "description": "Lookback window in hours"},
        {"name": "limit_per_host", "type": "integer", "default": 1000, "min": 1, "max": 100000,
         "description": "Maximum events to fetch per host"},
    ])

    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO script_library (
                script_id, name, description, platform, category, executor,
                script_body, parameters_json,
                requires_admin, risk_level, dangerous, enabled, readonly,
                created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,0,'low',0,1,1,?,?)
            """,
            (
                "fetch_wazuh_events",
                "Fetch Wazuh Events",
                (
                    "Pull raw alert events from the active Wazuh Indexer connection "
                    "and save them as a JSON file in the Example JSON folder. "
                    "Choose lookback window, event limit and optional host filter."
                ),
                "both",
                "data_collection",
                "local_runner",
                _RUNNER_SCRIPT_BODY,
                _RUNNER_SCRIPT_PARAMS,
                now, now,
            ),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO script_library (
                script_id, name, description, platform, category, executor,
                script_body, parameters_json,
                requires_admin, risk_level, dangerous, enabled, readonly,
                created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,0,'low',0,1,1,?,?)
            """,
            (
                "fetch_events_per_host",
                "Fetch Events per Host",
                (
                    "Automatically discovers every active Wazuh agent and fetches "
                    "events for each one separately. Each host gets its own JSON file "
                    "named after the PC (e.g. KS-01_events_20260526.json). "
                    "Configure lookback window and per-host event limit."
                ),
                "both",
                "data_collection",
                "local_runner",
                _per_host_body,
                _per_host_params,
                now, now,
            ),
        )

