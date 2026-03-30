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
        ensure_connection_columns(connection)


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
                "https://localhost:9200",
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
