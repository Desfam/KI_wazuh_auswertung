"""
remote_access/connection_store.py
CRUD helpers for server_connections table.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from db.database import get_connection
from .models import ServerConnection


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _row_to_conn(row) -> dict[str, Any]:
    d = dict(row)
    d["tags"] = json.loads(d.get("tags_json") or "[]")
    d.pop("tags_json", None)
    d["favorite"] = bool(d.get("favorite", 0))
    return d


# ── Read ──────────────────────────────────────────────────────────────

def list_connections(
    protocol: Optional[str] = None,
    tag: Optional[str] = None,
    search: Optional[str] = None,
    favorite_only: bool = False,
) -> list[dict[str, Any]]:
    with get_connection() as conn:
        q = "SELECT * FROM server_connections WHERE 1=1"
        params: list[Any] = []
        if protocol:
            q += " AND protocol = ?"
            params.append(protocol)
        if favorite_only:
            q += " AND favorite = 1"
        q += " ORDER BY favorite DESC, name COLLATE NOCASE ASC"
        rows = conn.execute(q, params).fetchall()

    results = [_row_to_conn(r) for r in rows]

    if tag:
        tl = tag.lower()
        results = [r for r in results if tl in [t.lower() for t in r["tags"]]]

    if search:
        sl = search.lower()
        results = [
            r for r in results
            if sl in r["name"].lower()
            or sl in (r.get("hostname") or "").lower()
            or sl in (r.get("ip") or "").lower()
            or any(sl in t.lower() for t in r["tags"])
        ]

    return results


def get_connection_by_id(connection_id: str) -> Optional[dict[str, Any]]:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM server_connections WHERE id = ?", (connection_id,)
        ).fetchone()
    return _row_to_conn(row) if row else None


# ── Write ─────────────────────────────────────────────────────────────

def create_connection(data: dict[str, Any]) -> dict[str, Any]:
    now = _utc()
    conn_id = data.get("id") or str(uuid.uuid4())
    tags_json = json.dumps(data.get("tags") or [])

    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO server_connections (
                id, name, hostname, ip, protocol, port, username,
                auth_type, credential_ref, key_ref,
                os, platform, tags_json, favorite, mac,
                unified_host_id, tactical_agent_id, wazuh_agent_id,
                notes, created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                conn_id,
                data.get("name", ""),
                data.get("hostname", ""),
                data.get("ip", ""),
                data.get("protocol", "ssh"),
                data.get("port", 22),
                data.get("username", ""),
                data.get("auth_type", "none"),
                data.get("credential_ref", ""),
                data.get("key_ref", ""),
                data.get("os", ""),
                data.get("platform", ""),
                tags_json,
                1 if data.get("favorite") else 0,
                data.get("mac", ""),
                data.get("unified_host_id", ""),
                data.get("tactical_agent_id", ""),
                data.get("wazuh_agent_id", ""),
                data.get("notes", ""),
                now, now,
            ),
        )
    return get_connection_by_id(conn_id)  # type: ignore[return-value]


def update_connection(connection_id: str, data: dict[str, Any]) -> Optional[dict[str, Any]]:
    existing = get_connection_by_id(connection_id)
    if not existing:
        return None
    now = _utc()
    merged = {**existing, **data, "updated_at": now}
    tags_json = json.dumps(merged.get("tags") or [])

    with get_connection() as conn:
        conn.execute(
            """
            UPDATE server_connections SET
                name=?, hostname=?, ip=?, protocol=?, port=?, username=?,
                auth_type=?, credential_ref=?, key_ref=?,
                os=?, platform=?, tags_json=?, favorite=?, mac=?,
                unified_host_id=?, tactical_agent_id=?, wazuh_agent_id=?,
                notes=?, updated_at=?
            WHERE id=?
            """,
            (
                merged.get("name", ""),
                merged.get("hostname", ""),
                merged.get("ip", ""),
                merged.get("protocol", "ssh"),
                merged.get("port", 22),
                merged.get("username", ""),
                merged.get("auth_type", "none"),
                merged.get("credential_ref", ""),
                merged.get("key_ref", ""),
                merged.get("os", ""),
                merged.get("platform", ""),
                tags_json,
                1 if merged.get("favorite") else 0,
                merged.get("mac", ""),
                merged.get("unified_host_id", ""),
                merged.get("tactical_agent_id", ""),
                merged.get("wazuh_agent_id", ""),
                merged.get("notes", ""),
                now,
                connection_id,
            ),
        )
    return get_connection_by_id(connection_id)


def delete_connection(connection_id: str) -> bool:
    with get_connection() as conn:
        affected = conn.execute(
            "DELETE FROM server_connections WHERE id=?", (connection_id,)
        ).rowcount
    return affected > 0


# ── Activity log ──────────────────────────────────────────────────────

def log_server_activity(
    action: str,
    connection_id: str = "",
    host: str = "",
    protocol: str = "",
    status: str = "ok",
    message: str = "",
    metadata: Optional[dict[str, Any]] = None,
) -> str:
    import uuid as _uuid
    log_id = str(_uuid.uuid4())
    now = _utc()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO server_activity_log
                (id, timestamp, action, connection_id, host, protocol, status, message, metadata_json)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (
                log_id, now, action, connection_id, host, protocol,
                status, message, json.dumps(metadata or {}),
            ),
        )
    return log_id


def list_activity(limit: int = 100, connection_id: Optional[str] = None) -> list[dict[str, Any]]:
    with get_connection() as conn:
        if connection_id:
            rows = conn.execute(
                "SELECT * FROM server_activity_log WHERE connection_id=? ORDER BY timestamp DESC LIMIT ?",
                (connection_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM server_activity_log ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["metadata"] = json.loads(d.get("metadata_json") or "{}")
        d.pop("metadata_json", None)
        results.append(d)
    return results


def list_sessions(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM remote_sessions ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["audit"] = json.loads(d.get("audit_json") or "{}")
        d.pop("audit_json", None)
        results.append(d)
    return results


def record_session(
    connection_id: str,
    protocol: str,
    host: str,
    status: str = "started",
    audit: Optional[dict[str, Any]] = None,
) -> str:
    import uuid as _uuid
    session_id = str(_uuid.uuid4())
    now = _utc()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO remote_sessions
                (id, connection_id, protocol, host, started_at, status, audit_json)
            VALUES (?,?,?,?,?,?,?)
            """,
            (session_id, connection_id, protocol, host, now, status, json.dumps(audit or {})),
        )
    return session_id
