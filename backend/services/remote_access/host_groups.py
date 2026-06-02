"""
remote_access/host_groups.py
Host Groups Manager — Phase 1 read-only safe.

Groups allow users to organise server connections into named sets
(e.g. "Proxmox", "Windows Clients", "Kritische Systeme") and later run
batch health checks, ping monitors, and reports across the set.
"""
from __future__ import annotations

import json
import uuid
from typing import Any

from db.database import get_connection, utc_now_iso


# ── Helpers ────────────────────────────────────────────────────────────

def _row_to_group(row: Any) -> dict[str, Any]:
    d = dict(row)
    d["tags"] = json.loads(d.pop("tags_json", "[]") or "[]")
    return d


def _row_to_member(row: Any) -> dict[str, Any]:
    return dict(row)


# ── Groups CRUD ────────────────────────────────────────────────────────

def create_group(
    name: str,
    description: str = "",
    color: str = "#6366f1",
    tags: list[str] | None = None,
) -> dict[str, Any]:
    now = utc_now_iso()
    gid = str(uuid.uuid4())
    with get_connection() as db:
        db.execute(
            """
            INSERT INTO server_host_groups (id, name, description, color, tags_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (gid, name.strip(), description.strip(), color, json.dumps(tags or []), now, now),
        )
        row = db.execute("SELECT * FROM server_host_groups WHERE id=?", (gid,)).fetchone()
    return _row_to_group(row)


def list_groups() -> list[dict[str, Any]]:
    with get_connection() as db:
        rows = db.execute(
            """
            SELECT g.*,
                   (SELECT COUNT(*) FROM server_host_group_members m WHERE m.group_id = g.id) AS member_count
            FROM server_host_groups g
            ORDER BY g.name ASC
            """
        ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d["tags"] = json.loads(d.pop("tags_json", "[]") or "[]")
        result.append(d)
    return result


def get_group(group_id: str) -> dict[str, Any] | None:
    with get_connection() as db:
        row = db.execute(
            """
            SELECT g.*,
                   (SELECT COUNT(*) FROM server_host_group_members m WHERE m.group_id = g.id) AS member_count
            FROM server_host_groups g WHERE g.id=?
            """,
            (group_id,),
        ).fetchone()
    return _row_to_group(row) if row else None


def update_group(
    group_id: str,
    name: str | None = None,
    description: str | None = None,
    color: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any] | None:
    existing = get_group(group_id)
    if not existing:
        return None
    now = utc_now_iso()
    new_name  = name.strip()        if name        is not None else existing["name"]
    new_desc  = description.strip() if description is not None else existing["description"]
    new_color = color               if color       is not None else existing["color"]
    new_tags  = tags                if tags        is not None else existing["tags"]
    with get_connection() as db:
        db.execute(
            """
            UPDATE server_host_groups
            SET name=?, description=?, color=?, tags_json=?, updated_at=?
            WHERE id=?
            """,
            (new_name, new_desc, new_color, json.dumps(new_tags), now, group_id),
        )
    return get_group(group_id)


def delete_group(group_id: str) -> bool:
    with get_connection() as db:
        row = db.execute("SELECT id FROM server_host_groups WHERE id=?", (group_id,)).fetchone()
        if not row:
            return False
        db.execute("DELETE FROM server_host_group_members WHERE group_id=?", (group_id,))
        db.execute("DELETE FROM server_host_groups WHERE id=?", (group_id,))
    return True


# ── Members ────────────────────────────────────────────────────────────

def add_member(group_id: str, connection_id: str) -> dict[str, Any]:
    mid = str(uuid.uuid4())
    now = utc_now_iso()
    with get_connection() as db:
        # INSERT OR IGNORE to respect UNIQUE constraint
        db.execute(
            """
            INSERT OR IGNORE INTO server_host_group_members (id, group_id, connection_id, added_at)
            VALUES (?, ?, ?, ?)
            """,
            (mid, group_id, connection_id, now),
        )
        row = db.execute(
            "SELECT * FROM server_host_group_members WHERE group_id=? AND connection_id=?",
            (group_id, connection_id),
        ).fetchone()
    return _row_to_member(row)


def remove_member(group_id: str, connection_id: str) -> bool:
    with get_connection() as db:
        cur = db.execute(
            "DELETE FROM server_host_group_members WHERE group_id=? AND connection_id=?",
            (group_id, connection_id),
        )
    return cur.rowcount > 0


def list_group_members(group_id: str) -> list[dict[str, Any]]:
    """Return members enriched with connection details."""
    with get_connection() as db:
        rows = db.execute(
            """
            SELECT m.id, m.group_id, m.connection_id, m.added_at,
                   c.name, c.hostname, c.ip, c.protocol, c.port,
                   c.username, c.os, c.platform, c.tags_json, c.favorite,
                   c.unified_host_id, c.wazuh_agent_id
            FROM server_host_group_members m
            LEFT JOIN server_connections c ON c.id = m.connection_id
            WHERE m.group_id = ?
            ORDER BY c.name ASC
            """,
            (group_id,),
        ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        tags_raw = d.pop("tags_json", "[]") or "[]"
        d["tags"] = json.loads(tags_raw)
        result.append(d)
    return result


def get_group_connection_ids(group_id: str) -> list[str]:
    with get_connection() as db:
        rows = db.execute(
            "SELECT connection_id FROM server_host_group_members WHERE group_id=?",
            (group_id,),
        ).fetchall()
    return [r["connection_id"] for r in rows]
