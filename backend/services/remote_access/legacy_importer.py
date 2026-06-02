"""
remote_access/legacy_importer.py
Import SSH/RDP connections from legacy SSH Manager JSON or CSV exports.
Never imports plaintext passwords.
"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

from .connection_store import create_connection, get_connection_by_id, list_connections


_WARNED_FIELDS = {"password", "passwd", "pass", "secret"}


def _sanitize_port(raw: Any, default: int) -> int:
    try:
        return int(raw)
    except Exception:
        return default


def _sanitize_mac(raw: str) -> str:
    """Normalize MAC address to colon-separated uppercase."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(cleaned) == 12:
        return ":".join(cleaned[i:i+2].upper() for i in range(0, 12, 2))
    return raw.upper()


def _import_single(
    name: str,
    entry: dict[str, Any],
    protocol: str,
    warnings: list[str],
    auto_link: bool,
) -> dict[str, Any] | None:
    """Convert one legacy entry to a connection dict. Returns None if should skip."""
    hostname = entry.get("host", "")
    ip = entry.get("ip", hostname if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname) else "")

    # Detect password fields — do NOT import
    for field in _WARNED_FIELDS:
        if field in entry and entry[field]:
            warnings.append(
                f"[{name}] Field '{field}' was found but NOT imported — passwords are excluded. "
                "Set up key-based auth or use a credential manager."
            )

    port_default = 3389 if protocol == "rdp" else 22
    port = _sanitize_port(entry.get("port", port_default), port_default)

    tags = entry.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]

    mac = _sanitize_mac(entry.get("mac", "")) if entry.get("mac") else ""

    conn: dict[str, Any] = {
        "name": name,
        "hostname": hostname if not ip else hostname,
        "ip": ip,
        "protocol": protocol,
        "port": port,
        "username": entry.get("user", entry.get("username", "")),
        "auth_type": "agent",   # default to SSH agent; no passwords imported
        "tags": tags,
        "favorite": bool(entry.get("favorite", False)),
        "mac": mac,
        "notes": entry.get("notes", ""),
        "os": entry.get("os", ""),
        "platform": entry.get("platform", ""),
    }

    # Try to auto-link to unified host by hostname/ip
    if auto_link:
        try:
            from db.database import get_connection as _db_conn
            with _db_conn() as db:
                search_vals = [v for v in [hostname, ip] if v]
                for sv in search_vals:
                    row = db.execute(
                        """SELECT id FROM unified_hosts
                           WHERE uh_display LIKE ? OR uh_fqdn LIKE ? OR primary_ip = ?
                           LIMIT 1""",
                        (f"%{sv}%", f"%{sv}%", sv),
                    ).fetchone()
                    if row:
                        conn["unified_host_id"] = row["id"]
                        break
        except Exception:
            pass

    return conn


def import_from_json(
    raw_json: str,
    auto_link: bool = True,
) -> dict[str, Any]:
    """
    Import from a JSON object in the legacy SSH Manager format:
    {"ssh": {"Name": {host, user, port, tags, favorite}}, "rdp": {...}}
    or a flat list of dicts with protocol field.
    """
    warnings: list[str] = []
    items: list[dict[str, Any]] = []
    skipped = 0
    conflicts = 0

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        return {"total": 0, "imported": 0, "skipped": 0, "conflicts": 0,
                "warnings": [f"JSON parse error: {exc}"], "items": []}

    # Normalize to list of (name, entry, protocol)
    entries: list[tuple[str, dict, str]] = []

    if isinstance(data, dict) and ("ssh" in data or "rdp" in data):
        for name, entry in (data.get("ssh") or {}).items():
            entries.append((name, entry, "ssh"))
        for name, entry in (data.get("rdp") or {}).items():
            entries.append((name, entry, "rdp"))
    elif isinstance(data, list):
        for item in data:
            proto = item.get("protocol", "ssh")
            name = item.get("name", item.get("host", "imported"))
            entries.append((name, item, proto))
    else:
        warnings.append("Unrecognized JSON format. Expected {ssh:{}, rdp:{}} or list.")
        return {"total": 0, "imported": 0, "skipped": 0, "conflicts": 0,
                "warnings": warnings, "items": []}

    for name, entry, protocol in entries:
        conn = _import_single(name, entry, protocol, warnings, auto_link)
        if conn is None:
            skipped += 1
            continue

        # Check for name conflict
        existing = [c for c in list_connections() if c["name"] == name]
        if existing:
            conflicts += 1
            warnings.append(f"[{name}] A connection with this name already exists — skipped.")
            continue

        created = create_connection(conn)
        items.append(created)

    return {
        "total": len(entries),
        "imported": len(items),
        "skipped": skipped,
        "conflicts": conflicts,
        "warnings": warnings,
        "items": items,
    }


def import_from_csv(
    raw_csv: str,
    auto_link: bool = True,
) -> dict[str, Any]:
    """
    Import from CSV with columns:
    name, hostname, ip, protocol, port, username, tags, favorite, mac, os, notes
    """
    warnings: list[str] = []
    items: list[dict[str, Any]] = []
    skipped = 0
    conflicts = 0

    reader = csv.DictReader(io.StringIO(raw_csv))
    rows = list(reader)

    for row in rows:
        name = row.get("name", "").strip()
        if not name:
            skipped += 1
            warnings.append("Row skipped — no name field.")
            continue

        protocol = row.get("protocol", "ssh").strip().lower()
        if protocol not in ("ssh", "rdp", "winrm"):
            protocol = "ssh"

        entry = {
            "host": row.get("hostname", row.get("host", "")).strip(),
            "ip": row.get("ip", "").strip(),
            "user": row.get("username", row.get("user", "")).strip(),
            "port": row.get("port", ""),
            "tags": [t.strip() for t in row.get("tags", "").split(",") if t.strip()],
            "favorite": row.get("favorite", "").strip().lower() in ("1", "true", "yes", "j"),
            "mac": row.get("mac", "").strip(),
            "os": row.get("os", "").strip(),
            "notes": row.get("notes", "").strip(),
        }

        conn = _import_single(name, entry, protocol, warnings, auto_link)
        if conn is None:
            skipped += 1
            continue

        existing = [c for c in list_connections() if c["name"] == name]
        if existing:
            conflicts += 1
            warnings.append(f"[{name}] Conflict — skipped.")
            continue

        created = create_connection(conn)
        items.append(created)

    return {
        "total": len(rows),
        "imported": len(items),
        "skipped": skipped,
        "conflicts": conflicts,
        "warnings": warnings,
        "items": items,
    }
