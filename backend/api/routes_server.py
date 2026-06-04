"""
backend/api/routes_server.py
Server / Remote-Access API routes.
All actions enforce remote_policy before executing.
"""
from __future__ import annotations

import os
import posixpath
import subprocess
import uuid
from typing import Any, Optional

from fastapi import APIRouter, File, Form, HTTPException, Query, Response, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from services.remote_access.connection_store import (
    create_connection,
    delete_connection,
    get_connection_by_id,
    list_activity,
    list_connections,
    list_sessions,
    log_server_activity,
    record_session,
    update_connection,
)
from services.app_config import (
    load_remote_access_mode_from_config,
    save_remote_access_mode_to_config,
)
from services.remote_access.host_tools_service import (
    arp_lookup,
    dns_lookup,
    ping_host,
    port_check,
    reverse_dns,
    traceroute,
    wake_on_lan,
)
from services.remote_access.legacy_importer import import_from_csv, import_from_json
from services.remote_access.rdp_service import generate_rdp_file_content, open_rdp
from services.remote_access.remote_policy import check_policy
from services.remote_access.ssh_service import (
    deploy_public_key,
    delete_file,
    download_file,
    generate_ssh_config_entry,
    get_host_info,
    health_check,
    launch_native_ssh_shell,
    list_remote_directory,
    run_arbitrary_command,
    upload_file,
    run_readonly_command,
    test_ssh_connection,
)

router = APIRouter(prefix="/server", tags=["server"])


# ── Helper ────────────────────────────────────────────────────────────

def _get_conn_or_404(connection_id: str) -> dict[str, Any]:
    conn = get_connection_by_id(connection_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    return conn


def _get_unified_host(unified_host_id: str) -> Optional[dict[str, Any]]:
    if not unified_host_id:
        return None
    try:
        from db.database import get_connection as _db
        with _db() as db:
            row = db.execute(
                "SELECT * FROM unified_hosts WHERE id=?", (unified_host_id,)
            ).fetchone()
        return dict(row) if row else None
    except Exception:
        return None


def _action_result(res, audit_id: str = "") -> dict[str, Any]:
    d = res.to_dict() if hasattr(res, "to_dict") else dict(res)
    if audit_id:
        d["audit_id"] = audit_id
    return d


def _target_for_confirmation(conn: dict[str, Any]) -> str:
    return str(conn.get("hostname") or conn.get("ip") or "").strip()


def _validate_high_risk_confirmation(conn: dict[str, Any], reason: str, confirm_target: str) -> tuple[str, str]:
    reason_clean = str(reason or "").strip()
    if not reason_clean:
        raise HTTPException(status_code=400, detail="reason is required")

    expected_target = _target_for_confirmation(conn)
    if not expected_target:
        raise HTTPException(status_code=400, detail="connection must have host or ip")

    if str(confirm_target or "").strip() != expected_target:
        raise HTTPException(
            status_code=400,
            detail=f"confirm_target mismatch (expected '{expected_target}')",
        )
    return reason_clean, expected_target


# ── Pydantic models ───────────────────────────────────────────────────

class ConnectionCreate(BaseModel):
    name: str
    hostname: str = ""
    ip: str = ""
    protocol: str = "ssh"
    port: int = 22
    username: str = ""
    auth_type: str = "none"
    credential_ref: str = ""
    key_ref: str = ""
    os: str = ""
    platform: str = ""
    tags: list[str] = []
    favorite: bool = False
    mac: str = ""
    unified_host_id: str = ""
    tactical_agent_id: str = ""
    wazuh_agent_id: str = ""
    notes: str = ""


class ConnectionUpdate(BaseModel):
    name: Optional[str] = None
    hostname: Optional[str] = None
    ip: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    auth_type: Optional[str] = None
    credential_ref: Optional[str] = None
    key_ref: Optional[str] = None
    os: Optional[str] = None
    platform: Optional[str] = None
    tags: Optional[list[str]] = None
    favorite: Optional[bool] = None
    mac: Optional[str] = None
    unified_host_id: Optional[str] = None
    tactical_agent_id: Optional[str] = None
    wazuh_agent_id: Optional[str] = None
    notes: Optional[str] = None


class LegacyImportRequest(BaseModel):
    format: str = "json"   # json | csv
    data: str              # raw JSON or CSV string
    auto_link: bool = True


class PortCheckRequest(BaseModel):
    ports: list[int] = [22, 80, 443, 3389, 5985]


class ReadOnlyCommandRequest(BaseModel):
    command_id: str


class ArbitraryCommandRequest(BaseModel):
    command: str
    reason: str
    timeout: int = 30
    confirm_target: str
    approve_review: bool = False


class PublicKeyDeployRequest(BaseModel):
    public_key: str
    reason: str
    confirm_target: str
    approve_review: bool = False


class PortForwardRequest(BaseModel):
    local_port: int
    remote_host: str = "localhost"
    remote_port: int
    reason: str
    confirm_target: str
    approve_review: bool = False


class WinRmOpenRequest(BaseModel):
    reason: str
    confirm_target: str
    approve_review: bool = False


class RemoteModeUpdateRequest(BaseModel):
    mode: str
    changed_by: str
    reason: str = ""


class FileBrowserRequest(BaseModel):
    path: str = "/"


class FileDownloadRequest(BaseModel):
    path: str


class FileDeleteRequest(BaseModel):
    path: str
    reason: str
    confirm_name: str
    confirm_target: str
    confirm_action: str


class WolRequest(BaseModel):
    mac: Optional[str] = None         # override mac from connection
    broadcast: str = "255.255.255.255"


@router.get("/remote-mode")
def get_remote_mode() -> dict[str, Any]:
    data = load_remote_access_mode_from_config()
    return {"status": "ok", "data": data}


@router.post("/remote-mode")
def set_remote_mode(body: RemoteModeUpdateRequest) -> dict[str, Any]:
    mode = body.mode.strip().lower()
    if mode not in {"safe", "admin", "break_glass"}:
        raise HTTPException(status_code=400, detail="mode must be one of: safe, admin, break_glass")

    saved = save_remote_access_mode_to_config(mode=mode, changed_by=body.changed_by, reason=body.reason)
    audit_id = log_server_activity(
        action="remote_mode_change",
        connection_id="",
        host="",
        protocol="server",
        status="ok",
        message=f"Remote access mode changed to '{saved['mode']}'",
        metadata={
            "mode": saved["mode"],
            "changed_by": saved["changed_by"],
            "changed_at": saved["changed_at"],
            "reason": saved["reason"],
        },
    )
    return {"status": "ok", "data": saved, "audit_id": audit_id}


# ── CRUD ──────────────────────────────────────────────────────────────

@router.get("/connections")
def get_all_connections(
    protocol: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    favorite_only: bool = Query(False),
) -> dict[str, Any]:
    items = list_connections(protocol=protocol, tag=tag, search=search, favorite_only=favorite_only)
    return {"status": "ok", "count": len(items), "data": items}


@router.post("/connections")
def create_new_connection(body: ConnectionCreate) -> dict[str, Any]:
    policy_result = check_policy("create_connection", None)
    if policy_result.status != "ok":
        return _action_result(policy_result)

    created = create_connection(body.model_dump())
    audit_id = log_server_activity(
        action="create_connection",
        connection_id=created["id"],
        host=created.get("hostname") or created.get("ip", ""),
        protocol=created.get("protocol", ""),
        status="ok",
        message=f"Created connection '{created['name']}'",
    )
    return {"status": "ok", "message": "Connection created", "data": created, "audit_id": audit_id}


@router.get("/connections/{connection_id}")
def get_single_connection(connection_id: str) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    return {"status": "ok", "data": conn}


@router.put("/connections/{connection_id}")
def update_existing_connection(connection_id: str, body: ConnectionUpdate) -> dict[str, Any]:
    policy_result = check_policy("update_connection", None)
    if policy_result.status != "ok":
        return _action_result(policy_result)

    updated_data = {k: v for k, v in body.model_dump().items() if v is not None}
    result = update_connection(connection_id, updated_data)
    if result is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    audit_id = log_server_activity(
        action="update_connection",
        connection_id=connection_id,
        host=result.get("hostname") or result.get("ip", ""),
        protocol=result.get("protocol", ""),
        status="ok",
        message=f"Updated connection '{result['name']}'",
    )
    return {"status": "ok", "message": "Connection updated", "data": result, "audit_id": audit_id}


@router.delete("/connections/{connection_id}")
def delete_existing_connection(connection_id: str) -> dict[str, Any]:
    policy_result = check_policy("delete_connection", None)
    if policy_result.status != "ok":
        return _action_result(policy_result)

    conn = _get_conn_or_404(connection_id)
    deleted = delete_connection(connection_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Connection not found")
    audit_id = log_server_activity(
        action="delete_connection",
        connection_id=connection_id,
        host=conn.get("hostname") or conn.get("ip", ""),
        status="ok",
        message=f"Deleted connection '{conn['name']}'",
    )
    return {"status": "ok", "message": "Connection deleted", "audit_id": audit_id}


# ── Legacy import ─────────────────────────────────────────────────────

@router.post("/import/legacy")
def import_legacy(body: LegacyImportRequest) -> dict[str, Any]:
    policy_result = check_policy("import_legacy", None)
    if policy_result.status != "ok":
        return _action_result(policy_result)

    fmt = body.format.lower()
    if fmt == "json":
        report = import_from_json(body.data, auto_link=body.auto_link)
    elif fmt == "csv":
        report = import_from_csv(body.data, auto_link=body.auto_link)
    else:
        return {"status": "error", "message": f"Unknown format '{fmt}'. Use 'json' or 'csv'."}

    audit_id = log_server_activity(
        action="import_legacy",
        status="ok",
        message=(
            f"Legacy import: {report['imported']} imported, "
            f"{report['conflicts']} conflicts, {report['skipped']} skipped"
        ),
        metadata={"report": report},
    )
    return {"status": "ok", "message": "Import complete", "data": report, "audit_id": audit_id}


# ── Network tools (per connection) ────────────────────────────────────

@router.post("/connections/{connection_id}/ping")
def ping_connection(connection_id: str) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("ping", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)

    host = conn.get("hostname") or conn.get("ip", "")
    result = ping_host(host)
    audit_id = log_server_activity(
        action="ping", connection_id=connection_id, host=host,
        status="ok" if result.get("reachable") else "unreachable",
        message=f"Ping {host}: {'reachable' if result.get('reachable') else 'unreachable'}",
    )
    return {"status": "ok", "data": result, "audit_id": audit_id}


@router.post("/connections/{connection_id}/dns")
def dns_connection(connection_id: str) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    host = conn.get("hostname") or conn.get("ip", "")
    result = dns_lookup(host)
    return {"status": "ok", "data": result}


@router.post("/connections/{connection_id}/reverse-dns")
def reverse_dns_connection(connection_id: str) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    ip = conn.get("ip") or conn.get("hostname", "")
    result = reverse_dns(ip)
    return {"status": "ok", "data": result}


@router.post("/connections/{connection_id}/ports")
def port_check_connection(connection_id: str, body: PortCheckRequest) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("port_check", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)

    host = conn.get("hostname") or conn.get("ip", "")
    result = port_check(host, body.ports)
    return {"status": "ok", "data": result}


@router.post("/connections/{connection_id}/test")
def test_connection(connection_id: str) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("connection_test", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)

    protocol = conn.get("protocol", "ssh")
    if protocol == "ssh":
        result = test_ssh_connection(conn)
    elif protocol == "rdp":
        host = conn.get("hostname") or conn.get("ip", "")
        port = int(conn.get("port") or 3389)
        import socket as _sock
        try:
            with _sock.create_connection((host, port), timeout=5):
                result = {"status": "ok", "host": host, "port": port, "message": "TCP reachable"}
        except Exception as exc:
            result = {"status": "error", "host": host, "port": port, "error": str(exc)}
    else:
        result = {"status": "unknown", "message": f"No test implemented for protocol '{protocol}'"}

    audit_id = log_server_activity(
        action="connection_test",
        connection_id=connection_id,
        host=conn.get("hostname") or conn.get("ip", ""),
        protocol=protocol,
        status=result.get("status", "unknown"),
        message=f"Connection test for '{conn['name']}'",
    )
    return {"status": "ok", "data": result, "audit_id": audit_id}


@router.post("/connections/{connection_id}/health")
def health_check_connection(connection_id: str) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("health_check", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)

    protocol = conn.get("protocol", "ssh")
    if protocol == "ssh":
        result = health_check(conn)
    else:
        host = conn.get("hostname") or conn.get("ip", "")
        ping_result = ping_host(host, count=2)
        result = {
            "status": "ok" if ping_result.get("reachable") else "offline",
            "ping": ping_result,
        }

    audit_id = log_server_activity(
        action="health_check",
        connection_id=connection_id,
        host=conn.get("hostname") or conn.get("ip", ""),
        protocol=protocol,
        status=result.get("status", "unknown"),
        message=f"Health check '{conn['name']}'",
    )
    return {"status": "ok", "data": result, "audit_id": audit_id}


# ── SSH actions ───────────────────────────────────────────────────────

@router.post("/connections/{connection_id}/ssh/host-info")
def ssh_host_info(connection_id: str) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("ssh_host_info", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)

    result = get_host_info(conn)
    audit_id = log_server_activity(
        action="ssh_host_info",
        connection_id=connection_id,
        host=conn.get("hostname") or conn.get("ip", ""),
        protocol="ssh",
        status=result.get("status", "ok"),
        message=f"SSH host info for '{conn['name']}'",
    )
    return {"status": "ok", "policy": policy_result.policy, "data": result, "audit_id": audit_id}


@router.post("/connections/{connection_id}/ssh/read-only-command")
def ssh_readonly_command(connection_id: str, body: ReadOnlyCommandRequest) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("ssh_readonly_command", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)

    result = run_readonly_command(conn, body.command_id)
    audit_id = log_server_activity(
        action="ssh_readonly_command",
        connection_id=connection_id,
        host=conn.get("hostname") or conn.get("ip", ""),
        protocol="ssh",
        status=result.get("status", "ok"),
        message=f"Read-only command '{body.command_id}' on '{conn['name']}'",
        metadata={"command_id": body.command_id},
    )
    return {"status": result.get("status", "ok"), "data": result, "audit_id": audit_id}


@router.post("/connections/{connection_id}/ssh/connect")
def ssh_connect(connection_id: str) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("ssh_connect", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)

    result = launch_native_ssh_shell(conn)
    audit_id = log_server_activity(
        action="ssh_connect",
        connection_id=connection_id,
        host=conn.get("hostname") or conn.get("ip", ""),
        protocol="ssh",
        status=result.get("status", "error"),
        message=f"Native SSH shell launch for '{conn['name']}'",
        metadata={"command": result.get("command_used", "")},
    )
    return {"status": result.get("status", "ok"), "policy": policy_result.policy, "data": result, "audit_id": audit_id}


@router.post("/connections/{connection_id}/ssh/interactive-shell")
def ssh_interactive_shell(connection_id: str) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("ssh_interactive_shell", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)

    result = launch_native_ssh_shell(conn)
    audit_id = log_server_activity(
        action="ssh_interactive_shell",
        connection_id=connection_id,
        host=conn.get("hostname") or conn.get("ip", ""),
        protocol="ssh",
        status=result.get("status", "error"),
        message=f"Interactive shell launch for '{conn['name']}'",
        metadata={"command": result.get("command_used", "")},
    )
    return {"status": result.get("status", "ok"), "policy": policy_result.policy, "data": result, "audit_id": audit_id}


@router.post("/connections/{connection_id}/ssh/arbitrary-command")
def ssh_arbitrary_command(connection_id: str, body: ArbitraryCommandRequest) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("ssh_arbitrary_command", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)
    if policy_result.status == "review_required" and not body.approve_review:
        return _action_result(policy_result)

    reason_clean, expected_target = _validate_high_risk_confirmation(conn, body.reason, body.confirm_target)

    result = run_arbitrary_command(conn, body.command, timeout=max(1, min(body.timeout, 300)))
    audit_id = log_server_activity(
        action="ssh_arbitrary_command",
        connection_id=connection_id,
        host=conn.get("hostname") or conn.get("ip", ""),
        protocol="ssh",
        status=result.get("status", "error"),
        message=f"Arbitrary SSH command on '{conn['name']}'",
        metadata={
            "command": body.command,
            "reason": reason_clean,
            "confirm_target": expected_target,
            "review_override": bool(policy_result.status == "review_required" and body.approve_review),
        },
    )
    return {"status": result.get("status", "ok"), "policy": policy_result.policy, "data": result, "audit_id": audit_id}


@router.post("/connections/{connection_id}/ssh/key-deploy")
def ssh_key_deploy(connection_id: str, body: PublicKeyDeployRequest) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("ssh_key_deploy", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)
    if policy_result.status == "review_required" and not body.approve_review:
        return _action_result(policy_result)

    reason_clean, expected_target = _validate_high_risk_confirmation(conn, body.reason, body.confirm_target)

    result = deploy_public_key(conn, body.public_key)
    audit_id = log_server_activity(
        action="ssh_key_deploy",
        connection_id=connection_id,
        host=conn.get("hostname") or conn.get("ip", ""),
        protocol="ssh",
        status=result.get("status", "error"),
        message=f"SSH public key deploy on '{conn['name']}'",
        metadata={
            "reason": reason_clean,
            "confirm_target": expected_target,
            "review_override": bool(policy_result.status == "review_required" and body.approve_review),
        },
    )
    return {"status": result.get("status", "ok"), "policy": policy_result.policy, "data": result, "audit_id": audit_id}


@router.post("/connections/{connection_id}/ssh/port-forward")
def ssh_port_forward(connection_id: str, body: PortForwardRequest) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("ssh_port_forward", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)
    if policy_result.status == "review_required" and not body.approve_review:
        return _action_result(policy_result)

    reason_clean, expected_target = _validate_high_risk_confirmation(conn, body.reason, body.confirm_target)

    host = conn.get("hostname") or conn.get("ip", "")
    port = int(conn.get("port") or 22)
    user = conn.get("username", "")
    if not host or not user:
        raise HTTPException(status_code=400, detail="connection must have host and username")

    cmd = [
        "ssh",
        "-L", f"{body.local_port}:{body.remote_host}:{body.remote_port}",
        "-p", str(port),
        f"{user}@{host}",
    ]
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
    proc = subprocess.Popen(cmd, creationflags=creationflags)

    audit_id = log_server_activity(
        action="ssh_port_forward",
        connection_id=connection_id,
        host=host,
        protocol="ssh",
        status="ok",
        message=f"SSH port forward started for '{conn['name']}'",
        metadata={
            "local_port": body.local_port,
            "remote_host": body.remote_host,
            "remote_port": body.remote_port,
            "reason": reason_clean,
            "confirm_target": expected_target,
            "pid": proc.pid,
            "command": " ".join(cmd),
            "review_override": bool(policy_result.status == "review_required" and body.approve_review),
        },
    )
    return {
        "status": "ok",
        "policy": policy_result.policy,
        "data": {
            "pid": proc.pid,
            "command_used": " ".join(cmd),
            "message": "Port forward tunnel started",
        },
        "audit_id": audit_id,
    }


@router.post("/connections/{connection_id}/ssh/file-list")
def ssh_file_list(connection_id: str, body: FileBrowserRequest) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("ssh_file_list", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)

    result = list_remote_directory(conn, body.path)
    return {"status": result.get("status", "ok"), "data": result}


@router.post("/connections/{connection_id}/ssh/file-download")
def ssh_file_download(connection_id: str, body: FileDownloadRequest) -> Response:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("ssh_file_download", conn, uh)
    if policy_result.status == "blocked":
        raise HTTPException(status_code=403, detail=policy_result.policy_reason)

    try:
        file_bytes, filename = download_file(conn, body.path)
        audit_id = log_server_activity(
            action="ssh_file_download",
            connection_id=connection_id,
            host=conn.get("hostname") or conn.get("ip", ""),
            protocol="ssh",
            status="ok",
            message=f"Downloaded '{body.path}' from '{conn['name']}'",
            metadata={"path": body.path, "size": len(file_bytes)},
        )
        return Response(
            content=file_bytes,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Audit-ID": audit_id,
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/connections/{connection_id}/ssh/file-upload")
async def ssh_file_upload(
    connection_id: str,
    file: UploadFile = File(...),
    remote_dir: str = Form("/"),
    reason: str = Form(...),
    confirm_target: str = Form(...),
) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("ssh_file_upload", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)

    reason_clean, expected_target = _validate_high_risk_confirmation(conn, reason, confirm_target)
    if not file.filename:
        raise HTTPException(status_code=400, detail="file is required")

    base = posixpath.basename(file.filename)
    clean_dir = (remote_dir or "/").strip()
    if not clean_dir:
        clean_dir = "/"
    clean_dir = clean_dir.rstrip("/") or "/"
    remote_path = f"{clean_dir}/{base}" if clean_dir != "/" else f"/{base}"

    content = await file.read()
    result = upload_file(conn, remote_path, content)
    status = result.get("status", "error")

    audit_id = log_server_activity(
        action="ssh_file_upload",
        connection_id=connection_id,
        host=conn.get("hostname") or conn.get("ip", ""),
        protocol="ssh",
        status=status,
        message=f"Uploaded '{remote_path}' to '{conn['name']}'",
        metadata={
            "remote_path": remote_path,
            "reason": reason_clean,
            "confirm_target": expected_target,
            "filename": base,
            "size": len(content),
            "policy": policy_result.policy,
        },
    )
    return {
        "status": status,
        "policy": policy_result.policy,
        "policy_reason": policy_result.policy_reason,
        "data": result,
        "audit_id": audit_id,
    }


@router.post("/connections/{connection_id}/ssh/file-delete")
def ssh_file_delete(connection_id: str, body: FileDeleteRequest) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("ssh_file_delete", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)

    reason_clean, expected_target = _validate_high_risk_confirmation(conn, body.reason, body.confirm_target)

    clean_path = body.path.strip()
    if not clean_path:
        raise HTTPException(status_code=400, detail="path is required")

    expected_name = posixpath.basename(clean_path)
    if body.confirm_name.strip() != expected_name:
        raise HTTPException(
            status_code=400,
            detail=f"confirm_name mismatch (expected '{expected_name}')",
        )
    if body.confirm_action.strip().upper() != "DELETE":
        raise HTTPException(
            status_code=400,
            detail="confirm_action mismatch (expected 'DELETE')",
        )

    result = delete_file(conn, clean_path)
    status = result.get("status", "error")
    audit_id = log_server_activity(
        action="ssh_file_delete",
        connection_id=connection_id,
        host=conn.get("hostname") or conn.get("ip", ""),
        protocol="ssh",
        status=status,
        message=f"Deleted '{clean_path}' from '{conn['name']}'",
        metadata={
            "path": clean_path,
            "confirm_name": body.confirm_name.strip(),
            "confirm_target": expected_target,
            "confirm_action": body.confirm_action.strip(),
            "reason": reason_clean,
            "policy": policy_result.policy,
        },
    )
    return {
        "status": status,
        "policy": policy_result.policy,
        "policy_reason": policy_result.policy_reason,
        "data": result,
        "audit_id": audit_id,
    }


@router.get("/connections/{connection_id}/ssh/config")
def ssh_export_config(connection_id: str) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    config_block = generate_ssh_config_entry(conn)
    return {"status": "ok", "data": {"config": config_block}}


# ── RDP actions ───────────────────────────────────────────────────────

@router.post("/connections/{connection_id}/rdp/open")
def rdp_open(connection_id: str) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("rdp_open", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)

    result = open_rdp(conn)
    audit_id = log_server_activity(
        action="rdp_open",
        connection_id=connection_id,
        host=conn.get("hostname") or conn.get("ip", ""),
        protocol="rdp",
        status=result.get("status", "ok"),
        message=f"RDP open '{conn['name']}'",
        metadata={"command": result.get("command_used", "")},
    )
    session_id = record_session(
        connection_id=connection_id,
        protocol="rdp",
        host=conn.get("hostname") or conn.get("ip", ""),
        status=result.get("status", "started"),
        audit={"audit_id": audit_id},
    )
    return {
        "status": result.get("status", "ok"),
        "message": result.get("message", ""),
        "policy": policy_result.policy,
        "data": result,
        "audit_id": audit_id,
        "session_id": session_id,
    }


@router.post("/connections/{connection_id}/winrm/open")
def winrm_open(connection_id: str, body: WinRmOpenRequest) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("winrm_execute", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)
    if policy_result.status == "review_required" and not body.approve_review:
        return _action_result(policy_result)

    reason_clean, expected_target = _validate_high_risk_confirmation(conn, body.reason, body.confirm_target)

    host = conn.get("hostname") or conn.get("ip", "")

    cmd = ["powershell", "-NoLogo", "-NoExit", "-Command", f"Enter-PSSession -ComputerName '{host}'"]
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
    proc = subprocess.Popen(cmd, creationflags=creationflags)

    audit_id = log_server_activity(
        action="winrm_execute",
        connection_id=connection_id,
        host=host,
        protocol="winrm",
        status="ok",
        message=f"WinRM session started for '{conn['name']}'",
        metadata={
            "pid": proc.pid,
            "command": " ".join(cmd),
            "reason": reason_clean,
            "confirm_target": expected_target,
            "review_override": bool(policy_result.status == "review_required" and body.approve_review),
        },
    )
    return {
        "status": "ok",
        "policy": policy_result.policy,
        "data": {
            "pid": proc.pid,
            "command_used": " ".join(cmd),
            "message": "PowerShell remoting session started",
        },
        "audit_id": audit_id,
    }


# ── Wake-on-LAN ───────────────────────────────────────────────────────

@router.post("/connections/{connection_id}/wol")
def wol_connection(connection_id: str, body: WolRequest) -> dict[str, Any]:
    conn = _get_conn_or_404(connection_id)
    uh = _get_unified_host(conn.get("unified_host_id", ""))
    policy_result = check_policy("wol", conn, uh)
    if policy_result.status == "blocked":
        return _action_result(policy_result)

    mac = body.mac or conn.get("mac", "")
    if not mac:
        return {"status": "error", "message": "No MAC address configured for this connection."}

    result = wake_on_lan(mac, broadcast=body.broadcast)
    audit_id = log_server_activity(
        action="wol",
        connection_id=connection_id,
        host=conn.get("hostname") or conn.get("ip", ""),
        protocol=conn.get("protocol", ""),
        status=result.get("status", "ok"),
        message=f"WoL sent to {mac} for '{conn['name']}'",
        metadata={"mac": mac, "broadcast": body.broadcast},
    )
    return {"status": result.get("status", "ok"), "data": result, "audit_id": audit_id}


# ── Standalone network tools ──────────────────────────────────────────

class StandaloneToolRequest(BaseModel):
    host: str = ""
    ip: str = ""
    ports: list[int] = [22, 80, 443, 3389]
    mac: str = ""
    broadcast: str = "255.255.255.255"


@router.post("/tools/ping")
def standalone_ping(body: StandaloneToolRequest) -> dict[str, Any]:
    policy_result = check_policy("ping", None)
    if policy_result.status == "blocked":
        return _action_result(policy_result)
    result = ping_host(body.host or body.ip)
    return {"status": "ok", "data": result}


@router.post("/tools/dns")
def standalone_dns(body: StandaloneToolRequest) -> dict[str, Any]:
    result = dns_lookup(body.host)
    return {"status": "ok", "data": result}


@router.post("/tools/reverse-dns")
def standalone_rdns(body: StandaloneToolRequest) -> dict[str, Any]:
    result = reverse_dns(body.ip or body.host)
    return {"status": "ok", "data": result}


@router.post("/tools/port-check")
def standalone_port_check(body: StandaloneToolRequest) -> dict[str, Any]:
    result = port_check(body.host or body.ip, body.ports)
    return {"status": "ok", "data": result}


@router.post("/tools/traceroute")
def standalone_traceroute(body: StandaloneToolRequest) -> dict[str, Any]:
    result = traceroute(body.host or body.ip)
    return {"status": "ok", "data": result}


@router.post("/tools/arp")
def standalone_arp(body: StandaloneToolRequest) -> dict[str, Any]:
    result = arp_lookup(body.ip or body.host)
    return {"status": "ok", "data": result}


@router.post("/tools/wol")
def standalone_wol(body: StandaloneToolRequest) -> dict[str, Any]:
    policy_result = check_policy("wol", None)
    if policy_result.status == "blocked":
        return _action_result(policy_result)
    result = wake_on_lan(body.mac, broadcast=body.broadcast)
    return {"status": result.get("status", "ok"), "data": result}


# ── Activity & Sessions ───────────────────────────────────────────────

@router.get("/activity")
def get_activity(
    limit: int = Query(100, ge=1, le=500),
    connection_id: Optional[str] = Query(None),
) -> dict[str, Any]:
    items = list_activity(limit=limit, connection_id=connection_id)
    return {"status": "ok", "count": len(items), "data": items}


@router.get("/sessions")
def get_sessions(limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    items = list_sessions(limit=limit)
    return {"status": "ok", "count": len(items), "data": items}


# ── Read-only commands catalog ────────────────────────────────────────

@router.get("/ssh/commands")
def get_ssh_commands() -> dict[str, Any]:
    from services.remote_access.models import SSH_READONLY_COMMANDS
    return {
        "status": "ok",
        "data": [
            {"id": k, "command": v}
            for k, v in SSH_READONLY_COMMANDS.items()
        ],
    }


# ── Legacy feature catalog ────────────────────────────────────────────

@router.get("/legacy-features")
def get_legacy_features() -> dict[str, Any]:
    """Return the SSH_Manager legacy feature catalog for UI display.

    This endpoint exposes which features from the SSH_Manager project have been
    evaluated, implemented, planned, disabled, or rejected.  The source repo is
    treated as an *idea source only* — it is never cloned, modified, or executed.
    """
    from services.remote_access.legacy_feature_catalog import (
        FEATURES, STATUS_DISABLED, STATUS_REJECTED,
    )
    total    = len(FEATURES)
    phase1   = sum(1 for f in FEATURES if f.get("phase1"))
    phase2   = sum(1 for f in FEATURES if f.get("phase2") and not f.get("phase1"))
    disabled = sum(1 for f in FEATURES if f["status"] == STATUS_DISABLED)
    rejected = sum(1 for f in FEATURES if f["status"] == STATUS_REJECTED)
    dangerous = sum(1 for f in FEATURES if f.get("risk_level") in ("high", "critical"))
    return {
        "status": "ok",
        "source_repo": "https://github.com/Desfam/SSH_Manager",
        "mode": "ideas_only_no_repo_modification",
        "features": FEATURES,
        "summary": {
            "total":     total,
            "phase1":    phase1,
            "phase2":    phase2,
            "disabled":  disabled,
            "rejected":  rejected,
            "dangerous": dangerous,
        },
    }


# ── SSH config bulk export ─────────────────────────────────────────────

@router.get("/export/ssh-config")
def bulk_export_ssh_config(
    favorites_only: bool = Query(False),
    tag: Optional[str] = Query(None),
) -> dict[str, Any]:
    """Export all SSH connections as an OpenSSH config text preview.

    Never writes to disk.  The caller (browser) may copy or download the text.
    Passwords and credential references are never included.
    """
    policy = check_policy("export_ssh_config", connection=None)
    if policy.status != "ok":
        raise HTTPException(status_code=403, detail=policy.message)

    from services.remote_access.ssh_config_exporter import generate_ssh_config

    conns  = list_connections(protocol="ssh", tag=tag or None, favorite_only=favorites_only)
    result = generate_ssh_config(conns)

    audit_id = log_server_activity(
        action="server_ssh_config_exported",
        status="ok",
        message=(
            f"SSH config export: {result['host_count']} connections; "
            f"favorites_only={favorites_only}; tag={tag}"
        ),
        metadata={"host_count": result["host_count"], "tag": tag, "favorites_only": favorites_only},
    )
    result["audit_id"] = audit_id
    return result


# ══════════════════════════════════════════════════════════════════════
# Host Groups
# ══════════════════════════════════════════════════════════════════════

class GroupCreate(BaseModel):
    name: str
    description: str = ""
    color: str = "#6366f1"
    tags: list[str] = []


class GroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    color: Optional[str] = None
    tags: Optional[list[str]] = None


class GroupMemberAdd(BaseModel):
    connection_id: str


@router.get("/groups")
def get_groups() -> dict[str, Any]:
    from services.remote_access.host_groups import list_groups
    return {"status": "ok", "data": list_groups()}


@router.post("/groups")
def post_group(body: GroupCreate) -> dict[str, Any]:
    from services.remote_access.host_groups import create_group
    g = create_group(body.name, body.description, body.color, body.tags)
    log_server_activity(action="group_manage", status="ok", message=f"Created group '{body.name}'")
    return {"status": "ok", "data": g}


@router.get("/groups/{group_id}")
def get_group(group_id: str) -> dict[str, Any]:
    from services.remote_access.host_groups import get_group as _get
    g = _get(group_id)
    if not g:
        raise HTTPException(status_code=404, detail="Group not found")
    return {"status": "ok", "data": g}


@router.put("/groups/{group_id}")
def put_group(group_id: str, body: GroupUpdate) -> dict[str, Any]:
    from services.remote_access.host_groups import update_group
    g = update_group(group_id, name=body.name, description=body.description,
                     color=body.color, tags=body.tags)
    if not g:
        raise HTTPException(status_code=404, detail="Group not found")
    log_server_activity(action="group_manage", status="ok", message=f"Updated group {group_id}")
    return {"status": "ok", "data": g}


@router.delete("/groups/{group_id}")
def del_group(group_id: str) -> dict[str, Any]:
    from services.remote_access.host_groups import delete_group
    ok = delete_group(group_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Group not found")
    log_server_activity(action="group_manage", status="ok", message=f"Deleted group {group_id}")
    return {"status": "ok"}


@router.get("/groups/{group_id}/members")
def get_group_members(group_id: str) -> dict[str, Any]:
    from services.remote_access.host_groups import list_group_members
    members = list_group_members(group_id)
    return {"status": "ok", "data": members}


@router.post("/groups/{group_id}/members")
def add_group_member(group_id: str, body: GroupMemberAdd) -> dict[str, Any]:
    from services.remote_access.host_groups import add_member, get_group
    if not get_group(group_id):
        raise HTTPException(status_code=404, detail="Group not found")
    m = add_member(group_id, body.connection_id)
    log_server_activity(action="group_manage", status="ok",
                        message=f"Added {body.connection_id} to group {group_id}")
    return {"status": "ok", "data": m}


@router.delete("/groups/{group_id}/members/{connection_id}")
def remove_group_member(group_id: str, connection_id: str) -> dict[str, Any]:
    from services.remote_access.host_groups import remove_member
    ok = remove_member(group_id, connection_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Member not found")
    log_server_activity(action="group_manage", status="ok",
                        message=f"Removed {connection_id} from group {group_id}")
    return {"status": "ok"}


# ══════════════════════════════════════════════════════════════════════
# Batch Health
# ══════════════════════════════════════════════════════════════════════

class BatchHealthRequest(BaseModel):
    connection_ids: list[str] = []
    checks: list[str] = ["ping", "port"]
    concurrency: int = 5


@router.post("/groups/{group_id}/health")
def run_group_health(group_id: str, body: Optional[BatchHealthRequest] = None) -> dict[str, Any]:
    from services.remote_access.batch_health import run_batch_health_for_group
    checks = body.checks if body else ["ping", "port"]
    concurrency = body.concurrency if body else 5
    result = run_batch_health_for_group(group_id, checks=checks, concurrency=concurrency)
    log_server_activity(action="batch_health", status="ok",
                        message=f"Batch health for group {group_id}: {result['summary']}")
    return result


@router.post("/batch/health")
def run_batch_health_endpoint(body: BatchHealthRequest) -> dict[str, Any]:
    from services.remote_access.batch_health import run_batch_health
    result = run_batch_health(body.connection_ids, checks=body.checks, concurrency=body.concurrency)
    log_server_activity(action="batch_health", status="ok",
                        message=f"Batch health {len(body.connection_ids)} hosts: {result['summary']}")
    return result


@router.get("/batch/runs")
def get_batch_runs(limit: int = Query(50, ge=1, le=200)) -> dict[str, Any]:
    from services.remote_access.batch_health import list_batch_runs
    return {"status": "ok", "data": list_batch_runs(limit=limit)}


@router.get("/batch/runs/{run_id}")
def get_batch_run(run_id: str) -> dict[str, Any]:
    from services.remote_access.batch_health import get_batch_run as _get
    run = _get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Batch run not found")
    return {"status": "ok", "data": run}


@router.get("/batch/runs/{run_id}/results")
def get_batch_run_results(run_id: str) -> dict[str, Any]:
    from services.remote_access.batch_health import get_batch_results
    return {"status": "ok", "data": get_batch_results(run_id)}
