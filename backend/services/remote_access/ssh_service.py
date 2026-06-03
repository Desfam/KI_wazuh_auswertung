"""
remote_access/ssh_service.py
SSH and SFTP operations using paramiko.

Safe/read-only operations are available directly through Server Operations.
Write operations are implemented as helpers and must be exposed only through
controlled routes with confirmation and audit logging.
"""
from __future__ import annotations

import io
import os
import socket
import subprocess
import time
from typing import Any, Optional

from .models import SSH_READONLY_COMMANDS

# paramiko is optional — imported lazily so the app starts without it
try:
    import paramiko  # type: ignore
    _PARAMIKO_AVAILABLE = True
except ImportError:
    _PARAMIKO_AVAILABLE = False


def _unavailable(reason: str = "paramiko not installed") -> dict[str, Any]:
    return {"status": "unavailable", "error": reason}


def _build_client(connection: dict[str, Any]) -> "paramiko.SSHClient":
    """Create and return an authenticated SSH client (caller must close it)."""
    if not _PARAMIKO_AVAILABLE:
        raise RuntimeError("paramiko not installed — run: pip install paramiko")

    host = connection.get("hostname") or connection.get("ip", "")
    port = int(connection.get("port") or 22)
    username = connection.get("username", "")
    key_ref = connection.get("key_ref", "")
    auth_type = connection.get("auth_type", "agent")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs: dict[str, Any] = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": 10,
        "banner_timeout": 10,
        "auth_timeout": 10,
    }

    if auth_type == "key_ref" and key_ref:
        connect_kwargs["key_filename"] = key_ref
    else:
        # Fall back to SSH agent / default keys
        connect_kwargs["allow_agent"] = True
        connect_kwargs["look_for_keys"] = True

    client.connect(**connect_kwargs)
    return client


def _run_command(
    client: "paramiko.SSHClient",
    command: str,
    timeout: int = 15,
) -> dict[str, Any]:
    stdin_, stdout_, stderr_ = client.exec_command(command, timeout=timeout)
    out = stdout_.read().decode("utf-8", errors="replace")
    err = stderr_.read().decode("utf-8", errors="replace")
    rc = stdout_.channel.recv_exit_status()
    return {"ok": rc == 0, "stdout": out, "stderr": err, "returncode": rc}


def _clean_remote_path(path: str) -> str:
    import posixpath
    clean = posixpath.normpath("/" + str(path or "").lstrip("/"))
    if clean in ("", "."):
        clean = "/"
    return clean


def test_ssh_connection(connection: dict[str, Any]) -> dict[str, Any]:
    """Test TCP + SSH handshake."""
    if not _PARAMIKO_AVAILABLE:
        return _unavailable()

    host = connection.get("hostname") or connection.get("ip", "")
    port = int(connection.get("port") or 22)

    # Step 1 — TCP reachability
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=5):
            tcp_ms = round((time.monotonic() - start) * 1000)
    except OSError as exc:
        return {"status": "error", "error": f"TCP connection failed: {exc}", "tcp_ms": None}

    # Step 2 — SSH handshake
    client = None
    try:
        client = _build_client(connection)
        ssh_ms = round((time.monotonic() - start) * 1000)
        result = _run_command(client, "echo OK", timeout=5)
        auth_ok = result.get("ok") and "OK" in result.get("stdout", "")
        return {
            "status": "ok" if auth_ok else "auth_failed",
            "tcp_ms": tcp_ms,
            "ssh_ms": ssh_ms,
            "auth": auth_ok,
        }
    except paramiko.AuthenticationException:
        return {"status": "auth_failed", "tcp_ms": tcp_ms, "error": "Authentication failed"}
    except Exception as exc:
        return {"status": "error", "tcp_ms": tcp_ms, "error": str(exc)}
    finally:
        if client:
            client.close()


def get_host_info(connection: dict[str, Any]) -> dict[str, Any]:
    """Gather basic host info using safe read-only commands."""
    if not _PARAMIKO_AVAILABLE:
        return _unavailable()

    client = None
    try:
        client = _build_client(connection)
        results: dict[str, Any] = {"status": "ok", "fields": {}}

        safe_cmds = {
            "hostname":    "hostname",
            "uname":       "uname -a 2>/dev/null || ver",
            "uptime":      "uptime 2>/dev/null || echo unavailable",
            "disk":        "df -h / 2>/dev/null | tail -n +2 | head -3",
            "memory":      "free -m 2>/dev/null | head -3",
            "ip_brief":    "ip -brief addr 2>/dev/null || ipconfig /all 2>nul",
        }

        for key, cmd in safe_cmds.items():
            r = _run_command(client, cmd, timeout=10)
            results["fields"][key] = r["stdout"].strip() if r["ok"] else f"(error: {r['stderr'].strip()[:80]})"

        return results
    except Exception as exc:
        return {"status": "error", "error": str(exc)}
    finally:
        if client:
            client.close()


def run_readonly_command(
    connection: dict[str, Any],
    command_id: str,
) -> dict[str, Any]:
    """Run a command from the SSH_READONLY_COMMANDS allowlist only."""
    if not _PARAMIKO_AVAILABLE:
        return _unavailable()

    if command_id not in SSH_READONLY_COMMANDS:
        return {
            "status": "blocked",
            "error": (
                f"command_id '{command_id}' is not in the read-only allowlist. "
                "Raw shell commands require a dedicated controlled action route."
            ),
        }

    command = SSH_READONLY_COMMANDS[command_id]
    client = None
    try:
        client = _build_client(connection)
        result = _run_command(client, command, timeout=20)
        return {
            "status": "ok",
            "command_id": command_id,
            "command": command,
            "output": result["stdout"],
            "error_output": result["stderr"],
            "returncode": result["returncode"],
        }
    except Exception as exc:
        return {"status": "error", "command_id": command_id, "error": str(exc)}
    finally:
        if client:
            client.close()


def run_arbitrary_command(
    connection: dict[str, Any],
    command: str,
    timeout: int = 30,
) -> dict[str, Any]:
    """Run a user-provided SSH command through paramiko."""
    if not _PARAMIKO_AVAILABLE:
        return _unavailable()
    if not str(command or "").strip():
        return {"status": "error", "error": "command is required"}

    client = None
    try:
        client = _build_client(connection)
        result = _run_command(client, command, timeout=timeout)
        return {
            "status": "ok",
            "command": command,
            "output": result["stdout"],
            "error_output": result["stderr"],
            "returncode": result["returncode"],
        }
    except Exception as exc:
        return {"status": "error", "command": command, "error": str(exc)}
    finally:
        if client:
            client.close()


def deploy_public_key(
    connection: dict[str, Any],
    public_key_text: str,
) -> dict[str, Any]:
    """Append a public key to remote ~/.ssh/authorized_keys using SFTP."""
    if not _PARAMIKO_AVAILABLE:
        return _unavailable()
    key = str(public_key_text or "").strip()
    if not key:
        return {"status": "error", "error": "public_key is required"}

    client = None
    sftp = None
    try:
        client = _build_client(connection)
        sftp = client.open_sftp()

        # Ensure remote .ssh directory exists and is private.
        stdin_mk, stdout_mk, stderr_mk = client.exec_command("mkdir -p ~/.ssh && chmod 700 ~/.ssh", timeout=10)
        _ = stdin_mk
        _ = stdout_mk.read()
        _ = stderr_mk.read()

        remote_path = ".ssh/authorized_keys"
        existing = ""
        try:
            with sftp.file(remote_path, "r") as f:
                existing = f.read().decode("utf-8", errors="replace")
        except Exception:
            existing = ""

        if key in existing:
            return {"status": "ok", "path": remote_path, "message": "Key already present"}

        with sftp.file(remote_path, "a") as f:
            if existing and not existing.endswith("\n"):
                f.write("\n")
            f.write(key + "\n")
        sftp.chmod(remote_path, 0o600)

        return {"status": "ok", "path": remote_path, "message": "Public key appended"}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}
    finally:
        if sftp:
            sftp.close()
        if client:
            client.close()


def launch_native_ssh_shell(connection: dict[str, Any]) -> dict[str, Any]:
    """Launch system SSH client in a separate process for an interactive shell."""
    host = connection.get("hostname") or connection.get("ip", "")
    port = int(connection.get("port") or 22)
    username = connection.get("username", "")
    if not host or not username:
        return {"status": "error", "error": "hostname/ip and username are required"}

    cmd = ["ssh", "-p", str(port), f"{username}@{host}"]
    try:
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
        proc = subprocess.Popen(cmd, creationflags=creationflags)
        return {
            "status": "ok",
            "message": "Interactive SSH shell started",
            "pid": proc.pid,
            "command_used": " ".join(cmd),
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc), "command_used": " ".join(cmd)}


def list_remote_directory(
    connection: dict[str, Any],
    path: str = "/",
) -> dict[str, Any]:
    """List a remote directory via SFTP."""
    if not _PARAMIKO_AVAILABLE:
        return _unavailable()

    clean_path = _clean_remote_path(path)

    client = None
    sftp = None
    try:
        client = _build_client(connection)
        sftp = client.open_sftp()
        attrs = sftp.listdir_attr(clean_path)
        entries = []
        for a in attrs:
            import stat as stat_mod
            is_dir = stat_mod.S_ISDIR(a.st_mode or 0)
            entries.append({
                "name": a.filename,
                "type": "dir" if is_dir else "file",
                "size": a.st_size,
                "mtime": a.st_mtime,
            })
        entries.sort(key=lambda x: (x["type"] != "dir", x["name"].lower()))
        return {"status": "ok", "path": clean_path, "entries": entries}
    except Exception as exc:
        return {"status": "error", "path": clean_path, "error": str(exc)}
    finally:
        if sftp:
            sftp.close()
        if client:
            client.close()


def download_file(
    connection: dict[str, Any],
    remote_path: str,
) -> tuple[bytes, str]:
    """
    Download a single file via SFTP.
    Returns (file_bytes, filename).
    Raises exceptions on error.
    """
    if not _PARAMIKO_AVAILABLE:
        raise RuntimeError("paramiko not installed")

    import posixpath
    clean_path = _clean_remote_path(remote_path)
    filename = posixpath.basename(clean_path)

    client = None
    sftp = None
    try:
        client = _build_client(connection)
        sftp = client.open_sftp()
        buf = io.BytesIO()
        sftp.getfo(clean_path, buf)
        return buf.getvalue(), filename
    finally:
        if sftp:
            sftp.close()
        if client:
            client.close()


def upload_file(
    connection: dict[str, Any],
    remote_path: str,
    content: bytes,
    *,
    max_bytes: int = 25 * 1024 * 1024,
) -> dict[str, Any]:
    """Upload bytes to a remote path via SFTP."""
    if not _PARAMIKO_AVAILABLE:
        return _unavailable()
    if not remote_path or remote_path.endswith("/"):
        return {"status": "error", "error": "remote_path must include a filename"}
    if len(content) > max_bytes:
        return {"status": "error", "error": f"Upload too large: {len(content)} bytes > {max_bytes} bytes"}

    clean_path = _clean_remote_path(remote_path)
    client = None
    sftp = None
    try:
        client = _build_client(connection)
        sftp = client.open_sftp()
        with sftp.file(clean_path, "wb") as remote_file:
            remote_file.write(content)
        return {"status": "ok", "path": clean_path, "size": len(content)}
    except Exception as exc:
        return {"status": "error", "path": clean_path, "error": str(exc)}
    finally:
        if sftp:
            sftp.close()
        if client:
            client.close()


def delete_file(connection: dict[str, Any], remote_path: str) -> dict[str, Any]:
    """Delete a single remote file via SFTP."""
    if not _PARAMIKO_AVAILABLE:
        return _unavailable()
    clean_path = _clean_remote_path(remote_path)
    if clean_path in ("/", ""):
        return {"status": "error", "error": "Refusing to delete root path"}

    client = None
    sftp = None
    try:
        client = _build_client(connection)
        sftp = client.open_sftp()
        sftp.remove(clean_path)
        return {"status": "ok", "path": clean_path}
    except Exception as exc:
        return {"status": "error", "path": clean_path, "error": str(exc)}
    finally:
        if sftp:
            sftp.close()
        if client:
            client.close()


def health_check(connection: dict[str, Any]) -> dict[str, Any]:
    """Quick SSH health check: TCP + auth + uptime."""
    test = test_ssh_connection(connection)
    if test.get("status") != "ok":
        return {
            "status": test.get("status", "error"),
            "error": test.get("error", "Connection failed"),
            "tcp_ms": test.get("tcp_ms"),
        }

    client = None
    try:
        client = _build_client(connection)
        uptime_r = _run_command(client, "uptime", timeout=10)
        load_r   = _run_command(client, "cat /proc/loadavg 2>/dev/null || wmic cpu get loadpercentage 2>nul", timeout=10)
        disk_r   = _run_command(client, "df -h / 2>/dev/null | tail -1", timeout=10)
        return {
            "status": "ok",
            "tcp_ms": test.get("tcp_ms"),
            "ssh_ms": test.get("ssh_ms"),
            "uptime": uptime_r["stdout"].strip() if uptime_r["ok"] else None,
            "load": load_r["stdout"].strip() if load_r["ok"] else None,
            "disk": disk_r["stdout"].strip() if disk_r["ok"] else None,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}
    finally:
        if client:
            client.close()


def generate_ssh_config_entry(connection: dict[str, Any]) -> str:
    """Generate an ~/.ssh/config Host block for this connection."""
    host = connection.get("hostname") or connection.get("ip", "")
    name = connection.get("name", host)
    username = connection.get("username", "")
    port = connection.get("port", 22)
    key_ref = connection.get("key_ref", "")

    lines = [
        f"Host {name}",
        f"    HostName {host}",
        f"    Port {port}",
    ]
    if username:
        lines.append(f"    User {username}")
    if key_ref:
        lines.append(f"    IdentityFile {key_ref}")
    lines.append("    ServerAliveInterval 60")
    lines.append("    ServerAliveCountMax 3")
    return "\n".join(lines)
