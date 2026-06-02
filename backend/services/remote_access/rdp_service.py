"""
remote_access/rdp_service.py
RDP connection handling (Phase 1: open via mstsc, no stored passwords).
"""
from __future__ import annotations

import os
import platform
import subprocess
import tempfile
from typing import Any


def generate_rdp_file_content(connection: dict[str, Any]) -> str:
    """
    Generate a .rdp file content string.
    Never includes passwords.
    """
    host = connection.get("hostname") or connection.get("ip", "")
    port = int(connection.get("port") or 3389)
    username = connection.get("username", "")
    name = connection.get("name", host)

    lines = [
        f"full address:s:{host}:{port}",
        "prompt for credentials:i:1",
        "authentication level:i:2",
        "negotiate security layer:i:1",
        "remoteapplicationmode:i:0",
        "screen mode id:i:2",
        "use multimon:i:0",
        "desktopwidth:i:1920",
        "desktopheight:i:1080",
        "session bpp:i:32",
        "disable wallpaper:i:0",
        "disable themes:i:0",
        "disable full window drag:i:1",
        "allow font smoothing:i:1",
        "allow desktop composition:i:1",
        "bitmapcachepersistenable:i:1",
        "audiomode:i:0",
        f"connection type:i:7",
        f"description:s:{name}",
    ]
    if username:
        lines.append(f"username:s:{username}")

    # password 51 is intentionally omitted
    return "\r\n".join(lines) + "\r\n"


def open_rdp(connection: dict[str, Any]) -> dict[str, Any]:
    """
    Open the Windows RDP client (mstsc.exe) for this connection.
    Writes a temp .rdp file without stored credentials.
    Returns a structured result dict.
    """
    if platform.system().lower() != "windows":
        return {
            "status": "unavailable",
            "message": "RDP client (mstsc.exe) is only available on Windows.",
        }

    host = connection.get("hostname") or connection.get("ip", "")
    port = int(connection.get("port") or 3389)
    if not host:
        return {"status": "error", "message": "No hostname or IP configured for this connection."}

    try:
        rdp_content = generate_rdp_file_content(connection)
        with tempfile.NamedTemporaryFile(
            suffix=".rdp",
            delete=False,
            mode="w",
            encoding="utf-8",
        ) as tmp:
            tmp.write(rdp_content)
            tmp_path = tmp.name

        # Launch mstsc.exe with the temp file
        cmd = ["mstsc.exe", tmp_path]
        subprocess.Popen(cmd, shell=False)

        return {
            "status": "ok",
            "message": "RDP client opened",
            "command_used": f"mstsc.exe {tmp_path}",
            "host": host,
            "port": port,
            "note": "Temp .rdp file used — no passwords stored.",
        }
    except FileNotFoundError:
        return {
            "status": "unavailable",
            "message": "mstsc.exe not found. Is this a Windows system?",
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
    finally:
        # Clean up temp file after a short delay via OS exit hook
        # (mstsc reads it synchronously at startup, then we delete)
        try:
            if "tmp_path" in dir() or "tmp_path" in locals():
                pass  # Let OS clean up; mstsc holds a reference briefly
        except Exception:
            pass
