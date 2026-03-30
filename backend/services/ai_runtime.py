from __future__ import annotations

import atexit
import os
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

import httpx


_process: subprocess.Popen[str] | None = None
_lock = threading.Lock()
_logs: deque[str] = deque(maxlen=500)
_last_error: str | None = None
_host = "0.0.0.0:11434"


def _port() -> int:
    return int(_host.rsplit(":", 1)[1])


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _append_log(message: str) -> None:
    _logs.append(f"{_utc_now()} {message}")


def _listening_pids(port: int) -> list[int]:
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        pids = [
            int(line.strip())
            for line in result.stdout.splitlines()
            if line.strip().isdigit() and int(line.strip()) != os.getpid()
        ]
        if pids:
            return list(dict.fromkeys(pids))
    except Exception as exc:
        _append_log(f"powershell port inspection failed: {exc}")

    try:
        result = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            check=False,
            capture_output=True,
            text=True,
        )
    except Exception as exc:
        _append_log(f"failed to inspect TCP listeners: {exc}")
        return []

    pids: list[int] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        local_address = parts[1]
        if not local_address.endswith(f":{port}"):
            continue
        try:
            pid = int(parts[-1])
        except ValueError:
            continue
        if pid != os.getpid() and pid not in pids:
            pids.append(pid)
    return pids


def _kill_pid(pid: int) -> None:
    subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=False, capture_output=True, text=True)


def _clear_port_blockers(port: int) -> None:
    blocker_pids = _listening_pids(port)
    if not blocker_pids:
        return

    for pid in blocker_pids:
        _append_log(f"killing process {pid} blocking port {port}")
        _kill_pid(pid)

    for _ in range(10):
        if not _listening_pids(port):
            _append_log(f"port {port} is free after cleanup")
            return
        time.sleep(0.2)

    _append_log(f"port {port} is still occupied after cleanup attempt")


def _pump_stream(stream: Any, prefix: str) -> None:
    try:
        # Use unbuffered reading to capture output immediately
        import io
        if hasattr(stream, 'buffer'):
            # If it's a text wrapper, use the underlying binary stream
            stream = stream.buffer
        
        for byte_line in iter(stream.readline, b""):
            if byte_line:
                text = byte_line.decode('utf-8', errors='replace').strip()
                if text:
                    _append_log(f"[{prefix}] {text}")
    except Exception as exc:
        _append_log(f"[{prefix}] stream error: {exc}")


def _is_running_no_lock() -> bool:
    return _process is not None and _process.poll() is None


def _state_no_lock() -> dict[str, Any]:
    running = _is_running_no_lock()
    pid = _process.pid if running and _process else None
    return {
        "running": running,
        "pid": pid,
        "host": _host,
        "last_error": _last_error,
        "logs": list(_logs),
    }


def get_state() -> dict[str, Any]:
    with _lock:
        return _state_no_lock()


def start_service() -> dict[str, Any]:
    global _process, _last_error

    with _lock:
        if _is_running_no_lock():
            _append_log("ollama already running")
            return _state_no_lock()

        env = dict(os.environ)
        env["OLLAMA_HOST"] = _host
        _clear_port_blockers(_port())
        try:
            _append_log("starting ollama serve")
            _process = subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=False,  # Use binary mode for unbuffered reading
                bufsize=0,   # Completely unbuffered
                env=env,
            )
            _last_error = None
        except Exception as exc:
            _last_error = str(exc)
            _append_log(f"failed to start ollama: {_last_error}")
            return _state_no_lock()

        if _process.stdout:
            threading.Thread(target=_pump_stream, args=(_process.stdout, "stdout"), daemon=True).start()
        if _process.stderr:
            threading.Thread(target=_pump_stream, args=(_process.stderr, "stderr"), daemon=True).start()
        return _state_no_lock()


def stop_service() -> dict[str, Any]:
    global _process

    with _lock:
        if not _is_running_no_lock():
            _append_log("ollama already stopped")
            return _state_no_lock()

        assert _process is not None
        _append_log("stopping ollama serve")
        _process.terminate()
        try:
            _process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            _process.kill()
            _process.wait(timeout=4)
        _process = None
        return _state_no_lock()


def test_generate() -> dict[str, Any]:
    payload = {
        "model": "llama3",
        "prompt": "test",
        "stream": False,
    }
    try:
        response = httpx.post(
            "http://localhost:11434/api/generate",
            json=payload,
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        _append_log("test request to /api/generate succeeded")
        return {
            "ok": True,
            "detail": "AI test successful",
            "response": data,
        }
    except Exception as exc:
        _append_log(f"test request failed: {exc}")
        return {
            "ok": False,
            "detail": str(exc),
            "response": None,
        }


@atexit.register
def _shutdown() -> None:
    try:
        stop_service()
    except Exception:
        pass
