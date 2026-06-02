"""
remote_access/host_tools_service.py
Ping, DNS, port check, traceroute, ARP, Wake-on-LAN.
All functions have timeouts and return structured dicts.
"""
from __future__ import annotations

import platform
import socket
import struct
import subprocess
import time
from typing import Any


def ping_host(host: str, count: int = 4, timeout: int = 5) -> dict[str, Any]:
    """ICMP ping using system ping command."""
    is_win = platform.system().lower() == "windows"
    count_flag = "-n" if is_win else "-c"
    timeout_flag = ["-w", str(timeout * 1000)] if is_win else ["-W", str(timeout)]

    cmd = ["ping", count_flag, str(count)] + timeout_flag + [host]
    try:
        start = time.monotonic()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        elapsed_ms = round((time.monotonic() - start) * 1000)
        success = result.returncode == 0
        output_lines = (result.stdout or result.stderr or "").strip().splitlines()

        # Parse avg RTT from output
        avg_ms: float | None = None
        for line in output_lines:
            ll = line.lower()
            if "average" in ll or "avg" in ll:
                parts = ll.replace("ms", "").split()
                for i, p in enumerate(parts):
                    if "average" in p or "avg" in p:
                        try:
                            avg_ms = float(parts[i + 1].strip(" ="))
                        except Exception:
                            pass

        return {
            "host": host,
            "reachable": success,
            "packets_sent": count,
            "elapsed_ms": elapsed_ms,
            "avg_rtt_ms": avg_ms,
            "raw": "\n".join(output_lines[-8:]),
        }
    except subprocess.TimeoutExpired:
        return {"host": host, "reachable": False, "error": "Ping timed out"}
    except Exception as exc:
        return {"host": host, "reachable": False, "error": str(exc)}


def dns_lookup(host: str, timeout: int = 5) -> dict[str, Any]:
    """Forward DNS lookup."""
    try:
        socket.setdefaulttimeout(timeout)
        addrs = socket.getaddrinfo(host, None)
        ips = list({a[4][0] for a in addrs})
        return {"host": host, "resolved": True, "addresses": ips}
    except socket.gaierror as exc:
        return {"host": host, "resolved": False, "error": str(exc)}
    except Exception as exc:
        return {"host": host, "resolved": False, "error": str(exc)}
    finally:
        socket.setdefaulttimeout(None)


def reverse_dns(ip: str, timeout: int = 5) -> dict[str, Any]:
    """Reverse DNS lookup."""
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return {"ip": ip, "resolved": True, "hostname": hostname}
    except socket.herror as exc:
        return {"ip": ip, "resolved": False, "error": str(exc)}
    except Exception as exc:
        return {"ip": ip, "resolved": False, "error": str(exc)}
    finally:
        socket.setdefaulttimeout(None)


def port_check(host: str, ports: list[int], timeout: float = 2.0) -> dict[str, Any]:
    """TCP port reachability check."""
    results: list[dict[str, Any]] = []
    for p in ports[:20]:  # cap at 20 ports per request
        try:
            with socket.create_connection((host, int(p)), timeout=timeout):
                results.append({"port": p, "open": True})
        except OSError:
            results.append({"port": p, "open": False})
        except Exception as exc:
            results.append({"port": p, "open": False, "error": str(exc)})
    open_count = sum(1 for r in results if r.get("open"))
    return {"host": host, "ports": results, "open_count": open_count}


def traceroute(host: str, timeout: int = 15) -> dict[str, Any]:
    """Run traceroute / tracert and return raw output."""
    is_win = platform.system().lower() == "windows"
    cmd = ["tracert", "-h", "15", host] if is_win else ["traceroute", "-m", "15", host]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        lines = (result.stdout or result.stderr or "").strip().splitlines()
        return {"host": host, "hops": lines}
    except FileNotFoundError:
        return {"host": host, "hops": [], "error": "traceroute not available"}
    except subprocess.TimeoutExpired:
        return {"host": host, "hops": [], "error": "Traceroute timed out"}
    except Exception as exc:
        return {"host": host, "hops": [], "error": str(exc)}


def arp_lookup(ip: str, timeout: int = 10) -> dict[str, Any]:
    """ARP table lookup for a given IP."""
    is_win = platform.system().lower() == "windows"
    cmd = ["arp", "-a", ip] if is_win else ["arp", "-n", ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        lines = (result.stdout or "").strip().splitlines()
        # Try to extract MAC from output
        mac: str | None = None
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                candidate = parts[1] if is_win else (parts[-1] if len(parts) > 2 else None)
                if candidate and (
                    len(candidate) == 17 and candidate.count("-") == 5
                    or len(candidate) == 17 and candidate.count(":") == 5
                ):
                    mac = candidate
                    break
        return {"ip": ip, "mac": mac, "raw": "\n".join(lines)}
    except subprocess.TimeoutExpired:
        return {"ip": ip, "mac": None, "error": "ARP lookup timed out"}
    except Exception as exc:
        return {"ip": ip, "mac": None, "error": str(exc)}


def wake_on_lan(mac: str, broadcast: str = "255.255.255.255", port: int = 9) -> dict[str, Any]:
    """Send a Wake-on-LAN magic packet."""
    try:
        mac_clean = mac.replace(":", "").replace("-", "").replace(".", "").upper()
        if len(mac_clean) != 12:
            return {"status": "error", "message": "Invalid MAC address format"}
        mac_bytes = bytes.fromhex(mac_clean)
        magic = b"\xff" * 6 + mac_bytes * 16
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(magic, (broadcast, port))
        return {"status": "ok", "message": f"Magic packet sent to {mac} via {broadcast}:{port}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
