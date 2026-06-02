"""
remote_access/models.py
Shared data models (plain dataclasses / TypedDicts) used across services.
No DB imports here — pure data structures.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ServerConnection:
    id: str
    name: str
    hostname: str = ""
    ip: str = ""
    protocol: str = "ssh"          # ssh | rdp | winrm
    port: int = 22
    username: str = ""
    auth_type: str = "none"        # none | key_ref | agent | credential_ref
    credential_ref: str = ""
    key_ref: str = ""
    os: str = ""
    platform: str = ""
    tags: list[str] = field(default_factory=list)
    favorite: bool = False
    mac: str = ""
    unified_host_id: str = ""
    tactical_agent_id: str = ""
    wazuh_agent_id: str = ""
    notes: str = ""
    created_at: str = ""
    updated_at: str = ""

    @property
    def target_host(self) -> str:
        return self.hostname or self.ip

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "hostname": self.hostname,
            "ip": self.ip,
            "protocol": self.protocol,
            "port": self.port,
            "username": self.username,
            "auth_type": self.auth_type,
            "credential_ref": self.credential_ref,
            "key_ref": self.key_ref,
            "os": self.os,
            "platform": self.platform,
            "tags": self.tags,
            "favorite": self.favorite,
            "mac": self.mac,
            "unified_host_id": self.unified_host_id,
            "tactical_agent_id": self.tactical_agent_id,
            "wazuh_agent_id": self.wazuh_agent_id,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class ServerActionResult:
    status: str                          # ok | blocked | review_required | error | unavailable
    message: str
    policy: str = ""
    policy_reason: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    audit_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "message": self.message,
            "policy": self.policy,
            "policy_reason": self.policy_reason,
            "data": self.data,
            "audit_id": self.audit_id,
        }


# Read-only SSH command allowlist
# Maps command_id -> actual command string
SSH_READONLY_COMMANDS: dict[str, str] = {
    # Linux
    "uname":           "uname -a",
    "hostnamectl":     "hostnamectl",
    "uptime":          "uptime",
    "df":              "df -h",
    "free":            "free -m",
    "who":             "who",
    "last":            "last -n 20",
    "ss":              "ss -tulpn",
    "systemctl_fail":  "systemctl --failed --no-pager",
    "ps_cpu":          "ps aux --sort=-%cpu | head -20",
    "journalctl_warn": "journalctl -p warning -n 100 --no-pager",
    # Linux — extended (from SSH_Manager idea import)
    "os_release":      "cat /etc/os-release",
    "ip_addr":         "ip addr show",
    "mini_top":        "top -b -n1 | head -20",
    "dmesg_tail":      "dmesg | tail -20",
    # Windows over SSH
    "win_hostname":    "hostname",
    "win_whoami":      "whoami",
    "win_ipconfig":    "ipconfig /all",
    "win_tasklist":    "tasklist",
    "win_netstat":     "netstat -ano",
    "win_systeminfo":  "systeminfo",
    "win_services":    'sc query type= all state= all | findstr /C:"SERVICE_NAME" /C:"STATE"',
}
