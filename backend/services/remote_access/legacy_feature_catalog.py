"""
remote_access/legacy_feature_catalog.py
Feature catalog documenting all concepts identified from SSH_Manager analysis.

Each entry describes a feature with its implementation status, risk classification,
and the current enablement profile. This catalog is used by the Trust Center validator
to assert that dangerous features remain disabled.

See: docs/SSH_MANAGER_IDEA_IMPORT_PLAN.md for full planning context.
"""
from __future__ import annotations

from typing import Any

# Feature status values
STATUS_IMPLEMENTED = "implemented"
STATUS_PLANNED = "planned"        # Roadmap / future work
STATUS_DISABLED = "disabled"      # Explicitly blocked, not implemented
STATUS_REJECTED = "rejected"      # Will never be implemented

FEATURES: list[dict[str, Any]] = [
    # ── Currently Enabled — Implemented ──────────────────────────────────────
    {
        "id": "json_import",
        "name": "JSON config import (SSH_Manager format)",
        "description": "Import connections from nested JSON format: {\"ssh\":{name:{...}}, \"rdp\":{...}}",
        "source": "ssh_manager.json / legacy_importer.py",
        "risk_level": "low",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "services/remote_access/legacy_importer.py",
        "frontend": "SnipenPage / ServerPage import dialog",
        "audit": False,
        "policy_action": "import_legacy",
    },
    {
        "id": "csv_import",
        "name": "CSV connection import",
        "description": "Import connections from CSV with columns: name, hostname, ip, port, username, tags, ...",
        "source": "legacy_importer.py",
        "risk_level": "low",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "services/remote_access/legacy_importer.py",
        "frontend": "ServerPage import dialog",
        "audit": False,
        "policy_action": "import_legacy",
    },
    {
        "id": "ssh_connection_test",
        "name": "SSH connection test (TCP handshake)",
        "description": "Verify SSH port is reachable and handshake succeeds. No command execution.",
        "source": "ssh_service.py test_ssh_connection()",
        "risk_level": "low",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "services/remote_access/ssh_service.py",
        "frontend": "ServerPage connection card",
        "audit": True,
        "policy_action": "connection_test",
    },
    {
        "id": "ssh_readonly_commands",
        "name": "SSH read-only command execution (allowlist)",
        "description": "Execute a fixed set of safe read-only commands via SSH. "
                       "Command IDs map to hardcoded strings in SSH_READONLY_COMMANDS — "
                       "no raw user input accepted.",
        "source": "models.SSH_READONLY_COMMANDS + ssh_service.run_readonly_command()",
        "risk_level": "low",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "services/remote_access/ssh_service.py, models.py",
        "frontend": "ServerPage SSH command panel",
        "audit": True,
        "policy_action": "ssh_readonly_command",
    },
    {
        "id": "ssh_file_list",
        "name": "SFTP directory listing",
        "description": "List files in a remote directory via SFTP. Read-only. "
                       "Paths sanitised with posixpath.normpath.",
        "source": "ssh_service.list_remote_directory()",
        "risk_level": "low",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "services/remote_access/ssh_service.py",
        "frontend": "ServerPage SFTP panel",
        "audit": True,
        "policy_action": "ssh_file_list",
    },
    {
        "id": "ssh_file_download",
        "name": "SFTP file download",
        "description": "Download a single file from a remote host via SFTP.",
        "source": "ssh_service.download_file()",
        "risk_level": "low",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "services/remote_access/ssh_service.py",
        "frontend": "ServerPage SFTP panel",
        "audit": True,
        "policy_action": "ssh_file_download",
    },
    {
        "id": "rdp_open",
        "name": "RDP session launch (mstsc.exe)",
        "description": "Open Windows Remote Desktop via mstsc.exe. No password injection. Windows-only.",
        "source": "rdp_service.py",
        "risk_level": "low",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "services/remote_access/rdp_service.py",
        "frontend": "ServerPage RDP button",
        "audit": True,
        "policy_action": "rdp_open",
    },
    {
        "id": "wol",
        "name": "Wake-on-LAN (Magic Packet)",
        "description": "Send UDP Magic Packet to wake a host. Requires MAC address. "
                       "Classified as controlled_action.",
        "source": "host_tools_service.py",
        "risk_level": "low",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "services/remote_access/host_tools_service.py",
        "frontend": "ServerPage host card",
        "audit": True,
        "policy_action": "wol",
    },
    {
        "id": "network_diagnostics",
        "name": "Network diagnostics (ping, DNS, ports, traceroute)",
        "description": "Passive network tools. No writes on remote system.",
        "source": "host_tools_service.py",
        "risk_level": "low",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "services/remote_access/host_tools_service.py",
        "frontend": "ServerPage tools panel",
        "audit": False,
        "policy_action": "ping",
    },
    {
        "id": "password_import_blocked",
        "name": "Password import prevention",
        "description": "Legacy importer never imports plaintext passwords. "
                       "_WARNED_FIELDS = {password, passwd, pass, secret}.",
        "source": "legacy_importer._WARNED_FIELDS",
        "risk_level": "none",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "services/remote_access/legacy_importer.py",
        "frontend": None,
        "audit": False,
        "policy_action": None,
    },
    {
        "id": "ssh_config_export",
        "name": "SSH config export (bulk OpenSSH format)",
        "description": "Generate ~/.ssh/config text from all SSH connections as a preview. "
                       "Never writes to disk automatically. Passwords are never included. "
                       "Host aliases are sanitised to prevent injection.",
        "source": "SSH_Manager: auto-generate ~/.ssh/config (adapted: preview-only, no auto-write)",
        "risk_level": "low",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "services/remote_access/ssh_config_exporter.py",
        "frontend": "ServerPage Export SSH Config modal",
        "audit": True,
        "policy_action": "export_ssh_config",
    },

    {
        "id": "file_upload",
        "name": "SFTP file upload",
        "description": "Upload files to remote host via SFTP with mandatory reason and audit logging.",
        "source": "ssh_service.upload_file() + routes_server ssh/file-upload",
        "risk_level": "medium",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "api/routes_server.py, services/remote_access/ssh_service.py",
        "frontend": "ServerPage SFTP panel",
        "audit": True,
        "policy_action": "ssh_file_upload",
    },
    {
        "id": "file_delete",
        "name": "SFTP file delete",
        "description": "Delete remote files via SFTP with mandatory reason, filename confirmation, and audit logging.",
        "source": "ssh_service.delete_file() + routes_server ssh/file-delete",
        "risk_level": "medium",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "api/routes_server.py, services/remote_access/ssh_service.py",
        "frontend": "ServerPage SFTP panel",
        "audit": True,
        "policy_action": "ssh_file_delete",
    },

    # ── Advanced remote operations (implemented) ─────────────────────────────
    {
        "id": "web_ssh_terminal",
        "name": "Interactive SSH terminal launch",
        "description": "Launches a native SSH client process for interactive terminal access with audit logging.",
        "source": "routes_server ssh/interactive-shell + ssh_service.launch_native_ssh_shell",
        "risk_level": "high",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "api/routes_server.py, services/remote_access/ssh_service.py",
        "frontend": "ServerPage SSH tab",
        "audit": True,
        "policy_action": "ssh_interactive_shell",
    },
    {
        "id": "ssh_key_deployment",
        "name": "SSH public key deployment",
        "description": "Append a public key to remote ~/.ssh/authorized_keys. "
                       "Requires Approval workflow and audit log.",
        "source": "SSH_Manager ssh-copy-id equivalent",
        "risk_level": "high",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "api/routes_server.py, services/remote_access/ssh_service.py",
        "frontend": "ServerPage SSH tab",
        "audit": True,
        "policy_action": "ssh_key_deploy",
    },
    {
        "id": "port_forwarding",
        "name": "SSH port forwarding (-L / -R)",
        "description": "Local or remote port forwarding via SSH tunnel. "
                       "Requires explicit connection context and audit.",
        "source": "routes_server ssh/port-forward launcher",
        "risk_level": "high",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "api/routes_server.py",
        "frontend": "ServerPage SSH tab",
        "audit": True,
        "policy_action": "ssh_port_forward",
    },
    {
        "id": "winrm_remoting",
        "name": "PowerShell / WinRM remoting",
        "description": "Execute PowerShell commands remotely via WinRM. "
                   "Requires allowlist and approval workflow.",
        "source": "SSH_Manager powershell.exe subprocess",
        "risk_level": "high",
        "phase1": True,
        "phase2": False,
        "status": STATUS_IMPLEMENTED,
        "backend": "api/routes_server.py",
        "frontend": "ServerPage RDP/SSH tabs",
        "audit": True,
        "policy_action": "winrm_execute",
    },

    # ── Rejected — Will never be implemented ─────────────────────────────────
    {
        "id": "agent_deployment",
        "name": "Remote agent deployment (psutil HTTP server)",
        "description": "SSH_Manager deployed a psutil HTTP server on port 9876 with no authentication. "
                       "This is a severe security vulnerability (unauthenticated RCE surface). REJECTED.",
        "source": "SSH_Manager agent.py (psutil HTTP port 9876, no auth)",
        "risk_level": "critical",
        "phase1": False,
        "phase2": False,
        "status": STATUS_REJECTED,
        "backend": "REJECTED",
        "frontend": "REJECTED",
        "audit": False,
        "policy_action": None,
        "rejection_reason": "Unauthenticated HTTP endpoint on remote host — severe RCE attack surface.",
    },
    {
        "id": "remote_reboot",
        "name": "Remote reboot / shutdown",
        "description": "Execute reboot or shutdown commands on remote hosts.",
        "source": "SSH_Manager ssh reboot",
        "risk_level": "critical",
        "phase1": False,
        "phase2": False,
        "status": STATUS_REJECTED,
        "backend": "REJECTED — destructive action remains safety_blocked",
        "frontend": "REJECTED",
        "audit": False,
        "policy_action": "reboot",
        "rejection_reason": "Irreversible destructive action — requires physical or out-of-band approval.",
    },
    {
        "id": "remote_process_kill",
        "name": "Remote process kill",
        "description": "Send kill signal to remote process by PID.",
        "source": "SSH_Manager kill -9",
        "risk_level": "high",
        "phase1": False,
        "phase2": False,
        "status": STATUS_REJECTED,
        "backend": "REJECTED — destructive action remains safety_blocked",
        "frontend": "REJECTED",
        "audit": False,
        "policy_action": "kill_process",
        "rejection_reason": "High potential for service disruption without reversibility.",
    },
    {
        "id": "remote_firewall_change",
        "name": "Remote firewall rule management",
        "description": "Add/remove iptables or firewalld rules on remote hosts via SSH.",
        "source": "SSH_Manager concept",
        "risk_level": "critical",
        "phase1": False,
        "phase2": False,
        "status": STATUS_REJECTED,
        "backend": "REJECTED — destructive action remains safety_blocked",
        "frontend": "REJECTED",
        "audit": False,
        "policy_action": "firewall_change",
        "rejection_reason": "Can lock out all access to a host — must go through change management.",
    },
    {
        "id": "remote_user_management",
        "name": "Remote user account management",
        "description": "Create/modify/delete user accounts on remote hosts via SSH.",
        "source": "SSH_Manager concept",
        "risk_level": "critical",
        "phase1": False,
        "phase2": False,
        "status": STATUS_REJECTED,
        "backend": "REJECTED — destructive action remains safety_blocked",
        "frontend": "REJECTED",
        "audit": False,
        "policy_action": "user_management",
        "rejection_reason": "Privilege escalation risk — out of scope for this platform.",
    },
]

# ── Helper accessors ──────────────────────────────────────────────────────────

_FEATURE_INDEX: dict[str, dict[str, Any]] = {f["id"]: f for f in FEATURES}


def get_feature(feature_id: str) -> dict[str, Any] | None:
    """Return a single feature entry by ID, or None if not found."""
    return _FEATURE_INDEX.get(feature_id)


def get_phase1_features() -> list[dict[str, Any]]:
    """Return all features currently enabled in the baseline profile."""
    return [f for f in FEATURES if f.get("phase1")]


def get_phase2_features() -> list[dict[str, Any]]:
    """Return all planned roadmap features."""
    return [f for f in FEATURES if f.get("phase2") and not f.get("phase1")]


def get_disabled_features() -> list[dict[str, Any]]:
    """Return all features that are currently disabled (planned or rejected)."""
    return [f for f in FEATURES if f["status"] in (STATUS_DISABLED, STATUS_REJECTED)]


def get_rejected_features() -> list[dict[str, Any]]:
    """Return all features that have been permanently rejected."""
    return [f for f in FEATURES if f["status"] == STATUS_REJECTED]
