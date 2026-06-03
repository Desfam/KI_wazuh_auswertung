"""
remote_access/remote_policy.py
Action-policy enforcement for the Server/Remote-Access layer.

Every remote action must pass through check_policy() before executing.
"""
from __future__ import annotations

import os
from typing import Any, Optional

from .models import ServerActionResult


# Safety hard-block list for destructive or not-yet-controlled operations.
_SAFETY_BLOCKED_ACTIONS: set[str] = {
    "rdp_password_inject",
    "ssh_edit_remote",
    "winrm_ps_remoting",
    "reboot",
    "shutdown",
    "kill_process",
    "install_software",
    "firewall_change",
    "user_management",
}

# High-risk actions require a linked and resolved unified host before execution.
_REQUIRES_UNIFIED_HOST_MATCH: set[str] = {
    "ssh_arbitrary_command",
    "ssh_key_deploy",
    "ssh_port_forward",
    "winrm_execute",
}

# Actions currently supported by the backend implementation
_IMPLEMENTED_ACTIONS = {
    "list_connections",
    "create_connection",
    "update_connection",
    "delete_connection",
    "ping",
    "dns_lookup",
    "reverse_dns",
    "port_check",
    "traceroute",
    "arp_lookup",
    "connection_test",
    "ssh_connect",
    "ssh_interactive_shell",
    "ssh_arbitrary_command",
    "ssh_key_deploy",
    "ssh_port_forward",
    "ssh_upload",
    "ssh_delete",
    "ssh_edit_remote",
    "ssh_host_info",
    "ssh_readonly_command",
    "ssh_file_list",
    "ssh_file_download",
    "ssh_file_upload",
    "ssh_file_delete",
    "rdp_open",
    "wol",
    "health_check",
    "import_legacy",
    "export_ssh_config",
    "batch_health",
    "batch_ping",
    "batch_port_check",
    "group_manage",
    "wazuh_agent_reconnect",
    "run_syscheck",
    "run_rootcheck",
    "winrm_execute",
    "winrm_ps_remoting",
    "reboot",
    "shutdown",
    "kill_process",
    "install_software",
    "firewall_change",
    "user_management",
}

_SAFE_MODE_ACTIONS = {
    "list_connections",
    "create_connection",
    "update_connection",
    "delete_connection",
    "import_legacy",
    "export_ssh_config",
    "batch_health",
    "batch_ping",
    "batch_port_check",
    "group_manage",
    "ping",
    "dns_lookup",
    "reverse_dns",
    "port_check",
    "traceroute",
    "arp_lookup",
    "connection_test",
    "ssh_host_info",
    "ssh_readonly_command",
    "ssh_file_list",
    "ssh_file_download",
    "rdp_open",
    "wol",
    "health_check",
}

_ADMIN_MODE_ACTIONS = _SAFE_MODE_ACTIONS | {
    "ssh_connect",
    "ssh_interactive_shell",
    "ssh_arbitrary_command",
    "ssh_key_deploy",
    "ssh_port_forward",
    "ssh_upload",
    "ssh_delete",
    "ssh_file_upload",
    "ssh_file_delete",
    "winrm_execute",
    "wazuh_agent_reconnect",
    "run_syscheck",
    "run_rootcheck",
}

_BREAK_GLASS_ACTIONS = _ADMIN_MODE_ACTIONS | {
    "winrm_ps_remoting",
    "reboot",
    "shutdown",
    "kill_process",
    "install_software",
    "firewall_change",
    "user_management",
}


def _current_remote_mode() -> str:
    """Return current remote-access operating mode: safe/admin/break_glass."""
    value = str(os.getenv("REMOTE_ACCESS_MODE", "admin")).strip().lower()
    if value in {"safe", "admin", "break_glass"}:
        return value
    return "admin"


def _actions_for_mode(mode: str) -> set[str]:
    if mode == "safe":
        return set(_SAFE_MODE_ACTIONS)
    if mode == "break_glass":
        return set(_BREAK_GLASS_ACTIONS)
    return set(_ADMIN_MODE_ACTIONS)


def check_policy(
    action: str,
    connection: Optional[dict[str, Any]],
    unified_host: Optional[dict[str, Any]] = None,
) -> ServerActionResult:
    """
    Returns a ServerActionResult.
    status == "ok"              → action is allowed, proceed
    status == "blocked"         → action must not execute
    status == "review_required" → can proceed but needs confirmation + audit
    """

    # 1. Safety block for operations without a dedicated controlled-action flow
    if action in _SAFETY_BLOCKED_ACTIONS:
        return ServerActionResult(
            status="blocked",
            message=f"Action '{action}' is disabled by safety policy.",
            policy="safety_blocked",
            policy_reason=(
                f"'{action}' needs a dedicated audit trail and confirmation dialog before enabling."
            ),
        )

    # 2. No connection → only CRUD management and local network tools allowed
    _NO_CONNECTION_ALLOWED = {
        # Store management — no host needed
        "list_connections", "create_connection", "update_connection",
        "delete_connection", "import_legacy",
        # Bulk export — reads local DB only, no network
        "export_ssh_config",
        # Batch and group operations use stored connection IDs
        "batch_health", "batch_ping", "batch_port_check", "group_manage",
        # Local network diagnostics
        "ping", "dns_lookup", "reverse_dns", "port_check", "traceroute", "arp_lookup",
    }
    if connection is None:
        if action not in _NO_CONNECTION_ALLOWED:
            return ServerActionResult(
                status="blocked",
                message="No connection context — only local network tools are allowed.",
                policy="no_connection",
                policy_reason="A connection record must exist before performing host actions.",
            )
        return ServerActionResult(status="ok", message="Action allowed without connection context.")

    # 3. High-risk actions require unified-host linkage/match context.
    if action in _REQUIRES_UNIFIED_HOST_MATCH:
        has_link = bool(connection.get("unified_host_id"))
        if not has_link or not unified_host:
            return ServerActionResult(
                status="blocked",
                message=f"Action '{action}' requires matched host identity.",
                policy="host_match_required",
                policy_reason=(
                    "Link this connection to a unified host and resolve host identity before running high-risk actions."
                ),
            )

    # 4. Unified host policy check
    if unified_host:
        uh_policy = unified_host.get("action_policy", "unknown")
        uh_reason = unified_host.get("policy_reason", "")
        identity   = unified_host.get("identity_status", "unknown")

        if uh_policy == "blocked":
            return ServerActionResult(
                status="blocked",
                message=f"Host action policy blocks '{action}': {uh_reason or uh_policy}",
                policy="host_blocked",
                policy_reason=uh_reason or "Host identity policy blocks remote actions for this endpoint.",
            )

        if uh_policy == "review_required" or identity in ("unknown", "uncertain", "likely"):
            return ServerActionResult(
                status="review_required",
                message=f"Host requires review before action '{action}'.",
                policy="review_required",
                policy_reason=uh_reason or "Identity review is required before controlled actions.",
            )

    # 5. Backend implementation guard
    if action not in _IMPLEMENTED_ACTIONS:
        return ServerActionResult(
            status="blocked",
            message=f"Action '{action}' is not implemented.",
            policy="backend_route_missing",
            policy_reason="Backend route missing for this action.",
        )

    # 6. Mode guard
    mode = _current_remote_mode()
    allowed_in_mode = _actions_for_mode(mode)
    if action not in allowed_in_mode:
        return ServerActionResult(
            status="blocked",
            message=f"Action '{action}' is blocked in '{mode}' mode.",
            policy="mode_blocked",
            policy_reason=(
                "Switch to ADMIN mode for confirmed admin actions or BREAK_GLASS for destructive actions."
            ),
        )

    return ServerActionResult(status="ok", message="Action allowed.")
