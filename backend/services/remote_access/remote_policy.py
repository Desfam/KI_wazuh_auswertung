"""
remote_access/remote_policy.py
Action-policy enforcement for the Server/Remote-Access layer.

Every remote action must pass through check_policy() before executing.
"""
from __future__ import annotations

from typing import Any, Optional

from .models import ServerActionResult


# Actions that are always blocked in Phase 1 regardless of policy
_PHASE1_BLOCKED_ACTIONS = {
    "ssh_connect",
    "ssh_interactive_shell",
    "ssh_arbitrary_command",
    "ssh_key_deploy",
    "ssh_port_forward",
    "ssh_upload",
    "ssh_delete",
    "ssh_edit_remote",
    "rdp_password_inject",
    "winrm_execute",
    "winrm_ps_remoting",
    "reboot",
    "shutdown",
    "kill_process",
    "install_software",
    "firewall_change",
    "user_management",
}

# Actions allowed in Phase 1
_PHASE1_ALLOWED_ACTIONS = {
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
    "ssh_host_info",
    "ssh_readonly_command",
    "ssh_file_list",
    "ssh_file_download",
    "rdp_open",           # opens mstsc without password — controlled + audited
    "wol",                # Wake-on-LAN — controlled + audited
    "health_check",
    "import_legacy",
    "export_ssh_config",
    # Phase 1 batch + group operations (read-only)
    "batch_health",
    "batch_ping",
    "batch_port_check",
    "group_manage",
}


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

    # 1. Phase 1 hard block
    if action in _PHASE1_BLOCKED_ACTIONS:
        return ServerActionResult(
            status="blocked",
            message=f"Action '{action}' is disabled in Phase 1.",
            policy="phase1_blocked",
            policy_reason=(
                f"'{action}' is on the Phase 1 disabled list. "
                "Implement audit trail and confirmation dialog before enabling."
            ),
        )

    # 2. No connection → only CRUD management and local network tools allowed
    _NO_CONNECTION_ALLOWED = {
        # Store management — no host needed
        "list_connections", "create_connection", "update_connection",
        "delete_connection", "import_legacy",
        # Bulk export — reads local DB only, no network
        "export_ssh_config",
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

    # 3. Unified host policy check
    if unified_host:
        uh_policy = unified_host.get("action_policy", "unknown")
        uh_reason = unified_host.get("policy_reason", "")
        identity   = unified_host.get("identity_status", "unknown")

        if uh_policy == "blocked":
            return ServerActionResult(
                status="blocked",
                message=f"Host is blocked by action policy: {uh_reason or uh_policy}",
                policy=uh_policy,
                policy_reason=uh_reason or "Host identity is blocked — no remote actions allowed.",
            )

        if uh_policy == "review_required":
            # Only read-only actions allowed without explicit confirmation here;
            # write-like actions require the caller to handle confirmation
            readonly_actions = {
                "ping", "dns_lookup", "reverse_dns", "port_check", "traceroute",
                "arp_lookup", "connection_test", "ssh_host_info", "ssh_readonly_command",
                "ssh_file_list", "health_check",
            }
            if action not in readonly_actions:
                return ServerActionResult(
                    status="review_required",
                    message=f"Host requires review before action '{action}'.",
                    policy=uh_policy,
                    policy_reason=uh_reason or "Identity review is required before controlled actions.",
                )

    # 4. Phase 1 allowed list
    if action not in _PHASE1_ALLOWED_ACTIONS:
        return ServerActionResult(
            status="blocked",
            message=f"Action '{action}' is not in the Phase 1 allowed list.",
            policy="not_allowed",
            policy_reason="Action has not been enabled in the current security phase.",
        )

    return ServerActionResult(status="ok", message="Action allowed.")
