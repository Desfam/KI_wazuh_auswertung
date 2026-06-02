"""Action Policy Service
========================
Normalise host action policy from unified host identity data.

Policy values
-------------
- blocked          : cannot safely take action on this host
- review_required  : read-only and controlled actions need review/audit
- allowed          : trusted identity; controlled actions may proceed via RBAC/audit

Security rule:
Destructive actions are never enabled by this generic host policy alone.  They
must be explicitly implemented as controlled actions with RBAC, confirmation and
audit logging in the caller.
"""
from __future__ import annotations


def get_action_policy_for_unified_host(
    host: dict,
    conflicts: list[dict] | None = None,
) -> dict:
    """Return a normalised action policy dict for a unified host.

    Returns a dict with:
        policy                     : "blocked" | "review_required" | "allowed"
        reason                     : human-readable reason
        read_only_actions_enabled  : bool
        controlled_actions_enabled : bool
        dangerous_actions_enabled  : bool  (always false here)
    """
    if not isinstance(host, dict):
        return _blocked("No host context available.")

    identity_status: str = (host.get("identity_status") or "unknown").lower()
    action_policy_raw: str = (host.get("action_policy") or "read_only").lower()

    # ── Active blocking conflicts ──────────────────────────────────────────────
    if conflicts:
        for c in conflicts:
            if not c.get("resolved") and c.get("is_active"):
                ctype: str = (c.get("conflict_type") or "").lower()
                csev: str = (c.get("severity") or "").lower()
                if csev == "critical" or ctype in ("os_mismatch", "duplicate_ip"):
                    desc = c.get("description") or ctype
                    return _blocked(f"Active conflict blocks action: {desc}")

    # ── Explicit database policy wins when blocked ─────────────────────────────
    if action_policy_raw == "blocked":
        return _blocked("Host action policy is explicitly blocked.")

    # ── Identity status → policy ───────────────────────────────────────────────
    if identity_status in ("unknown", "uncertain"):
        return _blocked(
            f"Host identity status is '{identity_status}'. "
            "Cannot confirm host identity before taking remote or endpoint actions."
        )

    if identity_status == "likely":
        return _review(
            "Host matched with likely confidence. Read-only actions are allowed; "
            "controlled actions require confirmation and audit."
        )

    if identity_status == "trusted":
        return {
            "policy": "allowed",
            "reason": (
                "Host identity is trusted. Read-only actions are allowed and "
                "controlled actions may proceed when RBAC, confirmation and audit pass."
            ),
            "dangerous_actions_enabled": False,
            "controlled_actions_enabled": True,
            "read_only_actions_enabled": True,
        }

    # ── Legacy action_policy value mapping ────────────────────────────────────
    if action_policy_raw in ("full", "allowed"):
        return {
            "policy": "allowed",
            "reason": (
                "Host action policy allows controlled actions when RBAC, "
                "confirmation and audit pass."
            ),
            "dangerous_actions_enabled": False,
            "controlled_actions_enabled": True,
            "read_only_actions_enabled": True,
        }

    # Default: read_only → review_required
    return _review("Host is in read-only / review mode.")


def _blocked(reason: str) -> dict:
    return {
        "policy": "blocked",
        "reason": reason,
        "dangerous_actions_enabled": False,
        "controlled_actions_enabled": False,
        "read_only_actions_enabled": False,
    }


def _review(reason: str) -> dict:
    return {
        "policy": "review_required",
        "reason": reason,
        "dangerous_actions_enabled": False,
        "controlled_actions_enabled": True,
        "read_only_actions_enabled": True,
    }
