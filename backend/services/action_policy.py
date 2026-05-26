"""Action Policy Service
========================
Normalise host action policy from unified host identity data.

Policy values
-------------
- blocked          : cannot safely take any action on this host
- review_required  : read-only actions allowed, manual review required
- allowed          : (reserved for future) all actions allowed pending RBAC

Security rule:
Even if policy is 'allowed', dangerous_actions_enabled is always False
in Phase 1.
"""
from __future__ import annotations


def get_action_policy_for_unified_host(
    host: dict,
    conflicts: list[dict] | None = None,
) -> dict:
    """Return a normalised action policy dict for a unified host.

    Parameters
    ----------
    host:
        Unified host dict from the database (or a partial dict with at
        least ``identity_status`` and ``action_policy`` keys).
    conflicts:
        Active host conflict list from ``list_host_conflicts()``.

    Returns
    -------
    dict with keys:
        policy                    : "blocked" | "review_required" | "allowed"
        reason                    : str
        dangerous_actions_enabled : False  (always in Phase 1)
        read_only_actions_enabled : bool
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

    # ── Identity status → policy ───────────────────────────────────────────────
    if identity_status in ("unknown", "uncertain"):
        return _blocked(
            f"Host identity status is '{identity_status}'. "
            "Cannot confirm host identity before taking any action."
        )

    if identity_status == "likely":
        return _review(
            "Host matched with 'likely' confidence. "
            "Manual review required before acting."
        )

    if identity_status == "trusted":
        return _review(
            "Host is trusted. Dangerous actions remain disabled in Phase 1."
        )

    # ── Legacy action_policy value mapping ────────────────────────────────────
    if action_policy_raw == "blocked":
        return _blocked("Host action policy is explicitly blocked.")

    if action_policy_raw in ("full", "allowed"):
        return {
            "policy": "allowed",
            "reason": (
                "Host action policy allows actions. "
                "Dangerous actions remain disabled in Phase 1."
            ),
            "dangerous_actions_enabled": False,
            "read_only_actions_enabled": True,
        }

    # Default: read_only → review_required
    return _review("Host is in read-only / review mode.")


def _blocked(reason: str) -> dict:
    return {
        "policy": "blocked",
        "reason": reason,
        "dangerous_actions_enabled": False,
        "read_only_actions_enabled": False,
    }


def _review(reason: str) -> dict:
    return {
        "policy": "review_required",
        "reason": reason,
        "dangerous_actions_enabled": False,
        "read_only_actions_enabled": True,
    }
