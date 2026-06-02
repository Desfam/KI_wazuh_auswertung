"""
host_explain.py
================
Pure helper that produces human-readable trust-explanation fields for a
unified_host dict.  No database calls – all inputs come from the caller.

Exported:
  explain_host_trust(host, conflicts=None) -> dict

Returned keys:
  identity_reason        : str
  policy_reason          : str
  match_confidence_label : "trusted" | "likely" | "uncertain" | "conflict" | "unknown"
  match_evidence         : list[str]
  conflict_evidence      : list[str]
  recommended_next_step  : str
"""
from __future__ import annotations

from typing import Any


def explain_host_trust(
    host: dict[str, Any],
    conflicts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build explanation fields from a unified_host record and its conflicts.

    All inputs are read-only; no side effects.
    """
    identity  = (host.get("identity_status") or "unknown").lower()
    policy    = (host.get("action_policy") or "blocked").lower()
    source    = (host.get("match_source") or "").lower()
    score     = int(host.get("match_score") or 0)
    wazuh_st  = (host.get("wazuh_status") or "unknown").lower()
    tact_st   = (host.get("tactical_status") or "unknown").lower()
    match_st  = (host.get("match_status") or "unknown").lower()
    wazuh_id  = host.get("wazuh_agent_id")
    tact_id   = host.get("tactical_agent_id")
    os_plat   = host.get("os_platform") or ""
    primary_ip = host.get("primary_ip") or ""

    # ── build match evidence ──────────────────────────────────────────────────
    evidence: list[str] = []

    if "agent_id" in source:
        evidence.append("Wazuh agent ID matched exactly in unified hosts")
    if "exact_hostname" in source:
        evidence.append("Hostname matched exactly (case-insensitive)")
    if "norm_hostname" in source:
        evidence.append("Hostname matched after normalisation (short label)")
    if "fqdn" in source:
        evidence.append("FQDN matched after DNS-label normalisation")
    if "ip" in source:
        evidence.append(f"IP address matched ({primary_ip})")
    if "+os" in source and os_plat:
        evidence.append(f"OS platform matched ({os_plat})")

    if wazuh_id:
        evidence.append(f"Wazuh agent ID linked: {wazuh_id} (status: {wazuh_st})")
    if tact_id:
        evidence.append(f"Tactical RMM agent linked: {tact_id} (status: {tact_st})")
    if score > 0 and "new" not in source:
        evidence.append(f"Match confidence score: {score}/100")

    # ── build conflict evidence ───────────────────────────────────────────────
    conflict_ev: list[str] = []

    if match_st == "conflict":
        conflict_ev.append("Multiple Wazuh agents matched the same unified host record")
    if conflicts:
        for c in conflicts:
            if not c.get("resolved"):
                desc = c.get("description") or c.get("conflict_type") or "unknown conflict"
                conflict_ev.append(desc)

    # ── identity reason ───────────────────────────────────────────────────────
    if match_st == "conflict" or (identity in ("uncertain",) and conflict_ev):
        id_reason = (
            "Multiple Wazuh agents matched the same host record, creating "
            "ambiguity about which agent represents this host."
        )
    elif identity == "trusted":
        if "agent_id" in source:
            id_reason = (
                "Wazuh agent ID matched exactly in unified hosts — "
                "highest-confidence identity signal."
            )
        elif "exact_hostname" in source:
            id_reason = (
                "Hostname and additional signals matched exactly between "
                "Wazuh and Tactical sources, giving trusted identity."
            )
        else:
            id_reason = (
                f"Strong match (score {score}/100) via "
                + _readable_source(source)
                + " — identity considered trusted."
            )
    elif identity == "likely":
        if "exact_hostname" in source or "norm_hostname" in source:
            id_reason = (
                f"Hostname match confirmed (score {score}/100), "
                "but Wazuh agent ID is not yet directly linked."
            )
        elif "fqdn" in source:
            id_reason = (
                f"FQDN normalised match (score {score}/100). "
                "Verify that the FQDN belongs to the expected host."
            )
        else:
            id_reason = (
                f"Partial match (score {score}/100) via "
                + _readable_source(source)
                + ". Identity is likely but not fully confirmed."
            )
    elif identity == "uncertain":
        if "ip" in source and "agent_id" not in source and "hostname" not in source:
            id_reason = (
                f"Host matched by IP address only ({primary_ip}). "
                "Hostname or agent ID do not align — identity is uncertain."
            )
        else:
            id_reason = (
                f"Low-confidence match (score {score}/100) via "
                + _readable_source(source)
                + ". Signals are insufficient to confirm identity."
            )
    else:
        # unknown
        if not wazuh_id and not tact_id:
            id_reason = "No Wazuh or Tactical agent is linked to this host."
        elif not wazuh_id:
            id_reason = (
                "Tactical RMM agent is linked, "
                "but no Wazuh agent has been matched yet. "
                "Run Wazuh Sync to attempt matching."
            )
        elif not tact_id:
            id_reason = (
                "Wazuh agent is linked, "
                "but no Tactical RMM agent has been matched yet. "
                "Run Tactical Sync to attempt matching."
            )
        else:
            id_reason = (
                "Host could not be positively matched from available signals."
            )

    # ── policy reason ─────────────────────────────────────────────────────────
    if match_st == "conflict" or (policy == "blocked" and conflict_ev):
        pol_reason = (
            "Action policy is blocked due to an identity conflict. "
            "Multiple agents match the same host — "
            "actions cannot be safely dispatched until the conflict is resolved."
        )
    elif policy == "blocked" and score == 0:
        pol_reason = (
            "No host identity match was found. "
            "All actions are blocked until the host is identified."
        )
    elif policy == "blocked":
        pol_reason = (
            f"Action policy is blocked: identity status is '{identity}'. "
            + (
                "Resolve active conflicts before enabling actions."
                if conflict_ev
                else "Confirm host identity before enabling actions."
            )
        )
    elif policy == "review_required":
        if identity == "trusted":
            pol_reason = (
                "Host identity is confirmed. "
                "Controlled actions require manual review in the current phase "
                "(Phase 1 safety constraint)."
            )
        elif identity == "likely":
            pol_reason = (
                "Host matched with high confidence. "
                "Manual review is required before taking any action."
            )
        else:
            pol_reason = (
                "Partial identity match. "
                "Manual review required before any action can be taken."
            )
    else:
        pol_reason = "Action policy allows read-only access."

    # ── recommended next step ─────────────────────────────────────────────────
    if match_st == "conflict":
        next_step = (
            "Go to Unified Hosts → open the conflicted host → resolve which "
            "Wazuh agent is correct and remove or re-link the others."
        )
    elif identity == "unknown" and not wazuh_id:
        next_step = "Run Wazuh Sync in Unified Hosts to attempt automatic agent matching."
    elif identity == "unknown" and not tact_id:
        next_step = "Run Tactical Sync in Unified Hosts to link the Tactical RMM agent."
    elif identity == "uncertain":
        next_step = (
            "Verify the hostname/IP mapping for this host, "
            "then re-run Wazuh Sync or manually link the correct agent ID."
        )
    elif identity == "likely":
        next_step = (
            "Confirm the Wazuh agent ID link manually, "
            "or correct the hostname and re-run Wazuh Sync."
        )
    else:
        next_step = ""

    # ── confidence label ──────────────────────────────────────────────────────
    if match_st == "conflict":
        confidence_label = "conflict"
    else:
        confidence_label = identity  # trusted / likely / uncertain / unknown

    return {
        "identity_reason": id_reason,
        "policy_reason": pol_reason,
        "match_confidence_label": confidence_label,
        "match_evidence": evidence,
        "conflict_evidence": conflict_ev,
        "recommended_next_step": next_step,
    }


# ── internal helpers ──────────────────────────────────────────────────────────

def _readable_source(source: str) -> str:
    """Convert a raw match_source string to a readable label."""
    base = source.replace("wazuh_", "").split("+")[0]
    mapping = {
        "agent_id":       "agent ID",
        "exact_hostname": "exact hostname",
        "norm_hostname":  "normalised hostname",
        "fqdn":           "FQDN",
        "ip":             "IP address",
        "new":            "new (unmatched)",
    }
    return mapping.get(base, base.replace("_", " "))
