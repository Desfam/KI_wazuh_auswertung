"""
wazuh_host_sync.py
==================
Sync Wazuh Manager agents into the unified_hosts table.

Matching priority (highest → lowest):
  1. Exact wazuh_agent_id       score=100  match_type='agent_id'
  2. Exact hostname              score=90   match_type='exact_hostname'
  3. Normalised hostname         score=75   match_type='norm_hostname'
  4. IP address                  score=60   match_type='ip'
  OS platform matching adds a +5 bonus when both sides agree.

Action policy from match score:
  score >= 60  → review_required  (known / uncertain match — human review needed)
  conflict     → blocked
  no match     → blocked (new entry created)

Identity status from match score:
  score == 100 → trusted
  score >=  75 → likely
  score >=  60 → uncertain
  else         → unknown

The manager agent "000" (the manager itself) is always excluded from sync.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ── hostname normalisation ─────────────────────────────────────────────────────

def _normalise(name: str | None) -> str:
    """Lowercase, take only the first DNS label, strip AD $ suffix."""
    if not name:
        return ""
    short = name.strip().lower().split(".")[0]
    short = short.rstrip("$")
    return short


# ── Wazuh agent status → canonical status ─────────────────────────────────────

def _wazuh_status(agent: dict[str, Any]) -> str:
    raw = str(agent.get("status") or "").lower()
    if raw == "active":
        return "online"
    if raw in ("disconnected", "never_connected"):
        return "offline"
    if raw == "pending":
        return "pending"
    return "unknown"


# ── per-agent matching ─────────────────────────────────────────────────────────

def _match_agent(
    agent: dict[str, Any],
    unified_hosts: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, int, str]:
    """
    Find the best-scoring unified_host for a Wazuh agent.
    Returns (host_dict | None, score, reason_code).
    """
    agent_id   = str(agent.get("id") or "").strip()
    agent_name = str(agent.get("name") or "").strip()
    agent_ip   = str(agent.get("ip") or "").strip()
    agent_os   = str((agent.get("os") or {}).get("platform") or "").lower()

    best: dict[str, Any] | None = None
    best_score = 0
    best_reason = "no_match"

    for uh in unified_hosts:
        score = 0
        reason = "no_match"

        uh_agent_id   = str(uh.get("wazuh_agent_id") or "")
        uh_short      = (uh.get("hostname_short") or "").lower()
        uh_display    = (uh.get("display_name") or "").lower()
        uh_fqdn       = (uh.get("fqdn") or "").lower()
        uh_ip         = str(uh.get("primary_ip") or "")
        uh_os         = (uh.get("os_platform") or "").lower()

        # Priority 1 — exact Wazuh agent ID
        if agent_id and uh_agent_id == agent_id:
            score, reason = 100, "agent_id"

        # Priority 2 — exact hostname (case-insensitive)
        elif agent_name and agent_name.lower() in (uh_short, uh_display):
            score, reason = 90, "exact_hostname"

        # Priority 3 — normalised hostname (strip domain / FQDN)
        elif agent_name and _normalise(agent_name):
            norm_agent = _normalise(agent_name)
            if norm_agent in (_normalise(uh_short), _normalise(uh_display)):
                score, reason = 75, "norm_hostname"
            elif uh_fqdn and norm_agent == _normalise(uh_fqdn):
                score, reason = 75, "fqdn"

        # Priority 4 — IP address match
        elif (
            agent_ip
            and agent_ip != "0.0.0.0"
            and uh_ip
            and agent_ip == uh_ip
        ):
            score, reason = 60, "ip"

        if score == 0:
            continue

        # OS bonus (supporting signal, not primary)
        if agent_os and uh_os and agent_os == uh_os:
            score = min(score + 5, 100)
            reason = reason + "+os"

        if score > best_score:
            best_score = score
            best_reason = reason
            best = uh

    return best, best_score, best_reason


# ── score → identity / policy ─────────────────────────────────────────────────

def _identity(score: int) -> str:
    if score >= 100:
        return "trusted"
    if score >= 75:
        return "likely"
    if score >= 60:
        return "uncertain"
    return "unknown"


def _policy(score: int, has_conflict: bool) -> str:
    if has_conflict:
        return "blocked"
    if score >= 60:
        return "review_required"
    return "blocked"


# ── public API ────────────────────────────────────────────────────────────────

def sync_wazuh_agents(connection: Any) -> dict[str, Any]:
    """
    Fetch all Wazuh Manager agents and upsert them into unified_hosts.

    Returns a detailed sync report:
      {
        "status": "ok" | "error",
        "agents_total": int,
        "unified_hosts_before": int,
        "matched": int,
        "created": int,
        "updated": int,
        "conflicts": int,
        "unmatched_agents": int,
        "match_methods": {"agent_id": int, "hostname": int, "fqdn": int, "ip": int, "created_new": int},
        "conflict_items": [...],
        "unmatched_items": [...],
        "warnings": [...],
        "duration_ms": int,
        "errors": [...],
        # legacy keys kept for backward compat:
        "agents_fetched": int,
        "new_hosts": int,
        "conflicts_detected": int,
      }
    """
    import time
    from db.database import (
        add_host_conflict,
        clear_host_conflicts,
        list_unified_hosts,
        upsert_unified_host,
    )
    from services.wazuh_manager_api import WazuhManagerAPIClient, check_manager_configured

    t0 = time.monotonic()
    result: dict[str, Any] = {
        "status": "ok",
        "agents_total": 0,
        "unified_hosts_before": 0,
        "matched": 0,
        "created": 0,
        "updated": 0,
        "conflicts": 0,
        "unmatched_agents": 0,
        "match_methods": {"agent_id": 0, "hostname": 0, "fqdn": 0, "ip": 0, "created_new": 0},
        "conflict_items": [],
        "unmatched_items": [],
        "warnings": [],
        "duration_ms": 0,
        "errors": [],
        # legacy compat
        "agents_fetched": 0,
        "new_hosts": 0,
        "conflicts_detected": 0,
    }

    check = check_manager_configured(connection)
    if not check.get("configured"):
        result["status"] = "error"
        result["errors"].append(f"Wazuh Manager not configured: {check.get('reason')}")
        result["duration_ms"] = round((time.monotonic() - t0) * 1000)
        return result

    # Fetch agents from Wazuh Manager
    try:
        client = WazuhManagerAPIClient.from_connection(connection)
        raw = client.get_agents(
            limit=1000,
            fields="id,name,ip,status,os.name,os.platform,os.version,version,lastKeepAlive,group",
        )
    except Exception as exc:
        result["status"] = "error"
        result["errors"].append(f"Failed to fetch Wazuh agents: {exc}")
        result["duration_ms"] = round((time.monotonic() - t0) * 1000)
        return result

    all_agents_raw: list[dict[str, Any]] = (raw.get("data") or {}).get("affected_items") or []
    result["agents_total"] = len(all_agents_raw)
    # Exclude agent "000" — the manager itself
    agents: list[dict[str, Any]] = [a for a in all_agents_raw if str(a.get("id") or "") != "000"]
    result["agents_fetched"] = len(agents)

    # Load current snapshot of unified_hosts
    existing = list_unified_hosts()
    result["unified_hosts_before"] = len(existing)

    if not agents:
        result["warnings"].append("Wazuh Manager returned zero agents (excluding manager itself).")
        result["duration_ms"] = round((time.monotonic() - t0) * 1000)
        return result

    # Track which unified_host_ids were claimed by multiple agents (conflict)
    claimed: dict[int, list[dict[str, Any]]] = {}
    # Track agent reason per uh_id for conflict items
    claimed_reasons: dict[int, list[str]] = {}

    for agent in agents:
        agent_id       = str(agent.get("id") or "").strip()
        agent_name     = str(agent.get("name") or "").strip()
        agent_ip_raw   = str(agent.get("ip") or "").strip()
        agent_ip       = agent_ip_raw if agent_ip_raw and agent_ip_raw != "0.0.0.0" else None
        agent_os_plat  = str((agent.get("os") or {}).get("platform") or "") or None
        agent_os_full  = (
            str((agent.get("os") or {}).get("version") or (agent.get("os") or {}).get("name") or "")
            or None
        )
        wazuh_st       = _wazuh_status(agent)
        last_keep      = agent.get("lastKeepAlive") or None

        best, score, reason = _match_agent(agent, existing)

        if best is not None:
            uh_id = int(best["id"])
            claimed.setdefault(uh_id, []).append(agent)
            claimed_reasons.setdefault(uh_id, []).append(reason)

            update: dict[str, Any] = {
                **best,
                "wazuh_agent_id": agent_id,
                "wazuh_status": wazuh_st,
                "match_score": score,
                "match_status": "matched" if score >= 75 else "uncertain",
                "match_source": f"wazuh_{reason}",
                "identity_status": _identity(score),
                "action_policy": _policy(score, has_conflict=False),
                "last_seen_wazuh": last_keep,
            }
            # Fill blanks from Wazuh data (Tactical data takes precedence)
            if not best.get("primary_ip") and agent_ip:
                update["primary_ip"] = agent_ip
            if not best.get("os_platform") and agent_os_plat:
                update["os_platform"] = agent_os_plat
            if not best.get("os_full") and agent_os_full:
                update["os_full"] = agent_os_full

            upsert_unified_host(update)
            result["matched"] += 1
            result["updated"] += 1

            # Count match method (strip +os suffix for bucketing)
            base_reason = reason.split("+")[0]
            mm = result["match_methods"]
            if base_reason == "agent_id":
                mm["agent_id"] += 1
            elif base_reason in ("exact_hostname", "norm_hostname"):
                mm["hostname"] += 1
            elif base_reason == "fqdn":
                mm["fqdn"] += 1
            elif base_reason == "ip":
                mm["ip"] += 1

        else:
            # No match → create a new entry sourced from Wazuh
            new_host: dict[str, Any] = {
                "display_name": agent_name,
                "hostname_short": _normalise(agent_name) or agent_name,
                "fqdn": None,
                "wazuh_agent_id": agent_id,
                "tactical_agent_id": None,
                "mesh_node_id": None,
                "match_score": 0,
                "match_status": "unmatched",
                "match_source": "wazuh_new",
                "identity_status": "unknown",
                "tactical_status": "unknown",
                "wazuh_status": wazuh_st,
                "mesh_status": "unknown",
                "action_policy": "blocked",
                "primary_ip": agent_ip,
                "os_platform": agent_os_plat,
                "os_full": agent_os_full,
                "last_seen_wazuh": last_keep,
                "last_seen_tactical": None,
                "notes": None,
            }
            upsert_unified_host(new_host)
            result["created"] += 1
            result["new_hosts"] += 1
            result["unmatched_agents"] += 1
            result["match_methods"]["created_new"] += 1
            result["unmatched_items"].append({
                "agent_id": agent_id,
                "agent_name": agent_name,
                "agent_ip": agent_ip or "",
                "status": wazuh_st,
            })

    # Pass 2 — detect conflicts (two agents matched the same unified host)
    for uh_id, agent_list in claimed.items():
        if len(agent_list) < 2:
            continue
        result["conflicts"] += 1
        result["conflicts_detected"] += 1
        matching_host = next((h for h in existing if int(h["id"]) == uh_id), None)
        reason_list = claimed_reasons.get(uh_id, [])
        result["conflict_items"].append({
            "unified_host_id": uh_id,
            "host_name": matching_host.get("display_name") if matching_host else str(uh_id),
            "reason": "Multiple Wazuh agents matched the same unified host",
            "candidates": [
                {
                    "agent_id": str(a.get("id")),
                    "agent_name": str(a.get("name") or ""),
                    "agent_ip": str(a.get("ip") or ""),
                    "match_reason": reason_list[i] if i < len(reason_list) else "",
                }
                for i, a in enumerate(agent_list)
            ],
        })
        if matching_host:
            clear_host_conflicts(uh_id)
            add_host_conflict({
                "unified_host_id": uh_id,
                "conflict_type": "duplicate_wazuh_agent",
                "severity": "critical",
                "field_name": "wazuh_agent_id",
                "tactical_value": None,
                "wazuh_value": ", ".join(str(a.get("id")) for a in agent_list),
                "description": (
                    f"Multiple Wazuh agents matched host '{matching_host.get('display_name')}': "
                    + ", ".join(
                        f"{a.get('name')} (id={a.get('id')})" for a in agent_list
                    )
                ),
            })
            upsert_unified_host({
                **matching_host,
                "match_status": "conflict",
                "action_policy": "blocked",
                "identity_status": "uncertain",
            })
        logger.warning(
            "Wazuh host sync conflict on unified_host_id=%s: %s",
            uh_id,
            [a.get("id") for a in agent_list],
        )

    result["duration_ms"] = round((time.monotonic() - t0) * 1000)
    logger.info(
        "Wazuh host sync complete: total=%d fetched=%d matched=%d created=%d conflicts=%d in %dms",
        result["agents_total"],
        result["agents_fetched"],
        result["matched"],
        result["created"],
        result["conflicts"],
        result["duration_ms"],
    )
    return result


# ── policy recompute ─────────────────────────────────────────────────────────

def recompute_action_policy_for_unified_hosts(connection: Any) -> dict[str, Any]:
    """
    Walk all unified_hosts rows and recompute identity_status + action_policy
    based on current wazuh_status, tactical_status, match_score, and conflict state.

    Rules (in priority order):
      1. conflict in match_status                   → blocked
      2. No trusted identity (score < 60)           → blocked
      3. trusted Wazuh + trusted Tactical           → review_required (Phase-2: allowed)
      4. Wazuh active + Tactical missing/unknown    → review_required
      5. Tactical online + Wazuh unknown/missing    → review_required
      6. Any other known identity (score ≥ 60)      → review_required
      default                                       → blocked

    Returns:
      {"updated": int, "blocked": int, "review_required": int, "duration_ms": int}
    """
    import time
    from db.database import list_unified_hosts, upsert_unified_host

    t0 = time.monotonic()
    counts = {"updated": 0, "blocked": 0, "review_required": 0}

    hosts = list_unified_hosts()
    for host in hosts:
        score         = int(host.get("match_score") or 0)
        match_status  = str(host.get("match_status") or "")
        wazuh_st      = str(host.get("wazuh_status") or "unknown").lower()
        tact_st       = str(host.get("tactical_status") or "unknown").lower()
        old_policy    = host.get("action_policy") or "blocked"
        old_identity  = host.get("identity_status") or "unknown"

        # Recompute identity
        new_identity = _identity(score)

        # Recompute policy
        if match_status == "conflict":
            new_policy = "blocked"
        elif score < 60:
            new_policy = "blocked"
        elif wazuh_st == "online" and tact_st == "online":
            # Both sources agree the host is active — best trust signal
            new_policy = "review_required"  # Phase 2: would be "allowed"
        elif wazuh_st == "online" and tact_st in ("unknown", "offline", ""):
            new_policy = "review_required"
        elif tact_st == "online" and wazuh_st in ("unknown", "offline", ""):
            new_policy = "review_required"
        elif score >= 60:
            new_policy = "review_required"
        else:
            new_policy = "blocked"

        if new_policy != old_policy or new_identity != old_identity:
            upsert_unified_host({**host, "action_policy": new_policy, "identity_status": new_identity})
            counts["updated"] += 1

        if new_policy == "blocked":
            counts["blocked"] += 1
        else:
            counts["review_required"] += 1

    counts["duration_ms"] = round((time.monotonic() - t0) * 1000)
    logger.info("Policy recompute: updated=%d blocked=%d review_required=%d in %dms",
                counts["updated"], counts["blocked"], counts["review_required"], counts["duration_ms"])
    return counts


# ── pure matching helpers (used by validation tests) ─────────────────────────

def match_agent_to_host_pure(
    agent: dict[str, Any],
    unified_hosts: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, int, str]:
    """
    Stateless matching helper for Trust Center validation tests.
    Same logic as sync but does NOT touch the database.
    """
    return _match_agent(agent, unified_hosts)
