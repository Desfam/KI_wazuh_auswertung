"""Wazuh ↔ Tactical RMM host matching and conflict detection.

Scoring algorithm:
  FQDN exact match      +100
  Hostname exact match  +80
  Primary IP match      +60
  Any IP from list      +40
  OS family match       +20
  OS family mismatch    -40
  Domain match          +20
  Hostname fuzzy (≥80%) +30

Thresholds:
  ≥120 → trusted
  80-119 → likely
  50-79 → uncertain
  <50 → unknown (no_match)
"""
from __future__ import annotations

import json
import re
from difflib import SequenceMatcher
from typing import Any

from db.database import (
    add_host_conflict,
    clear_host_conflicts,
    list_tactical_agents,
    upsert_unified_host,
    utc_now_iso,
)

# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _strip_domain(hostname: str) -> str:
    """Return the short hostname (first label only), lowercase."""
    return hostname.split(".")[0].strip().lower()


def _os_family(os_str: str | None) -> str:
    """Coerce an OS string to 'windows', 'linux', 'macos', or 'unknown'."""
    if not os_str:
        return "unknown"
    s = os_str.lower()
    if "win" in s:
        return "windows"
    if any(k in s for k in ("linux", "ubuntu", "debian", "centos", "redhat", "rhel", "fedora", "suse", "alpine")):
        return "linux"
    if any(k in s for k in ("mac", "darwin", "osx")):
        return "macos"
    return "unknown"


def _ip_set(agent: dict[str, Any], extra_field: str | None = None) -> set[str]:
    """Collect all IP addresses from an agent dict."""
    ips: set[str] = set()

    def _add(raw: Any) -> None:
        if isinstance(raw, str):
            for part in re.split(r"[,\s]+", raw):
                part = part.strip()
                if part and _is_ip(part):
                    ips.add(part)
        elif isinstance(raw, list):
            for item in raw:
                _add(item)

    for field in ("local_ips", "ip_addresses", "ip", "ips"):
        _add(agent.get(field))
    if extra_field:
        _add(agent.get(extra_field))
    return ips


def _is_ip(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))


def _wazuh_hostname(w: dict[str, Any]) -> str:
    return (w.get("hostname") or w.get("name") or "").strip().lower()


def _wazuh_ips(w: dict[str, Any]) -> set[str]:
    ips: set[str] = set()
    for field in ("ip", "ip_addresses", "local_ips"):
        raw = w.get(field)
        if isinstance(raw, str):
            for p in re.split(r"[,\s]+", raw):
                p = p.strip()
                if p and _is_ip(p):
                    ips.add(p)
        elif isinstance(raw, list):
            for item in raw:
                if item and _is_ip(str(item).strip()):
                    ips.add(str(item).strip())
    return ips


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _score_pair(tactical: dict[str, Any], wazuh: dict[str, Any]) -> int:
    score = 0

    t_hostname = _strip_domain(tactical.get("hostname") or "")
    t_fqdn = (tactical.get("fqdn") or "").lower().strip()
    t_ips = _ip_set(tactical)
    t_os_fam = _os_family(tactical.get("os_platform") or tactical.get("os_full"))

    w_hostname = _wazuh_hostname(wazuh)
    w_fqdn = (wazuh.get("hostname") or wazuh.get("fqdn") or "").lower().strip()
    w_ips = _wazuh_ips(wazuh)
    w_os_fam = _os_family(wazuh.get("os") or wazuh.get("os_name") or wazuh.get("platform"))

    # FQDN exact match
    if t_fqdn and w_fqdn and t_fqdn == w_fqdn:
        score += 100

    # Hostname short exact match
    w_short = _strip_domain(w_hostname)
    if t_hostname and w_short and t_hostname == w_short:
        score += 80
    elif t_hostname and w_short:
        # Fuzzy hostname similarity (≥80%)
        ratio = SequenceMatcher(None, t_hostname, w_short).ratio()
        if ratio >= 0.80:
            score += 30

    # IP matching
    common_ips = t_ips & w_ips
    if common_ips:
        score += 60

    # OS family
    if t_os_fam != "unknown" and w_os_fam != "unknown":
        if t_os_fam == w_os_fam:
            score += 20
        else:
            score -= 40

    return score


def _identity_status(score: int) -> str:
    if score >= 120:
        return "trusted"
    if score >= 80:
        return "likely"
    if score >= 50:
        return "uncertain"
    return "unknown"


def _action_policy(identity_status: str, tactical_status: str) -> str:
    """Determine action policy — Phase 1: all dangerous actions blocked."""
    if identity_status == "trusted":
        return "read_only"   # Phase 2 will allow 'full' for admin
    if identity_status == "likely":
        return "read_only"
    return "blocked"


# ---------------------------------------------------------------------------
# Conflict detection
# ---------------------------------------------------------------------------

def _detect_conflicts(
    tactical: dict[str, Any],
    wazuh: dict[str, Any] | None,
    score: int,
    unified_host_id: int,
) -> list[dict[str, Any]]:
    conflicts: list[dict[str, Any]] = []
    now = utc_now_iso()

    if wazuh is None:
        # Tactical agent with no Wazuh counterpart
        conflicts.append({
            "unified_host_id": unified_host_id,
            "conflict_type": "wazuh_missing",
            "severity": "warning",
            "description": f"No Wazuh agent found for Tactical agent '{tactical.get('hostname')}'",
            "detected_at": now,
        })
        return conflicts

    # OS family mismatch
    t_os = _os_family(tactical.get("os_platform") or tactical.get("os_full"))
    w_os = _os_family(wazuh.get("os") or wazuh.get("os_name") or wazuh.get("platform"))
    if t_os != "unknown" and w_os != "unknown" and t_os != w_os:
        conflicts.append({
            "unified_host_id": unified_host_id,
            "conflict_type": "os_mismatch",
            "severity": "critical",
            "field_name": "os_family",
            "tactical_value": t_os,
            "wazuh_value": w_os,
            "description": f"OS family mismatch: Tactical={t_os}, Wazuh={w_os}",
        })

    # Hostname mismatch (both known, differ)
    t_short = _strip_domain(tactical.get("hostname") or "")
    w_short = _strip_domain(_wazuh_hostname(wazuh))
    if t_short and w_short and t_short != w_short:
        ratio = SequenceMatcher(None, t_short, w_short).ratio()
        if ratio < 0.60:
            conflicts.append({
                "unified_host_id": unified_host_id,
                "conflict_type": "hostname_mismatch",
                "severity": "warning",
                "field_name": "hostname",
                "tactical_value": t_short,
                "wazuh_value": w_short,
                "description": f"Hostname mismatch: Tactical={t_short}, Wazuh={w_short}",
            })

    # Low match score
    if 0 <= score < 50:
        conflicts.append({
            "unified_host_id": unified_host_id,
            "conflict_type": "low_match_score",
            "severity": "warning",
            "description": f"Low identity match score ({score}) — manual verification recommended",
        })

    # Add detected_at to all
    for c in conflicts:
        c.setdefault("detected_at", now)

    return conflicts


# ---------------------------------------------------------------------------
# Main matching entry point
# ---------------------------------------------------------------------------

def run_host_matching(wazuh_agents: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Match cached Tactical agents against Wazuh agents and populate unified_hosts.

    Parameters
    ----------
    wazuh_agents:
        Optional list of Wazuh agent dicts (from wazuh_indexer / manager API).
        If None, matching is done for Tactical agents only (creates unmatched rows).

    Returns
    -------
    Summary dict with host counts.
    """
    tactical_agents = list_tactical_agents()
    if wazuh_agents is None:
        wazuh_agents = []

    # For duplicate IP detection across wazuh agents
    wazuh_ip_map: dict[str, list[str]] = {}
    for w in wazuh_agents:
        w_id = str(w.get("id") or w.get("agent_id") or id(w))
        for ip in _wazuh_ips(w):
            wazuh_ip_map.setdefault(ip, []).append(w_id)

    matched_wazuh_ids: set[str] = set()
    hosts_created = 0
    hosts_updated = 0
    conflicts_total = 0

    for t_agent in tactical_agents:
        best_wazuh: dict[str, Any] | None = None
        best_score = 0

        for w in wazuh_agents:
            s = _score_pair(t_agent, w)
            if s > best_score:
                best_score = s
                best_wazuh = w

        identity = _identity_status(best_score)
        policy = _action_policy(identity, t_agent.get("status", "unknown"))

        # Build unified host record
        t_ips = _ip_set(t_agent)
        primary_ip = next(iter(t_ips), None)

        wazuh_agent_id: str | None = None
        wazuh_status = "unknown"
        if best_wazuh and best_score >= 50:
            wazuh_agent_id = str(best_wazuh.get("id") or best_wazuh.get("agent_id") or "")
            matched_wazuh_ids.add(wazuh_agent_id)
            wazuh_status = _wazuh_status(best_wazuh)

        host_record: dict[str, Any] = {
            "display_name": t_agent["hostname"],
            "hostname_short": _strip_domain(t_agent["hostname"]),
            "fqdn": t_agent.get("fqdn"),
            "tactical_agent_id": t_agent["tactical_agent_id"],
            "wazuh_agent_id": wazuh_agent_id,
            "mesh_node_id": t_agent.get("mesh_node_id"),
            "match_score": best_score,
            "match_status": "matched" if best_score >= 50 else "unmatched",
            "match_source": "auto",
            "identity_status": identity,
            "tactical_status": t_agent.get("status", "unknown"),
            "wazuh_status": wazuh_status,
            "mesh_status": "unknown",
            "action_policy": policy,
            "primary_ip": primary_ip,
            "os_platform": t_agent.get("os_platform"),
            "os_full": t_agent.get("os_full"),
            "last_seen_tactical": t_agent.get("last_checkin"),
            "last_seen_wazuh": best_wazuh.get("lastKeepAlive") if best_wazuh else None,
        }

        host_id = upsert_unified_host(host_record)
        if host_id:
            hosts_updated += 1
        else:
            hosts_created += 1

        # Conflicts
        clear_host_conflicts(host_id)
        conflicts = _detect_conflicts(t_agent, best_wazuh if best_score >= 50 else None, best_score, host_id)
        for c in conflicts:
            add_host_conflict(c)
        conflicts_total += len(conflicts)

    # Wazuh agents with no Tactical counterpart → "wazuh-only" unified hosts
    for w in wazuh_agents:
        w_id = str(w.get("id") or w.get("agent_id") or "")
        if w_id in matched_wazuh_ids:
            continue
        w_hostname = _wazuh_hostname(w)
        if not w_hostname:
            continue

        host_record = {
            "display_name": w_hostname,
            "hostname_short": _strip_domain(w_hostname),
            "fqdn": w.get("hostname") if "." in (w.get("hostname") or "") else None,
            "tactical_agent_id": None,
            "wazuh_agent_id": w_id,
            "mesh_node_id": None,
            "match_score": 0,
            "match_status": "unmatched",
            "match_source": "auto",
            "identity_status": "unknown",
            "tactical_status": "unknown",
            "wazuh_status": _wazuh_status(w),
            "mesh_status": "unknown",
            "action_policy": "blocked",
            "primary_ip": next(iter(_wazuh_ips(w)), None),
            "os_platform": w.get("os") or w.get("platform"),
            "os_full": w.get("os_name") or w.get("os"),
            "last_seen_tactical": None,
            "last_seen_wazuh": w.get("lastKeepAlive") or w.get("last_seen"),
        }
        host_id = upsert_unified_host(host_record)
        hosts_updated += 1

        # Conflict: tactical missing
        clear_host_conflicts(host_id)
        add_host_conflict({
            "unified_host_id": host_id,
            "conflict_type": "tactical_missing",
            "severity": "info",
            "description": f"Wazuh agent '{w_hostname}' has no Tactical RMM counterpart",
            "detected_at": utc_now_iso(),
        })
        conflicts_total += 1

    return {
        "hosts_created": hosts_created,
        "hosts_updated": hosts_updated,
        "conflicts_detected": conflicts_total,
        "tactical_agents": len(tactical_agents),
        "wazuh_agents": len(wazuh_agents),
    }


def _wazuh_status(w: dict[str, Any]) -> str:
    raw = w.get("status") or w.get("connection_status") or ""
    if isinstance(raw, str):
        raw = raw.lower()
        if raw in ("active", "online", "connected"):
            return "online"
        if raw in ("disconnected", "offline", "inactive"):
            return "offline"
    return "unknown"
