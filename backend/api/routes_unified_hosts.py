"""Unified Hosts API routes.

Endpoints:
  GET /unified-hosts                    → all unified hosts
  GET /unified-hosts/resolve            → resolve a host by hostname/agent_id/ip
  GET /unified-hosts/{id}               → single unified host
  GET /unified-hosts/{id}/conflicts     → active conflicts for host
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from db.database import get_unified_host, list_host_conflicts, list_unified_hosts
from services.action_policy import get_action_policy_for_unified_host
from services.host_explain import explain_host_trust

router = APIRouter(prefix="/unified-hosts", tags=["unified-hosts"])


def _enrich(host: dict[str, Any], conflicts: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Attach explanation fields to a unified host dict in-place."""
    if conflicts is None:
        conflicts = []
    host.update(explain_host_trust(host, conflicts))
    return host


@router.get("")
def get_all_unified_hosts() -> list[dict[str, Any]]:
    """Return all unified hosts with their current status, match info, and trust explanations."""
    hosts = list_unified_hosts()
    for host in hosts:
        conflicts = list_host_conflicts(host["id"])
        host["conflict_count"] = len(conflicts)
        _enrich(host, conflicts)
    return hosts


@router.get("/resolve")
def resolve_unified_host(
    hostname: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    ip: str | None = Query(default=None),
) -> dict[str, Any]:
    """Resolve a unified host by hostname, Wazuh agent ID, or primary IP.

    Resolution order:
      1. wazuh_agent_id exact match
      2. hostname_short / display_name case-insensitive match
      3. primary_ip exact match

    Returns the matched host, its active conflicts, and normalised action policy.
    """
    if not any([hostname, agent_id, ip]):
        raise HTTPException(
            status_code=400,
            detail="Provide at least one of: hostname, agent_id, ip",
        )

    all_hosts = list_unified_hosts()
    matched: dict[str, Any] | None = None

    # Pass 1: Wazuh agent ID (exact)
    if agent_id:
        for h in all_hosts:
            if h.get("wazuh_agent_id") == agent_id:
                matched = h
                break

    # Pass 2: hostname (case-insensitive, short or display)
    if not matched and hostname:
        hn_lower = hostname.lower()
        for h in all_hosts:
            short = (h.get("hostname_short") or "").lower()
            display = (h.get("display_name") or "").lower()
            if short == hn_lower or display == hn_lower:
                matched = h
                break
        # Partial match fallback
        if not matched:
            for h in all_hosts:
                short = (h.get("hostname_short") or "").lower()
                display = (h.get("display_name") or "").lower()
                if hn_lower in short or hn_lower in display:
                    matched = h
                    break

    # Pass 3: primary IP
    if not matched and ip:
        for h in all_hosts:
            if h.get("primary_ip") == ip:
                matched = h
                break

    conflicts: list[dict[str, Any]] = []
    if matched:
        conflicts = list_host_conflicts(matched["id"])
        matched["conflict_count"] = len(conflicts)

    policy = get_action_policy_for_unified_host(matched or {}, conflicts)

    if not matched:
        policy["reason"] = (
            "Wazuh event host could not be confidently mapped to a Unified/Tactical host. "
            + policy.get("reason", "")
        ).strip()

    return {
        "host": matched,
        "conflicts": conflicts,
        "action_policy": policy,
    }


@router.get("/{host_id}")
def get_single_unified_host(host_id: int) -> dict[str, Any]:
    """Return a single unified host by ID with trust explanations."""
    host = get_unified_host(host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Unified host not found")
    conflicts = list_host_conflicts(host_id)
    host["conflict_count"] = len(conflicts)
    _enrich(host, conflicts)
    return host


@router.get("/{host_id}/conflicts")
def get_host_conflicts(host_id: int) -> list[dict[str, Any]]:
    """Return all active conflicts for a unified host."""
    host = get_unified_host(host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Unified host not found")
    return list_host_conflicts(host_id)
