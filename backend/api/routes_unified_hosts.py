"""Unified Hosts API routes.

Endpoints:
  GET /unified-hosts             → all unified hosts
  GET /unified-hosts/{id}        → single unified host
  GET /unified-hosts/{id}/conflicts  → active conflicts for host
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from db.database import get_unified_host, list_host_conflicts, list_unified_hosts

router = APIRouter(prefix="/unified-hosts", tags=["unified-hosts"])


@router.get("")
def get_all_unified_hosts() -> list[dict[str, Any]]:
    """Return all unified hosts with their current status and match info."""
    hosts = list_unified_hosts()
    # Attach conflict count per host
    for host in hosts:
        conflicts = list_host_conflicts(host["id"])
        host["conflict_count"] = len(conflicts)
    return hosts


@router.get("/{host_id}")
def get_single_unified_host(host_id: int) -> dict[str, Any]:
    """Return a single unified host by ID."""
    host = get_unified_host(host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Unified host not found")
    conflicts = list_host_conflicts(host_id)
    host["conflict_count"] = len(conflicts)
    return host


@router.get("/{host_id}/conflicts")
def get_host_conflicts(host_id: int) -> list[dict[str, Any]]:
    """Return all active conflicts for a unified host."""
    host = get_unified_host(host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Unified host not found")
    return list_host_conflicts(host_id)
