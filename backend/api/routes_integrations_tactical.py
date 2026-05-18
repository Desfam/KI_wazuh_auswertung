"""Tactical RMM integration API routes.

Endpoints (all read-only or trigger-only):
  GET  /integrations/tactical/health   → connectivity check
  GET  /integrations/tactical/agents   → cached agent list
  GET  /integrations/tactical/agents/{id}  → single cached agent
  POST /integrations/tactical/sync     → pull from Tactical + run matching
"""
from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter, HTTPException

from db.database import get_tactical_agent, list_tactical_agents
from services.host_matching import run_host_matching
from services.tactical_client import check_health
from services.tactical_sync import sync_tactical_agents

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations/tactical", tags=["tactical"])


@router.get("/health")
def tactical_health() -> dict[str, Any]:
    """Check connectivity to the Tactical RMM API."""
    return check_health()


@router.get("/agents")
def list_agents() -> list[dict[str, Any]]:
    """Return the cached Tactical RMM agent list."""
    return list_tactical_agents()


@router.get("/agents/{tactical_agent_id}")
def get_agent(tactical_agent_id: str) -> dict[str, Any]:
    """Return a single cached agent by its Tactical agent ID."""
    agent = get_tactical_agent(tactical_agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found in cache")
    return agent


@router.post("/sync")
def sync_tactical() -> dict[str, Any]:
    """Pull agents from Tactical RMM, update cache, re-run host matching.

    No dangerous writes are performed on remote systems.
    """
    t0 = time.monotonic()

    sync_result = sync_tactical_agents()
    if not sync_result["success"] and sync_result["agents_pulled"] == 0:
        raise HTTPException(
            status_code=502,
            detail=f"Tactical sync failed: {'; '.join(sync_result['errors']) or 'unknown error'}",
        )

    match_result = run_host_matching(wazuh_agents=None)

    duration_ms = int((time.monotonic() - t0) * 1000)
    return {
        "success": sync_result["success"],
        "agents_pulled": sync_result["agents_pulled"],
        "agents_cached": sync_result["agents_cached"],
        "hosts_created": match_result["hosts_created"],
        "hosts_updated": match_result["hosts_updated"],
        "conflicts_detected": match_result["conflicts_detected"],
        "errors": sync_result["errors"],
        "duration_ms": duration_ms,
    }
