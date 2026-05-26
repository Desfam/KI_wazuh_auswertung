"""Audit Log Foundation API routes.

Endpoints:
  GET  /audit/actions            → list audit log entries
  POST /audit/actions            → log a new audit entry

Phase 1 use:
  Log harmless UI actions:
  - tactical_sync_clicked
  - host_match_requested
  - baseline_added
  - false_positive_marked
  - report_exported
  - script_suggested_clicked
  - playbook_viewed

Security rules:
  - Do NOT log secrets, passwords, API keys
  - Do NOT log remote execution results (no execution yet)
  - Audit log is append-only via this API
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from db.database import create_audit_entry, list_audit_entries

router = APIRouter(prefix="/audit", tags=["audit"])

# Allowed Phase-1 action types (harmless UI / review actions only)
_ALLOWED_ACTION_TYPES: frozenset[str] = frozenset({
    "tactical_sync_clicked",
    "host_match_requested",
    "baseline_added",
    "false_positive_marked",
    "report_exported",
    "script_suggested_clicked",
    "playbook_viewed",
    "host_resolved",
    "timeline_opened",
    "cluster_selected",
    "investigation_opened",
})


@router.get("/actions")
def get_audit_actions(
    action_type: str | None = Query(default=None),
    host: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    """Return audit log entries, optionally filtered."""
    return list_audit_entries(action_type=action_type, host=host, limit=limit)


@router.post("/actions")
def log_audit_action(payload: dict[str, Any]) -> dict[str, Any]:
    """Log a Phase-1 audit action.

    Required fields:
      action_type  — must be a known Phase-1 action type
      source_page  — page or component that triggered the action

    Optional fields:
      user, host, unified_host_id, wazuh_agent_id, tactical_agent_id,
      source_event_id, source_rule_id, action_policy, policy_reason,
      details_json
    """
    action_type = payload.get("action_type", "")
    if action_type not in _ALLOWED_ACTION_TYPES:
        # Accept unknown types but mark them as unclassified
        payload["action_type"] = f"unclassified:{action_type}"

    entry_id = create_audit_entry(payload)
    return {"status": "logged", "id": entry_id}
