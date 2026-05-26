"""Script Library API routes — Phase 1: catalog only, no execution.

Endpoints:
  GET    /scripts                → list scripts (filterable)
  GET    /scripts/{script_id}    → single script
  POST   /scripts                → create script
  PUT    /scripts/{script_id}    → update script
  DELETE /scripts/{script_id}    → delete script

Security rule:
  No script execution endpoint exists in Phase 1.
  All scripts are catalogued only.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from db.database import (
    create_script,
    delete_script,
    get_script,
    list_scripts,
    update_script,
)

router = APIRouter(prefix="/scripts", tags=["scripts"])


@router.get("")
def get_scripts(
    platform: str | None = Query(default=None),
    category: str | None = Query(default=None),
    dangerous: bool | None = Query(default=None),
    enabled: bool | None = Query(default=None),
    search: str | None = Query(default=None),
) -> list[dict[str, Any]]:
    """Return the script catalog with optional filters."""
    return list_scripts(
        platform=platform,
        category=category,
        dangerous=dangerous,
        enabled=enabled,
        search=search,
    )


@router.get("/{script_id}")
def get_single_script(script_id: str) -> dict[str, Any]:
    """Return a single script by its script_id."""
    script = get_script(script_id)
    if not script:
        raise HTTPException(status_code=404, detail="Script not found")
    return script


@router.post("")
def create_new_script(payload: dict[str, Any]) -> dict[str, Any]:
    """Create a new script catalog entry.

    Required fields: script_id, name, platform, executor
    No execution endpoint exists — this is catalog only.
    """
    required = {"script_id", "name", "platform", "executor"}
    missing = required - set(payload.keys())
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"Missing required fields: {sorted(missing)}",
        )
    # Execution is not allowed in Phase 1 — enforce safe defaults
    payload["dangerous"] = payload.get("dangerous", False)
    payload["enabled"] = payload.get("enabled", True)
    payload["readonly"] = payload.get("readonly", True)
    script_id = create_script(payload)
    script = get_script(script_id)
    if not script:
        raise HTTPException(status_code=500, detail="Script creation failed")
    return script


@router.put("/{script_id}")
def update_existing_script(script_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Update an existing script catalog entry."""
    existing = get_script(script_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Script not found")
    update_script(script_id, payload)
    return get_script(script_id) or {}


@router.delete("/{script_id}")
def delete_existing_script(script_id: str) -> dict[str, str]:
    """Delete a script catalog entry."""
    existing = get_script(script_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Script not found")
    delete_script(script_id)
    return {"status": "deleted", "script_id": script_id}
