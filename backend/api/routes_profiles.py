"""Host Profile API routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from schemas.types import (
    HostProfile,
    HostProfileAssignment,
    HostProfileAssignRequest,
    HostProfileCreate,
)
from services.snipen_profiles import (
    assign_profile_to_host,
    create_profile,
    delete_profile,
    get_host_assignment,
    get_profile_by_id,
    list_all_assignments,
    list_profiles,
    remove_host_assignment,
    update_profile,
)

router = APIRouter(prefix="/profiles", tags=["profiles"])


# ── Profile CRUD ──────────────────────────────────────────────────────────────

@router.get("")
def profiles_list() -> list[HostProfile]:
    """List all host profiles (built-in + custom)."""
    return list_profiles()


@router.post("")
def profiles_create(body: HostProfileCreate) -> HostProfile:
    """Create a new custom host profile."""
    try:
        return create_profile(body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{profile_id}")
def profiles_get(profile_id: int) -> HostProfile:
    profile = get_profile_by_id(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


@router.put("/{profile_id}")
def profiles_update(profile_id: int, body: HostProfileCreate) -> HostProfile:
    """Update a host profile (built-in profiles can also be customized)."""
    result = update_profile(profile_id, body)
    if not result:
        raise HTTPException(status_code=404, detail="Profile not found")
    return result


@router.delete("/{profile_id}")
def profiles_delete(profile_id: int) -> dict[str, str]:
    """Delete a custom profile. Built-in profiles cannot be deleted."""
    ok = delete_profile(profile_id)
    if not ok:
        raise HTTPException(
            status_code=400,
            detail="Profile not found or is a built-in profile that cannot be deleted",
        )
    return {"status": "deleted"}


# ── Assignment endpoints ──────────────────────────────────────────────────────

@router.get("/assignments/all")
def assignments_list() -> list[HostProfileAssignment]:
    """List all host → profile assignments."""
    return list_all_assignments()


@router.get("/assignments/host/{host}")
def assignment_get(host: str) -> HostProfileAssignment:
    """Get the profile assignment for a specific host."""
    assignment = get_host_assignment(host)
    if not assignment:
        raise HTTPException(status_code=404, detail=f"No profile assigned to host '{host}'")
    return assignment


@router.put("/assignments/host/{host}")
def assignment_set(host: str, body: HostProfileAssignRequest) -> HostProfileAssignment:
    """Assign a profile to a host (creates or replaces)."""
    profile = get_profile_by_id(body.profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return assign_profile_to_host(
        host=host,
        profile_id=body.profile_id,
        assigned_by=body.assigned_by,
        notes=body.notes,
    )


@router.delete("/assignments/host/{host}")
def assignment_remove(host: str) -> dict[str, str]:
    """Remove the profile assignment from a host."""
    ok = remove_host_assignment(host)
    if not ok:
        raise HTTPException(status_code=404, detail=f"No profile assigned to host '{host}'")
    return {"status": "removed"}
