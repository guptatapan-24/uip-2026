# services/gateway/routes/policy.py
"""
Policy management and analyst override endpoints.

Allows SOC_ADMIN to override automated decisions and manage policy profiles.
"""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from auth import CurrentUser, require_role
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from services.audit.audit_log import get_audit_log
from services.common.config import ROOT_DIR, load_yaml_config
import yaml

from services.gateway.state import OverrideRecord, get_gateway_state

router = APIRouter()


class PolicyOverrideRequest(BaseModel):
    """Analyst override of automated decision."""

    decision_id: str
    new_outcome: str = Field(
        ..., description="Override outcome: ALLOW | FLAG | BLOCK | CORRECT"
    )
    rationale: str = Field(..., min_length=10, description="Reason for override")
    correction_suggestion: Optional[str] = None


class PolicyOverrideResponse(BaseModel):
    """Response confirming override."""

    override_id: str
    decision_id: str
    previous_outcome: str
    new_outcome: str
    overridden_by: str
    override_timestamp: str
    audit_hash: str


@router.post(
    "/policy/override",
    response_model=PolicyOverrideResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Override automated decision (SOC_ADMIN only)",
)
async def override_decision(
    request: PolicyOverrideRequest,
    current_user: CurrentUser = Depends(require_role(["SOC_ADMIN"])),
) -> PolicyOverrideResponse:
    """
    Allow SOC_ADMIN to override automated decision and provide rationale.

    This creates an audit trail entry and updates the decision record.

    Args:
        request: Override details with rationale
        current_user: Authenticated SOC_ADMIN user

    Returns:
        Confirmation of override with audit hash

    Raises:
        403: User is not SOC_ADMIN
        404: Decision not found
        400: Invalid outcome value
    """
    valid_outcomes = ["ALLOW", "FLAG", "BLOCK", "CORRECT"]
    if request.new_outcome not in valid_outcomes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid outcome. Must be one of: {', '.join(valid_outcomes)}",
        )

    state = get_gateway_state()
    original = state.get_decision(request.decision_id)
    if original is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Decision {request.decision_id} not found",
        )

    previous_outcome = original.outcome
    updated = state.apply_override(
        decision_id=request.decision_id,
        new_outcome=request.new_outcome,
        overridden_by=current_user.user_id,
    )
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Decision {request.decision_id} not found",
        )

    override_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    audit_entry = await get_audit_log().append(
        decision_id=request.decision_id,
        record_data={
            "type": "policy_override",
            "override_id": override_id,
            "decision_id": request.decision_id,
            "previous_outcome": previous_outcome,
            "new_outcome": request.new_outcome,
            "rationale": request.rationale,
            "correction_suggestion": request.correction_suggestion,
            "overridden_by": current_user.user_id,
            "override_timestamp": timestamp,
        },
    )

    audit_hash = audit_entry.curr_hash if audit_entry else ""
    state.add_override(
        OverrideRecord(
            override_id=override_id,
            decision_id=request.decision_id,
            previous_outcome=previous_outcome,
            new_outcome=request.new_outcome,
            rationale=request.rationale,
            correction_suggestion=request.correction_suggestion,
            overridden_by=current_user.user_id,
            override_timestamp=timestamp,
            audit_hash=audit_hash,
        )
    )

    return PolicyOverrideResponse(
        override_id=override_id,
        decision_id=request.decision_id,
        previous_outcome=previous_outcome,
        new_outcome=request.new_outcome,
        overridden_by=current_user.user_id,
        override_timestamp=timestamp,
        audit_hash=audit_hash,
    )


@router.get("/policy/profiles", summary="List policy profiles")
async def list_policy_profiles(
    current_user: CurrentUser = Depends(require_role(["SOC_ADMIN", "SYSTEM"]))
) -> dict:
    """
    List available policy profiles for decision thresholds.

    Each profile contains risk score thresholds and rule weights.

    Args:
        current_user: Authenticated user (SOC_ADMIN or SYSTEM)

    Returns:
        {"profiles": [{"name": str, "thresholds": {...}, "active": bool}, ...]}
    """
    profiles = load_yaml_config("config/policy_profiles.yaml").get("profiles", {})
    active_profile = load_yaml_config("config/policy_profiles.yaml").get(
        "active_profile", "default"
    )

    payload = []
    for name, profile in profiles.items():
        payload.append(
            {
                "name": name,
                "description": profile.get("description", f"{name} policy profile"),
                "thresholds": profile.get("thresholds", {}),
                "weights": profile.get("weights", {}),
                "active": name == active_profile,
            }
        )

    return {"profiles": payload}


@router.post(
    "/policy/profiles",
    status_code=status.HTTP_201_CREATED,
    summary="Create new policy profile (SYSTEM only)",
)
async def create_policy_profile(
    profile_data: dict, current_user: CurrentUser = Depends(require_role(["SYSTEM"]))
) -> dict:
    """
    Create a new decision policy profile.

    Args:
        profile_data: Policy profile configuration
        current_user: Authenticated SYSTEM user

    Returns:
        Created profile details
    """
    name = str(profile_data.get("name", "")).strip()
    profile = profile_data.get("profile")

    if not name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Profile name is required",
        )
    if not isinstance(profile, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="profile must be an object",
        )

    for required in ("weights", "thresholds", "signal_defaults"):
        if required not in profile or not isinstance(profile[required], dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"profile.{required} must be provided as an object",
            )

    path = ROOT_DIR / "config" / "policy_profiles.yaml"
    with path.open("r", encoding="utf-8") as handle:
        current = yaml.safe_load(handle) or {}

    profiles = current.setdefault("profiles", {})
    if name in profiles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Profile '{name}' already exists",
        )

    profiles[name] = profile

    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(current, handle, sort_keys=False)

    load_yaml_config.cache_clear()
    return {"name": name, "profile": profile, "created": True}
