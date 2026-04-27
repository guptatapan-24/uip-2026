# services/gateway/routes/policy.py
"""
Policy management and analyst override endpoints.

Allows SOC_ADMIN to override automated decisions and manage policy profiles.
"""

from typing import Optional

from auth import CurrentUser, require_role
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

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

    # TODO: Fetch original decision from PostgreSQL
    # TODO: Create override record in analyst_overrides table
    # TODO: Update decisions table
    # TODO: Append to audit log with hash chain

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Decision {request.decision_id} not found",
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
    # TODO: Load policy_profiles.yaml
    # TODO: Return parsed profiles

    return {
        "profiles": [
            {
                "name": "default",
                "description": "Default SOC policy",
                "thresholds": {"allow_min": 0.85, "flag_min": 0.60, "block_max": 0.60},
                "active": True,
            }
        ]
    }


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
    # TODO: Validate profile structure
    # TODO: Save to policy_profiles.yaml
    # TODO: Return created profile

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid profile configuration"
    )
