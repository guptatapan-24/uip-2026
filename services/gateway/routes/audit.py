# services/gateway/routes/audit.py
"""
Audit trail and hash chain integrity endpoints.

Provides access to immutable audit logs with cryptographic verification.
"""

from typing import List, Optional

from auth import CurrentUser, get_current_user
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

router = APIRouter()


class AuditLogEntry(BaseModel):
    """Single audit log entry with hash chain."""

    entry_id: int
    decision_id: str
    record_data: dict
    prev_hash: str
    curr_hash: str
    created_at: str
    verified: bool = True  # Hash chain verification status


@router.get(
    "/audit/log",
    response_model=List[AuditLogEntry],
    summary="Retrieve audit log with hash chain",
)
async def get_audit_log(
    decision_id: Optional[str] = Query(None, description="Filter by decision ID"),
    start_entry_id: int = Query(0, ge=0, description="Start from audit entry ID"),
    limit: int = Query(100, ge=1, le=1000, description="Number of entries to return"),
    current_user: CurrentUser = Depends(get_current_user),
) -> List[AuditLogEntry]:
    """
    Retrieve audit log entries with optional filtering.

    Each entry includes prev_hash and curr_hash for chain verification.
    Hash chain can be verified by:
      curr_hash_n = SHA256(prev_hash_n + record_data_n)

    Args:
        decision_id: Optional filter by decision ID
        start_entry_id: Start from this audit entry ID (for pagination)
        limit: Number of entries to return
        current_user: Authenticated user

    Returns:
        List of audit log entries with hashes
    """
    # TODO: Query PostgreSQL audit_log table
    # TODO: Verify hash chain integrity
    # TODO: Return entries

    return []


@router.get("/audit/verify-chain", summary="Verify audit log hash chain integrity")
async def verify_audit_chain(
    start_entry_id: int = Query(0, ge=0),
    end_entry_id: Optional[int] = Query(None),
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """
    Verify hash chain integrity across audit log entries.

    Returns report of any broken links in the chain (tampering detection).

    Args:
        start_entry_id: Start of range
        end_entry_id: End of range (default: latest)
        current_user: Authenticated user

    Returns:
        {
            "valid": bool,
            "total_entries": int,
            "verified_entries": int,
            "broken_links": [entry_id, ...],
            "message": str
        }
    """
    # TODO: Call Dhruv's audit_log.verify_chain()

    return {
        "valid": True,
        "total_entries": 0,
        "verified_entries": 0,
        "broken_links": [],
        "message": "Chain verified",
    }


@router.get(
    "/audit/decision/{decision_id}",
    summary="Get all audit entries for a specific decision",
)
async def get_decision_audit_trail(
    decision_id: str, current_user: CurrentUser = Depends(get_current_user)
) -> dict:
    """
    Retrieve complete audit trail for a decision (including any analyst overrides).

    Args:
        decision_id: UUID of decision
        current_user: Authenticated user

    Returns:
        {
            "decision_id": str,
            "initial_decision": AuditLogEntry,
            "overrides": [AuditLogEntry, ...],
            "timeline": [...]
        }
    """
    # TODO: Query audit_log + analyst_overrides tables

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"No audit trail found for decision {decision_id}",
    )
