# services/gateway/routes/audit.py
"""
Audit trail and hash chain integrity endpoints.

Provides access to immutable audit logs with cryptographic verification.
"""

from typing import List, Optional

from auth import CurrentUser, get_current_user
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from services.audit.audit_log import get_audit_log as get_audit_log_service
from services.gateway.state import get_gateway_state

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
    audit = get_audit_log_service()
    start_id = max(1, start_entry_id)
    entries = await audit._fetch_entries(start_id=start_id, end_id=None)

    if decision_id:
        entries = [entry for entry in entries if entry.get("decision_id") == decision_id]

    entries = entries[:limit]
    verification = await audit.verify_chain(start_id=start_id)
    broken_links = set(verification.get("broken_links", []))

    return [
        AuditLogEntry(
            entry_id=int(entry["id"]),
            decision_id=str(entry["decision_id"]),
            record_data=dict(entry.get("record_data") or {}),
            prev_hash=str(entry.get("prev_hash") or ""),
            curr_hash=str(entry.get("curr_hash") or ""),
            created_at=str(entry.get("created_at") or ""),
            verified=int(entry["id"]) not in broken_links,
        )
        for entry in entries
    ]


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
    audit = get_audit_log_service()
    return await audit.verify_chain(start_id=max(1, start_entry_id), end_id=end_entry_id)


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
    audit = get_audit_log_service()
    entries = await audit._fetch_entries(start_id=1, end_id=None)
    decision_entries = [entry for entry in entries if entry.get("decision_id") == decision_id]
    overrides = get_gateway_state().list_overrides_for_decision(decision_id)

    if not decision_entries and not overrides:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No audit trail found for decision {decision_id}",
        )

    timeline = []
    for entry in decision_entries:
        timeline.append(
            {
                "type": "audit_entry",
                "entry_id": entry.get("id"),
                "timestamp": str(entry.get("created_at") or ""),
            }
        )
    for record in overrides:
        timeline.append(
            {
                "type": "override",
                "override_id": record.override_id,
                "timestamp": record.override_timestamp,
            }
        )
    timeline.sort(key=lambda item: item.get("timestamp", ""))

    initial = None
    if decision_entries:
        first = decision_entries[0]
        initial = AuditLogEntry(
            entry_id=int(first["id"]),
            decision_id=str(first["decision_id"]),
            record_data=dict(first.get("record_data") or {}),
            prev_hash=str(first.get("prev_hash") or ""),
            curr_hash=str(first.get("curr_hash") or ""),
            created_at=str(first.get("created_at") or ""),
            verified=True,
        ).model_dump()

    return {
        "decision_id": decision_id,
        "initial_decision": initial,
        "overrides": [item.model_dump() for item in overrides],
        "timeline": timeline,
    }
