"""DB-backed helpers for gateway routes.

These functions prefer PostgreSQL persistence through db.orm models and fall back
to the existing in-memory gateway state when a database session is not available.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

try:
    from sqlalchemy import desc, select
    from db.orm import (
        AnalystOverride,
        Decision,
        PolicyProfile,
        ValidationResult,
        get_db_manager,
    )
except ImportError:  # pragma: no cover - optional DB dependency fallback
    desc = None
    select = None
    AnalystOverride = Decision = PolicyProfile = ValidationResult = None

    def get_db_manager():
        return None
from services.gateway.state import OverrideRecord, StoredDecision, get_gateway_state


def _coerce_uuid(value: str | None) -> uuid.UUID | None:
    if not value:
        return None
    try:
        return uuid.UUID(str(value))
    except ValueError:
        return uuid.uuid5(uuid.NAMESPACE_URL, str(value))


def _decision_from_row(row: Decision, override: AnalystOverride | None = None) -> StoredDecision:
    validation_results = row.component_scores if isinstance(row.component_scores, list) else []
    created_at = row.created_at.isoformat() if row.created_at else datetime.now(timezone.utc).isoformat()
    updated_at = row.updated_at.isoformat() if row.updated_at else None
    return StoredDecision(
        decision_id=str(row.decision_id),
        alert_id=row.alert_id or "",
        llm_output=row.llm_output or "",
        outcome=override.new_outcome if override else (row.outcome or ""),
        risk_score=float(row.risk_score or 0.0),
        validation_results=validation_results,
        analyst_rationale=row.analyst_rationale or "",
        analyst_override=override.new_outcome if override else None,
        created_at=created_at,
        created_by=str(row.created_by) if row.created_by else "system",
        updated_at=updated_at,
    )


def _override_from_row(row: AnalystOverride) -> OverrideRecord:
    return OverrideRecord(
        override_id=str(row.override_id),
        decision_id=str(row.decision_id),
        previous_outcome=row.original_outcome or "",
        new_outcome=row.new_outcome or "",
        rationale=row.rationale or "",
        correction_suggestion=row.correction_suggestion,
        overridden_by=str(row.overridden_by),
        override_timestamp=row.override_timestamp.isoformat() if row.override_timestamp else datetime.now(timezone.utc).isoformat(),
        audit_hash=row.audit_hash or "",
    )


async def _get_session():
    if get_db_manager is None or select is None:
        return None

    manager = get_db_manager()
    if manager is None:
        return None
    try:
        if manager.async_session_maker is None:
            await manager.initialize()
        return await manager.get_session()
    except Exception:
        return None


async def get_db_session():
    """Open a gateway database session when PostgreSQL is available."""
    return await _get_session()


async def save_decision(
    decision: StoredDecision,
    *,
    policy_profile_name: str | None = None,
    correction_candidate: Any = None,
) -> bool:
    session = await _get_session()
    if session is None or Decision is None or ValidationResult is None:
        get_gateway_state().add_decision(decision)
        return False

    try:
        row = Decision(
            decision_id=_coerce_uuid(decision.decision_id),
            alert_id=decision.alert_id,
            llm_output=decision.llm_output,
            outcome=decision.outcome,
            risk_score=decision.risk_score,
            component_scores=decision.validation_results,
            correction_candidate=json.dumps(correction_candidate, sort_keys=True, default=str) if correction_candidate is not None else None,
            analyst_rationale=decision.analyst_rationale,
            policy_profile_name=policy_profile_name,
            created_by=_coerce_uuid(decision.created_by),
        )
        session.add(row)
        await session.flush()

        for result in decision.validation_results:
            validation_row = ValidationResult(
                decision_id=row.decision_id,
                rule_id=str(result.get("rule_id") or ""),
                rule_name=str((result.get("metadata") or {}).get("rule_name") or result.get("signal") or result.get("rule_id") or ""),
                passed=bool(result.get("passed", False)),
                evidence=str(result.get("evidence") or ""),
                confidence=float(result.get("confidence") or 0.0),
            )
            session.add(validation_row)

        await session.commit()
        return True
    except Exception:
        await session.rollback()
        return False
    finally:
        await session.close()


async def list_decisions(
    *,
    outcome: str | None = None,
    alert_id: str | None = None,
    start_dt: datetime | None = None,
    end_dt: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[StoredDecision] | None:
    session = await _get_session()
    if session is None or Decision is None:
        return None

    try:
        stmt = select(Decision)
        if outcome:
            stmt = stmt.where(Decision.outcome == outcome)
        if alert_id:
            stmt = stmt.where(Decision.alert_id == alert_id)
        if start_dt:
            stmt = stmt.where(Decision.created_at >= start_dt)
        if end_dt:
            stmt = stmt.where(Decision.created_at <= end_dt)

        stmt = stmt.order_by(desc(Decision.created_at)).offset(offset).limit(limit)
        result = await session.execute(stmt)
        rows = result.scalars().all()

        decisions: list[StoredDecision] = []
        for row in rows:
            override = await _latest_override(session, str(row.decision_id))
            decisions.append(_decision_from_row(row, override))
        return decisions
    finally:
        await session.close()


async def get_decision(decision_id: str) -> StoredDecision | None:
    session = await _get_session()
    if session is None or Decision is None:
        return get_gateway_state().get_decision(decision_id)

    try:
        stmt = select(Decision).where(Decision.decision_id == _coerce_uuid(decision_id))
        result = await session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        override = await _latest_override(session, decision_id)
        return _decision_from_row(row, override)
    finally:
        await session.close()


async def list_overrides_for_decision(decision_id: str) -> list[OverrideRecord]:
    session = await _get_session()
    if session is None or AnalystOverride is None:
        return get_gateway_state().list_overrides_for_decision(decision_id)

    try:
        stmt = (
            select(AnalystOverride)
            .where(AnalystOverride.decision_id == _coerce_uuid(decision_id))
            .order_by(AnalystOverride.override_timestamp.asc())
        )
        result = await session.execute(stmt)
        rows = result.scalars().all()
        return [_override_from_row(row) for row in rows]
    finally:
        await session.close()


async def save_override(
    *,
    decision_id: str,
    previous_outcome: str,
    new_outcome: str,
    rationale: str,
    correction_suggestion: str | None,
    overridden_by: str,
    audit_hash: str,
    override_id: str,
) -> bool:
    session = await _get_session()
    if session is None or AnalystOverride is None:
        get_gateway_state().add_override(
            OverrideRecord(
                override_id=override_id,
                decision_id=decision_id,
                previous_outcome=previous_outcome,
                new_outcome=new_outcome,
                rationale=rationale,
                correction_suggestion=correction_suggestion,
                overridden_by=overridden_by,
                override_timestamp=datetime.now(timezone.utc).isoformat(),
                audit_hash=audit_hash,
            )
        )
        return False

    try:
        row = AnalystOverride(
            override_id=_coerce_uuid(override_id),
            decision_id=_coerce_uuid(decision_id),
            original_outcome=previous_outcome,
            new_outcome=new_outcome,
            rationale=rationale,
            correction_suggestion=correction_suggestion,
            overridden_by=_coerce_uuid(overridden_by),
            audit_hash=audit_hash,
        )
        session.add(row)

        decision_stmt = select(Decision).where(Decision.decision_id == _coerce_uuid(decision_id))
        decision_result = await session.execute(decision_stmt)
        decision_row = decision_result.scalar_one_or_none()
        if decision_row is not None:
            decision_row.outcome = new_outcome
            decision_row.updated_at = datetime.now(timezone.utc)

        await session.commit()
        return True
    except Exception:
        await session.rollback()
        return False
    finally:
        await session.close()


async def list_policy_profiles() -> list[dict[str, Any]] | None:
    session = await _get_session()
    if session is None or PolicyProfile is None:
        return None

    try:
        stmt = select(PolicyProfile).order_by(PolicyProfile.name.asc())
        result = await session.execute(stmt)
        rows = result.scalars().all()
        return [
            {
                "name": row.name,
                "description": row.description or "",
                "thresholds": row.thresholds or {},
                "weights": row.rule_weights or {},
                "active": bool(row.active),
            }
            for row in rows
        ]
    finally:
        await session.close()


async def create_policy_profile(
    *,
    name: str,
    description: str | None,
    thresholds: dict[str, Any],
    weights: dict[str, Any],
    active: bool = True,
) -> bool:
    session = await _get_session()
    if session is None or PolicyProfile is None:
        return False

    try:
        row = PolicyProfile(
            name=name,
            description=description,
            thresholds=thresholds,
            rule_weights=weights,
            active=active,
        )
        session.add(row)
        await session.commit()
        return True
    except Exception:
        await session.rollback()
        return False
    finally:
        await session.close()


async def get_outcome_counts() -> dict[str, int] | None:
    session = await _get_session()
    if session is None or Decision is None:
        return None

    try:
        stmt = select(Decision.outcome)
        result = await session.execute(stmt)
        rows = result.all()
        counts = {"ALLOW": 0, "FLAG": 0, "BLOCK": 0, "CORRECT": 0}
        for row in rows:
            outcome = str(row[0] or "")
            if outcome in counts:
                counts[outcome] += 1
        return counts
    finally:
        await session.close()


async def _latest_override(session, decision_id: str) -> AnalystOverride | None:
    stmt = (
        select(AnalystOverride)
        .where(AnalystOverride.decision_id == _coerce_uuid(decision_id))
        .order_by(desc(AnalystOverride.override_timestamp))
        .limit(1)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()
