"""Shared gateway runtime state.

Provides an in-memory compatibility layer for decisions, audit linking, and metrics.
This keeps routes functional before full database integration is wired.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any

from pydantic import BaseModel, Field


class StoredDecision(BaseModel):
    """Canonical decision record used by gateway routes."""

    decision_id: str
    alert_id: str
    llm_output: str = ""
    outcome: str
    risk_score: float
    validation_results: list[dict[str, Any]] = Field(default_factory=list)
    analyst_rationale: str = ""
    analyst_override: str | None = None
    created_at: str
    created_by: str = "system"
    updated_at: str | None = None


class OverrideRecord(BaseModel):
    """Record of analyst override actions."""

    override_id: str
    decision_id: str
    previous_outcome: str
    new_outcome: str
    rationale: str
    correction_suggestion: str | None = None
    overridden_by: str
    override_timestamp: str
    audit_hash: str


class GatewayState:
    """Thread-safe runtime state for gateway compatibility routes."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._decisions: dict[str, StoredDecision] = {}
        self._overrides: dict[str, OverrideRecord] = {}
        self._validation_latencies_ms: deque[tuple[datetime, float]] = deque(maxlen=5000)

    def add_decision(self, decision: StoredDecision) -> None:
        with self._lock:
            self._decisions[decision.decision_id] = decision

    def get_decision(self, decision_id: str) -> StoredDecision | None:
        with self._lock:
            decision = self._decisions.get(decision_id)
            return StoredDecision.model_validate(decision.model_dump()) if decision else None

    def list_decisions(self) -> list[StoredDecision]:
        with self._lock:
            values = [StoredDecision.model_validate(item.model_dump()) for item in self._decisions.values()]
        values.sort(key=lambda item: item.created_at, reverse=True)
        return values

    def add_override(self, record: OverrideRecord) -> None:
        with self._lock:
            self._overrides[record.override_id] = record

    def list_overrides_for_decision(self, decision_id: str) -> list[OverrideRecord]:
        with self._lock:
            return [
                OverrideRecord.model_validate(item.model_dump())
                for item in self._overrides.values()
                if item.decision_id == decision_id
            ]

    def apply_override(
        self,
        decision_id: str,
        new_outcome: str,
        overridden_by: str,
    ) -> StoredDecision | None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            decision = self._decisions.get(decision_id)
            if decision is None:
                return None
            decision.analyst_override = new_outcome
            decision.outcome = new_outcome
            decision.updated_at = now_iso
            decision.created_by = overridden_by
            return StoredDecision.model_validate(decision.model_dump())

    def record_validation_latency(self, latency_ms: float) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            self._validation_latencies_ms.append((now, float(latency_ms)))

    def get_latency_window(self, minutes: int) -> list[float]:
        threshold = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        with self._lock:
            return [
                latency
                for timestamp, latency in self._validation_latencies_ms
                if timestamp >= threshold
            ]


_state: GatewayState | None = None


def get_gateway_state() -> GatewayState:
    global _state
    if _state is None:
        _state = GatewayState()
    return _state
