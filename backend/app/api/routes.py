#FASTAPI to 



from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.api.schemas import HealthResponse, ValidateRequest, ValidateResponse
from app.core.config import settings
from app.core.metrics import metrics_store, timed
from app.services.decision_engine import evaluate_claims
from app.services.demo_data import DEMO_SCENARIOS

router = APIRouter()
_decision_cache: dict[str, dict] = {}


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", app=settings.app_name, version=settings.app_version)


@router.get("/metrics")
def get_metrics() -> dict:
    return metrics_store.snapshot()


@router.get("/demo-scenarios")
def get_demo_scenarios() -> list[dict]:
    return DEMO_SCENARIOS


@router.post("/validate", response_model=ValidateResponse)
def validate(payload: ValidateRequest) -> ValidateResponse:
    cache_key = payload.model_dump_json()

    def compute() -> tuple[dict, bool]:
        cached = _decision_cache.get(cache_key)
        if cached:
            return cached, True
        result = evaluate_claims(payload.claims.model_dump()).as_dict()
        _decision_cache[cache_key] = result
        return result, False

    result, latency_ms, cache_hit = timed(compute)
    metrics_store.track_cache(cache_hit)
    metrics_store.track_request(payload.scenario_id, result["decision"], latency_ms)
    metrics_store.track_demo_expectation(result["decision"], payload.expected_decision)

    return ValidateResponse(**result, metrics=metrics_store.snapshot())


@router.get("/demo-scenarios/{scenario_id}")
def get_demo_scenario(scenario_id: str) -> dict:
    for scenario in DEMO_SCENARIOS:
        if scenario["id"] == scenario_id:
            return scenario
    raise HTTPException(status_code=404, detail="Scenario not found")
