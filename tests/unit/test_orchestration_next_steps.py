"""Unit tests for newly integrated orchestration helpers (audit, RAG, explainability)."""

from __future__ import annotations

import asyncio

import pytest

from services.audit.audit_log import AuditLog
from services.common.models import DecisionResult, RuleResult, RuleSignal
from services.explainability.report_builder import ReportBuilder
from services.gateway.rag_integration import RAGPipeline


def test_audit_log_append_and_verify_in_memory() -> None:
    audit = AuditLog(db_connection=None)

    first = asyncio.run(audit.append("dec-1", {"outcome": "ALLOW"}))
    second = asyncio.run(audit.append("dec-2", {"outcome": "BLOCK"}))

    assert first is not None
    assert second is not None
    assert second.prev_hash == first.curr_hash

    verification = asyncio.run(audit.verify_chain())
    assert verification["valid"] is True
    assert verification["total_entries"] == 2


def test_explainability_report_from_models_contains_trace() -> None:
    builder = ReportBuilder()

    decision = DecisionResult(
        outcome="FLAG",
        risk_score=0.71,
        applied_profile="default",
        signal_scores={"cve_validity": 0.8, "mitigation_relevance": 0.6},
        hard_fail_rule_ids=[],
        rationale="Needs review.",
    )
    rules = [
        RuleResult(
            rule_id="cve_exists_in_nvd",
            passed=True,
            evidence="CVE found",
            confidence=0.96,
            signal=RuleSignal.CVE_VALIDITY,
        ),
        RuleResult(
            rule_id="semantic_mitigation_relevance",
            passed=False,
            evidence="Low similarity",
            confidence=0.62,
            signal=RuleSignal.MITIGATION_RELEVANCE,
            correction_candidates=["Apply vendor hotfix"],
        ),
    ]

    report = asyncio.run(
        builder.build_report_from_models(
            decision_id="dec-10",
            decision=decision,
            validation_results=rules,
            threat_intel_matches=[{"source": "NVD", "match_id": "CVE-2024-0001"}],
            processing_latency_ms=14.0,
            override_available=True,
        )
    )

    assert report.decision_id == "dec-10"
    assert report.override_available is True
    assert report.rule_trace
    assert any(item.startswith("NVD:") for item in report.citations)
    assert "validation_average" in report.confidence_breakdown


def test_rag_pipeline_combines_retrieval() -> None:
    class FakeNVDClient:
        async def get_cve(self, cve_id: str):
            return type(
                "FakeRecord",
                (),
                {
                    "cve_id": cve_id,
                    "cvss_v3_score": 9.8,
                    "affected_products": [
                        "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
                    ],
                },
            )()

    class FakeAttackClient:
        async def get_technique(self, technique_id: str):
            return {
                "name": "Exploit Public-Facing Application",
                "kill_chain_phases": [{"phase_name": "initial-access"}],
                "x_mitre_platforms": ["Linux"],
            }

    class FakeKEVClient:
        async def get_kev_info(self, cve_id: str):
            return {"dateAdded": "2024-01-10", "knownRansomwareCampaignUse": "Known"}

    pipeline = RAGPipeline()
    pipeline._nvd_client = FakeNVDClient()
    pipeline._attack_client = FakeAttackClient()
    pipeline._kev_client = FakeKEVClient()
    result = asyncio.run(
        pipeline.retrieve_threat_intel(cve_id="CVE-2024-0001", technique_id="T1190")
    )

    assert result["nvd"]["source"] == "nvd"
    assert result["kev"]["is_exploited"] is True
    assert result["attack"]["source"] == "attack"
