"""
Unit tests for ExplainabilityReport builder.
"""
import pytest
from services.explainability.report_builder import ReportBuilder

@pytest.mark.asyncio
async def test_build_report():
    builder = ReportBuilder()
    report = await builder.build_report(
        decision_id="dec1",
        outcome="ALLOW",
        risk_score=0.95,
        validation_results=[{"stage": "cve", "rule_name": "cve_exists_in_nvd", "passed": True, "evidence": "Found", "confidence": 0.95}],
        threat_intel_matches=[{"source": "NVD", "url": "http://nvd", "snippet": "desc"}],
        component_scores={"cve_validity": 1.0},
        processing_latency_ms=123.4
    )
    assert report.outcome == "ALLOW"
    assert report.risk_score == 0.95
    assert report.analyst_rationale
    assert report.validation_chain
    assert report.threat_intel_matches
