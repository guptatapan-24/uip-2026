"""Unit tests for LLMVerifier fallback and mock behavior."""

from __future__ import annotations

import asyncio

from services.validation_engine.llm_verifier import LLMVerifier


def test_mock_mode_returns_structured_result(monkeypatch):
    monkeypatch.setenv("MOCK_LLM_VERIFIER", "true")
    verifier = LLMVerifier()
    result = asyncio.run(verifier.verify("test claim", ["evidence"], {"cve": "CVE-2024-0001"}))

    assert result.provider == "mock"
    assert result.contradiction_prob == 0.1
    assert result.skipped is False
    assert isinstance(result.latency_ms, float)


def test_verify_alias_accepts_evidence_list(monkeypatch):
    monkeypatch.setenv("MOCK_LLM_VERIFIER", "true")
    verifier = LLMVerifier()
    result = asyncio.run(verifier.verify_claim("claim", "context", {}))

    assert result.contradiction_detected is False
    assert result.provider == "mock"
