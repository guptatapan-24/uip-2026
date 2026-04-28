"""
Unit tests for LLMVerifier (mock mode).
"""
import pytest
import os
from services.validation_engine.llm_verifier import LLMVerifier

@pytest.mark.asyncio
async def test_mock_mode():
    os.environ["MOCK_LLM_VERIFIER"] = "true"
    verifier = LLMVerifier()
    result = await verifier.verify("test claim", ["evidence"])
    assert result.contradiction_prob == 0.1
    assert not result.skipped
    assert isinstance(result.latency_ms, float)
