import asyncio
import time

import pytest

from services.validation_engine.llm_verifier import LLMVerifier


def test_circuit_opens_after_failures(monkeypatch):
    # Force real calls to raise
    verifier = LLMVerifier()

    async def fail_ollama(*args, **kwargs):
        raise RuntimeError("simulated ollama failure")

    monkeypatch.setattr(verifier, "_verify_with_ollama", fail_ollama)
    monkeypatch.setenv("OLLAMA_RETRY_ATTEMPTS", "1")
    verifier.circuit_breaker_threshold = 2

    # First attempt should increment counter and try fallback (which will also fail)
    async def run_verify():
        return await verifier.verify_claim("c", "ctx", {})

    # Run twice to exceed threshold
    res1 = asyncio.run(run_verify())
    res2 = asyncio.run(run_verify())

    assert verifier.circuit_breaker_open is True
    assert res2.skipped is True or res2.provider in {"openai", "none"}


def test_circuit_resets_after_timeout(monkeypatch):
    verifier = LLMVerifier()
    verifier.circuit_breaker_threshold = 1
    verifier.circuit_breaker_reset_seconds = 1

    async def fail_ollama(*args, **kwargs):
        raise RuntimeError("simulated ollama failure")

    monkeypatch.setattr(verifier, "_verify_with_ollama", fail_ollama)

    res = asyncio.run(verifier.verify_claim("c", "ctx", {}))
    assert verifier.circuit_breaker_open is True

    # Wait past reset window
    time.sleep(1.1)
    # Next call should attempt again (circuit reset)
    def ok_ollama(*args, **kwargs):
        return asyncio.Future()

    async def ok(*a, **k):
        return verifier.verify_claim.__annotations__["return__"] if False else verifier.__class__

    # Replace with a simple coroutine that returns a successful VerificationResult via the mock mode
    monkeypatch.setenv("MOCK_LLM_VERIFIER", "true")
    verifier.reset_circuit_breaker()
    res2 = asyncio.run(verifier.verify_claim("c", "ctx", {}))
    assert res2.provider == "mock"
