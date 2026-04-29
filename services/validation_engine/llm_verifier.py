# services/validation_engine/llm_verifier.py
"""
LLM-based contradiction detection using Ollama + Mistral-7B.

Asks Mistral to detect contradictions or hallucinations in LLM recommendations.
If Ollama unavailable or latency > 2s, falls back to OpenAI GPT-3.5-turbo.

Circuit breaker pattern prevents cascading failures.
"""

import asyncio
import json
import os
import time
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

import httpx

try:
    from prometheus_client import Counter, Gauge
except Exception:  # pragma: no cover - optional dependency
    class _NoopMetric:
        def labels(self, **kwargs):
            return self

        def inc(self, amount=1):
            return None

        def set(self, value):
            return None

    def Counter(*args, **kwargs):
        return _NoopMetric()

    def Gauge(*args, **kwargs):
        return _NoopMetric()


# Prometheus metrics
llm_calls = Counter("llm_verifier_calls_total", "Total LLM verifier calls", ["provider"])  # provider: ollama/openai/mock
llm_failures = Counter("llm_verifier_failures_total", "LLM verifier failures", ["provider"])  # failures per provider
llm_fallbacks = Counter("llm_verifier_fallbacks_total", "LLM verifier fallbacks")
llm_circuit_open_total = Counter("llm_verifier_circuit_open_total", "Times LLM circuit breaker opened")
llm_circuit_open = Gauge("llm_verifier_circuit_open", "Is circuit breaker currently open (0/1)")


class VerificationResult(BaseModel):
    """Structured contradiction-detection result."""

    contradiction_detected: bool = False
    contradiction_prob: float = Field(default=0.0, ge=0.0, le=1.0)
    explanation: str = ""
    skipped: bool = False
    latency_ms: float = 0.0
    provider: str = "none"


def _coerce_evidence(evidence: Any) -> str:
    if evidence is None:
        return ""
    if isinstance(evidence, str):
        return evidence
    if isinstance(evidence, (list, tuple, set)):
        return "; ".join(str(item) for item in evidence)
    if isinstance(evidence, dict):
        return json.dumps(evidence, sort_keys=True)
    return str(evidence)


class LLMVerifier:
    """
    LLM-based verification using Ollama + fallback to OpenAI.
    """

    def __init__(self):
        """Initialize LLM verifier."""
        self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "mistral:7b")
        self.ollama_timeout = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "2"))

        self.fallback_provider = os.getenv("OLLAMA_FALLBACK_PROVIDER", "openai")
        self.openai_api_key = os.getenv("OPENAI_API_KEY", "")
        self.openai_base_url = os.getenv(
            "OPENAI_BASE_URL", "https://api.openai.com/v1"
        )
        self.openai_model = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")

        # Circuit-breaker and retry configuration (env-overridable)
        self.circuit_breaker_threshold = int(os.getenv("LLM_CB_THRESHOLD", "5"))
        self.circuit_breaker_count = 0
        self.circuit_breaker_open = False
        # When breaker opens, automatically reset after this many seconds
        self.circuit_breaker_reset_seconds = int(os.getenv("LLM_CB_RESET_SECONDS", "60"))
        self._last_failure_ts = 0

        # Retry/backoff for Ollama calls: number of attempts and base backoff seconds
        self.ollama_retry_attempts = int(os.getenv("OLLAMA_RETRY_ATTEMPTS", "2"))
        self.ollama_backoff_base = float(os.getenv("OLLAMA_BACKOFF_BASE", "0.5"))

        # Simple logger
        try:
            import logging

            self._log = logging.getLogger(__name__)
        except Exception:
            self._log = None

    async def verify(self, claim: str, evidence: Any, threat_intel: Dict | None = None) -> VerificationResult:
        """Compatibility alias for callers that provide a claim and evidence list."""
        return await self.verify_claim(claim, _coerce_evidence(evidence), threat_intel or {})

    async def verify_claim(self, claim: str, context: str, threat_intel: Dict) -> VerificationResult:
        """
        Verify if claim contains contradictions or hallucinations.

        Args:
            claim: Extracted claim from LLM output
            context: Original LLM recommendation
            threat_intel: Retrieved threat intelligence

        Returns:
            {
                "contradiction_detected": bool,
                "contradiction_prob": float,  # 0.0-1.0
                "explanation": str,
                "skipped": bool,  # True if circuit breaker active
                "latency_ms": float,
                "provider": str  # "ollama" or "openai"
            }
        """
        start_time = time.time()

        if os.getenv("MOCK_LLM_VERIFIER", "false").lower() in {"1", "true", "yes"}:
            return VerificationResult(
                contradiction_detected=False,
                contradiction_prob=0.1,
                explanation="Mock verifier mode enabled",
                skipped=False,
                latency_ms=round((time.time() - start_time) * 1000, 2),
                provider="mock",
            )

        # If circuit is open, check if reset interval passed; if so, reset
        if self.circuit_breaker_open:
            if time.time() - self._last_failure_ts > self.circuit_breaker_reset_seconds:
                self.reset_circuit_breaker()
            else:
                return VerificationResult(
                    contradiction_detected=False,
                    contradiction_prob=0.0,
                    explanation="LLM verifier unavailable (circuit breaker open)",
                    skipped=True,
                    latency_ms=0.0,
                    provider="none",
                )

        # Try Ollama first
        # Try Ollama with retries and exponential backoff
        ollama_exception = None
        for attempt in range(1, self.ollama_retry_attempts + 1):
            try:
                # record attempt
                llm_calls.labels(provider="ollama").inc()
                result = await self._verify_with_ollama(claim, context, threat_intel)
                latency_ms = (time.time() - start_time) * 1000

                # Success - reset counter
                self.circuit_breaker_count = 0

                result.latency_ms = round(latency_ms, 2)
                result.provider = "ollama"
                return result
            except Exception as e:
                ollama_exception = e
                self.circuit_breaker_count += 1
                self._last_failure_ts = time.time()
                # metric: failure on ollama
                llm_failures.labels(provider="ollama").inc()
                if self._log:
                    self._log.warning("Ollama attempt %d failed: %s", attempt, str(e))
                # If reached threshold, open circuit
                if self.circuit_breaker_count >= self.circuit_breaker_threshold:
                    self.circuit_breaker_open = True
                    if self._log:
                        self._log.error("LLM verifier circuit breaker opened")
                    break
                # Backoff before next attempt
                backoff = self.ollama_backoff_base * (2 ** (attempt - 1))
                await asyncio.sleep(backoff)

        # Fallback to OpenAI
        if self.fallback_provider == "openai":
            try:
                llm_fallbacks.inc()
                llm_calls.labels(provider="openai").inc()
                result = await self._verify_with_openai(claim, context, threat_intel)
                result.latency_ms = round((time.time() - start_time) * 1000, 2)
                result.provider = "openai"
                return result
            except Exception as e:
                if self._log:
                    self._log.warning("OpenAI fallback failed: %s", str(e))
                llm_failures.labels(provider="openai").inc()

        # Both failed - return safe default
        # If circuit just opened, update metrics
        if self.circuit_breaker_open:
            llm_circuit_open_total.inc()
            llm_circuit_open.set(1)

        return VerificationResult(
            contradiction_detected=False,
            contradiction_prob=0.0,
            explanation="LLM verification unavailable",
            skipped=True,
            latency_ms=round((time.time() - start_time) * 1000, 2),
            provider="none",
        )

    async def _verify_with_ollama(
        self, claim: str, context: str, threat_intel: Dict
    ) -> VerificationResult:
        """
        Verify using Ollama + Mistral-7B.

        Args:
            claim: Claim to verify
            context: Original LLM output
            threat_intel: Threat intelligence data

        Returns:
            Verification result
        """
        prompt = f"""You are a security analyst verifying LLM recommendations against threat intelligence.

LLM Recommendation: {context}

Extracted Claim: {claim}

Threat Intelligence Context:
{json.dumps(threat_intel, indent=2)[:500]}

Analyze if the claim contradicts or hallucinating based on the threat intelligence.
Respond with JSON:
{{"contradiction_detected": bool, "confidence": float (0-1), "explanation": str}}"""

        async with httpx.AsyncClient(timeout=self.ollama_timeout) as client:
            response = await client.post(
                f"{self.ollama_base_url}/api/generate",
                json={
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                },
            )
            response.raise_for_status()

            data = response.json()
            response_text = data.get("response", "{}")

            try:
                result = json.loads(response_text)
                return VerificationResult(
                    contradiction_detected=bool(result.get("contradiction_detected", False)),
                    contradiction_prob=float(result.get("confidence", 0.0)),
                    explanation=str(result.get("explanation", "")),
                )
            except json.JSONDecodeError:
                return VerificationResult(
                    contradiction_detected=False,
                    contradiction_prob=0.0,
                    explanation="Failed to parse LLM response",
                )

    async def _verify_with_openai(
        self, claim: str, context: str, threat_intel: Dict
    ) -> VerificationResult:
        """
        Fallback verification using OpenAI GPT-3.5-turbo.
        """
        prompt = f"""You are a security analyst verifying LLM recommendations against threat intelligence.

LLM Recommendation: {context}

Extracted Claim: {claim}

Threat Intelligence Context:
{json.dumps(threat_intel, indent=2)[:500]}

Analyze whether the claim contradicts or hallucinates the threat intelligence.
Respond with JSON in the form:
{{"contradiction_detected": bool, "confidence": float, "explanation": str}}"""

        headers = {"Authorization": f"Bearer {self.openai_api_key}"}
        payload = {
            "model": self.openai_model,
            "messages": [
                {"role": "system", "content": "You are a precise SOC verifier."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
        }

        async with httpx.AsyncClient(timeout=self.ollama_timeout) as client:
            response = await client.post(
                f"{self.openai_base_url.rstrip('/')}/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        content = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "{}")
        )

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            parsed = {}

        return VerificationResult(
            contradiction_detected=bool(parsed.get("contradiction_detected", False)),
            contradiction_prob=float(parsed.get("confidence", 0.0)),
            explanation=str(parsed.get("explanation", "OpenAI fallback completed")),
        )

    def reset_circuit_breaker(self):
        """Manually reset circuit breaker for recovery."""
        self.circuit_breaker_count = 0
        self.circuit_breaker_open = False
        self._last_failure_ts = 0
        # update prometheus gauge
        try:
            llm_circuit_open.set(0)
        except Exception:
            pass


# Singleton
_verifier: Optional[LLMVerifier] = None


def get_llm_verifier() -> LLMVerifier:
    """Get or create LLM verifier singleton."""
    global _verifier
    if _verifier is None:
        _verifier = LLMVerifier()
    return _verifier
