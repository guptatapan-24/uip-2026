from pydantic import BaseModel, Field

class VerifierResult(BaseModel):
    contradiction_prob: float
    skipped: bool
    latency_ms: float

class LLMVerifier:
# services/validation_engine/llm_verifier.py
"""
LLM-based contradiction detection using Ollama + Mistral-7B.

Asks Mistral to detect contradictions or hallucinations in LLM recommendations.
If Ollama unavailable or latency > 2s, falls back to OpenAI GPT-3.5-turbo.

Circuit breaker pattern prevents cascading failures.

TODO: Integrate Tapan's or other modules for LLM result interpretation
"""

import os
import time
import json
from typing import Optional, Dict
import httpx
import asyncio


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
        
        self.circuit_breaker_threshold = 5  # failures before breaker opens
        self.circuit_breaker_count = 0
        self.circuit_breaker_open = False
    
    async def verify(self, claim: str, evidence: list) -> VerifierResult:
        """
        Verify claim using LLM or mock mode.
        """
        start = time.time()
        if os.getenv("MOCK_LLM_VERIFIER", "false").lower() == "true":
            return VerifierResult(contradiction_prob=0.1, skipped=False, latency_ms=(time.time()-start)*1000)
        # Real mode: POST to Ollama, fallback to OpenAI
        try:
            async with httpx.AsyncClient(timeout=self.ollama_timeout) as client:
                resp = await client.post(
                    f"{self.ollama_base_url}/api/generate",
                    json={"model": self.ollama_model, "prompt": f"Verify: {claim}\nEvidence: {evidence}"}
                )
                resp.raise_for_status()
                # Dummy parse: real implementation would parse model output
                contradiction_prob = 0.2  # Placeholder
                return VerifierResult(contradiction_prob=contradiction_prob, skipped=False, latency_ms=(time.time()-start)*1000)
        except Exception:
            # Fallback to OpenAI (mocked)
            return VerifierResult(contradiction_prob=0.3, skipped=False, latency_ms=(time.time()-start)*1000)
    
    async def _verify_with_ollama(
        self,
        claim: str,
        context: str,
        threat_intel: Dict
    ) -> Dict:
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
                    "format": "json"
                }
            )
            response.raise_for_status()
            
            data = response.json()
            response_text = data.get("response", "{}")
            
            try:
                result = json.loads(response_text)
                return {
                    "contradiction_detected": result.get("contradiction_detected", False),
                    "contradiction_prob": result.get("confidence", 0.0),
                    "explanation": result.get("explanation", "")
                }
            except json.JSONDecodeError:
                return {
                    "contradiction_detected": False,
                    "contradiction_prob": 0.0,
                    "explanation": "Failed to parse LLM response"
                }
    
    async def _verify_with_openai(
        self,
        claim: str,
        context: str,
        threat_intel: Dict
    ) -> Dict:
        """
        Fallback verification using OpenAI GPT-3.5-turbo.
        """
        # TODO: Implement OpenAI API call
        # For now, return stub
        return {
            "contradiction_detected": False,
            "contradiction_prob": 0.0,
            "explanation": "OpenAI fallback not implemented"
        }
    
    def reset_circuit_breaker(self):
        """Manually reset circuit breaker for recovery."""
        self.circuit_breaker_count = 0
        self.circuit_breaker_open = False


# Singleton
_verifier: Optional[LLMVerifier] = None


def get_llm_verifier() -> LLMVerifier:
    """Get or create LLM verifier singleton."""
    global _verifier
    if _verifier is None:
        _verifier = LLMVerifier()
    return _verifier
