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
    
    async def verify_claim(
        self,
        claim: str,
        context: str,
        threat_intel: Dict
    ) -> Dict:
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
        
        # Circuit breaker check
        if self.circuit_breaker_open:
            return {
                "contradiction_detected": False,
                "contradiction_prob": 0.0,
                "explanation": "LLM verifier unavailable (circuit breaker open)",
                "skipped": True,
                "latency_ms": 0.0,
                "provider": "none"
            }
        
        # Try Ollama first
        try:
            result = await self._verify_with_ollama(claim, context, threat_intel)
            latency_ms = (time.time() - start_time) * 1000
            
            if latency_ms > self.ollama_timeout * 1000:
                # Timeout - circuit breaker increments
                self.circuit_breaker_count += 1
                if self.circuit_breaker_count >= self.circuit_breaker_threshold:
                    self.circuit_breaker_open = True
            else:
                # Success - reset counter
                self.circuit_breaker_count = 0
            
            result["latency_ms"] = latency_ms
            result["provider"] = "ollama"
            return result
        
        except Exception as e:
            print(f"Ollama verification failed: {e}")
            self.circuit_breaker_count += 1
            
            if self.circuit_breaker_count >= self.circuit_breaker_threshold:
                self.circuit_breaker_open = True
        
        # Fallback to OpenAI
        if self.fallback_provider == "openai":
            try:
                result = await self._verify_with_openai(claim, context, threat_intel)
                result["latency_ms"] = (time.time() - start_time) * 1000
                result["provider"] = "openai"
                return result
            except Exception as e:
                print(f"OpenAI fallback failed: {e}")
        
        # Both failed - return safe default
        return {
            "contradiction_detected": False,
            "contradiction_prob": 0.0,
            "explanation": "LLM verification unavailable",
            "skipped": True,
            "latency_ms": (time.time() - start_time) * 1000,
            "provider": "none"
        }
    
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
