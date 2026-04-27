"""Semantic validation using sentence-transformer similarity with policy overrides."""

from __future__ import annotations

import asyncio
from functools import cached_property
from typing import Any

from services.common.config import load_profile
from services.common.models import SemanticValidationResult

try:
    from sentence_transformers import SentenceTransformer
except Exception:  # pragma: no cover - optional dependency fallback
    SentenceTransformer = None  # type: ignore[assignment]


class SemanticScorer:
    """Similarity scorer for mitigation relevance and contextual grounding."""

    def __init__(self, profile_name: str = "default") -> None:
        self.profile_name = profile_name
        self.profile = load_profile(profile_name)

    @cached_property
    def model_name(self) -> str:
        return str(self.profile.get("embedding_model", "sentence-transformers/all-MiniLM-L6-v2"))

    @cached_property
    def model(self) -> Any | None:
        if SentenceTransformer is None:
            return None
        try:
            return SentenceTransformer(self.model_name)
        except Exception:
            return None

    async def score(
        self,
        claim_text: str,
        evidence_texts: list[str],
        threshold_override: float | None = None,
    ) -> SemanticValidationResult:
        """Score the best evidence chunk against a claim using embeddings or lexical fallback."""
        threshold = float(threshold_override if threshold_override is not None else self.profile.get("semantic_threshold", 0.72))
        if not evidence_texts:
            return SemanticValidationResult(
                claim_text=claim_text,
                evidence_text="",
                similarity=0.0,
                threshold=threshold,
                passed=False,
                model_name=self.model_name,
            policy_profile=self.profile_name,
        )

        best_text, best_score = await asyncio.to_thread(self._best_similarity, claim_text, evidence_texts)
        return SemanticValidationResult(
            claim_text=claim_text,
            evidence_text=best_text,
            similarity=round(best_score, 4),
            threshold=threshold,
            passed=best_score >= threshold,
            model_name=self.model_name if self.model is not None else "lexical-fallback",
            policy_profile=self.profile_name,
        )

    async def similarity(self, claim_text: str, evidence_texts: list[str]) -> tuple[str, float]:
        """Return the best evidence chunk and raw similarity score without thresholding."""
        if not evidence_texts:
            return "", 0.0
        return await asyncio.to_thread(self._best_similarity, claim_text, evidence_texts)

    def _best_similarity(self, claim_text: str, evidence_texts: list[str]) -> tuple[str, float]:
        if self.model is not None:
            claim_embedding = self.model.encode(claim_text, normalize_embeddings=True)
            evidence_embeddings = self.model.encode(evidence_texts, normalize_embeddings=True)
            similarities = [float(claim_embedding @ embedding) for embedding in evidence_embeddings]
        else:
            similarities = [self._lexical_similarity(claim_text, evidence) for evidence in evidence_texts]

        best_index = max(range(len(evidence_texts)), key=lambda idx: similarities[idx])
        return evidence_texts[best_index], float(similarities[best_index])

    @staticmethod
    def _lexical_similarity(left: str, right: str) -> float:
        left_tokens = {token.lower() for token in left.split() if token.strip()}
        right_tokens = {token.lower() for token in right.split() if token.strip()}
        if not left_tokens or not right_tokens:
            return 0.0
        intersection = len(left_tokens & right_tokens)
        union = len(left_tokens | right_tokens)
        return intersection / union
