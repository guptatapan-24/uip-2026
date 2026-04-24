# services/validation_engine/semantic.py
"""
Semantic validation using cosine similarity.

Compares claim text against threat intelligence descriptions using 
sentence-transformers embeddings. Threshold loaded from policy profile (default 0.72).

Returns: {rule_id, passed, evidence, confidence, similarity_score}

TODO: Load semantic threshold from policy_profiles.yaml dynamically
"""

import numpy as np
from typing import Optional, Dict
from sentence_transformers import SentenceTransformer, util


class SemanticValidator:
    """
    Semantic similarity-based validator.
    """
    
    # Default embedding model and similarity threshold
    EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
    DEFAULT_THRESHOLD = 0.72
    
    def __init__(self, threshold: float = DEFAULT_THRESHOLD):
        """
        Initialize semantic validator.
        
        Args:
            threshold: Cosine similarity threshold (0.0-1.0)
        """
        self.model = SentenceTransformer(self.EMBEDDING_MODEL)
        self.threshold = threshold
    
    async def validate_claim(
        self,
        claim_text: str,
        reference_text: str,
        policy_profile: Optional[Dict] = None
    ) -> Dict:
        """
        Validate claim against reference text using semantic similarity.
        
        Args:
            claim_text: Extracted claim from LLM output
            reference_text: Authoritative description from threat intel
            policy_profile: Optional profile with custom threshold
            
        Returns:
            {
                "rule_id": "semantic_similarity",
                "passed": bool,
                "evidence": str,
                "confidence": float,
                "similarity_score": float,
                "threshold": float
            }
        """
        # Get threshold from policy profile if provided
        threshold = self.threshold
        if policy_profile:
            threshold = policy_profile.get("semantic_threshold", self.threshold)
        
        # Generate embeddings
        claim_embedding = self.model.encode(claim_text, convert_to_tensor=True)
        reference_embedding = self.model.encode(reference_text, convert_to_tensor=True)
        
        # Compute cosine similarity
        similarity = util.pytorch_cos_sim(claim_embedding, reference_embedding).item()
        
        # Determine pass/fail
        passed = similarity >= threshold
        
        return {
            "rule_id": "semantic_similarity",
            "rule_name": "Semantic similarity to threat intel",
            "passed": passed,
            "evidence": (
                f"Similarity: {similarity:.3f} vs threshold {threshold:.3f}. "
                f"Claim: '{claim_text[:60]}...' matches reference context."
            ),
            "confidence": min(1.0, similarity + 0.1),  # Confidence increases with similarity
            "similarity_score": similarity,
            "threshold": threshold
        }
    
    async def validate_batch(
        self,
        claims: list,
        threat_intel_texts: list,
        policy_profile: Optional[Dict] = None
    ) -> list:
        """
        Validate multiple claims against threat intel in batch.
        
        Args:
            claims: List of claim text strings
            threat_intel_texts: List of reference text strings (same length)
            policy_profile: Optional policy profile
            
        Returns:
            List of validation results
        """
        results = []
        for claim, ref_text in zip(claims, threat_intel_texts):
            result = await self.validate_claim(claim, ref_text, policy_profile)
            results.append(result)
        return results
