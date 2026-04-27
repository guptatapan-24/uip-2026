# services/decision_engine/engine.py
"""
Decision engine with weighted risk scoring and policy profile support.

Risk Score Formula:
  risk_score = (0.4 × cve_validity) 
             + (0.3 × severity_accuracy)
             + (0.2 × mitigation_relevance)
             + (0.1 × urgency_consistency)

Decision Outcomes:
  ALLOW:  0.85 ≤ risk_score ≤ 1.0  (high confidence)
  FLAG:   0.60 ≤ risk_score < 0.85  (analyst review recommended)
  BLOCK:  risk_score < 0.60 or any hard-fail rule
  CORRECT: triggered on BLOCK if correction candidate exists

TODO: Integrate Tapan's decision engine final coordination
TODO: Wire policy profile override logic from gateway
"""

import uuid
from typing import List, Dict, Optional
from datetime import datetime
from pydantic import BaseModel, Field
import yaml
import os


class PolicyProfile(BaseModel):
    """Policy decision thresholds."""
    name: str
    description: str
    thresholds: Dict[str, float] = Field(default_factory=dict)
    rule_weights: Dict[str, float] = Field(default_factory=dict)
    active: bool = True


class DecisionInput(BaseModel):
    """Input to decision engine."""
    validation_results: List[Dict]  # From validation_engine outputs
    threat_intel_match_quality: float = Field(..., ge=0.0, le=1.0)  # RAG retrieval quality
    llm_verification_contradiction_prob: Optional[float] = None
    policy_profile_name: str = Field(default="default")


class DecisionOutput(BaseModel):
    """Decision engine output."""
    decision_id: str
    outcome: str  # ALLOW | FLAG | BLOCK | CORRECT
    risk_score: float = Field(..., ge=0.0, le=1.0)
    component_scores: Dict[str, float]  # Breakdown of risk score components
    correction_candidate: Optional[str] = None  # If outcome is CORRECT
    rationale: str


class DecisionEngine:
    """
    Deterministic decision engine with policy profile support.
    """
    
    # Default risk score thresholds
    DEFAULT_THRESHOLDS = {
        "allow_min": 0.85,
        "flag_min": 0.60,
        "flag_max": 0.84,
        "block_max": 0.59
    }
    
    # Default component weights
    DEFAULT_WEIGHTS = {
        "cve_validity": 0.40,
        "severity_accuracy": 0.30,
        "mitigation_relevance": 0.20,
        "urgency_consistency": 0.10
    }
    
    def __init__(self, policy_profiles_path: str = "policy_profiles.yaml"):
        """Initialize decision engine with policy profiles."""
        self.policy_profiles = {}
        self.policy_profiles_path = policy_profiles_path
        self._load_policy_profiles()
    
    def _load_policy_profiles(self):
        """Load policy profiles from YAML file."""
        if not os.path.exists(self.policy_profiles_path):
            # Create default profile
            self.policy_profiles["default"] = PolicyProfile(
                name="default",
                description="Default SOC policy",
                thresholds=self.DEFAULT_THRESHOLDS,
                rule_weights=self.DEFAULT_WEIGHTS,
                active=True
            )
            return
        
        try:
            with open(self.policy_profiles_path, 'r') as f:
                data = yaml.safe_load(f)
                for profile_name, profile_data in data.get("profiles", {}).items():
                    self.policy_profiles[profile_name] = PolicyProfile(**profile_data)
        except Exception as e:
            print(f"Error loading policy profiles: {e}")
            # Fallback to default
            self.policy_profiles["default"] = PolicyProfile(
                name="default",
                description="Default SOC policy",
                thresholds=self.DEFAULT_THRESHOLDS,
                rule_weights=self.DEFAULT_WEIGHTS
            )
    
    async def decide(self, decision_input: DecisionInput) -> DecisionOutput:
        """
        Compute decision outcome from validation results.
        Uses weighted risk scoring and policy profile thresholds.
        """
        profile = self.policy_profiles.get(
            decision_input.policy_profile_name, self.policy_profiles["default"]
        )
        weights = profile.rule_weights or self.DEFAULT_WEIGHTS
        thresholds = profile.thresholds or self.DEFAULT_THRESHOLDS

        # Map rule results to component scores
        component_scores = {
            "cve_validity": 0.0,
            "severity_accuracy": 0.0,
            "mitigation_relevance": 0.0,
            "urgency_consistency": 0.0
        }
        hard_fail = False
        correction_candidate = None
        for r in decision_input.validation_results:
            rule_id = r.get("rule_id")
            score = r.get("score", 0.0)
            passed = r.get("passed", True)
            if rule_id in component_scores:
                component_scores[rule_id] = score
            if not passed:
                hard_fail = True
                if r.get("correction_candidate"):
                    correction_candidate = r["correction_candidate"]

        # Risk score calculation
        risk_score = sum(
            weights.get(k, 0.0) * component_scores.get(k, 0.0)
            for k in component_scores
        )
        # Clamp to [0, 1]
        risk_score = max(0.0, min(1.0, risk_score))

        # Decision logic
        if hard_fail:
            if correction_candidate:
                outcome = "CORRECT"
            else:
                outcome = "BLOCK"
        elif risk_score >= thresholds.get("allow_min", 0.85):
            outcome = "ALLOW"
        elif risk_score >= thresholds.get("flag_min", 0.60):
            outcome = "FLAG"
        else:
            outcome = "BLOCK"

        rationale = (
            f"Decision: {outcome}. Risk score: {risk_score:.2f}. "
            f"Component scores: {component_scores}."
        )
        return DecisionOutput(
            decision_id=str(uuid.uuid4()),
            outcome=outcome,
            risk_score=risk_score,
            component_scores=component_scores,
            correction_candidate=correction_candidate,
            rationale=rationale
        )
        decision_id = str(uuid.uuid4())
        
        # Get policy profile
        profile = self.policy_profiles.get(
            decision_input.policy_profile_name,
            self.policy_profiles.get("default")
        )
        
        # Compute component scores from validation results
        component_scores = self._compute_component_scores(
            decision_input.validation_results,
            decision_input.threat_intel_match_quality,
            decision_input.llm_verification_contradiction_prob
        )
        
        # Compute weighted risk score
        risk_score = sum(
            component_scores.get(component, 0.0) * profile.rule_weights.get(component, 0.0)
            for component in profile.rule_weights.keys()
        )
        
        # Determine outcome
        outcome, rationale = self._determine_outcome(
            risk_score,
            component_scores,
            profile,
            decision_input.validation_results
        )
        
        # Check for correction candidate if BLOCK
        correction_candidate = None
        if outcome == "BLOCK":
            correction_candidate = await self._find_correction_candidate(
                decision_input.validation_results
            )
            if correction_candidate:
                outcome = "CORRECT"
        
        return DecisionOutput(
            decision_id=decision_id,
            outcome=outcome,
            risk_score=risk_score,
            component_scores=component_scores,
            correction_candidate=correction_candidate,
            rationale=rationale
        )
    
    def _compute_component_scores(
        self,
        validation_results: List[Dict],
        threat_intel_quality: float,
        llm_contradiction_prob: Optional[float]
    ) -> Dict[str, float]:
        """
        Compute component risk scores from validation results.
        
        Args:
            validation_results: Deterministic + semantic + LLM validation outputs
            threat_intel_quality: FAISS retrieval quality
            llm_contradiction_prob: Likelihood of contradiction from Ollama
            
        Returns:
            Dictionary mapping component names to scores (0.0-1.0)
        """
        scores = {}
        
        # CVE validity: proportion of deterministic rules passed
        cve_rules = [r for r in validation_results if "cve" in r.get("rule_id", "").lower()]
        if cve_rules:
            cve_passed = sum(1 for r in cve_rules if r.get("passed", False))
            scores["cve_validity"] = cve_passed / len(cve_rules)
        else:
            scores["cve_validity"] = 0.5
        
        # Severity accuracy: semantic similarity to threat intel
        semantic_results = [r for r in validation_results if r.get("rule_id") == "semantic_similarity"]
        if semantic_results:
            scores["severity_accuracy"] = semantic_results[0].get("similarity_score", 0.5)
        else:
            scores["severity_accuracy"] = threat_intel_quality
        
        # Mitigation relevance: presence of remediation guidance
        mitigation_results = [r for r in validation_results if "remediation" in r.get("rule_id", "").lower()]
        scores["mitigation_relevance"] = 0.8 if mitigation_results else 0.4
        
        # Urgency consistency: inverse of contradiction probability
        if llm_contradiction_prob is not None:
            scores["urgency_consistency"] = 1.0 - llm_contradiction_prob
        else:
            scores["urgency_consistency"] = 0.7
        
        return scores
    
    def _determine_outcome(
        self,
        risk_score: float,
        component_scores: Dict[str, float],
        profile: PolicyProfile,
        validation_results: List[Dict]
    ) -> tuple:
        """
        Determine final outcome based on risk score and policy.
        
        Args:
            risk_score: Computed weighted risk score
            component_scores: Component breakdown
            profile: Active policy profile
            validation_results: Validation rule results
            
        Returns:
            (outcome: str, rationale: str)
        """
        thresholds = profile.thresholds
        allow_min = thresholds.get("allow_min", self.DEFAULT_THRESHOLDS["allow_min"])
        flag_min = thresholds.get("flag_min", self.DEFAULT_THRESHOLDS["flag_min"])
        
        # Hard-fail detection: any critical rule failed
        hard_fails = [r for r in validation_results if r.get("hard_fail", False)]
        
        if hard_fails:
            return "BLOCK", f"Hard-fail rule triggered: {hard_fails[0].get('rule_name', 'unknown')}"
        
        if risk_score >= allow_min:
            return "ALLOW", f"High confidence recommendation (risk score: {risk_score:.2f})"
        
        elif risk_score >= flag_min:
            return "FLAG", f"Possible inconsistencies detected (risk score: {risk_score:.2f}). Review recommended."
        
        else:
            return "BLOCK", f"Hallucination likely detected (risk score: {risk_score:.2f})"
    
    async def _find_correction_candidate(
        self,
        validation_results: List[Dict]
    ) -> Optional[str]:
        """
        Attempt to find corrected recommendation on BLOCK.
        
        Args:
            validation_results: Validation outputs
            
        Returns:
            Corrected claim if found, None otherwise
        """
        # TODO: Orchestrate with Tanushree's or another module to generate correction
        # For now, return None
        return None


# Singleton
_engine: Optional[DecisionEngine] = None


def get_decision_engine(profiles_path: str = "policy_profiles.yaml") -> DecisionEngine:
    """Get or create decision engine singleton."""
    global _engine
    if _engine is None:
        _engine = DecisionEngine(profiles_path)
    return _engine
