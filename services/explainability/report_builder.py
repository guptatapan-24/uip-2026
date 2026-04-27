# services/explainability/report_builder.py
"""
Explainability report builder.

Assembles validation chain evidence into human-readable rationale for SOC analysts.

Report includes:
- Decision summary (outcome + risk score)
- Validation rule evidence chain
- Threat intelligence matches
- Component score breakdown
- Recommendation for analyst action

TODO: Wire Tanushree's, Tapan's, and Dhruv's modules for comprehensive evidence
"""

from typing import List, Dict, Optional
from datetime import datetime
from pydantic import BaseModel


class ValidationStep(BaseModel):
    """Single step in validation chain."""
    step_name: str
    rule_name: str
    passed: bool
    evidence: str
    confidence: float


class ExplainabilityReport(BaseModel):
    """Comprehensive explainability report."""
    decision_id: str
    outcome: str  # ALLOW | FLAG | BLOCK | CORRECT
    risk_score: float
    
    # Validation evidence
    validation_chain: List[ValidationStep] = []
    threat_intel_matches: List[Dict] = []
    
    # Component breakdown
    component_scores: Dict[str, float] = {}
    
    # Analyst guidance
    analyst_rationale: str
    recommended_action: str  # "APPROVE", "INVESTIGATE", "BLOCK", "APPLY_CORRECTION"
    
    # Metadata
    generated_at: str
    processing_latency_ms: float


class ReportBuilder:
    """
    Builds explainability reports from validation results.
    """
    
    def __init__(self):
        """Initialize report builder."""
        pass
    
    async def build_report(
        self,
        decision_id: str,
        outcome: str,
        risk_score: float,
        validation_results: List[Dict],
        threat_intel_matches: List[Dict],
        component_scores: Dict[str, float],
        processing_latency_ms: float
    ) -> ExplainabilityReport:
        """
        Build comprehensive explainability report.
        
        Args:
            decision_id: Unique decision identifier
            outcome: Final decision outcome
            risk_score: Computed risk score
            validation_results: Results from all validation stages
            threat_intel_matches: Retrieved threat intelligence
            component_scores: Risk score component breakdown
            processing_latency_ms: End-to-end pipeline latency
            
        Returns:
            Comprehensive explainability report
        """
        # Build validation chain
        validation_chain = self._build_validation_chain(validation_results)
        
        # Select analyst rationale
        rationale = self._generate_rationale(
            outcome,
            risk_score,
            validation_chain,
            threat_intel_matches
        )
        
        # Recommend action
        recommended_action = self._recommend_action(outcome, risk_score)
        
        return ExplainabilityReport(
            decision_id=decision_id,
            outcome=outcome,
            risk_score=risk_score,
            validation_chain=validation_chain,
            threat_intel_matches=threat_intel_matches,
            component_scores=component_scores,
            analyst_rationale=rationale,
            recommended_action=recommended_action,
            generated_at=datetime.now().isoformat(),
            processing_latency_ms=processing_latency_ms
        )
    
    def _build_validation_chain(self, validation_results: List[Dict]) -> List[ValidationStep]:
        """Convert validation results to explanation chain."""
        chain = []
        for result in validation_results:
            step = ValidationStep(
                step_name=result.get("stage", "unknown"),
                rule_name=result.get("rule_name", ""),
                passed=result.get("passed", False),
                evidence=result.get("evidence", ""),
                confidence=result.get("confidence", 0.0)
            )
            chain.append(step)
        return chain
    
    def _generate_rationale(
        self,
        outcome: str,
        risk_score: float,
        validation_chain: List[ValidationStep],
        threat_intel_matches: List[Dict]
    ) -> str:
        """Generate human-readable rationale for decision."""
        
        if outcome == "ALLOW":
            base = f"LLM recommendation is highly trustworthy (risk score: {risk_score:.2f}). "
            base += "All validation checks passed with high confidence. "
            
        elif outcome == "FLAG":
            base = f"LLM recommendation requires analyst review (risk score: {risk_score:.2f}). "
            failed = [step.rule_name for step in validation_chain if not step.passed]
            if failed:
                base += f"Some validation checks failed: {', '.join(failed)}. "
            base += "Human verification recommended before enforcement."
            
        elif outcome == "BLOCK":
            base = f"LLM recommendation blocked due to hallucination risk (risk score: {risk_score:.2f}). "
            hard_fails = [step.rule_name for step in validation_chain if not step.passed and step.confidence > 0.90]
            if hard_fails:
                base += f"Critical failures: {', '.join(hard_fails)}. "
            base += "Recommendation does not match authoritative threat intelligence."
            
        elif outcome == "CORRECT":
            base = f"LLM recommendation corrected. "
            base += "Original had hallucination risk, but valid correction candidate identified. "
            
        else:
            base = f"Decision: {outcome} (risk score: {risk_score:.2f}). "
        
        # Add threat intel context
        if threat_intel_matches:
            base += f"Found {len(threat_intel_matches)} threat intelligence matches."
        
        return base
    
    def _recommend_action(self, outcome: str, risk_score: float) -> str:
        """Recommend action for analyst."""
        if outcome == "ALLOW":
            return "APPROVE"
        elif outcome == "FLAG":
            return "INVESTIGATE"
        elif outcome == "BLOCK":
            return "BLOCK"
        elif outcome == "CORRECT":
            return "APPLY_CORRECTION"
        else:
            return "REVIEW"


# Singleton
_builder: Optional[ReportBuilder] = None


def get_report_builder() -> ReportBuilder:
    """Get or create report builder singleton."""
    global _builder
    if _builder is None:
        _builder = ReportBuilder()
    return _builder
