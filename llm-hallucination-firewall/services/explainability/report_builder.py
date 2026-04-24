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



class SourceCitation(BaseModel):
    source: str
    url: str
    snippet: str

class ExplainabilityReport(BaseModel):
    """Comprehensive explainability report."""
    decision_id: str
    outcome: str  # ALLOW | FLAG | BLOCK | CORRECT
    risk_score: float
    source_citations: List[SourceCitation] = []
    confidence_breakdown: Dict[str, float] = {}
    rule_trace: List[Dict] = []
    analyst_rationale: str
    override_available: bool = False
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
        claims: List[Dict],
        validation_results: List[Dict],
        decision: Dict
    ) -> ExplainabilityReport:
        """
        Build explainability report from claims, validation, and decision.
        """
        # Source citations from threat intel evidence
        source_citations = [
            SourceCitation(
                source=ev.get("source", "NVD"),
                url=ev.get("url", ""),
                snippet=ev.get("snippet", "")
            ) for ev in decision.get("threat_intel_matches", [])
        ]
        # Confidence breakdown per claim
        confidence_breakdown = {
            c.get("claim_type", f"claim_{i}"): c.get("confidence", 0.0)
            for i, c in enumerate(claims)
        }
        # Rule trace
        rule_trace = [
            {
                "rule_id": r.get("rule_id"),
                "passed": r.get("passed"),
                "evidence": r.get("evidence")
            } for r in validation_results
        ]
        # Analyst rationale (template-based)
        rationale = self._template_rationale(claims, validation_results, decision)
        # Override available
        override_available = decision.get("outcome") == "BLOCK" and bool(decision.get("correction_candidate"))
        return ExplainabilityReport(
            decision_id=decision.get("decision_id", ""),
            outcome=decision.get("outcome", ""),
            risk_score=decision.get("risk_score", 0.0),
            source_citations=source_citations,
            confidence_breakdown=confidence_breakdown,
            rule_trace=rule_trace,
            analyst_rationale=rationale,
            override_available=override_available,
            generated_at=datetime.now().isoformat(),
            processing_latency_ms=decision.get("processing_latency_ms", 0.0)
        )
    

    def _template_rationale(self, claims, validation_results, decision) -> str:
        """
        Generate analyst rationale using template strings.
        """
        cve = next((c for c in claims if c.get("claim_type") == "CVE_ID"), None)
        cvss = next((c for c in claims if c.get("claim_type") == "CVSS_SCORE"), None)
        attack = next((c for c in claims if c.get("claim_type") == "ATTACK_TECHNIQUE"), None)
        parts = []
        if cve:
            parts.append(f"CVE {cve.get('text')} found in NVD.")
        if cvss:
            parts.append(f"CVSS {cvss.get('text')} extracted.")
        if attack:
            parts.append(f"ATT&CK technique {attack.get('text')} is valid.")
        parts.append(f"Decision: {decision.get('outcome')} with confidence {decision.get('risk_score', 0.0):.2f}.")
        return " ".join(parts)
    
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
