from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DecisionResult:
    decision: str
    confidence: float
    risk_score: int
    reasoning: list[str]
    failed_rules: list[str]
    corrections: list[str]

    def as_dict(self) -> dict:
        return {
            "decision": self.decision,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "reasoning": self.reasoning,
            "failed_rules": self.failed_rules,
            "corrections": self.corrections,
        }


def evaluate_claims(claims: dict) -> DecisionResult:
    reasoning: list[str] = []
    failed_rules: list[str] = []
    corrections: list[str] = []
    risk_score = 0
    confidence = 0.5

    for cve in claims.get("cves", []):
        if not cve.get("exists"):
            risk_score += 50
            confidence -= 0.2
            failed_rules.append(f"{cve['id']} does not exist in trusted data.")
            corrections.append(f"Remove or replace fabricated CVE {cve['id']}.")
        else:
            reasoning.append(f"{cve['id']} exists in trusted data.")
            confidence += 0.15
            if cve.get("claimed_severity") and cve.get("actual_severity"):
                if cve["claimed_severity"].lower() != cve["actual_severity"].lower():
                    risk_score += 20
                    confidence -= 0.1
                    failed_rules.append(
                        f"{cve['id']} severity mismatch: claimed {cve['claimed_severity']} vs actual {cve['actual_severity']}."
                    )
                    corrections.append(
                        f"Use the validated severity for {cve['id']}: {cve['actual_severity']}."
                    )
            if cve.get("in_kev"):
                reasoning.append(f"{cve['id']} is present in CISA KEV, raising urgency.")
                confidence += 0.05

    for mapping in claims.get("attack_mappings", []):
        if not mapping.get("exists"):
            risk_score += 25
            confidence -= 0.1
            failed_rules.append(f"{mapping['technique_id']} is not a valid ATT&CK mapping.")
            corrections.append(f"Review ATT&CK technique {mapping['technique_id']}.")
        else:
            reasoning.append(f"{mapping['technique_id']} matches MITRE ATT&CK.")
            confidence += 0.05
            if mapping.get("claimed_name") and mapping.get("actual_name"):
                if mapping["claimed_name"].strip().lower() != mapping["actual_name"].strip().lower():
                    risk_score += 10
                    confidence -= 0.05
                    failed_rules.append(
                        f"{mapping['technique_id']} name mismatch: claimed {mapping['claimed_name']} vs actual {mapping['actual_name']}."
                    )
                    corrections.append(
                        f"Use ATT&CK label '{mapping['actual_name']}' for {mapping['technique_id']}."
                    )

    for mitigation in claims.get("mitigations", []):
        relevance = mitigation.get("relevance", "medium")
        risk = mitigation.get("risk", "medium")
        if relevance == "low":
            risk_score += 20
            confidence -= 0.1
            failed_rules.append(f"Mitigation may not fit the validated threat context: {mitigation['text']}.")
        else:
            reasoning.append(f"Mitigation is contextually relevant: {mitigation['text']}.")
            confidence += 0.05
        if risk == "high":
            risk_score += 30
            confidence -= 0.1
            failed_rules.append(f"Mitigation is operationally risky: {mitigation['text']}.")
            corrections.append("Require analyst approval before high-impact remediation.")

    confidence = max(0.05, min(round(confidence, 2), 0.99))

    if risk_score >= 60:
        decision = "block"
    elif corrections and risk_score < 60:
        decision = "correct"
    elif failed_rules:
        decision = "flag"
    else:
        decision = "allow"

    if not reasoning:
        reasoning.append("No strongly grounded evidence was found; conservative decision applied.")

    return DecisionResult(
        decision=decision,
        confidence=confidence,
        risk_score=risk_score,
        reasoning=reasoning,
        failed_rules=failed_rules,
        corrections=corrections,
    )
