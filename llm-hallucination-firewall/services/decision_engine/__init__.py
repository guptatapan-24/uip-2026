# services/decision_engine/__init__.py
"""
Decision engine service module.

Weighted scoring system:
- CVE validity: 40%
- Severity accuracy: 30%
- Mitigation relevance: 20%
- Urgency consistency: 10%

Decision outcomes:
- ALLOW (0.85–1.0): Recommendation is accurate
- FLAG (0.60–0.84): Requires analyst review
- BLOCK (<0.60 or hard-fail): Reject recommendation
- CORRECT: Provide corrected version
"""
