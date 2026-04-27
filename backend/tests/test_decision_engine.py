from app.services.decision_engine import evaluate_claims


def test_blocks_fabricated_cve() -> None:
    result = evaluate_claims(
        {
            "cves": [{"id": "CVE-2099-99999", "exists": False, "claimed_severity": "critical"}],
            "attack_mappings": [],
            "mitigations": [{"text": "Isolate finance", "relevance": "low", "risk": "high"}],
        }
    )
    assert result.decision == "block"


def test_allows_grounded_safe_recommendation() -> None:
    result = evaluate_claims(
        {
            "cves": [
                {
                    "id": "CVE-2023-23397",
                    "exists": True,
                    "claimed_severity": "critical",
                    "actual_severity": "critical",
                    "in_kev": True,
                }
            ],
            "attack_mappings": [
                {
                    "technique_id": "T1110",
                    "exists": True,
                    "claimed_name": "Brute Force",
                    "actual_name": "Brute Force",
                }
            ],
            "mitigations": [{"text": "Patch Outlook systems", "relevance": "high", "risk": "low"}],
        }
    )
    assert result.decision == "allow"
