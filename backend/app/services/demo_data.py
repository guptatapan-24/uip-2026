DEMO_SCENARIOS = [
    {
        "id": "real-cve-safe-block",
        "title": "Real CVE with risky broad firewall action",
        "prompt": "CVE-2021-44228 is critical and exploited. Immediately block all outbound traffic from every Java server.",
        "claims": {
            "cves": [
                {
                    "id": "CVE-2021-44228",
                    "claimed_severity": "critical",
                    "exists": True,
                    "actual_severity": "critical",
                    "in_kev": True,
                }
            ],
            "attack_mappings": [
                {
                    "technique_id": "T1190",
                    "claimed_name": "Exploit Public-Facing Application",
                    "exists": True,
                    "actual_name": "Exploit Public-Facing Application",
                }
            ],
            "mitigations": [
                {
                    "text": "Block all outbound traffic from every Java server",
                    "relevance": "low",
                    "risk": "high",
                }
            ],
        },
        "expected_decision": "block",
    },
    {
        "id": "fabricated-cve",
        "title": "Fabricated CVE reference",
        "prompt": "Prioritize CVE-2099-99999 and isolate the finance subnet immediately.",
        "claims": {
            "cves": [
                {
                    "id": "CVE-2099-99999",
                    "claimed_severity": "critical",
                    "exists": False,
                    "actual_severity": None,
                    "in_kev": False,
                }
            ],
            "attack_mappings": [],
            "mitigations": [
                {
                    "text": "Isolate the finance subnet immediately",
                    "relevance": "low",
                    "risk": "high",
                }
            ],
        },
        "expected_decision": "block",
    },
    {
        "id": "grounded-patch",
        "title": "Grounded recommendation with safe mitigation",
        "prompt": "Patch CVE-2023-23397 on exposed Outlook systems and hunt for associated credential theft activity.",
        "claims": {
            "cves": [
                {
                    "id": "CVE-2023-23397",
                    "claimed_severity": "critical",
                    "exists": True,
                    "actual_severity": "critical",
                    "in_kev": True,
                }
            ],
            "attack_mappings": [
                {
                    "technique_id": "T1110",
                    "claimed_name": "Brute Force",
                    "exists": True,
                    "actual_name": "Brute Force",
                }
            ],
            "mitigations": [
                {
                    "text": "Patch exposed Outlook systems and increase hunting coverage",
                    "relevance": "high",
                    "risk": "low",
                }
            ],
        },
        "expected_decision": "allow",
    },
]
