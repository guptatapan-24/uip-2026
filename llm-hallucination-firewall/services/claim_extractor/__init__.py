# services/claim_extractor/__init__.py
"""
Claim extraction service module.

Extracts structured claims from unstructured LLM recommendations using:
- Regex patterns for CVE IDs, CVSS scores, technique IDs
- spaCy NER for entity recognition
- BERT span extraction for semantic claim boundaries
"""
