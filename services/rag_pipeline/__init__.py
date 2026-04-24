# services/rag_pipeline/__init__.py
"""
RAG pipeline service module.

Retrieves threat intelligence from:
- NVD (CVE database)
- MITRE ATT&CK (techniques)
- CISA KEV (exploited vulnerabilities)

Uses FAISS for semantic vector search and Redis for caching.
"""
