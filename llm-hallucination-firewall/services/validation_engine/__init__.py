# services/validation_engine/__init__.py
"""
Validation engine service module.

Three-stage validation:
1. Deterministic: Rule-based checks (CVE exists, CVSS range, technique valid)
2. Semantic: Cosine similarity thresholding against threat intel embeddings
3. LLM Verifier: Mistral-7B contradiction detection via Ollama
"""
