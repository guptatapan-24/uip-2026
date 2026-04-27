# services/gateway/routes/__init__.py
"""
Gateway API route modules.

Exposes:
- extract.py: Claim extraction endpoint
- validate.py: Validation pipeline (deterministic + semantic)
- decide.py: Policy-driven decision engine
- health.py: Health check with dependency status
- decisions.py: Decision retrieval and history (legacy)
- audit.py: Audit log with hash chain verification
- metrics.py: Custom metrics endpoint
- policy.py: Policy profile management
"""
