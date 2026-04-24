# services/audit/__init__.py
"""
Audit logging service module.

Append-only immutable audit log with SHA-256 hash chaining.

Each entry: curr_hash = SHA256(prev_hash + record_data)
Chain verification validates integrity across all entries.
"""
