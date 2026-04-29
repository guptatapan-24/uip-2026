# Security Disclosure

If you discover a security vulnerability, please do not open a public issue. Instead, contact the maintainers privately via the project email or repo owner.

Checklist for PRs with security impact:
- Rotate and do not commit secrets to the repo.
- Add tests that demonstrate the intended secure behavior.
- Document threat model changes in `docs/`.
- Run static analysis (bandit, ruff) before merging.
