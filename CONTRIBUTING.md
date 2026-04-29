# Contributing

Thanks for contributing! Quick guidelines to get started:

- Fork the repo and open a pull request against `main`.
- Run unit tests locally: `pytest -q` from project root.
- Use `black` / `ruff` for Python formatting and linting.
- For frontend changes run `cd frontend && npm install && npm test`.
- Small feature branches should be named `feat/<short-description>`; bugfix branches `fix/<short-description>`.
- Include tests for new behavior and update `README.md` if necessary.

Security-sensitive changes (auth, secrets, RBAC) require at least one code review from a maintainer.
