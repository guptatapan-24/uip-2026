# Hand-off Checklist

This document lists final acceptance steps for delivering the `llm-hallucination-firewall` project.

1. CI
  - Ensure `infra-smoke.yml`, `faiss-ci.yml`, `frontend-e2e.yml`, and `code-quality.yml` pass in GitHub Actions.
  - Configure required secrets: `GITHUB_TOKEN`, `OPENAI_API_KEY`, `SNYK_TOKEN` (optional), registry credentials.

2. Deployment
  - Push Docker images to registry (GHCR) and verify image tags.
  - Apply `infra/k8s/` manifests to target cluster (or use Helm chart if provided).

3. Monitoring
  - Verify Prometheus scrapes `/metrics` and Grafana dashboard appears at `/api/dashboards`.
  - Set alerting rules in Prometheus for `llm_verifier_circuit_open`.

4. Security
  - Rotate any ephemeral secrets used for testing.
  - Run `bandit`/`safety` and resolve critical findings.

5. Documentation
  - Ensure `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `infra/k8s/README.md` are complete.

6. Handover
  - Share runbook and access for monitoring dashboards, container registry, and cluster.
