# LLM Hallucination Firewall

**Enterprise-grade risk-aware middleware for SOC environments**

Validates LLM-generated security recommendations against authoritative threat intelligence sources (NVD, MITRE ATT&CK, CISA KEV) with four decision outcomes: **ALLOW | FLAG | BLOCK | CORRECT**.

## Features

- **Risk-Aware Decision Engine**: Weighted scoring across CVE validity, severity accuracy, mitigation relevance, and urgency consistency
- **Multi-Stage Validation**: Deterministic rule checking → Semantic similarity → LLM verification (Mistral-7B via Ollama)
- **Threat Intelligence Integration**: Real-time NVD, MITRE ATT&CK, CISA KEV data with FAISS vector search
- **Hash-Chained Audit Logs**: Cryptographic verification of all decisions for compliance
- **Role-Based Access Control**: SOC_ANALYST, SOC_ADMIN, SYSTEM roles with JWT RS256 auth
- **Production Monitoring**: Prometheus metrics + Grafana dashboards
- **Self-Hosted LLM**: Ollama + Mistral-7B (with GPT-3.5 fallback)
- **Async-First Architecture**: FastAPI + asyncio + Celery for high throughput

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11 (for local development)
- PostgreSQL 15+, Redis 7+

### Local Development with Docker

```bash
cd infra
docker-compose up -d

# Apply migrations
docker-compose exec api_gateway alembic upgrade head

# Run tests
docker-compose exec api_gateway pytest tests/

# Dashboard: http://localhost:3000
# API docs: http://localhost:8000/docs
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3000 (admin/admin)
```

### Environment Setup

```bash
cp .env.example .env
# Edit .env with your NVD API key, JWT keys, etc.
```

## Project Structure

```
llm-hallucination-firewall/
├── services/
│   ├── gateway/               # FastAPI orchestration layer
│   ├── claim_extractor/       # NER + span extraction
│   ├── rag_pipeline/          # Vector retrieval + threat intel sync
│   ├── validation_engine/     # Deterministic + semantic + LLM validation
│   ├── decision_engine/       # Risk scoring + policy enforcement
│   ├── explainability/        # Decision rationale reports
│   └── audit/                 # Hash-chained audit logging
├── db/                         # Database schemas + ORM models
├── dashboard/                  # React analyst UI (scaffolded)
├── infra/                      # Docker Compose + monitoring config
├── tests/                      # Unit + integration tests
└── .github/workflows/          # CI/CD pipeline
```

## API Endpoints

### Validation Pipeline

**POST /v1/validate**
- Validate LLM output against threat intelligence
- Request: `{ llm_output: str, context: { alert_id, severity_hint, policy_profile } }`
- Response: `{ decision_id, outcome, risk_score, claims[], analyst_rationale, latency_ms }`

**GET /v1/decisions/{decision_id}**
- Retrieve detailed decision with explainability

### Audit & Policy

**GET /v1/audit/log**
- Audit trail with cryptographic hash chain verification
- Supports filtering by decision_id, outcome, date range

**POST /v1/policy/override**
- SOC_ADMIN only: Override automated decision with analyst rationale

**GET /v1/metrics**
- Prometheus metrics endpoint

## Tech Stack

| Component | Technology |
|-----------|------------|
| API Gateway | FastAPI + Uvicorn |
| NLP/NER | spaCy + HuggingFace Transformers |
| Vector Search | FAISS + sentence-transformers |
| Self-Hosted LLM | Ollama + Mistral-7B |
| LLM Fallback | OpenAI GPT-3.5-turbo |
| Database | PostgreSQL + async SQLAlchemy |
| Cache/Queue | Redis + Celery |
| Auth | JWT RS256 |
| Monitoring | Prometheus + Grafana |
| Frontend | React + TailwindCSS + Recharts |

## Architecture

### Validation Pipeline (Core Flow)

```
LLM Output
    ↓
[1] Claim Extraction (spaCy NER + BERT)
    ↓
[2] RAG Retrieval (FAISS search → NVD, MITRE ATT&CK, CISA KEV)
    ↓
[3] Validation (3-stage)
    ├─ Deterministic Rules (CVE exists, CVSS range, technique valid)
    ├─ Semantic Similarity (threshold: 0.72)
    └─ LLM Verifier (Mistral-7B contradiction detection)
    ↓
[4] Decision Engine (weighted risk scoring)
    ├─ CVE validity (40%)
    ├─ Severity accuracy (30%)
    ├─ Mitigation relevance (20%)
    └─ Urgency consistency (10%)
    ↓
[5] Decision Outcomes
    ├─ ALLOW (0.85–1.0): High confidence
    ├─ FLAG (0.60–0.84): Analyst review
    ├─ BLOCK (<0.60 or hard-fail): Reject
    └─ CORRECT: Provide correction
    ↓
[6] Explainability (Decision rationale + evidence chain)
    ↓
[7] Audit Logging (SHA-256 hash-chained)
    ↓
Response to Analyst Dashboard
```

## Key Decision Engine Weights

```
Risk Score = (0.40 × CVE_validity)
           + (0.30 × severity_accuracy)
           + (0.20 × mitigation_relevance)
           + (0.10 × urgency_consistency)
```

### Outcome Thresholds

- **ALLOW**: `0.85 ≤ score ≤ 1.0`
- **FLAG**: `0.60 ≤ score < 0.85`
- **BLOCK**: `score < 0.60` or any hard-fail rule triggered
- **CORRECT**: BLOCK outcome with correction candidate provided

## Audit & Compliance

All decisions are logged to an immutable, hash-chained audit trail:

```
Entry N: curr_hash_n = SHA256(prev_hash_n + record_data_n)
```

This enables:
- Tamper detection (hash chain verification)
- Compliance auditing
- Decision reversal tracking
- Analyst override attribution

## RBAC (Role-Based Access Control)

Three roles with specific permissions:

| Role | Permissions |
|------|-------------|
| **SOC_ANALYST** | View decisions, audit logs, validate claims |
| **SOC_ADMIN** | Override decisions, manage policies, create users |
| **SYSTEM** | Full access (for automated integrations) |

## Policy Profiles

Configurable decision thresholds in `services/decision_engine/policy_profiles.yaml`:

- **default**: Standard SOC validation
- **strict**: Lower thresholds (more FLAGs, fewer ALLOWs)
- **permissive**: Higher thresholds (more ALLOWs, fewer BLOCKs)

## Development

### Prerequisites

```bash
Python 3.11
Docker & Docker Compose
PostgreSQL 15+
Redis 7+
```

### Installation

```bash
# Clone and navigate
cd llm-hallucination-firewall

# Create environment
cp .env.example .env
# Edit .env with your API keys

# Quick start with Docker
bash quickstart.sh

# OR manual setup
make install
make docker-up
make dev
```

### Running Tests

```bash
# All tests
make test

# Unit tests only
make test-unit

# Integration tests only
make test-integration

# Linting
make lint
make format
```

### Generate Test Data

```python
# Create sample decisions for testing
from services.gateway.auth import generate_test_token
from auth import UserRole

token = generate_test_token(
    user_id="analyst-001",
    username="analyst",
    role=UserRole.SOC_ANALYST
)
```

## API Documentation

Interactive API docs available at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Example: Validate LLM Output

```bash
curl -X POST http://localhost:8000/v1/validate \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "llm_output": "Patch CVE-2024-1234 immediately. CVSS 9.8. Affects Apache 2.4.x. ATT&CK technique T1566.",
    "context": {
      "alert_id": "SOC-2024-04-24-001",
      "severity_hint": "CRITICAL",
      "policy_profile": "default"
    }
  }'
```

Response:
```json
{
  "decision_id": "dec-20240424-001",
  "outcome": "FLAG",
  "risk_score": 0.72,
  "claims": [
    {"claim_id": "cid-001", "text": "CVE-2024-1234", "claim_type": "CVE_ID", "confidence": 0.95},
    {"claim_id": "cid-002", "text": "9.8", "claim_type": "CVSS_SCORE", "confidence": 0.90}
  ],
  "validation_results": [
    {"rule_id": "cve_exists_in_nvd", "passed": true, "confidence": 0.95},
    {"rule_id": "cvss_score_in_range", "passed": true, "confidence": 0.85}
  ],
  "analyst_rationale": "CVE found in NVD. CVSS score verified. Requires analyst review for product impact.",
  "latency_ms": 320.5,
  "timestamp": "2024-04-24T12:34:56"
}
```

## Monitoring & Observability

### Prometheus Metrics

Exposed at `/metrics`:
- `validation_requests_total[outcome]`: Total validations by outcome
- `validation_latency_ms`: Histogram of pipeline latencies
- `http_requests_total[method,endpoint,status]`: HTTP request metrics

### Grafana Dashboards

Pre-configured dashboards available at `http://localhost:3000`:
- Validation Pipeline Overview
- Decision Distribution
- Error Rate & Latency
- LLM Verifier Circuit Breaker Status
- Audit Log Volume

## Database Schema

Key tables:
- **claims**: Extracted claims from LLM output
- **validation_results**: Individual validation rule results
- **decisions**: Final decisions per validation request
- **audit_log**: Hash-chained audit trail
- **analyst_overrides**: Manual decision overrides
- **policy_profiles**: Configurable decision thresholds

## Troubleshooting

### Service won't start

```bash
# Check logs
docker-compose logs api_gateway

# Verify database connection
docker-compose exec postgres psql -U llm_user -d llm_firewall -c "SELECT 1"

# Verify Redis
docker-compose exec redis redis-cli ping
```

### Tests failing

```bash
# Reset test database
make db-reset

# Run with verbose output
pytest tests/ -v --tb=long
```

### LLM Verifier timeouts

- Increase `OLLAMA_TIMEOUT_SECONDS` in .env
- Or reduce load on Ollama container
- Circuit breaker automatically falls back to neutral result after 2s

## Deployment

### Docker Production Build

```bash
docker build -f infra/Dockerfile -t llm-firewall:latest .
docker run -p 8000:8000 \
  -e DATABASE_URL="postgresql://user:pass@host/db" \
  -e REDIS_URL="redis://redis:6379/0" \
  -e JWT_SECRET_KEY="$(openssl rand -hex 32)" \
  llm-firewall:latest
```

### Kubernetes (kubectl)

```bash
# TODO: Add k8s manifests
# - Deployment
# - Service
# - ConfigMap
# - StatefulSet (PostgreSQL, Redis)
# - NetworkPolicy (RBAC)
```

## Contributing

Team members assigned to specific modules:

- **Tanushree**: `services/claim_extractor/` (NER + BERT extraction)
- **Tapan**: `services/decision_engine/` (Risk scoring + policy)
- **Dhruv**: `services/rag_pipeline/` + `db/` + `services/audit/` (RAG, database, audit)

Integration points marked with `TODO:` comments in code.

## Compliance & Auditing

- ✅ SOC 2 audit-ready (hash-chained audit logs)
- ✅ JWT RS256 authentication
- ✅ Role-based access control
- ✅ Encrypted database connections
- ✅ Comprehensive audit trail
- ✅ PII-aware logging

## License

Proprietary - Unisys Corporation

## Progress & Next Steps (snapshot: 2026-04-28)

This project is actively developed. Below is a concise, actionable summary of what is implemented, what's remaining, and recommended next steps.

- **Completion (rough):** Backend core flow ~85% complete; verifier & RAG ~80%; frontend dashboard ~70%; testing & CI ~60%; infra & observability ~50%.

- **Key implemented features (files / modules):**
  - **Gateway runtime & persistence:** `services/gateway/persistence.py`, `services/gateway/state.py` (DB-first with in-memory fallback).
  - **Gateway routes:** `services/gateway/routes/decide.py`, `decisions.py`, `audit.py`, `policy.py`, `metrics.py` (decisioning, audit, overrides, metrics).
  - **Audit log:** `services/audit/audit_log.py` (SHA-256 hash-chained append & verify; in-memory fallback).
  - **Decision engine:** `services/decision_engine/engine.py` (policy profiles in `config/policy_profiles.yaml`).
  - **Validation engine:** `services/validation_engine/deterministic.py` (CVE/CVSS/ATT&CK/version rules) and `services/validation_engine/llm_verifier.py` (mock + fallback patterns).
  - **Claim extractor:** `services/claim_extractor/extractor.py` and `services/claim_extractor/models.py` (regex, spaCy, BERT fallback; async + legacy bridge).
  - **RAG pipeline & FAISS:** `services/rag_pipeline/*` and `services/rag_pipeline/sync_jobs.py` (indexing + Celery sync tasks).
  - **DB ORM:** `db/orm.py` (SQLAlchemy async models and manager).
  - **Frontend fixes:** `dashboard/src/App.jsx` and supporting files — Vite build validated.
  - **Tests:** multiple unit and integration tests fixed; `llm-hallucination-firewall/tests/unit` currently passing locally (18 passed).

- **Remaining / Open work (prioritized):**
  1. Implement an end-to-end integration test covering: extract → validate → decide → override → audit verify (high priority).
  2. Add CI workflow with two profiles (minimal vs full): install minimal deps for quick tests; full profile runs all tests + dashboard build.
  3. Resolve pytest collection collisions (duplicate test basenames across subfolders) or scope tests per-subproject in CI.
  4. Finalize DB migrations and production persistence for SQLAlchemy tables and ensure DB-first flows run in the full profile.
  5. Persist FAISS indexes to durable storage and make rebuild jobs incremental/resumable.
  6. Dashboard UX: charts, pagination, auth flows, policy profile management UI.
  7. Observability: enable Prometheus metrics when dependency present, add Grafana dashboards into infra manifests.
  8. Security: finalize JWT auth, RBAC enforcement in gateway routes, and rotateable secrets management.

- **Recommended immediate next actions:**
  - Implement the E2E integration test (adds high confidence for the full pipeline).
  - Add a GitHub Actions workflow with a matrix for minimal/full profiles (run unit tests + integration/E2E in full job, run dashboard build in full job).
  - In CI, run tests per-subproject (avoid cross-folder import collisions) or rename conflicting test files.

- **How to reproduce local test runs (quick):**
  ```powershell
  # Activate venv
  & .\.venv\Scripts\Activate.ps1
  # Install requirements
  & .\.venv\Scripts\python.exe -m pip install -r requirements.txt
  & .\.venv\Scripts\python.exe -m pip install pytest-asyncio
  # Run all tests (may need to adjust PYTHONPATH or run per-subproject)
  $env:PYTHONPATH='f:\uip-2026'
  & .\.venv\Scripts\python.exe -m pytest -q
  ```

If you'd like, I can implement the E2E test next and/or add a CI workflow draft — tell me which and I'll proceed.

## Support

For issues and questions:
- 📧 Email: security-team@unisys.com
- 📝 Documentation: See `/docs` folder
- 🐛 Bug Reports: GitHub Issues
| LLM Verification | Ollama (Mistral-7B) + OpenAI fallback |
| Database | PostgreSQL + asyncpg + SQLAlchemy |
| Cache/Queue | Redis + Celery + Celery Beat |
| Monitoring | Prometheus + Grafana |
| Frontend | React + TailwindCSS + Recharts |
| Deployment | Docker Compose (dev) / Kubernetes (prod) |
| Auth | JWT RS256 + RBAC |

## Decision Outcomes

- **ALLOW** (risk_score 0.85–1.0): LLM output is highly trustworthy
- **FLAG** (risk_score 0.60–0.84): Possible inconsistency; SOC analyst review recommended
- **BLOCK** (risk_score < 0.60): Hallucinatory claim detected; blocked from enforcement
- **CORRECT** (high confidence correction): If BLOCK, provides corrected recommendation

## Risk Scoring Algorithm

```
risk_score = (0.4 × cve_validity_confidence) 
           + (0.3 × severity_accuracy)
           + (0.2 × mitigation_relevance)
           + (0.1 × urgency_consistency)
```

## Development

### Adding New Validation Rules

See `services/validation_engine/deterministic.py` for rule templates.

### Extending Threat Intelligence Sources

See `services/rag_pipeline/` for integrating new data sources.

### Customizing Decision Profiles

Edit `services/decision_engine/policy_profiles.yaml` to adjust thresholds per environment.

## Security Considerations

- All secrets loaded via environment variables (never hardcoded)
- JWT RS256 (asymmetric) for API authentication
- Hash-chained audit logs prevent tampering
- Rate limiting on public endpoints via Redis
- SQL injection prevention via parameterized queries + asyncpg
- CORS configured for trusted origins only
- Input validation via Pydantic v2

## Monitoring

**Key Metrics:**
- `validation_latency_ms`: End-to-end validation pipeline duration
- `decision_outcome_count`: Per-outcome decision frequency
- `rag_retrieval_similarity`: Vector search quality
- `llm_verifier_skipped`: Ollama circuit breaker activations

**Alerts (Grafana):**
- Validation pipeline p95 latency > 3s
- BLOCK decision rate > 15%
- Ollama service unavailable
- Audit hash chain verification failures

## Testing

```bash
# Unit tests
pytest tests/unit/ -v

# Integration tests (requires Docker Compose)
pytest tests/integration/ -v

# Coverage
pytest --cov=services tests/
```

## Deployment

### Kubernetes
- Update `docker-compose.yml` → Helm charts
- Use managed PostgreSQL + Redis services
- Deploy Ollama sidecar or external inference service

### Production Checklist
- [ ] Generate and rotate RS256 key pair
- [ ] Configure NVD API key (exponential backoff already implemented)
- [ ] Set up PostgreSQL automated backups
- [ ] Enable Redis persistence + replication
- [ ] Configure Prometheus scrape intervals
- [ ] Set up Grafana dashboards and alerts
- [ ] Test audit hash chain integrity
- [ ] Load test with production threat intel volumes

## TODO & Integration Points

**Tanushree's Module (Claim Extraction):** connects to gateway validate endpoint via orchestration layer  
**Tapan's Module (Decision Engine):** consumes validation results, produces final outcome + correction pathway  
**Dhruv's Module (RAG Pipeline & Audit):** provides threat intel retrieval and cryptographic audit logging

## Support

For issues or feature requests, open a GitHub issue or contact the SOC platform team.

## License

Proprietary — Unisys Enterprise Security Platform
