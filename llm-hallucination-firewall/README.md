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
