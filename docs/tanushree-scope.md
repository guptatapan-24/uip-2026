# Tanushree Scope

This repo now contains the validation-engine ownership area for Tanushree:

- `services/claim_extractor/extractor.py`
  Three-pass extraction pipeline using regex, spaCy fallback NER, and BERT-style span extraction hooks.
- `services/claim_extractor/training.py`
  Custom spaCy security NER training utility backed by annotated JSONL fixtures.
- `services/validation_engine/deterministic.py`
  Independently testable deterministic validation rules, including mitigation-to-technique mapping.
- `services/validation_engine/semantic.py`
  Sentence-transformer style similarity scorer with policy-profile threshold overrides.
- `services/validation_engine/calibration.py`
  Semantic threshold calibration utility for labelled mitigation relevance pairs.
- `services/validation_engine/ablation.py`
  Synthetic benchmark and ablation runner for FAR, FBR, catch rate, and decision consistency.
- `services/decision_engine/engine.py`
  YAML-driven weighted decisioning with `ALLOW`, `FLAG`, `BLOCK`, and `CORRECT`.
- `config/*.yaml`
  Extraction config, deterministic rule settings, calibration candidates, and policy profiles.
- `tests/unit/*`
  Unit tests for extraction, deterministic rules, semantic scoring, calibration, and decision logic.
- `tests/fixtures/hallucination_benchmark.json`
  Synthetic benchmark dataset for ablation and evaluation work.
- `tests/fixtures/security_ner_annotations.jsonl`
  Starter annotations for the custom spaCy security NER model.
- `tests/fixtures/semantic_pairs.json`
  Labelled mitigation-evidence pairs for semantic threshold calibration.

## What still depends on teammates

- API routes and orchestration
- database-backed audit logging
- explainability reports
- LLM verifier integration
- Docker, monitoring, auth, CI/CD, and deployment

## Local setup note

The validation modules are written to degrade gracefully when the heavy NLP stack is unavailable.

- Use `requirements.txt` for the base unit-test path on Python 3.14.
- `pydantic==2.13.3` is pinned because older `2.11.x` releases predate Python 3.14 support.
- Use `requirements-ml.txt` for the heavier NLP stack. `spaCy 3.8.13` has Python 3.14 wheels, while `sentence-transformers` is still treated as optional here.

## Useful commands

```powershell
.\.venv\Scripts\python -m pytest tests/unit
.\.venv\Scripts\python -m services.validation_engine.calibration
.\.venv\Scripts\python -m services.validation_engine.ablation
.\.venv\Scripts\python -c "from services.claim_extractor.training import train_custom_security_ner; print(train_custom_security_ner())"
```

## Current benchmark snapshot

- Extraction recall on the synthetic benchmark: `97.5%`
- Full-system hallucination catch rate: `100%`
- Full-system FAR: `0%`
- Full-system FBR: `0%`
- Full-system decision consistency: `80%`

## Semantic threshold note

The default policy profile still uses `0.72` for ML-backed deployment. On the current Python 3.14 lightweight stack, the lexical fallback calibration utility selects a lower local optimum because sentence-transformers is optional in this environment.

## Recommended next integration order

1. Wire `services/claim_extractor/extractor.py` into `/extract`.
2. Wire deterministic and semantic validation into `/validate`.
3. Wire `services/decision_engine/engine.py` into `/decide`.
4. Feed benchmark fixtures into the end-to-end and ablation test flows.
