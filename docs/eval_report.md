# Evaluation Report

## Benchmark Ownership

Tanushree owns the hallucination benchmark set, ablation runs, and the final comparison between baseline and firewall-enabled validation.

## Synthetic Benchmark Setup

- Dataset: `tests/fixtures/hallucination_benchmark.json`
- Cases: `10`
- Mix: `3` grounded-safe recommendations, `7` hallucinated or unsafe recommendations
- Extraction pipeline: regex + spaCy/custom-model path + BERT-style span extraction with heuristics
- Validation layers: deterministic rules, semantic similarity, urgency consistency, correction ranking

## Core Metrics

| Configuration | Catch Rate | FAR | FBR | Decision Consistency | Extraction Recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline, no firewall | 0.00 | 1.00 | 0.00 | 0.30 | 0.975 |
| Full system | 1.00 | 0.00 | 0.00 | 0.80 | 0.975 |
| Without deterministic validation | 1.00 | 0.00 | 1.00 | 0.10 | 0.975 |
| Without semantic validation | 1.00 | 0.00 | 0.00 | 0.90 | 0.975 |
| Without correction pathway | 1.00 | 0.00 | 0.00 | 0.50 | 0.975 |
| Without urgency scoring | 1.00 | 0.00 | 0.00 | 0.70 | 0.975 |

## Interpretation

- The current synthetic benchmark clears the Phase 1 extraction recall target with `97.5%`.
- The deterministic layer is essential for avoiding blanket overblocking. Disabling it pushes FBR to `100%`.
- The correction pathway materially improves final outcome quality. Removing it drops decision consistency from `0.80` to `0.50`.
- The semantic layer is currently additive but less decisive than the deterministic layer on this benchmark because the cases are strongly structured.

## Semantic Threshold Calibration

- Calibration utility: `services/validation_engine/calibration.py`
- Labelled pairs: `tests/fixtures/semantic_pairs.json`
- Policy default threshold: `0.72` in `config/policy_profiles.yaml`
- Local lightweight calibration result: `0.60`

The difference between `0.72` and the local `0.60` calibration result is expected in the current environment because sentence-transformers is optional on Python 3.14 here, so the calibration run is using the lexical fallback scorer. Once the ML stack is installed and the embedding model is active, the same calibration path can be rerun and the policy profile updated with a more representative threshold.

## Repro Commands

```powershell
.\.venv\Scripts\python -m pytest tests/unit
.\.venv\Scripts\python -m services.validation_engine.calibration
.\.venv\Scripts\python -m services.validation_engine.ablation
```
