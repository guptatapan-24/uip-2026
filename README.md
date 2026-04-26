# LLM Hallucination Firewall for Enterprise Security Decisions

This repository contains the following deliverables:

- FastAPI skeleton with `POST /validate`
- decision engine with `allow`, `flag`, `block`, `correct`
- React UI for running demo scenarios
- metrics dashboard showing FAR, FBR, latency, and cache hit rate
- demo scenarios for presentation day
- local backup run scripts in `scripts/`
- validation-engine modules aligned to the UIP Y17 architecture PDF under `services/`

## Project structure

```text
backend/
  app/
    api/
    core/
    services/
frontend/
docs/
services/
tests/
config/
```

## Backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Shortcut:

```powershell
.\scripts\run-backend.ps1
```

Backend endpoints:

- `GET /health`
- `GET /metrics`
- `GET /demo-scenarios`
- `POST /validate`

## Frontend

```powershell
cd frontend
npm install
npm run dev
```

Shortcut:

```powershell
.\scripts\run-frontend.ps1
```

The UI assumes the backend is running at `http://127.0.0.1:8000`.

## Demo flow

1. Open the React UI.
2. Choose a demo scenario.
3. Review or edit the JSON claim payload.
4. Click `Run /validate`.
5. Show the decision, reasoning, and updated metrics dashboard.

## One-click API demo

With the backend running:

```powershell
.\scripts\demo-api.ps1
```

This triggers the fabricated-CVE scenario and returns a `block` response for a fast command-line backup demo.

## Team integration notes

- Person C can replace manual JSON claims with the claim extractor output.
- Person A can replace mock claim booleans with real validator results.
- The decision engine and UI contracts are already in place for that handoff.

## Validation Engine Workstream

The repo also contains the newer Tanushree-owned validation stack that follows the architecture PDF:

- `services/claim_extractor/extractor.py`
- `services/claim_extractor/training.py`
- `services/validation_engine/deterministic.py`
- `services/validation_engine/semantic.py`
- `services/validation_engine/calibration.py`
- `services/validation_engine/ablation.py`
- `services/decision_engine/engine.py`

Useful commands:

```powershell
.\.venv\Scripts\python -m pytest tests/unit
.\.venv\Scripts\python -m services.validation_engine.calibration
.\.venv\Scripts\python -m services.validation_engine.ablation
```
