PYTHON=python
PIP=$(PYTHON) -m pip

.PHONY: help build docker-build docker-run lint format release k8s-apply load-test gen-keys

help:
	@printf "Makefile targets:\n  build        - install deps into .venv\n  docker-build - build container image\n  docker-run   - run infra/docker-compose up\n  lint         - run ruff/black checks\n  format       - run black/ruff fixes\n  gen-keys     - generate RSA JWT keypair (infra/scripts)\n  release      - build and pack release artifact\n  k8s-apply    - apply infra/k8s manifests (requires kubectl)\n  load-test    - run local load test against API\"

build:
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

docker-build:
	docker build -f infra/Dockerfile -t llm-firewall:local .

docker-run:
	cd infra && docker compose up -d --build

lint:
	$(PYTHON) -m ruff check .
	black --check .

format:
	black .
	ruff check --fix .

gen-keys:
	sh infra/scripts/generate_jwt_keys.sh infra/keys || powershell -File infra/scripts/generate_jwt_keys.ps1 infra/keys

release:
	# Create a source tarball and Docker image tag
	git rev-parse --short HEAD > .git/HEAD_SHORT || true
	TGZ=release/llm-firewall-$$(date +%Y%m%d)-$$(git rev-parse --short HEAD).tar.gz
	mkdir -p release
	tar -czf $$TGZ .
	echo "Release artifact created: $$TGZ"

k8s-apply:
	kubectl apply -f infra/k8s/

load-test:
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) infra/load_test/locustfile.py --target http://localhost:8000
# Makefile
# Convenient commands for development, testing, and deployment

.PHONY: help install dev test lint format docker-up docker-down clean

help:
	@echo "LLM Hallucination Firewall - Available Commands"
	@echo ""
	@echo "Development:"
	@echo "  make install         Install all dependencies"
	@echo "  make dev            Start development server with hot reload"
	@echo "  make test           Run all tests"
	@echo "  make lint           Run linters (flake8, black, isort)"
	@echo "  make format         Format code (black, isort)"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-up      Start all services (docker-compose up)"
	@echo "  make docker-down    Stop all services"
	@echo "  make docker-logs    View service logs"
	@echo ""
	@echo "Database:"
	@echo "  make db-migrate     Run Alembic migrations"
	@echo "  make db-reset       Drop and recreate database"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean          Remove cache and build artifacts"
	@echo "  make docs           Generate API documentation"

install:
	pip install -r services/gateway/requirements.txt
	pip install -r services/claim_extractor/requirements.txt
	pip install -r services/rag_pipeline/requirements.txt
	pip install -r services/validation_engine/requirements.txt
	pip install -r services/decision_engine/requirements.txt
	pip install -r services/explainability/requirements.txt
	pip install -r services/audit/requirements.txt

dev:
	cd services/gateway && uvicorn main:app --host 0.0.0.0 --port 8000 --reload

test:
	pytest tests/ -v --tb=short

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

lint:
	flake8 services/ db/ --count --select=E9,F63,F7,F82
	black --check services/ db/
	isort --check-only services/ db/

format:
	black services/ db/
	isort services/ db/

docker-up:
	cd infra && docker-compose up -d

docker-down:
	cd infra && docker-compose down

docker-logs:
	cd infra && docker-compose logs -f

db-migrate:
	alembic upgrade head

db-reset:
	alembic downgrade base
	alembic upgrade head

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache build dist *.egg-info

docs:
	@echo "API documentation available at http://localhost:8000/docs"

.PHONY: all
all: install lint test
