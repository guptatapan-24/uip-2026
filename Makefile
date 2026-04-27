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
