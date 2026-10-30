# ==============================================================================
# CyberDuel AI — Development & Operations Automation
# ==============================================================================

.PHONY: help install test lint format typecheck up down logs clean migrate

PYTHON ?= python
UV ?= uv
DOCKER_COMPOSE ?= docker compose

help:
	@echo "Available commands:"
	@echo "  make install    - Install workspace dependencies in editable mode"
	@echo "  make test       - Run all unit and contract tests"
	@echo "  make lint       - Run ruff linter checks"
	@echo "  make format     - Format code using ruff"
	@echo "  make typecheck  - Run static type checking with mypy"
	@echo "  make up         - Build and start Docker Compose local stack"
	@echo "  make down       - Stop and tear down Docker Compose local stack"
	@echo "  make logs       - Tail logs from all Docker Compose services"
	@echo "  make migrate    - Run database migrations via Alembic"
	@echo "  make clean      - Clean temporary files, caches, and test artifacts"

install:
	$(UV) pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check .

format:
	ruff format .

typecheck:
	mypy apps/api/app packages/shared-contracts/cyberduel_contracts

up:
	$(DOCKER_COMPOSE) up -d --build

down:
	$(DOCKER_COMPOSE) down

logs:
	$(DOCKER_COMPOSE) logs -f

migrate:
	alembic -c apps/api/alembic.ini upgrade head

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .coverage htmlcov .mypy_cache .ruff_cache 2>/dev/null || true

