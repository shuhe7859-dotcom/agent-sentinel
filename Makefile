.DEFAULT_GOAL := help

PYTHON ?= python

.PHONY: help venv install test cov lint fmt typecheck check example build clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

venv: ## Create .venv
	$(PYTHON) -m venv .venv

install: ## Install the package with the dev extra
	$(PYTHON) -m pip install -e ".[dev]"

test: ## Run the test suite
	$(PYTHON) -m pytest

cov: ## Run the test suite with coverage
	$(PYTHON) -m pytest --cov=agent_sentinel --cov-report=term-missing

lint: ## Check style and common mistakes
	$(PYTHON) -m ruff check .

fmt: ## Format the code
	$(PYTHON) -m ruff format .
	$(PYTHON) -m ruff check --fix .

typecheck: ## Run the type checker
	$(PYTHON) -m mypy

check: lint typecheck test ## Everything CI runs

example: ## Run the quickstart tour
	$(PYTHON) examples/quickstart.py

build: ## Build a wheel and sdist
	$(PYTHON) -m build

clean: ## Remove caches and build output
	rm -rf build dist .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

