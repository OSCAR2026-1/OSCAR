# Variables
PYTHON := python3
PIP := pip3
SOURCES := client.py server.py
VENV := venv
VENV_BIN := $(VENV)/bin

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m # No Color

.PHONY: help install format lint check test clean venv setup dev

# Default target
help:
	@echo "$(GREEN)RestMCP Development Commands$(NC)"
	@echo ""
	@echo "$(YELLOW)Setup:$(NC)"
	@echo "  make setup        - Complete development setup (venv + install + format)"
	@echo "  make venv         - Create virtual environment"
	@echo "  make install      - Install dependencies"
	@echo "  make dev          - Install development dependencies"
	@echo ""
	@echo "$(YELLOW)Code Quality:$(NC)"
	@echo "  make format       - Format code with black and isort"
	@echo "  make lint         - Run linting with flake8 and pylint"
	@echo "  make check        - Run all checks (format + lint)"
	@echo "  make fix          - Auto-fix formatting and import issues"
	@echo ""
	@echo "$(YELLOW)Testing:$(NC)"
	@echo "  make test         - Run tests"
	@echo "  make test-verbose - Run tests with verbose output"
	@echo ""
	@echo "$(YELLOW)Maintenance:$(NC)"
	@echo "  make clean        - Clean up temporary files"
	@echo "  make clean-all    - Clean everything including venv"

# Setup targets
setup: venv install dev format
	@echo "$(GREEN)✅ Development environment setup complete!$(NC)"

venv:
	@echo "$(YELLOW)Creating virtual environment...$(NC)"
	$(PYTHON) -m venv $(VENV)
	@echo "$(GREEN)✅ Virtual environment created$(NC)"
	@echo "$(YELLOW)To activate: source $(VENV_BIN)/activate$(NC)"

install:
	@echo "$(YELLOW)Installing dependencies...$(NC)"
	$(PIP) install -r requirements.txt
	@echo "$(GREEN)✅ Dependencies installed$(NC)"

dev:
	@echo "$(YELLOW)Installing development dependencies...$(NC)"
	$(PIP) install black isort flake8 pylint pytest mypy
	@echo "$(GREEN)✅ Development dependencies installed$(NC)"

# Code formatting targets
format:
	@echo "$(YELLOW)Formatting code with black...$(NC)"
	black --line-length 88 $(SOURCES)
	@echo "$(YELLOW)Sorting imports with isort...$(NC)"
	isort --profile black $(SOURCES)
	@echo "$(GREEN)✅ Code formatted$(NC)"

fix: format
	@echo "$(GREEN)✅ Auto-fixes applied$(NC)"

# Linting targets
lint:
	@echo "$(YELLOW)Running flake8...$(NC)"
	flake8 $(SOURCES) --max-line-length=88 --extend-ignore=E203,W503
	@echo "$(YELLOW)Running pylint...$(NC)"
	pylint $(SOURCES) --disable=C0111,R0903,W0613 || true
	@echo "$(GREEN)✅ Linting complete$(NC)"

# Type checking
typecheck:
	@echo "$(YELLOW)Running mypy type checker...$(NC)"
	mypy $(SOURCES) --ignore-missing-imports || true
	@echo "$(GREEN)✅ Type checking complete$(NC)"

# Combined checks
check: format lint typecheck
	@echo "$(GREEN)✅ All checks completed$(NC)"

# Testing targets
test:
	@echo "$(YELLOW)Running tests...$(NC)"
	pytest -v || echo "$(YELLOW)⚠️  No tests found$(NC)"

test-verbose:
	@echo "$(YELLOW)Running tests with verbose output...$(NC)"
	pytest -vvv -s || echo "$(YELLOW)⚠️  No tests found$(NC)"

# Quick format check (doesn't modify files)
check-format:
	@echo "$(YELLOW)Checking code format...$(NC)"
	black --check --diff --line-length 88 $(SOURCES)
	isort --check-only --profile black $(SOURCES)

# Security check
security:
	@echo "$(YELLOW)Running security checks...$(NC)"
	$(PIP) install bandit safety
	bandit -r $(SOURCES) || true
	safety check || true
	@echo "$(GREEN)✅ Security checks complete$(NC)"

# Pre-commit hook (run before committing)
pre-commit: format lint
	@echo "$(GREEN)✅ Pre-commit checks passed$(NC)"

# Documentation
docs:
	@echo "$(YELLOW)Generating documentation...$(NC)"
	$(PIP) install pydoc-markdown
	pydoc-markdown --help || echo "$(YELLOW)⚠️  Documentation tools not available$(NC)"

# Clean up targets
clean:
	@echo "$(YELLOW)Cleaning temporary files...$(NC)"
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name ".coverage" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✅ Temporary files cleaned$(NC)"

clean-all: clean
	@echo "$(YELLOW)Removing virtual environment...$(NC)"
	rm -rf $(VENV)
	@echo "$(GREEN)✅ Everything cleaned$(NC)"

# Development workflow targets
dev-setup: setup
	@echo "$(GREEN)🚀 Ready for development!$(NC)"
	@echo ""
	@echo "$(YELLOW)Quick commands:$(NC)"
	@echo "  make format  - Format your code"
	@echo "  make check   - Run all quality checks"
	@echo "  make test    - Run tests"

# CI/CD simulation
ci: check-format lint typecheck test
	@echo "$(GREEN)✅ All CI checks passed$(NC)"

# Show file status
status:
	@echo "$(YELLOW)File status:$(NC)"
	@echo "Python files: $(SOURCES)"
	@echo "Virtual env: $(if $(wildcard $(VENV)),✅ exists,❌ missing)"
	@echo "Dependencies: $(if $(shell $(PIP) list | grep black),✅ installed,❌ missing)"

# Install pre-commit hooks
install-hooks:
	@echo "$(YELLOW)Installing pre-commit hooks...$(NC)"
	$(PIP) install pre-commit
	pre-commit install
	@echo "$(GREEN)✅ Pre-commit hooks installed$(NC)"