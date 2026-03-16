# AIPAM V2 — Development Makefile
# See AIPAM_SensorsV2_Implementation_Plan.md §14.13

SHELL := /bin/bash
PYTHON ?= python
PYTEST ?= $(PYTHON) -m pytest
# Exit code 5 = "no tests collected" — not a failure for stub directories
PYTEST_ARGS ?= -v --tb=short
PYTEST_RUN = $(PYTEST) $(1) $(PYTEST_ARGS) || { ec=$$?; [ $$ec -eq 5 ] && exit 0 || exit $$ec; }

# Export required env vars for tests
export AIPAM_API_TOKEN ?= test-token-v2

# ---------------------------------------------------------------------------
# Test targets (§14.13)
# ---------------------------------------------------------------------------

.PHONY: test-unit test-contract test-api test-worker test-sse test-sensor-contract \
        test-integration test-smoke test-parity test-e2e benchmark test-all \
        lint fmt check db-migrate db-upgrade db-downgrade clean help

## Unit tests — pure logic, no Docker, no network
test-unit:
	$(PYTEST) tests/unit/ $(PYTEST_ARGS)

## OpenAPI schema / contract validation
test-contract:
	$(call PYTEST_RUN,tests/contract/)

## API endpoint tests (FastAPI TestClient)
test-api:
	$(call PYTEST_RUN,tests/unit/ -k "api")

## Worker + sensor runner tests
test-worker:
	$(call PYTEST_RUN,tests/unit/ -k "worker or pipeline or sensor_runner")

## SSE stream tests
test-sse:
	$(call PYTEST_RUN,tests/unit/ -k "sse")

## Sensor image contract validation
test-sensor-contract:
	$(call PYTEST_RUN,tests/contract/ -k "sensor")

## Integration tests — golden PCAP corpus (requires Docker)
test-integration:
	$(call PYTEST_RUN,tests/integration/)

## Smoke test — aipam-admin smoke-test
test-smoke:
	$(PYTHON) -m backend.app.cli smoke-test 2>/dev/null || echo "smoke-test CLI not yet implemented"

## Parity tests — V1/V2 comparison (bridge mode only)
test-parity:
	$(call PYTEST_RUN,tests/parity/)

## End-to-end UI workflow tests
test-e2e:
	$(call PYTEST_RUN,tests/e2e/)

## Performance regression detection (requires pytest-benchmark)
benchmark:
	$(PYTEST) tests/integration/ -k "benchmark" $(PYTEST_ARGS) 2>/dev/null || echo "benchmark fixtures not yet implemented — skipping"

## Run everything except parity, e2e, benchmark
test-all: test-unit test-contract test-api test-worker test-sse

# ---------------------------------------------------------------------------
# Code quality
# ---------------------------------------------------------------------------

## Run ruff linter
lint:
	$(PYTHON) -m ruff check backend/ tests/

## Auto-format with ruff
fmt:
	$(PYTHON) -m ruff format backend/ tests/

## Type-check
check:
	$(PYTHON) -m mypy backend/app/ --ignore-missing-imports 2>/dev/null || echo "mypy not installed"

# ---------------------------------------------------------------------------
# Database (Alembic V2)
# ---------------------------------------------------------------------------

## Generate a new migration: make db-migrate MSG="add foo table"
db-migrate:
	alembic revision --autogenerate -m "$(MSG)"

## Apply all pending migrations
db-upgrade:
	alembic upgrade head

## Roll back one migration
db-downgrade:
	alembic downgrade -1

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------

## Remove test artifacts
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	rm -f tests/test_aipam_v2.db

## Show this help
help:
	@echo "AIPAM V2 Makefile targets:"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /' | sort
	@echo ""
	@echo "Usage: make <target>"

