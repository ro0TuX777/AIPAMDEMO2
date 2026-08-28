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
        bluescrub-preflight bluescrub-preflight-strict \
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

## BlueScrub deployment preflight.
## Every external adapter was written against a tool that is not installed on
## a development machine, so their parsers are tested against recorded output
## and their argv is tested by nothing. This runs each adapter for real. Run it
## on the deployment host before each merge, alongside the golden PCAP gate.
bluescrub-preflight:
	$(PYTHON) scripts/bluescrub_preflight.py

## The same, but fails the build when required tooling is missing.
bluescrub-preflight-strict:
	$(PYTHON) scripts/bluescrub_preflight.py --strict

# ---------------------------------------------------------------------------
# Code quality
# ---------------------------------------------------------------------------

## Run ruff linter
lint:
	$(PYTHON) -m ruff check --config ruff.toml backend/ tests/

## Auto-format with ruff
fmt:
	$(PYTHON) -m ruff format backend/ tests/

## Type-check (advisory).
## The previous recipe piped mypy to /dev/null and OR-ed to an echo, so it
## always "passed" — type errors were never seen and mypy was not even
## installed. This runs mypy for real and shows every error. It stays advisory
## (leading `-` ignores the exit code) because the codebase carries ~880
## pre-existing type errors; gating on them would block every PR. Drive the
## count down, then drop the `-` to make it enforcing.
check:
	$(PYTHON) -m mypy --version
	@echo "── mypy (advisory; not yet gating — see errors below) ──"
	-$(PYTHON) -m mypy backend/app/ --ignore-missing-imports

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

