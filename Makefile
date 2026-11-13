PYTHON ?= python3

.PHONY: install lint typecheck test check audit lock migrate

install:
	$(PYTHON) -m pip install --require-hashes -r requirements.lock

lint:
	$(PYTHON) -m ruff check backend scripts
	$(PYTHON) -m ruff format --check backend scripts

typecheck:
	$(PYTHON) -m mypy backend/app

test:
	$(PYTHON) -m pytest

check: lint typecheck test

migrate:
	PYTHONPATH=backend $(PYTHON) -m alembic upgrade head

audit:
	$(PYTHON) -m pip_audit --disable-pip --require-hashes -r requirements.lock --progress-spinner off
	$(PYTHON) -m piplicenses --with-system --fail-on UNKNOWN --format=plain
	$(PYTHON) scripts/check_secrets.py

lock:
	$(PYTHON) -m piptools compile --extra dev --generate-hashes --strip-extras --allow-unsafe --no-emit-index-url --no-emit-trusted-host --output-file=requirements.lock pyproject.toml
