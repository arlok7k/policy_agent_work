"""The deployed Celery entrypoint must initialize mappings in a fresh interpreter."""

import os
import subprocess
import sys
from pathlib import Path

import yaml


def _compose_celery_target() -> str:
    config = yaml.safe_load(Path("infra/docker-compose.yml").read_text(encoding="utf-8"))
    worker = config["services"]["celery-worker"]["command"]
    beat = config["services"]["celery-beat"]["command"]
    assert worker[:2] == beat[:2] == ["celery", "-A"]
    assert worker[2] == beat[2]
    for name in ("celery-worker", "celery-beat"):
        health = config["services"][name]["healthcheck"]["test"][1]
        assert f"celery -A {worker[2]} inspect ping" in health
    return str(worker[2])


def test_deployed_worker_resolves_all_foreign_keys_in_a_clean_process() -> None:
    target = _compose_celery_target()
    # A fresh interpreter is essential: API/in-process worker tests happen to
    # import incident models before the worker and otherwise hide this defect.
    code = """
import importlib, sys
module, attribute = sys.argv[1].split(':')
assert getattr(importlib.import_module(module), attribute) is not None
from app.core.models import Base
assert 'incidents' in Base.metadata.tables
for table in Base.metadata.sorted_tables:
    for foreign_key in table.foreign_keys:
        assert foreign_key.column.table in Base.metadata.tables.values()
"""
    environ = dict(os.environ, PYTHONPATH=str(Path("backend").resolve()))
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code, target],
        env=environ,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
