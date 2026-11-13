"""Automated failure output must not dump generated credential values."""

import os
import subprocess
import sys
from pathlib import Path


def test_failure_output_names_the_test_but_redacts_values(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[3]
    probe = tmp_path / "test_redaction_probe.py"
    marker = "nonsecret-failure-output-canary"
    probe.write_text(
        f"def test_probe():\n    value = {marker!r}\n    assert value == 'different'\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "backend" / "tests")
    result = subprocess.run(  # noqa: S603 - fixed interpreter and pytest arguments
        [
            sys.executable,
            "-m",
            "pytest",
            "-c",
            str(root / "pyproject.toml"),
            "-p",
            "conftest",
            "-q",
            str(probe),
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 1
    output = result.stdout + result.stderr
    assert "test_probe" in output
    if marker in output:
        raise AssertionError("Failure output included a test value")
