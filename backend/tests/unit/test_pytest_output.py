"""Normal pytest diagnostics must not expose wrapped test credentials."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi import FastAPI, Request

from tests.sensitive import Redacted, SecretAwareTestClient, assert_not_disclosed, reveal


def test_redacted_representation_and_boundary_unwrapping() -> None:
    password = Redacted.random()
    nested = {"password": password, "values": [password]}
    assert repr(password) == "Redacted(<redacted>)"
    assert str(password) == "<redacted>"
    assert_not_disclosed("Nested representation", repr(nested), password)
    unwrapped = reveal(nested)
    matches = unwrapped["password"] == password.reveal()
    assert matches
    assert nested["password"] is password


def test_leak_assertion_fails_without_echoing_the_value() -> None:
    password = Redacted.random()
    contaminated = f"response:{password.reveal()}"
    with pytest.raises(AssertionError, match="disclosed a protected test value") as error:
        assert_not_disclosed("Response", contaminated, password)
    assert_not_disclosed("Assertion message", str(error.value), password)


def test_test_client_unwraps_requests_without_mutating_the_original_data() -> None:
    password = Redacted.random()
    payload = {"password": password, "nested": [password]}
    headers = {"X-Probe": password}
    app = FastAPI()

    @app.post("/probe")
    async def endpoint(request: Request) -> dict[str, bool]:
        body = await request.json()
        return {
            "matched": body["password"] == password.reveal()
            and body["nested"][0] == password.reveal()
            and request.headers["X-Probe"] == password.reveal()
        }

    with SecretAwareTestClient(app) as client:
        response = client.post("/probe", json=payload, headers=headers)
    assert response.json() == {"matched": True}
    assert payload["password"] is password and headers["X-Probe"] is password


def test_failure_output_names_the_test_but_redacts_values(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[3]
    password = Redacted.random()
    digest = Redacted(PasswordHasher().hash(password.reveal()))
    probe = tmp_path / "test_redaction_probe.py"
    probe.write_text(
        """import os

import httpx2
import pytest
from fastapi import FastAPI

from tests.sensitive import Redacted, SecretAwareTestClient


@pytest.fixture
def account():
    return {
        "password": Redacted(os.environ["PROBE_PASSWORD"]),
        "digest": Redacted(os.environ["PROBE_DIGEST"]),
    }


def test_wrapped_value_comparison(account):
    different = "different-value"
    assert account["password"] == different


def test_nested_fixture_comparison(account):
    different = "different"
    assert account == {"password": different, "digest": different}


def test_diagnostic_and_capture_are_visible(account):
    print("nonsecret captured diagnostic")
    raise ValueError("nonsecret exception diagnostic")


def test_unicode_encoder_failure(account):
    httpx2.Request(
        "POST", "https://testserver.invalid/",
        json={"username": "\\ud800", "password": account["password"].reveal()},
    )


def test_http_request_failure(account):
    app = FastAPI()

    @app.post("/probe")
    def endpoint():
        return {"ok": True}

    with SecretAwareTestClient(app) as client:
        assert client.post("/probe", json={"password": account["password"]}).status_code == 418
""",
        encoding="utf-8",
    )
    env = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "LANG", "LC_ALL", "LD_LIBRARY_PATH")
        if key in os.environ
    }
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["PYTHONPATH"] = str(root / "backend")
    env["PROBE_PASSWORD"] = password.reveal()
    env["PROBE_DIGEST"] = digest.reveal()
    result = subprocess.run(  # noqa: S603 - fixed interpreter and pytest arguments
        [sys.executable, "-m", "pytest", "-c", str(root / "pyproject.toml"), "-q", str(probe)],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = result.stdout + result.stderr
    assert_not_disclosed("Pytest failure output", output, password, digest)
    exit_code = result.returncode
    assert exit_code == 1
    assert "test_wrapped_value_comparison" in output
    assert "test_nested_fixture_comparison" in output
    assert "test_diagnostic_and_capture_are_visible" in output
    assert "test_unicode_encoder_failure" in output
    assert "test_http_request_failure" in output
    assert "AssertionError" in output and "<redacted>" in output
    assert "ValueError: nonsecret exception diagnostic" in output
    assert "UnicodeEncodeError" in output
    assert "Captured stdout call" in output and "nonsecret captured diagnostic" in output
    assert "200 == 418" in output
