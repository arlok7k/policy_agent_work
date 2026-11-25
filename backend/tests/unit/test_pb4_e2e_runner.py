"""The Compose smoke harness is opt-in and keeps test credentials redacted."""

import os
import sys

import pytest
from scripts.run_compose_e2e import Redacted, _stream, redact_output, require_disposable


def test_smoke_runner_requires_explicit_disposable_development_http() -> None:
    valid = {"ENV": "development", "DEV_INSECURE_COOKIES": "true"}
    require_disposable(valid, confirmed=True)
    for environ, confirmed in (
        (valid, False),
        ({**valid, "ENV": "production"}, True),
        ({**valid, "DEV_INSECURE_COOKIES": "false"}, True),
        ({"ENV": "development"}, True),
    ):
        with pytest.raises(ValueError, match="requires --disposable"):
            require_disposable(environ, confirmed=confirmed)


def test_redaction_preserves_diagnostics_without_disclosing_secrets() -> None:
    password, webhook, cookie = Redacted.random(), Redacted.random(), Redacted.random()
    line = (
        f"diagnostic {password.reveal()} {webhook.reveal()}\n"
        f"  - Cookie: soc_dev_session={cookie.reveal()}\n"
        f"X-CSRF-Token: {cookie.reveal()}\n"
        "sha256=" + "a" * 64 + "\n"
    )
    result = redact_output(line, [password, webhook])
    if any(secret.reveal() in result for secret in (password, webhook, cookie)):
        raise AssertionError("End-to-end diagnostic disclosed a test secret")
    assert "diagnostic <redacted> <redacted>" in result
    assert "Cookie: <redacted>" in result
    assert "X-CSRF-Token: <redacted>" in result
    assert "sha256=<redacted>" in result
    assert str(password) == "<redacted>"
    assert repr(password) == "Redacted(<redacted>)"


def test_failure_output_and_ci_annotation_remain_visible_and_redacted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    password = Redacted.random()
    environ = dict(os.environ, GITHUB_ACTIONS="true", SMOKE_TEST_SECRET=password.reveal())
    command = [
        sys.executable,
        "-c",
        "import os, sys; print('diagnostic ' + os.environ['SMOKE_TEST_SECRET']); sys.exit(7)",
    ]
    assert _stream(command, environ, [password]) == 7
    output = capsys.readouterr().out
    if password.reveal() in output:
        raise AssertionError("End-to-end failure output disclosed a test secret")
    assert "diagnostic <redacted>" in output
    assert "::error title=Compose smoke::" in output
