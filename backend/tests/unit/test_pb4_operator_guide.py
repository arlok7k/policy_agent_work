"""Run the operator guide's webhook example against the real verifier contract."""

from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from urllib.request import Request

import pytest
from pydantic import SecretStr

from app.alerts.validation import validate_alert
from app.alerts.webhook import verify_webhook_signature
from app.core.config import _read_secret
from tests.sensitive import Redacted


@pytest.mark.parametrize("ending", ["", "\n", "\r\n", "\n\n"])
def test_documented_webhook_example_signs_the_exact_request(
    ending: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Execute the published snippet without networking, including file newline handling."""
    secret = Redacted.random(48)
    secret_file = tmp_path / "webhook"
    secret_file.write_bytes((secret.reveal() + ending).encode("utf-8"))
    monkeypatch.setenv("SOC_WEBHOOK_SECRET_FILE", str(secret_file))
    captured: list[Request] = []

    def capture(request: Request, timeout: int) -> nullcontext[SimpleNamespace]:
        assert timeout == 10
        captured.append(request)
        return nullcontext(SimpleNamespace(status=202))

    monkeypatch.setattr("urllib.request.urlopen", capture)
    guide = Path("docs/governance/HPB_README.md").read_text(encoding="utf-8")
    _, marker, remainder = guide.partition("python3 - <<'PY'\n")
    assert marker
    example, marker, _ = remainder.partition("\nPY\n")
    assert marker
    # The snippet is checked-in documentation; the URL opener is intercepted.
    exec(compile(example, "HPB_README webhook example", "exec"), {})  # noqa: S102
    assert capsys.readouterr().out == "Webhook HTTP status: 202\n"
    assert len(captured) == 1
    request = captured[0]
    assert request.full_url == "http://127.0.0.1:8080/api/alerts/webhook"
    assert request.method == "POST"
    assert request.data is not None
    headers = {name.lower(): value for name, value in request.header_items()}
    key = _read_secret("WEBHOOK_SECRET", {"WEBHOOK_SECRET_FILE": str(secret_file)})
    verify_webhook_signature(
        SecretStr(key),
        headers["x-webhook-timestamp"],
        headers["x-webhook-id"],
        headers["x-webhook-signature"],
        request.data,
        skew=300,
    )
    payload = validate_alert(request.data, max_field_chars=512)
    assert (payload.source, payload.rule_id, payload.severity) == (
        "local-demo",
        "sample-rule",
        "high",
    )
