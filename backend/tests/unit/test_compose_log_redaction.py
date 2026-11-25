"""Failure diagnostics remain useful without disclosing throwaway secrets."""

from pathlib import Path

import pytest
from scripts.redact_compose_logs import redact

from tests.sensitive import Redacted, assert_not_disclosed


def test_log_redaction_masks_secret_files_and_embedded_url_passwords(tmp_path: Path) -> None:
    credential = Redacted.random()
    hmac_key = Redacted.random(48)
    database_url = Redacted(f"postgresql://runtime:{credential.reveal()}@db/soc")
    (tmp_path / "runtime_database_url").write_text(database_url.reveal())
    (tmp_path / "webhook_secret").write_text(hmac_key.reveal())
    raw = (
        f"database error for {database_url.reveal()} with {credential.reveal()}\n"
        f"key {hmac_key.reveal()}"
    )
    sanitized = redact(raw, tmp_path)
    assert_not_disclosed(
        "Redacted Compose diagnostics", sanitized, credential, hmac_key, database_url
    )
    assert "database error for <redacted> with <redacted>" in sanitized
    assert "key <redacted>" in sanitized


def test_log_redaction_fails_closed_without_secrets(tmp_path: Path) -> None:
    empty = tmp_path / "empty-secrets"
    empty.mkdir()
    with pytest.raises(ValueError):
        redact("diagnostic", empty)
    with pytest.raises(ValueError):
        redact("diagnostic", tmp_path / "missing")
