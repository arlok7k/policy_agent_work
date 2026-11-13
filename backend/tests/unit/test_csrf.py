"""CSRF comparison requires the submitted pair and the session-bound digest."""

import secrets

from pydantic import SecretStr

from app.auth.csrf import csrf_matches
from app.core.security import credential_digest
from tests.sensitive import Redacted, reveal


def test_csrf_requires_matching_cookie_header_and_stored_digest() -> None:
    key = SecretStr(secrets.token_urlsafe(48))
    legitimate = Redacted.random()
    forged = Redacted.random()
    stored = credential_digest(key, "csrf", legitimate.reveal())

    def matches(cookie: Redacted | str | None, header: Redacted | str | None) -> bool:
        return csrf_matches(key, stored, reveal(cookie), reveal(header))

    assert matches(legitimate, legitimate)
    assert not matches(None, legitimate)
    assert not matches(legitimate, None)
    assert not matches(legitimate, forged)
    assert not matches(forged, forged)
    assert not matches("\ud800", "\ud800")
