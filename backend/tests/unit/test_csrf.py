"""CSRF comparison requires the submitted pair and the session-bound digest."""

import secrets

from pydantic import SecretStr

from app.auth.csrf import csrf_matches
from app.core.security import credential_digest


def test_csrf_requires_matching_cookie_header_and_stored_digest() -> None:
    key = SecretStr(secrets.token_urlsafe(48))
    legitimate = secrets.token_urlsafe(32)
    forged = secrets.token_urlsafe(32)
    stored = credential_digest(key, "csrf", legitimate)
    assert csrf_matches(key, stored, legitimate, legitimate)
    assert not csrf_matches(key, stored, None, legitimate)
    assert not csrf_matches(key, stored, legitimate, None)
    assert not csrf_matches(key, stored, legitimate, forged)
    assert not csrf_matches(key, stored, forged, forged)
    assert not csrf_matches(key, stored, "\ud800", "\ud800")
