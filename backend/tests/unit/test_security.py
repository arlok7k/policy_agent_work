"""Password and credential digest primitives."""

import secrets

from pydantic import SecretStr

from app.core.security import PasswordService, credential_digest


def test_argon2id_password_verification_and_unknown_account() -> None:
    service = PasswordService()
    password = secrets.token_urlsafe(32)
    wrong = secrets.token_urlsafe(32)
    hashed = service.hash_password(password)
    assert hashed.startswith("$argon2id$")
    assert service.verify(password, hashed)
    assert not service.verify(wrong, hashed)
    assert not service.verify(password, None)
    assert not service.verify(password, "invalid-hash")


def test_credential_digests_are_keyed_and_domain_separated() -> None:
    key = SecretStr(secrets.token_urlsafe(48))
    other_key = SecretStr(secrets.token_urlsafe(48))
    value = secrets.token_urlsafe(32)
    first = credential_digest(key, "session", value)
    assert first == credential_digest(key, "session", value)
    assert first != credential_digest(key, "csrf", value)
    assert first != credential_digest(other_key, "session", value)
