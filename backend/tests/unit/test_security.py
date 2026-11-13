"""Password and credential digest primitives."""

import hmac
import secrets

from pydantic import SecretStr

from app.core.security import PasswordService, credential_digest
from tests.sensitive import Redacted


def test_argon2id_password_verification_and_unknown_account() -> None:
    service = PasswordService()
    password = Redacted.random()
    wrong = Redacted.random()
    hashed = Redacted(service.hash_password(password.reveal()))
    is_argon2id = hashed.reveal().startswith("$argon2id$")
    assert is_argon2id
    valid = service.verify(password.reveal(), hashed.reveal())
    assert valid
    wrong_accepted = service.verify(wrong.reveal(), hashed.reveal())
    assert not wrong_accepted
    unknown_accepted = service.verify(password.reveal(), None)
    assert not unknown_accepted
    invalid_hash_accepted = service.verify(password.reveal(), "invalid-hash")
    assert not invalid_hash_accepted


def test_credential_digests_are_keyed_and_domain_separated() -> None:
    key = SecretStr(secrets.token_urlsafe(48))
    other_key = SecretStr(secrets.token_urlsafe(48))
    value = Redacted.random()
    first = credential_digest(key, "session", value.reveal())
    same = credential_digest(key, "session", value.reveal())
    other_purpose = credential_digest(key, "csrf", value.reveal())
    other_digest = credential_digest(other_key, "session", value.reveal())
    same_matches = hmac.compare_digest(first, same)
    purpose_matches = hmac.compare_digest(first, other_purpose)
    key_matches = hmac.compare_digest(first, other_digest)
    assert same_matches
    assert not purpose_matches
    assert not key_matches
