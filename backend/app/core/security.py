"""Password verification and domain-separated digests for opaque credentials."""

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from pydantic import SecretStr


class PasswordService:
    """Use Argon2id, including a dummy verification for unknown accounts."""

    def __init__(self) -> None:
        self._hasher = PasswordHasher(type=Type.ID)
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(hashlib.sha256().digest_size))

    def hash_password(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password: str, stored_hash: str | None) -> bool:
        target = stored_hash if stored_hash is not None else self._dummy_hash
        try:
            verified = self._hasher.verify(target, password)
        except VerifyMismatchError:
            return False
        except InvalidHashError, VerificationError:
            # A corrupt stored hash must neither authenticate nor skip the costly path.
            try:
                self._hasher.verify(self._dummy_hash, password)
            except InvalidHashError, VerificationError:
                return False
            return False
        return bool(verified and stored_hash is not None)


def credential_digest(secret: SecretStr, purpose: str, value: str) -> bytes:
    key = secret.get_secret_value().encode("utf-8")
    message = purpose.encode("utf-8") + b"\0" + value.encode("utf-8")
    return hmac.digest(key, message, "sha256")


def new_opaque_token() -> str:
    return secrets.token_urlsafe(hashlib.sha256().digest_size)
