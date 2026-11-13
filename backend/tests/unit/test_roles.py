"""The legacy role guard denies by default and does not trust client role claims."""

import secrets
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.auth.roles import require_roles
from app.auth.session import SessionIdentity


def identity(role: str) -> SessionIdentity:
    return SessionIdentity(
        session_id=uuid4(),
        user_id=uuid4(),
        username="example",
        role=role,
        reauth_at=None,
        csrf_digest=secrets.token_bytes(32),
    )


@pytest.mark.parametrize("role", ["analyst", "senior_analyst", "ADMIN", "unknown", ""])
def test_admin_guard_rejects_non_admin_roles(role: str) -> None:
    check = require_roles("admin")
    with pytest.raises(HTTPException) as error:
        check(identity(role))
    assert error.value.status_code == 403


def test_role_guard_returns_verified_identity_for_allowed_role() -> None:
    user = identity("senior_analyst")
    assert require_roles("senior_analyst", "admin")(user) is user


@pytest.mark.parametrize("roles", [(), ("",), (" admin",)])
def test_unconfigured_role_guard_is_rejected(roles: tuple[str, ...]) -> None:
    with pytest.raises(ValueError):
        require_roles(*roles)
