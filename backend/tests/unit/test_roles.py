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


def test_legacy_policy_is_immutable_and_contains_specified_admin_rules() -> None:
    from app.auth.legacy_policy import load_legacy_policy

    policy = load_legacy_policy()
    assert policy["users"] == ("admin",)
    assert policy["api_keys"] == ("admin",)
    with pytest.raises(TypeError):
        policy["users"] = ("analyst",)  # type: ignore[index]


@pytest.mark.parametrize(
    "content",
    [
        "{}",
        '{"users": [], "api_keys": ["admin"]}',
        '{"users": ["admin"], "users": ["analyst"], "api_keys": ["admin"]}',
    ],
)
def test_invalid_legacy_policy_fails_closed(tmp_path: object, content: str) -> None:
    from pathlib import Path

    from app.auth.legacy_policy import load_legacy_policy

    assert isinstance(tmp_path, Path)
    path = tmp_path / "roles.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid"):
        load_legacy_policy(path)
