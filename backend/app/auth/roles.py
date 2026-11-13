"""Legacy role guard; governed operations will wrap rather than replace it."""

from collections.abc import Callable, Mapping
from typing import Annotated

from fastapi import Depends, Request

from app.auth.dependencies import current_user
from app.auth.session import SessionIdentity
from app.core.exceptions import Forbidden, Unavailable


def require_roles(*allowed_roles: str) -> Callable[[SessionIdentity], SessionIdentity]:
    """Require one explicitly declared role of a currently active cookie user."""
    allowed = frozenset(allowed_roles)
    if not allowed or any(not role or role != role.strip() for role in allowed):
        raise ValueError("At least one nonempty role is required")

    def check(identity: Annotated[SessionIdentity, Depends(current_user)]) -> SessionIdentity:
        if identity.role not in allowed:
            raise Forbidden()
        return identity

    return check


def operation_roles(request: Request, operation: str) -> tuple[str, ...]:
    rules: Mapping[str, tuple[str, ...]] = request.app.state.legacy_policy
    roles = rules.get(operation)
    if not roles:
        raise Unavailable()
    return roles


def require_operation(operation: str) -> Callable[[Request, SessionIdentity], SessionIdentity]:
    """Bind a route to the configured legacy operation rather than an inline role."""
    if not operation:
        raise ValueError("An operation is required")

    def check(
        request: Request, identity: Annotated[SessionIdentity, Depends(current_user)]
    ) -> SessionIdentity:
        return require_roles(*operation_roles(request, operation))(identity)

    return check
