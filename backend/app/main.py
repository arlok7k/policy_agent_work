"""FastAPI application entry point for the host baseline."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.auth.csrf import csrf_guard
from app.auth.key_router import router as key_router
from app.auth.legacy_policy import load_legacy_policy
from app.auth.router import router as auth_router
from app.core.config import ConfigurationError, load_settings
from app.core.db import (
    RuntimeDatabaseError,
    create_db_engine,
    create_session_factory,
    validate_runtime_database_access,
)
from app.core.errors import install_error_handling
from app.core.health import router as health_router
from app.core.security import PasswordService
from app.users.router import router as users_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        app.state.settings = load_settings()
    except ConfigurationError:
        raise RuntimeError("Application configuration is invalid") from None
    app.state.legacy_policy = load_legacy_policy()
    engine = create_db_engine(app.state.settings)
    try:
        validate_runtime_database_access(engine)
    except RuntimeDatabaseError:
        engine.dispose()
        raise RuntimeError("Runtime database access is unsafe or unavailable") from None
    app.state.session_factory = create_session_factory(engine)
    app.state.passwords = PasswordService()
    try:
        yield
    finally:
        engine.dispose()


app = FastAPI(title="SMART SOC host baseline", lifespan=lifespan)
app.middleware("http")(csrf_guard)
install_error_handling(app)
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(key_router)
app.include_router(users_router)
