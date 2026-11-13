"""FastAPI application entry point for the host baseline."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import ConfigurationError, load_settings
from app.core.db import (
    RuntimeDatabaseError,
    create_db_engine,
    create_session_factory,
    validate_runtime_database_access,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        app.state.settings = load_settings()
    except ConfigurationError:
        raise RuntimeError("Application configuration is invalid") from None
    engine = create_db_engine(app.state.settings)
    try:
        validate_runtime_database_access(engine)
    except RuntimeDatabaseError:
        engine.dispose()
        raise RuntimeError("Runtime database access is unsafe or unavailable") from None
    app.state.session_factory = create_session_factory(engine)
    try:
        yield
    finally:
        engine.dispose()


app = FastAPI(title="SMART SOC host baseline", lifespan=lifespan)
