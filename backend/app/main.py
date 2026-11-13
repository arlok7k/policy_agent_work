"""FastAPI application entry point for the host baseline."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import ConfigurationError, load_settings
from app.core.db import create_db_engine, create_session_factory


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        app.state.settings = load_settings()
    except ConfigurationError:
        raise RuntimeError("Application configuration is invalid") from None
    engine = create_db_engine(app.state.settings)
    app.state.session_factory = create_session_factory(engine)
    try:
        yield
    finally:
        engine.dispose()


app = FastAPI(title="SMART SOC host baseline", lifespan=lifespan)
