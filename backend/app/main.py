"""FastAPI application entry point for the host baseline."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import ConfigurationError, load_settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    try:
        app.state.settings = load_settings()
    except ConfigurationError:
        raise RuntimeError("Application configuration is invalid") from None
    yield


app = FastAPI(title="SMART SOC host baseline", lifespan=lifespan)
