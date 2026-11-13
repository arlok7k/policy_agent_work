"""PostgreSQL engine and session lifecycle for the host application."""

from collections.abc import Iterator

from fastapi import Request
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings


def create_db_engine(settings: Settings) -> Engine:
    return create_engine(
        settings.database_url.get_secret_value(), pool_pre_ping=True, hide_parameters=True
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def get_db(request: Request) -> Iterator[Session]:
    """Yield one session; an uncommitted transaction is rolled back on close."""
    factory: sessionmaker[Session] = request.app.state.session_factory
    with factory() as session:
        yield session
