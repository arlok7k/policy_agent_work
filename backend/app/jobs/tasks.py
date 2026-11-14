"""Registered Celery entry points for alert ingestion and throttle maintenance."""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from celery import Celery
from sqlalchemy.orm import Session

from app.alerts.normalize import normalize_alert, store_alert
from app.auth.throttle import cleanup_expired_buckets
from app.core.config import Settings, load_settings
from app.core.db import create_db_engine, create_session_factory, validate_runtime_database_access
from app.core.pb2_config import PB2Settings
from app.jobs.celery_app import CLEANUP_THROTTLE_TASK, NORMALIZE_ALERT_TASK


@contextmanager
def task_database() -> Iterator[tuple[Session, Settings]]:
    """Use the restricted runtime identity and one transaction for a task."""
    settings = load_settings()
    engine = create_db_engine(settings)
    try:
        validate_runtime_database_access(engine)
        sessions = create_session_factory(engine)
        with sessions.begin() as db:
            yield db, settings
    finally:
        engine.dispose()


def register_tasks(celery: Celery, settings: PB2Settings) -> None:
    @celery.task(name=NORMALIZE_ALERT_TASK, shared=False)
    def normalize_alert_task(payload: dict[str, Any]) -> dict[str, object]:
        """Normalize and insert exactly once for a fingerprint."""
        alert = normalize_alert(payload, max_field_chars=settings.webhook_max_field_chars)
        with task_database() as (db, _):
            identifier, created = store_alert(db, alert)
        return {"id": str(identifier), "created": created}

    @celery.task(name=CLEANUP_THROTTLE_TASK, shared=False)
    def cleanup_throttles_task() -> dict[str, int]:
        """Delete at most one configured batch of safely expired buckets."""
        with task_database() as (db, base_settings):
            deleted = cleanup_expired_buckets(
                db,
                window_seconds=base_settings.login_window_seconds,
                batch_size=settings.throttle_cleanup_batch_size,
            )
        return {"deleted": deleted}
