"""Registered Celery entry points for PB2 alert ingestion."""

from typing import Any

from celery import Celery

from app.alerts.normalize import normalize_alert, store_alert
from app.core.config import load_settings
from app.core.db import create_db_engine, create_session_factory, validate_runtime_database_access
from app.core.pb2_config import PB2Settings
from app.jobs.celery_app import NORMALIZE_ALERT_TASK


def register_tasks(celery: Celery, settings: PB2Settings) -> None:
    @celery.task(name=NORMALIZE_ALERT_TASK, shared=False)
    def normalize_alert_task(payload: dict[str, Any]) -> dict[str, object]:
        """Normalize and insert exactly once for a fingerprint."""
        alert = normalize_alert(payload, max_field_chars=settings.webhook_max_field_chars)
        base_settings = load_settings()
        engine = create_db_engine(base_settings)
        try:
            validate_runtime_database_access(engine)
            sessions = create_session_factory(engine)
            with sessions.begin() as db:
                identifier, created = store_alert(db, alert)
            return {"id": str(identifier), "created": created}
        finally:
            engine.dispose()
