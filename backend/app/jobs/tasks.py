"""Registered Celery entry points for alert ingestion and throttle maintenance."""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import Any
from uuid import UUID

from celery import Celery
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.alerts.normalize import normalize_alert, store_alert
from app.auth.legacy_policy import load_legacy_policy
from app.auth.throttle import cleanup_expired_buckets
from app.core.config import Settings, load_settings
from app.core.db import create_db_engine, create_session_factory, validate_runtime_database_access
from app.core.pb2_config import PB2Settings
from app.core.pb3_config import PB3Settings
from app.jobs.celery_app import (
    CLEANUP_THROTTLE_TASK,
    EXECUTE_RESPONSE_TASK,
    MANUAL_ROLLBACK_TASK,
    NORMALIZE_ALERT_TASK,
    RECONCILE_RESPONSE_TASK,
    TTL_SWEEP_TASK,
)
from app.response.execution import approved_for_reconciliation, execute_approved
from app.response.manual_rollback import pending_manual_rollbacks, perform_manual_rollback
from app.response.ttl import due_for_rollback, rollback_expired


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


def register_tasks(celery: Celery, settings: PB2Settings, response: PB3Settings) -> None:
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

    @celery.task(name=EXECUTE_RESPONSE_TASK, shared=False)
    def execute_response_task(action_id: str) -> dict[str, str]:
        """Re-read all facts in a worker; the message header is not authorization."""
        identifier = UUID(action_id)
        policy = load_legacy_policy()
        with task_database() as (db, _):
            result = execute_approved(db, identifier, policy, response)
        return {"result": result}

    @celery.task(name=MANUAL_ROLLBACK_TASK, shared=False)
    def manual_rollback_response_task(
        action_id: str, actor_id: str, requested_at: str
    ) -> dict[str, str]:
        """Execute only the still-current, revalidated human rollback intent."""
        action, actor, at = UUID(action_id), UUID(actor_id), datetime.fromisoformat(requested_at)
        with task_database() as (db, _):
            result = perform_manual_rollback(db, action, actor, at, load_legacy_policy())
        return {"result": result}

    @celery.task(name=RECONCILE_RESPONSE_TASK, shared=False)
    def reconcile_response_task() -> dict[str, int]:
        """Recover approved work after loss, pausing automation without starving humans."""
        policy = load_legacy_policy()
        with task_database() as (db, _):
            identifiers = approved_for_reconciliation(db, response.response_sweep_batch_size)
            rollbacks = pending_manual_rollbacks(db, response.response_sweep_batch_size)
        counts = {
            "executed": 0,
            "paused": 0,
            "failed": 0,
            "noop": 0,
            "errors": 0,
            "manual_rolled_back": 0,
            "manual_refused": 0,
            "manual_noop": 0,
        }
        for identifier in identifiers:
            try:
                with task_database() as (db, _):
                    result = execute_approved(db, identifier, policy, response)
                counts[result] += 1
            except SQLAlchemyError:
                # Keep other actions moving; a later bounded sweep retries this row.
                counts["errors"] += 1
        for identifier, actor, at in rollbacks:
            try:
                with task_database() as (db, _):
                    manual_result = perform_manual_rollback(db, identifier, actor, at, policy)
                counts[f"manual_{manual_result}"] += 1
            except SQLAlchemyError:
                counts["errors"] += 1
        return counts

    @celery.task(name=TTL_SWEEP_TASK, shared=False)
    def rollback_expired_responses_task() -> dict[str, int]:
        """Retry overdue L2 rollbacks in bounded, independent transactions."""
        with task_database() as (db, _):
            identifiers = due_for_rollback(db, response.response_sweep_batch_size)
        counts = {"rolled_back": 0, "paused": 0, "refused": 0, "noop": 0, "errors": 0}
        for identifier in identifiers:
            try:
                with task_database() as (db, _):
                    result = rollback_expired(db, identifier)
                counts[result] += 1
            except SQLAlchemyError:
                counts["errors"] += 1
        return counts
