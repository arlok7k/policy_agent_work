"""Create the JSON-only Celery app and require attribution for every task."""

import re
from collections.abc import Mapping
from typing import Any

from celery import Celery, Task
from celery.result import AsyncResult
from kombu import Queue

from app.core.pb2_config import PB2Settings
from app.core.pb3_config import PB3Settings, load_pb3_settings

NORMALIZE_ALERT_TASK = "app.jobs.normalize_alert"
CLEANUP_THROTTLE_TASK = "app.jobs.cleanup_login_throttles"
CLEANUP_SCHEDULE = "cleanup-expired-login-throttles"
EXECUTE_RESPONSE_TASK = "app.jobs.execute_response"
RECONCILE_RESPONSE_TASK = "app.jobs.reconcile_responses"
RECONCILE_RESPONSE_SCHEDULE = "reconcile-approved-responses"
RECONCILE_INITIATOR = "service:response-reconcile"
TTL_SWEEP_TASK = "app.jobs.rollback_expired_responses"
TTL_SWEEP_SCHEDULE = "rollback-expired-responses"
TTL_INITIATOR = "service:response-ttl"


def require_initiator(headers: object) -> str:
    """Reject absent or malformed attribution without echoing header contents."""
    if not isinstance(headers, Mapping):
        raise ValueError("A valid initiator header is required")
    value = headers.get("initiator")
    if (
        not isinstance(value, str)
        or re.fullmatch(r"(?:service|user):[A-Za-z0-9][A-Za-z0-9._:-]*", value, re.ASCII) is None
    ):
        raise ValueError("A valid initiator header is required")
    return value


class InitiatedTask(Task[..., Any]):
    """Enforce initiator headers for both eager publication and worker execution."""

    abstract = True

    def apply_async(self, *args: Any, **kwargs: Any) -> AsyncResult[Any]:
        require_initiator(kwargs.get("headers"))
        return super().apply_async(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        require_initiator(self.request.headers)
        return super().__call__(*args, **kwargs)


class InitiatedCelery(Celery):
    """Enforce initiator headers even when publishing a task by name."""

    def send_task(self, *args: Any, **kwargs: Any) -> AsyncResult[Any]:
        require_initiator(kwargs.get("headers"))
        kwargs.setdefault("argsrepr", "<redacted>")
        kwargs.setdefault("kwargsrepr", "<redacted>")
        return super().send_task(*args, **kwargs)


def create_celery(settings: PB2Settings, response: PB3Settings | None = None) -> Celery:
    from app.jobs.tasks import register_tasks

    response = response or load_pb3_settings()
    celery = InitiatedCelery(
        "smart_soc", broker=settings.celery_broker_url.get_secret_value(), task_cls=InitiatedTask
    )
    celery.conf.update(
        task_default_queue="default",
        task_queues=(Queue("default"),),
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        task_ignore_result=True,
        result_expires=None,
        beat_schedule={
            CLEANUP_SCHEDULE: {
                "task": CLEANUP_THROTTLE_TASK,
                "schedule": settings.throttle_cleanup_interval_seconds,
                "options": {
                    "queue": "default",
                    "headers": {"initiator": settings.throttle_cleanup_initiator},
                    "argsrepr": "<redacted>",
                    "kwargsrepr": "<redacted>",
                },
            },
            RECONCILE_RESPONSE_SCHEDULE: {
                "task": RECONCILE_RESPONSE_TASK,
                "schedule": response.response_sweep_interval_seconds,
                "options": {
                    "queue": "default",
                    "headers": {"initiator": RECONCILE_INITIATOR},
                    "argsrepr": "<redacted>",
                    "kwargsrepr": "<redacted>",
                },
            },
            TTL_SWEEP_SCHEDULE: {
                "task": TTL_SWEEP_TASK,
                "schedule": response.response_sweep_interval_seconds,
                "options": {
                    "queue": "default",
                    "headers": {"initiator": TTL_INITIATOR},
                    "argsrepr": "<redacted>",
                    "kwargsrepr": "<redacted>",
                },
            },
        },
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        task_publish_retry=False,
        broker_connection_retry=False,
        broker_connection_retry_on_startup=False,
        broker_connection_timeout=settings.redis_timeout_seconds,
        broker_transport_options={
            "socket_connect_timeout": settings.redis_timeout_seconds,
            "socket_timeout": settings.redis_timeout_seconds,
        },
    )
    register_tasks(celery, settings, response)
    return celery
