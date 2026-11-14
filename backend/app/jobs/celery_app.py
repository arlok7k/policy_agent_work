"""Create the JSON-only Celery app and require attribution for every task."""

import re
from collections.abc import Mapping
from typing import Any

from celery import Celery, Task
from celery.result import AsyncResult
from kombu import Queue

from app.core.pb2_config import PB2Settings

NORMALIZE_ALERT_TASK = "app.jobs.normalize_alert"


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


def create_celery(settings: PB2Settings) -> Celery:
    from app.jobs.tasks import register_tasks

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
    register_tasks(celery, settings)
    return celery
