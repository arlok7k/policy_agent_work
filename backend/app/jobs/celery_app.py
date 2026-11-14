"""Create the JSON-only Celery producer shared with the PB2 worker."""

from celery import Celery
from kombu import Queue

from app.core.pb2_config import PB2Settings

NORMALIZE_ALERT_TASK = "app.jobs.normalize_alert"


def create_celery(settings: PB2Settings) -> Celery:
    celery = Celery("smart_soc", broker=settings.celery_broker_url.get_secret_value())
    celery.conf.update(
        task_default_queue="default",
        task_queues=(Queue("default"),),
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        task_ignore_result=True,
        task_publish_retry=False,
        broker_connection_retry=False,
        broker_connection_timeout=settings.redis_timeout_seconds,
        broker_transport_options={
            "socket_connect_timeout": settings.redis_timeout_seconds,
            "socket_timeout": settings.redis_timeout_seconds,
        },
    )
    return celery
