"""Every scheduled maintenance task carries an attributed service initiator."""

import pytest
from celery.beat import Scheduler

from app.core.pb2_config import load_pb2_settings
from app.jobs.celery_app import CLEANUP_SCHEDULE, CLEANUP_THROTTLE_TASK, create_celery


def test_beat_schedule_is_bounded_configured_and_attributed() -> None:
    settings = load_pb2_settings()
    celery = create_celery(settings)
    try:
        scheduler = Scheduler(app=celery)
        assert set(scheduler.schedule) == {CLEANUP_SCHEDULE}
        entry = scheduler.schedule[CLEANUP_SCHEDULE]
        assert entry.task == CLEANUP_THROTTLE_TASK
        assert entry.options["headers"]["initiator"] == settings.throttle_cleanup_initiator
        assert entry.options["queue"] == "default"
        assert (
            entry.schedule.run_every.total_seconds() == settings.throttle_cleanup_interval_seconds
        )
        task = celery.tasks[CLEANUP_THROTTLE_TASK]
        with pytest.raises(ValueError, match="valid initiator"):
            celery.send_task(CLEANUP_THROTTLE_TASK)
        with pytest.raises(ValueError, match="valid initiator"):
            task.apply_async()
        with pytest.raises(ValueError, match="valid initiator"):
            task.apply(throw=True)
    finally:
        celery.close()
