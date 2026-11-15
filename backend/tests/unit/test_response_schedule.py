"""PB3 schedules are bounded, attributed and configured without secrets."""

import pytest
from celery.beat import Scheduler

from app.core.config import ConfigurationError
from app.core.pb2_config import load_pb2_settings
from app.core.pb3_config import load_pb3_settings
from app.jobs.celery_app import (
    EXECUTE_RESPONSE_TASK,
    RECONCILE_INITIATOR,
    RECONCILE_RESPONSE_SCHEDULE,
    RECONCILE_RESPONSE_TASK,
    TTL_INITIATOR,
    TTL_SWEEP_SCHEDULE,
    TTL_SWEEP_TASK,
    create_celery,
)


def test_response_defaults_bounds_and_custom_configuration() -> None:
    defaults = load_pb3_settings({})
    assert defaults.response_sweep_interval_seconds == 5
    assert defaults.response_sweep_batch_size == 100
    assert defaults.l2_ttl_default_seconds == 3600
    assert defaults.l2_ttl_max_seconds == 86400
    custom = load_pb3_settings(
        {"RESPONSE_SWEEP_INTERVAL_SECONDS": "9", "RESPONSE_SWEEP_BATCH_SIZE": "7"}
    )
    assert (custom.response_sweep_interval_seconds, custom.response_sweep_batch_size) == (9, 7)
    shorter = load_pb3_settings(
        {"RESPONSE_L2_TTL_DEFAULT_SECONDS": "30", "RESPONSE_L2_TTL_MAX_SECONDS": "60"}
    )
    assert (shorter.l2_ttl_default_seconds, shorter.l2_ttl_max_seconds) == (30, 60)
    for config in (
        {"RESPONSE_L2_TTL_MAX_SECONDS": "86401"},
        {"RESPONSE_L2_TTL_MAX_SECONDS": "0"},
        {"RESPONSE_L2_TTL_DEFAULT_SECONDS": "0"},
        {"RESPONSE_L2_TTL_DEFAULT_SECONDS": "61", "RESPONSE_L2_TTL_MAX_SECONDS": "60"},
        {"RESPONSE_SWEEP_INTERVAL_SECONDS": "0"},
        {"RESPONSE_SWEEP_INTERVAL_SECONDS": "3601"},
        {"RESPONSE_SWEEP_BATCH_SIZE": "1001"},
        {"RESPONSE_SWEEP_BATCH_SIZE": "not-a-number"},
    ):
        with pytest.raises(ConfigurationError):
            load_pb3_settings(config)


def test_response_beat_and_direct_tasks_require_attribution() -> None:
    response = load_pb3_settings(
        {"RESPONSE_SWEEP_INTERVAL_SECONDS": "9", "RESPONSE_SWEEP_BATCH_SIZE": "7"}
    )
    celery = create_celery(load_pb2_settings(), response)
    try:
        schedule = Scheduler(app=celery).schedule[RECONCILE_RESPONSE_SCHEDULE]
        assert schedule.task == RECONCILE_RESPONSE_TASK
        assert schedule.schedule.run_every.total_seconds() == 9
        assert schedule.options["headers"]["initiator"] == RECONCILE_INITIATOR
        assert schedule.options["queue"] == "default"
        ttl = Scheduler(app=celery).schedule[TTL_SWEEP_SCHEDULE]
        assert ttl.task == TTL_SWEEP_TASK
        assert ttl.schedule.run_every.total_seconds() == 9
        assert ttl.options["headers"]["initiator"] == TTL_INITIATOR
        assert ttl.options["queue"] == "default"
        with pytest.raises(ValueError, match="valid initiator"):
            celery.send_task(EXECUTE_RESPONSE_TASK, args=["missing-header"])
        with pytest.raises(ValueError, match="valid initiator"):
            celery.tasks[RECONCILE_RESPONSE_TASK].apply(throw=True)
    finally:
        celery.close()
