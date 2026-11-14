"""Deterministic, data-only normalization and task attribution."""

import pytest

from app.alerts.normalize import normalize_alert
from app.core.exceptions import BadRequest
from app.core.pb2_config import load_pb2_settings
from app.jobs.celery_app import NORMALIZE_ALERT_TASK, create_celery


def test_equivalent_alerts_have_one_fingerprint_and_preserve_plain_data() -> None:
    first = {
        "source": " sensor ",
        "rule_id": " rule-42 ",
        "severity": " HIGH ",
        "src_ip": "2001:0db8:0:0:0:0:0:1",
        "raw": {"message": "<script>alert('text')</script>; DROP TABLE alerts", "x": 1},
    }
    second = {
        "severity": "high",
        "rule_id": "rule-42",
        "source": "sensor",
        "src_ip": "2001:db8::1",
        "raw": {"x": 1, "message": "<script>alert('text')</script>; DROP TABLE alerts"},
    }
    a = normalize_alert(first, max_field_chars=128)
    b = normalize_alert(second, max_field_chars=128)
    assert a.fingerprint == b.fingerprint
    assert a.src_ip == "2001:db8::1"
    assert a.severity == "high" and a.agent is None and a.dst_ip is None
    assert a.raw["message"] == "<script>alert('text')</script>; DROP TABLE alerts"
    altered = normalize_alert({**second, "raw": {"x": 2}}, max_field_chars=128)
    assert altered.fingerprint != a.fingerprint


@pytest.mark.parametrize(
    "payload",
    [
        {"source": "\ud800", "rule_id": "r", "severity": "high"},
        {"source": "test", "rule_id": "r", "severity": "high", "raw": {"n": float("inf")}},
        {"source": "test", "rule_id": "r", "severity": "high", "raw": {"n": {1, 2}}},
    ],
)
def test_task_payloads_are_revalidated(payload: dict[str, object]) -> None:
    with pytest.raises(BadRequest):
        normalize_alert(payload, max_field_chars=128)


def test_task_producers_and_direct_execution_require_an_initiator() -> None:
    celery = create_celery(load_pb2_settings())
    try:
        task = celery.tasks[NORMALIZE_ALERT_TASK]
        with pytest.raises(ValueError, match="valid initiator"):
            celery.send_task(NORMALIZE_ALERT_TASK, args=[{}])
        with pytest.raises(ValueError, match="valid initiator"):
            task.apply_async(args=[{}])
        with pytest.raises(ValueError, match="valid initiator"):
            task.apply(args=[{}], throw=True)
        with pytest.raises(ValueError, match="valid initiator"):
            celery.send_task(NORMALIZE_ALERT_TASK, args=[{}], headers={"initiator": "anonymous"})
    finally:
        celery.close()
