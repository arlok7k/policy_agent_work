"""Strict, stable and opaque keyset cursor encoding."""

from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.core.exceptions import BadRequest
from app.core.pagination import decode_cursor, encode_cursor


def test_cursor_round_trips_timestamp_and_uuid_with_microsecond_precision() -> None:
    identifier = uuid4()
    timestamp = datetime(2025, 1, 2, 3, 4, 5, 678901, tzinfo=timezone(timedelta(hours=3)))
    cursor = encode_cursor(timestamp, identifier)
    assert len(cursor) == 32
    decoded_time, decoded_id = decode_cursor(cursor)
    assert decoded_time == timestamp.astimezone(UTC)
    assert decoded_id == identifier


@pytest.mark.parametrize("cursor", ["", "A" * 31, "A" * 33, "!" * 32, "é" * 32])
def test_invalid_cursor_is_a_generic_bad_request(cursor: str) -> None:
    with pytest.raises(BadRequest):
        decode_cursor(cursor)


def test_naive_timestamp_cannot_be_encoded() -> None:
    with pytest.raises(ValueError):
        encode_cursor(datetime(2025, 1, 1), uuid4())
