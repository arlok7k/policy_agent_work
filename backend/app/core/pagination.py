"""Opaque, stable timestamp/UUID keyset cursors for host list APIs."""

import base64
import binascii
import struct
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.core.exceptions import BadRequest

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def encode_cursor(created_at: datetime, identifier: UUID) -> str:
    if created_at.tzinfo is None:
        raise ValueError("Cursor timestamps must be timezone-aware")
    delta = created_at.astimezone(UTC) - _EPOCH
    microseconds = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    data = struct.pack(">q", microseconds) + identifier.bytes
    return base64.urlsafe_b64encode(data).decode("ascii")


def decode_cursor(cursor: str) -> tuple[datetime, UUID]:
    try:
        if len(cursor) != 32:
            raise ValueError("invalid cursor size")
        data = base64.b64decode(cursor.encode("ascii"), altchars=b"-_", validate=True)
        if len(data) != 24 or base64.urlsafe_b64encode(data).decode("ascii") != cursor:
            raise ValueError("invalid cursor")
        micros = struct.unpack(">q", data[:8])[0]
        return _EPOCH + timedelta(microseconds=micros), UUID(bytes=data[8:])
    except ValueError, UnicodeError, OverflowError, binascii.Error, struct.error:
        raise BadRequest() from None
