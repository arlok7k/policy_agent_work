"""Atomic, database-clock-backed login failure buckets."""

from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.auth.models import LoginThrottle
from app.core.config import Settings
from app.core.security import credential_digest


def acquire_buckets(
    db: Session, settings: Settings, username: str, ip: IPv4Address | IPv6Address
) -> list[LoginThrottle]:
    values = {
        credential_digest(settings.session_signing_secret, "throttle-account", username),
        credential_digest(settings.session_signing_secret, "throttle-ip", str(ip)),
    }
    buckets = []
    for value in sorted(values):
        db.execute(
            insert(LoginThrottle)
            .values(bucket_digest=value)
            .on_conflict_do_nothing(index_elements=[LoginThrottle.bucket_digest])
        )
        bucket = db.execute(
            select(LoginThrottle).where(LoginThrottle.bucket_digest == value).with_for_update()
        ).scalar_one()
        buckets.append(bucket)
    now = db.execute(select(func.clock_timestamp())).scalar_one()
    for bucket in buckets:
        if now >= bucket.window_started_at + timedelta(seconds=settings.login_window_seconds):
            bucket.window_started_at = now
            bucket.failure_count = 0
    return buckets


def blocked(buckets: list[LoginThrottle], settings: Settings) -> bool:
    return any(bucket.failure_count >= settings.login_failure_limit for bucket in buckets)


def record_failure(buckets: list[LoginThrottle]) -> None:
    for bucket in buckets:
        bucket.failure_count += 1
