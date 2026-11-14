"""Atomic, database-clock-backed login failure buckets."""

from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address

from sqlalchemy import delete, func, literal, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.auth.models import LoginThrottle
from app.core.config import Settings
from app.core.security import credential_digest


def _lock_bucket(db: Session, value: bytes, settings: Settings) -> LoginThrottle:
    db.execute(
        insert(LoginThrottle)
        .values(bucket_digest=value)
        .on_conflict_do_nothing(index_elements=[LoginThrottle.bucket_digest])
    )
    bucket = db.execute(
        select(LoginThrottle).where(LoginThrottle.bucket_digest == value).with_for_update()
    ).scalar_one()
    now = db.execute(select(func.clock_timestamp())).scalar_one()
    if now >= bucket.window_started_at + timedelta(seconds=settings.login_window_seconds):
        bucket.window_started_at = now
        bucket.failure_count = 0
    return bucket


def acquire_buckets(
    db: Session, settings: Settings, username: str, ip: IPv4Address | IPv6Address
) -> list[LoginThrottle]:
    # Every caller locks the IP bucket before the account bucket. This gives a
    # consistent lock order without allocating new accounts for a blocked IP.
    source_digest = credential_digest(settings.session_signing_secret, "throttle-ip", str(ip))
    account_digest = credential_digest(
        settings.session_signing_secret, "throttle-account", username
    )
    source = _lock_bucket(db, source_digest, settings)
    if blocked([source], settings) or source_digest == account_digest:
        return [source]
    return [source, _lock_bucket(db, account_digest, settings)]


def blocked(buckets: list[LoginThrottle], settings: Settings) -> bool:
    return any(bucket.failure_count >= settings.login_failure_limit for bucket in buckets)


def record_failure(buckets: list[LoginThrottle]) -> None:
    for bucket in buckets:
        bucket.failure_count += 1


def cleanup_expired_buckets(db: Session, *, window_seconds: int, batch_size: int) -> int:
    """Delete one bounded batch, skipping rows held by concurrent logins."""
    if window_seconds <= 0 or batch_size <= 0:
        raise ValueError("Cleanup bounds must be positive")
    now = db.execute(select(func.clock_timestamp())).scalar_one()
    cutoff = now - timedelta(seconds=window_seconds)
    candidates = (
        select(LoginThrottle.bucket_digest)
        .where(LoginThrottle.window_started_at <= cutoff)
        .order_by(LoginThrottle.window_started_at, LoginThrottle.bucket_digest)
        .limit(batch_size)
        .with_for_update(skip_locked=True)
        .cte("expired_throttles")
    )
    statement = (
        delete(LoginThrottle)
        .where(LoginThrottle.bucket_digest == candidates.c.bucket_digest)
        .returning(literal(1))
    )
    return len(db.execute(statement).scalars().all())
