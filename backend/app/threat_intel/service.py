"""Mock threat-intelligence checks with an authoritative PostgreSQL cache."""

import asyncio
import math
from datetime import timedelta

from pydantic import ValidationError
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.exceptions import Unavailable
from app.core.pb2_config import PB2Settings
from app.threat_intel.models import IocCache
from app.threat_intel.providers import (
    IPAddress,
    NotConfigured,
    ProviderVerdict,
    ThreatIntelProvider,
)
from app.threat_intel.schemas import CacheStats, IntelResult


def _redis_get(cache: Redis, key: str) -> bytes | None:
    try:
        result = cache.get(key)
        return result if isinstance(result, bytes) else None
    except RedisError:
        raise Unavailable() from None


def _redis_set(cache: Redis, key: str, value: bytes, ttl: int) -> None:
    try:
        cache.set(key, value, ex=ttl)
    except RedisError:
        raise Unavailable() from None


def _from_row(row: IocCache) -> IntelResult:
    try:
        result = IntelResult.model_validate(
            {
                "indicator": row.indicator,
                "verdict": row.verdict,
                "score": row.score,
                "sources": row.sources,
                "mock": row.is_mock,
                "degraded": False,
                "expires_at": row.expires_at,
            }
        )
        if not result.mock or result.sources != ["mock"]:
            raise ValueError("invalid cache provenance")
        return result
    except ValueError, ValidationError:
        raise Unavailable() from None


async def _run_provider(
    provider: ThreatIntelProvider, indicator: IPAddress, timeout: float
) -> ProviderVerdict:
    return await asyncio.wait_for(provider.check_ip(indicator), timeout=timeout)


def check_indicator(
    db: Session,
    cache: Redis,
    provider: ThreatIntelProvider,
    settings: PB2Settings,
    indicator: IPAddress,
) -> IntelResult:
    """Check one IP; the caller commits or rolls back the cache transaction."""
    if not provider.is_mock:
        raise Unavailable()
    canonical = str(indicator)
    key = f"threat-intel:ip:{canonical}"
    cached_copy = _redis_get(cache, key)
    now = db.execute(select(func.clock_timestamp())).scalar_one()
    row = db.get(IocCache, canonical)
    if row is not None and row.expires_at > now:
        result = _from_row(row)
        encoded = result.model_dump_json().encode("utf-8")
        if cached_copy != encoded:
            remaining = max(1, math.ceil((row.expires_at - now).total_seconds()))
            _redis_set(cache, key, encoded, remaining)
        return result
    try:
        verdict = asyncio.run(
            _run_provider(provider, indicator, settings.threat_intel_timeout_seconds)
        )
    except TimeoutError:
        return IntelResult(
            indicator=indicator,
            verdict="unknown",
            score=None,
            sources=[],
            mock=True,
            degraded=True,
            expires_at=None,
        )
    except NotConfigured:
        raise Unavailable() from None
    if not verdict.mock or verdict.sources != ("mock",):
        raise Unavailable()
    now = db.execute(select(func.clock_timestamp())).scalar_one()
    expires = now + timedelta(seconds=settings.threat_intel_cache_ttl_seconds)
    try:
        result = IntelResult(
            indicator=indicator,
            verdict=verdict.verdict,
            score=verdict.score,
            sources=list(verdict.sources),
            mock=True,
            degraded=False,
            expires_at=expires,
        )
    except ValidationError:
        raise Unavailable() from None
    values = {
        "indicator": canonical,
        "verdict": result.verdict,
        "score": result.score,
        "sources": result.sources,
        "is_mock": result.mock,
        "cached_at": now,
        "expires_at": expires,
    }
    statement = insert(IocCache).values(**values)
    db.execute(
        statement.on_conflict_do_update(
            index_elements=[IocCache.indicator],
            set_={key: value for key, value in values.items() if key != "indicator"},
        )
    )
    _redis_set(
        cache,
        key,
        result.model_dump_json().encode("utf-8"),
        settings.threat_intel_cache_ttl_seconds,
    )
    return result


def cache_stats(db: Session, cache: Redis) -> CacheStats:
    try:
        if not cache.ping():
            raise Unavailable()
    except RedisError:
        raise Unavailable() from None
    now = func.clock_timestamp()
    fresh, expired = db.execute(
        select(
            func.count().filter(IocCache.expires_at > now),
            func.count().filter(IocCache.expires_at <= now),
        )
    ).one()
    return CacheStats(fresh=fresh, expired=expired, redis_available=True)
