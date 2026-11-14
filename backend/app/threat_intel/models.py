"""Persistent, expiring IOC cache mapping."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base


class IocCache(Base):
    __tablename__ = "ioc_cache"

    indicator: Mapped[str] = mapped_column(Text, primary_key=True)
    verdict: Mapped[str] = mapped_column(Text)
    score: Mapped[int | None] = mapped_column(Integer)
    sources: Mapped[list[str]] = mapped_column(JSONB)
    is_mock: Mapped[bool] = mapped_column(Boolean)
    cached_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
