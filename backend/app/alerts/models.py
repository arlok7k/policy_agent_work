"""Host alert persistence mapping."""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, LargeBinary, Text, Uuid, text
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[UUID] = mapped_column(
        Uuid, primary_key=True, server_default=text("gen_random_uuid()")
    )
    source: Mapped[str] = mapped_column(Text)
    rule_id: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text)
    agent: Mapped[str | None] = mapped_column(Text)
    src_ip: Mapped[str | IPv4Address | IPv6Address | None] = mapped_column(INET)
    dst_ip: Mapped[str | IPv4Address | IPv6Address | None] = mapped_column(INET)
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(Text, server_default=text("'open'"))
    fingerprint: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
