"""Host incident, alert-association and evidence mappings."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Text, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[UUID] = mapped_column(
        Uuid, primary_key=True, server_default=text("gen_random_uuid()")
    )
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default=text("'open'"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    incident_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("incidents.id", ondelete="RESTRICT"), primary_key=True
    )
    alert_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("alerts.id", ondelete="RESTRICT"), primary_key=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[UUID] = mapped_column(
        Uuid, primary_key=True, server_default=text("gen_random_uuid()")
    )
    incident_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("incidents.id", ondelete="RESTRICT"))
    alert_id: Mapped[UUID | None] = mapped_column(Uuid)
    kind: Mapped[str] = mapped_column(Text)
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
