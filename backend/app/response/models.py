"""Response persistence mappings; schema changes remain explicit migrations."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Identity,
    Integer,
    LargeBinary,
    SmallInteger,
    Text,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[UUID] = mapped_column(
        Uuid, primary_key=True, server_default=text("gen_random_uuid()")
    )
    incident_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("incidents.id", ondelete="RESTRICT"))
    action_type: Mapped[str] = mapped_column(Text)
    target: Mapped[dict[str, Any]] = mapped_column(JSONB)
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, server_default=text("'{}'::jsonb"))
    level: Mapped[int] = mapped_column(SmallInteger)
    approval_mode: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default=text("'requested'"))
    requested_by: Mapped[UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
    decided_by: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT")
    )
    idempotency_key_digest: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    idempotency_request_digest: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    ttl_seconds: Mapped[int | None] = mapped_column(Integer)
    ttl_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rollback_of_id: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("response_actions.id", ondelete="RESTRICT")
    )
    rollback_requested_by: Mapped[UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT")
    )
    rollback_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class ResponseApproval(Base):
    __tablename__ = "response_approvals"

    id: Mapped[UUID] = mapped_column(
        Uuid, primary_key=True, server_default=text("gen_random_uuid()")
    )
    action_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("response_actions.id", ondelete="RESTRICT")
    )
    approver_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="RESTRICT"))
    decision: Mapped[str] = mapped_column(Text)
    reason: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )


class ExecutedCommand(Base):
    __tablename__ = "executed_commands"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    action_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey("response_actions.id", ondelete="RESTRICT")
    )
    phase: Mapped[str] = mapped_column(Text)
    connector: Mapped[str] = mapped_column(Text)
    command: Mapped[str] = mapped_column(Text)
    target: Mapped[dict[str, Any]] = mapped_column(JSONB)
    params: Mapped[dict[str, Any]] = mapped_column(JSONB)
    initiator: Mapped[str] = mapped_column(Text)
    simulated: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
