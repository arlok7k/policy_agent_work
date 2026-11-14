"""Create immutable response requests and their bounded lifecycle.

Revision ID: 006_response_actions
Revises: 005_ioc_cache
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "006_response_actions"
down_revision = "005_ioc_cache"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "response_actions",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "incident_id",
            sa.Uuid(),
            sa.ForeignKey("incidents.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("action_type", sa.Text(), nullable=False),
        sa.Column("target", postgresql.JSONB(), nullable=False),
        sa.Column(
            "params", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("level", sa.SmallInteger(), nullable=False),
        sa.Column("approval_mode", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="requested"),
        sa.Column(
            "requested_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("decided_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column("idempotency_key_digest", sa.LargeBinary(length=32)),
        sa.Column("idempotency_request_digest", sa.LargeBinary(length=32)),
        sa.Column("ttl_seconds", sa.Integer()),
        sa.Column("ttl_expires_at", postgresql.TIMESTAMP(timezone=True)),
        sa.Column(
            "rollback_of_id", sa.Uuid(), sa.ForeignKey("response_actions.id", ondelete="RESTRICT")
        ),
        sa.Column(
            "rollback_requested_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")
        ),
        sa.Column("rollback_requested_at", postgresql.TIMESTAMP(timezone=True)),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("action_type <> ''", name="ck_response_actions_action_type"),
        sa.CheckConstraint(
            "(idempotency_key_digest IS NULL AND idempotency_request_digest IS NULL) OR "
            "(idempotency_key_digest IS NOT NULL AND idempotency_request_digest IS NOT NULL AND "
            "octet_length(idempotency_key_digest) = 32 AND "
            "octet_length(idempotency_request_digest) = 32)",
            name="ck_response_actions_idempotency",
        ),
        sa.CheckConstraint("jsonb_typeof(target) = 'object'", name="ck_response_actions_target"),
        sa.CheckConstraint("jsonb_typeof(params) = 'object'", name="ck_response_actions_params"),
        sa.CheckConstraint("level BETWEEN 0 AND 3", name="ck_response_actions_level"),
        sa.CheckConstraint(
            "(level = 0 AND approval_mode = 'advisory') OR "
            "(level = 1 AND approval_mode = 'automatic') OR "
            "(level = 2 AND approval_mode IN ('automatic', 'manual')) OR "
            "(level = 3 AND approval_mode = 'manual')",
            name="ck_response_actions_mode",
        ),
        sa.CheckConstraint(
            "status IN ('requested', 'advised', 'pending_approval', 'approved', 'executing', "
            "'executed', 'failed', 'rejected', 'rolled_back', 'expired')",
            name="ck_response_actions_status",
        ),
        sa.CheckConstraint(
            "(level = 0 AND status IN ('requested', 'advised')) OR "
            "(level <> 0 AND status <> 'advised')",
            name="ck_response_actions_advisory",
        ),
        sa.CheckConstraint(
            "(level = 2 AND ttl_seconds IS NOT NULL AND ttl_seconds > 0) OR "
            "(level <> 2 AND ttl_seconds IS NULL AND ttl_expires_at IS NULL)",
            name="ck_response_actions_ttl",
        ),
        sa.CheckConstraint(
            "level <> 2 OR status NOT IN ('executed', 'rolled_back') OR ttl_expires_at IS NOT NULL",
            name="ck_response_actions_ttl_executed",
        ),
        sa.CheckConstraint(
            "approval_mode <> 'manual' OR status NOT IN "
            "('approved', 'executing', 'executed', 'failed', 'rolled_back') OR "
            "(decided_by IS NOT NULL AND decided_by <> requested_by)",
            name="ck_response_actions_four_eyes",
        ),
        sa.CheckConstraint(
            "approval_mode = 'manual' OR decided_by IS NULL",
            name="ck_response_actions_decider_mode",
        ),
        sa.CheckConstraint(
            "status <> 'rejected' OR decided_by IS NOT NULL",
            name="ck_response_actions_reject_decider",
        ),
        sa.CheckConstraint(
            "(rollback_requested_by IS NULL) = (rollback_requested_at IS NULL)",
            name="ck_response_actions_rollback_request",
        ),
    )
    op.create_index("ix_response_actions_created_id", "response_actions", ["created_at", "id"])
    op.create_index(
        "uq_response_actions_idempotency",
        "response_actions",
        ["requested_by", "idempotency_key_digest"],
        unique=True,
        postgresql_where=sa.text("idempotency_key_digest IS NOT NULL"),
    )
    op.create_index(
        "ix_response_actions_incident", "response_actions", ["incident_id", "created_at"]
    )
    op.create_index(
        "ix_response_actions_approved",
        "response_actions",
        ["created_at", "id"],
        postgresql_where=sa.text("status = 'approved'"),
    )
    op.create_index(
        "ix_response_actions_ttl_due",
        "response_actions",
        ["ttl_expires_at", "id"],
        postgresql_where=sa.text("level = 2 AND status = 'executed'"),
    )
    op.execute(
        """
        CREATE FUNCTION hpb_guard_response_action() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.status <> 'requested' OR NEW.decided_by IS NOT NULL OR
                   NEW.ttl_expires_at IS NOT NULL OR NEW.rollback_requested_by IS NOT NULL OR
                   NEW.rollback_requested_at IS NOT NULL THEN
                    RAISE EXCEPTION 'invalid initial response action state' USING ERRCODE = '23514';
                END IF;
                RETURN NEW;
            END IF;
            IF ROW(NEW.id, NEW.incident_id, NEW.action_type, NEW.target, NEW.params, NEW.level,
                   NEW.approval_mode, NEW.requested_by, NEW.idempotency_key_digest,
                   NEW.idempotency_request_digest, NEW.ttl_seconds, NEW.rollback_of_id,
                   NEW.created_at)
               IS DISTINCT FROM
               ROW(OLD.id, OLD.incident_id, OLD.action_type, OLD.target, OLD.params, OLD.level,
                   OLD.approval_mode, OLD.requested_by, OLD.idempotency_key_digest,
                   OLD.idempotency_request_digest, OLD.ttl_seconds, OLD.rollback_of_id,
                   OLD.created_at) THEN
                RAISE EXCEPTION 'response action request is immutable' USING ERRCODE = '23514';
            END IF;
            IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
                (OLD.status = 'requested' AND
                 NEW.status IN ('advised', 'pending_approval', 'approved')) OR
                (OLD.status = 'pending_approval' AND
                 NEW.status IN ('approved', 'rejected', 'expired')) OR
                (OLD.status = 'approved' AND NEW.status IN ('executing', 'failed', 'expired')) OR
                (OLD.status = 'executing' AND NEW.status IN ('executed', 'failed')) OR
                (OLD.status = 'executed' AND NEW.status = 'rolled_back')
            ) THEN
                RAISE EXCEPTION 'invalid response action transition' USING ERRCODE = '23514';
            END IF;
            IF OLD.status = 'requested' AND NEW.status = 'approved' AND
               NEW.approval_mode <> 'automatic' THEN
                RAISE EXCEPTION 'manual action requires approval' USING ERRCODE = '23514';
            END IF;
            IF OLD.status = 'requested' AND NEW.status = 'pending_approval' AND
               NEW.approval_mode <> 'manual' THEN
                RAISE EXCEPTION 'automatic action cannot require approval' USING ERRCODE = '23514';
            END IF;
            IF NEW.decided_by IS DISTINCT FROM OLD.decided_by AND NOT (
                OLD.status = 'pending_approval' AND NEW.status IN ('approved', 'rejected') AND
                OLD.decided_by IS NULL AND NEW.decided_by IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'invalid response action decision' USING ERRCODE = '23514';
            END IF;
            IF NEW.ttl_expires_at IS DISTINCT FROM OLD.ttl_expires_at AND NOT (
                OLD.status = 'executing' AND NEW.status = 'executed' AND NEW.level = 2 AND
                OLD.ttl_expires_at IS NULL AND NEW.ttl_expires_at IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'invalid response action TTL' USING ERRCODE = '23514';
            END IF;
            IF ROW(NEW.rollback_requested_by, NEW.rollback_requested_at) IS DISTINCT FROM
               ROW(OLD.rollback_requested_by, OLD.rollback_requested_at) AND NOT (
                OLD.status = 'executed' AND NEW.status = 'executed' AND
                NEW.rollback_requested_by IS NOT NULL AND NEW.rollback_requested_at IS NOT NULL
            ) THEN
                RAISE EXCEPTION 'invalid rollback request' USING ERRCODE = '23514';
            END IF;
            NEW.updated_at := clock_timestamp();
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER response_action_guard BEFORE INSERT OR UPDATE ON response_actions
        FOR EACH ROW EXECUTE FUNCTION hpb_guard_response_action()
        """
    )
    op.execute("GRANT SELECT, INSERT, UPDATE ON response_actions TO hpb_app")


def downgrade() -> None:
    op.execute("DROP TRIGGER response_action_guard ON response_actions")
    op.execute("DROP FUNCTION hpb_guard_response_action()")
    op.drop_table("response_actions")
