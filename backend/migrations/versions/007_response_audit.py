"""Create response approvals and an append-only simulated command log.

Revision ID: 007_response_audit
Revises: 006_response_actions
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "007_response_audit"
down_revision = "006_response_actions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "response_approvals",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "action_id",
            sa.Uuid(),
            sa.ForeignKey("response_actions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "approver_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("decision", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text()),
        sa.Column(
            "decided_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "decision IN ('approved', 'rejected')", name="ck_response_approval_decision"
        ),
        sa.UniqueConstraint("action_id", "approver_id", name="uq_response_approval_actor"),
        sa.UniqueConstraint("action_id", name="uq_response_approval_decision"),
    )
    op.create_table(
        "executed_commands",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column(
            "action_id",
            sa.Uuid(),
            sa.ForeignKey("response_actions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("phase", sa.Text(), nullable=False),
        sa.Column("connector", sa.Text(), nullable=False),
        sa.Column("command", sa.Text(), nullable=False),
        sa.Column("target", postgresql.JSONB(), nullable=False),
        sa.Column("params", postgresql.JSONB(), nullable=False),
        sa.Column("initiator", sa.Text(), nullable=False),
        sa.Column("simulated", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "executed_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("action_id", "phase", name="uq_executed_commands_action_phase"),
        sa.CheckConstraint("phase IN ('execute', 'rollback')", name="ck_executed_commands_phase"),
        sa.CheckConstraint(
            "connector <> '' AND command <> '' AND initiator <> ''",
            name="ck_executed_commands_names",
        ),
        sa.CheckConstraint("jsonb_typeof(target) = 'object'", name="ck_executed_commands_target"),
        sa.CheckConstraint("jsonb_typeof(params) = 'object'", name="ck_executed_commands_params"),
        sa.CheckConstraint("simulated", name="ck_executed_commands_simulated"),
    )
    op.create_index("ix_executed_commands_time", "executed_commands", ["executed_at", "id"])
    op.execute(
        """
        CREATE FUNCTION hpb_guard_response_approval() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE request_actor uuid; action_status text; mode text;
        BEGIN
            SELECT requested_by, status, approval_mode INTO request_actor, action_status, mode
            FROM response_actions WHERE id = NEW.action_id FOR UPDATE;
            IF NOT FOUND OR action_status <> 'pending_approval' OR mode <> 'manual' THEN
                RAISE EXCEPTION 'action is not awaiting a decision' USING ERRCODE = '23514';
            END IF;
            IF NEW.decision = 'approved' AND NEW.approver_id = request_actor THEN
                RAISE EXCEPTION 'self-approval is forbidden' USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER response_approval_guard BEFORE INSERT ON response_approvals
        FOR EACH ROW EXECUTE FUNCTION hpb_guard_response_approval()
        """
    )
    op.execute(
        """
        CREATE FUNCTION hpb_require_response_decision() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE required_decision text;
        BEGIN
            IF NEW.approval_mode = 'manual' AND NEW.status IN
               ('approved', 'executing', 'executed', 'failed', 'rolled_back', 'rejected') THEN
                required_decision := CASE WHEN NEW.status = 'rejected' THEN 'rejected'
                                          ELSE 'approved' END;
                IF NOT EXISTS (
                    SELECT 1 FROM response_approvals
                    WHERE action_id = NEW.id AND approver_id = NEW.decided_by
                      AND decision = required_decision
                ) THEN
                    RAISE EXCEPTION 'response action requires its recorded decision'
                        USING ERRCODE = '23514';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER response_action_decision_guard BEFORE UPDATE ON response_actions
        FOR EACH ROW EXECUTE FUNCTION hpb_require_response_decision()
        """
    )
    op.execute(
        """
        CREATE FUNCTION hpb_reject_response_log_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'response logs are append-only' USING ERRCODE = '55000';
        END;
        $$
        """
    )
    for table in ("response_approvals", "executed_commands"):
        op.execute(
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON {table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION hpb_reject_response_log_mutation()"
        )
        op.execute(f"REVOKE ALL ON {table} FROM PUBLIC, hpb_app")
        op.execute(f"GRANT SELECT, INSERT ON {table} TO hpb_app")
    op.execute("GRANT USAGE, SELECT ON SEQUENCE executed_commands_id_seq TO hpb_app")


def downgrade() -> None:
    op.execute("DROP TRIGGER response_action_decision_guard ON response_actions")
    op.execute("DROP FUNCTION hpb_require_response_decision()")
    op.execute("DROP TRIGGER response_approval_guard ON response_approvals")
    op.execute("DROP FUNCTION hpb_guard_response_approval()")
    op.execute("DROP TRIGGER response_approvals_append_only ON response_approvals")
    op.execute("DROP TRIGGER executed_commands_append_only ON executed_commands")
    op.execute("DROP FUNCTION hpb_reject_response_log_mutation()")
    op.drop_table("executed_commands")
    op.drop_table("response_approvals")
