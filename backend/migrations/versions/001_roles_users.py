"""Create the host role catalogue and user accounts.

Revision ID: 001_roles_users
Revises:
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "001_roles_users"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    roles = op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.Text(), nullable=False, unique=True),
    )
    # These three legacy roles are explicit seed data required by §3.4.
    op.bulk_insert(
        roles,
        [{"name": "admin"}, {"name": "senior_analyst"}, {"name": "analyst"}],
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("username", sa.Text(), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column(
            "role_id", sa.Uuid(), sa.ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
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
        sa.CheckConstraint(
            "username <> '' AND username = lower(username)", name="ck_users_username_normalized"
        ),
        sa.CheckConstraint("password_hash LIKE '$argon2id$%'", name="ck_users_argon2id"),
    )
    op.execute(
        """
        CREATE FUNCTION hpb_touch_user_updated_at() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            NEW.updated_at := clock_timestamp();
            RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER users_touch_updated_at BEFORE UPDATE ON users
        FOR EACH ROW EXECUTE FUNCTION hpb_touch_user_updated_at()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER users_touch_updated_at ON users")
    op.execute("DROP FUNCTION hpb_touch_user_updated_at()")
    op.drop_table("users")
    op.drop_table("roles")
