"""Create revocable sessions, API keys and multi-worker login throttles.

Revision ID: 002_auth_sessions_keys
Revises: 001_roles_users
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "002_auth_sessions_keys"
down_revision = "001_roles_users"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("token_digest", sa.LargeBinary(), nullable=False, unique=True),
        sa.Column("csrf_digest", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", postgresql.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("revoked_at", postgresql.TIMESTAMP(timezone=True)),
        sa.Column("reauth_at", postgresql.TIMESTAMP(timezone=True)),
        sa.CheckConstraint("octet_length(token_digest) = 32", name="ck_sessions_token_digest"),
        sa.CheckConstraint("octet_length(csrf_digest) = 32", name="ck_sessions_csrf_digest"),
        sa.CheckConstraint("expires_at > created_at", name="ck_sessions_expiry"),
    )
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])
    op.create_index("ix_auth_sessions_expires_at", "auth_sessions", ["expires_at"])
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "owner_user_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("prefix", sa.Text(), nullable=False, unique=True),
        sa.Column("key_digest", sa.LargeBinary(), nullable=False, unique=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", postgresql.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("revoked_at", postgresql.TIMESTAMP(timezone=True)),
        sa.CheckConstraint("octet_length(key_digest) = 32", name="ck_api_keys_digest"),
        sa.CheckConstraint("expires_at > created_at", name="ck_api_keys_expiry"),
    )
    op.create_index("ix_api_keys_owner_user_id", "api_keys", ["owner_user_id"])
    op.create_table(
        "auth_login_throttle",
        sa.Column("bucket_digest", sa.LargeBinary(), primary_key=True),
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "window_started_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("octet_length(bucket_digest) = 32", name="ck_throttle_bucket_digest"),
        sa.CheckConstraint("failure_count >= 0", name="ck_throttle_failure_count"),
    )
    op.create_index("ix_auth_login_throttle_window", "auth_login_throttle", ["window_started_at"])


def downgrade() -> None:
    op.drop_table("auth_login_throttle")
    op.drop_table("api_keys")
    op.drop_table("auth_sessions")
