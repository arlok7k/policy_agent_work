"""Create a host-only presentation settings singleton.

Revision ID: 009_host_settings
Revises: 008_response_safety
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "009_host_settings"
down_revision = "008_response_safety"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "host_settings",
        sa.Column("id", sa.SmallInteger(), primary_key=True, server_default="1"),
        sa.Column("display_name", sa.Text(), nullable=False, server_default="SMART SOC"),
        sa.Column("default_direction", sa.Text(), nullable=False, server_default="rtl"),
        sa.Column(
            "updated_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("id = 1", name="ck_host_settings_singleton"),
        sa.CheckConstraint("length(trim(display_name)) > 0", name="ck_host_settings_name"),
        sa.CheckConstraint(
            "default_direction IN ('ltr', 'rtl')", name="ck_host_settings_direction"
        ),
    )
    op.execute("INSERT INTO host_settings (id) VALUES (1)")
    op.execute("REVOKE ALL ON host_settings FROM PUBLIC, hpb_app")
    op.execute("GRANT SELECT, UPDATE ON host_settings TO hpb_app")


def downgrade() -> None:
    op.drop_table("host_settings")
