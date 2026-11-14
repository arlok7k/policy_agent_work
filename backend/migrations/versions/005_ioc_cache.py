"""Create the persistent IOC cache.

Revision ID: 005_ioc_cache
Revises: 004_alerts_incidents
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "005_ioc_cache"
down_revision = "004_alerts_incidents"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ioc_cache",
        sa.Column("indicator", sa.Text(), primary_key=True),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("score", sa.Integer()),
        sa.Column("sources", postgresql.JSONB(), nullable=False),
        sa.Column("is_mock", sa.Boolean(), nullable=False),
        sa.Column(
            "cached_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", postgresql.TIMESTAMP(timezone=True), nullable=False),
        sa.CheckConstraint("indicator <> ''", name="ck_ioc_cache_indicator_nonempty"),
        sa.CheckConstraint("verdict <> ''", name="ck_ioc_cache_verdict_nonempty"),
        sa.CheckConstraint("score IS NULL OR score BETWEEN 0 AND 100", name="ck_ioc_cache_score"),
        sa.CheckConstraint("jsonb_typeof(sources) = 'array'", name="ck_ioc_cache_sources_array"),
        sa.CheckConstraint("expires_at > cached_at", name="ck_ioc_cache_expiry"),
    )
    op.create_index("ix_ioc_cache_expires_at", "ioc_cache", ["expires_at"])
    op.execute("GRANT SELECT, INSERT, UPDATE ON ioc_cache TO hpb_app")


def downgrade() -> None:
    op.drop_table("ioc_cache")
