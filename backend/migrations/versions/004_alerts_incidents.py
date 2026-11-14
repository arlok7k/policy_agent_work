"""Create alerts, incidents, their associations, and incident evidence.

Revision ID: 004_alerts_incidents
Revises: 003_case_activities
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "004_alerts_incidents"
down_revision = "003_case_activities"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("agent", sa.Text()),
        sa.Column("src_ip", postgresql.INET()),
        sa.Column("dst_ip", postgresql.INET()),
        sa.Column("raw", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="open"),
        sa.Column("fingerprint", sa.LargeBinary(), nullable=False, unique=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("source <> ''", name="ck_alerts_source_nonempty"),
        sa.CheckConstraint("rule_id <> ''", name="ck_alerts_rule_id_nonempty"),
        sa.CheckConstraint("severity <> ''", name="ck_alerts_severity_nonempty"),
        sa.CheckConstraint("status <> ''", name="ck_alerts_status_nonempty"),
        sa.CheckConstraint("jsonb_typeof(raw) = 'object'", name="ck_alerts_raw_object"),
        sa.CheckConstraint("octet_length(fingerprint) = 32", name="ck_alerts_fingerprint_length"),
    )
    op.create_index("ix_alerts_created_id", "alerts", ["created_at", "id"])
    op.create_index("ix_alerts_severity_created", "alerts", ["severity", "created_at"])
    op.create_index("ix_alerts_status_created", "alerts", ["status", "created_at"])

    op.create_table(
        "incidents",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("status", sa.Text(), nullable=False, server_default="open"),
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
        sa.CheckConstraint("title <> ''", name="ck_incidents_title_nonempty"),
        sa.CheckConstraint("status <> ''", name="ck_incidents_status_nonempty"),
    )
    op.create_index("ix_incidents_created_id", "incidents", ["created_at", "id"])

    op.create_table(
        "incident_alerts",
        sa.Column(
            "incident_id",
            sa.Uuid(),
            sa.ForeignKey("incidents.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "alert_id",
            sa.Uuid(),
            sa.ForeignKey("alerts.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_incident_alerts_alert_id", "incident_alerts", ["alert_id"])

    op.create_table(
        "evidence",
        sa.Column("id", sa.Uuid(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "incident_id",
            sa.Uuid(),
            sa.ForeignKey("incidents.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("alert_id", sa.Uuid()),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("data", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(
            ["incident_id", "alert_id"],
            ["incident_alerts.incident_id", "incident_alerts.alert_id"],
            ondelete="RESTRICT",
            name="fk_evidence_incident_alert",
        ),
        sa.CheckConstraint("kind <> ''", name="ck_evidence_kind_nonempty"),
        sa.CheckConstraint("jsonb_typeof(data) = 'object'", name="ck_evidence_data_object"),
    )
    op.create_index(
        "ix_evidence_incident_created_id", "evidence", ["incident_id", "created_at", "id"]
    )

    op.execute("GRANT SELECT, INSERT, UPDATE ON alerts, incidents TO hpb_app")
    op.execute("GRANT SELECT, INSERT ON incident_alerts, evidence TO hpb_app")


def downgrade() -> None:
    op.drop_table("evidence")
    op.drop_table("incident_alerts")
    op.drop_table("incidents")
    op.drop_table("alerts")
