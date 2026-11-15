"""Create the singleton automation switch and seeded safeguard facts.

Revision ID: 008_response_safety
Revises: 007_response_audit
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "008_response_safety"
down_revision = "007_response_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "kill_switch_state",
        sa.Column("id", sa.SmallInteger(), primary_key=True, server_default="1"),
        sa.Column("engaged", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("changed_by", sa.Uuid(), sa.ForeignKey("users.id", ondelete="RESTRICT")),
        sa.Column(
            "changed_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint("id = 1", name="ck_kill_switch_singleton"),
    )
    op.execute("INSERT INTO kill_switch_state (id, engaged) VALUES (1, false)")
    op.execute(
        """
        CREATE FUNCTION hpb_protect_kill_switch_row() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'kill switch row cannot be removed' USING ERRCODE = '55000';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER kill_switch_no_delete BEFORE DELETE OR TRUNCATE ON kill_switch_state
        FOR EACH STATEMENT EXECUTE FUNCTION hpb_protect_kill_switch_row()
        """
    )
    op.create_table(
        "response_safeguard_rule",
        sa.Column("code", sa.Text(), primary_key=True),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.CheckConstraint("code <> '' AND value <> ''", name="ck_response_safeguard_nonempty"),
        sa.CheckConstraint(
            "kind IN ('agent', 'network', 'shell')", name="ck_response_safeguard_kind"
        ),
        sa.UniqueConstraint("kind", "value", name="uq_response_safeguard_kind_value"),
    )
    op.execute(
        """
        INSERT INTO response_safeguard_rule (code, kind, value) VALUES
          ('agent-000', 'agent', '000'),
          ('ipv4-rfc1918-10', 'network', '10.0.0.0/8'),
          ('ipv4-rfc1918-172', 'network', '172.16.0.0/12'),
          ('ipv4-rfc1918-192', 'network', '192.168.0.0/16'),
          ('ipv4-loopback', 'network', '127.0.0.0/8'),
          ('ipv4-link-local', 'network', '169.254.0.0/16'),
          ('ipv4-unspecified', 'network', '0.0.0.0/32'),
          ('ipv4-multicast', 'network', '224.0.0.0/4'),
          ('ipv6-unspecified', 'network', '::/128'),
          ('ipv6-loopback', 'network', '::1/128'),
          ('ipv6-link-local', 'network', 'fe80::/10'),
          ('ipv6-unique-local', 'network', 'fc00::/7'),
          ('ipv6-multicast', 'network', 'ff00::/8'),
          ('shell-metacharacters', 'shell', 'baseline')
        """
    )
    op.execute(
        """
        CREATE FUNCTION hpb_lock_safeguard_rules() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            PERFORM id FROM kill_switch_state WHERE id = 1 FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'kill switch state is missing' USING ERRCODE = '23514';
            END IF;
            RETURN NULL;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER response_safeguard_serialization
        BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON response_safeguard_rule
        FOR EACH STATEMENT EXECUTE FUNCTION hpb_lock_safeguard_rules()
        """
    )
    op.execute("REVOKE ALL ON kill_switch_state, response_safeguard_rule FROM PUBLIC, hpb_app")
    op.execute("GRANT SELECT, UPDATE ON kill_switch_state TO hpb_app")
    op.execute("GRANT SELECT ON response_safeguard_rule TO hpb_app")


def downgrade() -> None:
    op.execute("DROP TRIGGER response_safeguard_serialization ON response_safeguard_rule")
    op.execute("DROP FUNCTION hpb_lock_safeguard_rules()")
    op.drop_table("response_safeguard_rule")
    op.execute("DROP TRIGGER kill_switch_no_delete ON kill_switch_state")
    op.execute("DROP FUNCTION hpb_protect_kill_switch_row()")
    op.drop_table("kill_switch_state")
