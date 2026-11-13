"""Create the append-only host activity log and restricted runtime role.

Revision ID: 003_case_activities
Revises: 002_auth_sessions_keys
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "003_case_activities"
down_revision = "002_auth_sessions_keys"
branch_labels = None
depends_on = None


def _ensure_runtime_role() -> None:
    # The role is cluster-wide; do not silently reuse an elevated role.
    op.execute(
        """
        DO $$
        DECLARE app_role oid;
        BEGIN
            SELECT oid INTO app_role FROM pg_roles WHERE rolname = 'hpb_app';
            IF app_role IS NULL THEN
                CREATE ROLE hpb_app NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB
                    NOCREATEROLE NOREPLICATION NOBYPASSRLS;
                SELECT oid INTO app_role FROM pg_roles WHERE rolname = 'hpb_app';
            END IF;
            IF EXISTS (
                SELECT 1 FROM pg_roles WHERE oid = app_role AND
                    (rolcanlogin OR rolinherit OR rolsuper OR rolcreatedb OR
                     rolcreaterole OR rolreplication OR rolbypassrls)
            ) OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member = app_role) THEN
                RAISE EXCEPTION 'hpb_app must be an unprivileged non-login role';
            END IF;
        END;
        $$
        """
    )


def _grant_runtime_privileges() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            EXECUTE format('GRANT USAGE ON SCHEMA %I TO hpb_app', current_schema());
        END;
        $$
        """
    )
    op.execute("GRANT SELECT ON roles TO hpb_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON users, auth_sessions, api_keys TO hpb_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON auth_login_throttle TO hpb_app")
    op.execute("REVOKE ALL ON case_activities FROM PUBLIC, hpb_app")
    op.execute("GRANT SELECT, INSERT ON case_activities TO hpb_app")
    op.execute("GRANT USAGE, SELECT ON SEQUENCE case_activities_id_seq TO hpb_app")


def upgrade() -> None:
    _ensure_runtime_role()
    op.create_table(
        "case_activities",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column(
            "occurred_at",
            postgresql.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("ip", postgresql.INET()),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target", sa.Text()),
        sa.Column(
            "details", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
    )
    op.create_index("ix_case_activities_occurred_at", "case_activities", ["occurred_at"])
    op.execute(
        """
        CREATE FUNCTION hpb_reject_case_activity_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'case_activities is append-only' USING ERRCODE = '55000';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER case_activities_append_only
        BEFORE UPDATE OR DELETE OR TRUNCATE ON case_activities
        FOR EACH STATEMENT EXECUTE FUNCTION hpb_reject_case_activity_mutation()
        """
    )
    _grant_runtime_privileges()


def downgrade() -> None:
    op.execute("REVOKE SELECT ON roles FROM hpb_app")
    op.execute("REVOKE SELECT, INSERT, UPDATE ON users, auth_sessions, api_keys FROM hpb_app")
    op.execute("REVOKE SELECT, INSERT, UPDATE, DELETE ON auth_login_throttle FROM hpb_app")
    op.execute("DROP TRIGGER case_activities_append_only ON case_activities")
    op.execute("DROP FUNCTION hpb_reject_case_activity_mutation()")
    op.drop_table("case_activities")
    op.execute(
        """
        DO $$
        BEGIN
            EXECUTE format('REVOKE USAGE ON SCHEMA %I FROM hpb_app', current_schema());
        END;
        $$
        """
    )
