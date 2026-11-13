"""Exercise real PostgreSQL sessions and Alembic on disposable schemas."""

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from app.core.config import Settings
from app.core.db import create_db_engine, create_session_factory


@pytest.fixture
def settings(disposable_database_url: str) -> Settings:
    import secrets

    return Settings.model_validate(
        {
            "environment": "test",
            "database_url": disposable_database_url,
            "session_signing_secret": secrets.token_urlsafe(48),
            "session_ttl_seconds": 3600,
            "login_failure_limit": 5,
            "login_window_seconds": 60,
            "password_min_chars": 14,
            "password_max_chars": 1024,
        }
    )


def test_session_factory_commits_and_rolls_back(settings: Settings) -> None:
    engine = create_db_engine(settings)
    sessions = create_session_factory(engine)
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE db_probe (value integer NOT NULL)"))
        with sessions.begin() as session:
            session.execute(text("INSERT INTO db_probe VALUES (1)"))
        with pytest.raises(RuntimeError, match="abort"):
            with sessions.begin() as session:
                session.execute(text("INSERT INTO db_probe VALUES (2)"))
                raise RuntimeError("abort")
        with sessions() as session:
            assert session.execute(text("SELECT value FROM db_probe")).scalars().all() == [1]
    finally:
        engine.dispose()


def test_alembic_upgrade_and_downgrade_round_trip(
    disposable_database_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    versions = tmp_path / "versions"
    versions.mkdir()
    (versions / "001_probe.py").write_text(
        """from alembic import op
import sqlalchemy as sa
revision = "001_probe"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("migration_probe", sa.Column("id", sa.Integer, primary_key=True))

def downgrade():
    op.drop_table("migration_probe")
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("DATABASE_URL", disposable_database_url)
    monkeypatch.delenv("DATABASE_URL_FILE", raising=False)
    monkeypatch.delenv("SESSION_SIGNING_SECRET", raising=False)
    monkeypatch.delenv("SESSION_SIGNING_SECRET_FILE", raising=False)
    config = Config("alembic.ini")
    config.set_main_option("version_locations", str(versions))
    engine = create_engine(disposable_database_url, hide_parameters=True)
    try:
        command.upgrade(config, "head")
        assert "migration_probe" in inspect(engine).get_table_names()
        command.downgrade(config, "base")
        assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT count(*) FROM alembic_version")).scalar_one() == 0
            )
    finally:
        engine.dispose()
