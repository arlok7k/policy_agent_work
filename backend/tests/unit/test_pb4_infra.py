"""Infrastructure choices that can be checked without a container runtime."""

import os
import stat
from pathlib import Path

import pytest
from pydantic import SecretStr
from scripts.bootstrap_dev_secrets import bootstrap
from scripts.provision_runtime import ProvisionError, _validate_urls

from app.core.gunicorn_worker import HostUvicornWorker
from tests.sensitive import Redacted


def test_worker_does_not_rewrite_the_socket_peer_from_forwarded_headers() -> None:
    assert HostUvicornWorker.CONFIG_KWARGS["proxy_headers"] is False


def test_development_secrets_are_private_nonoverwriting_and_refuse_production(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "throwaway"
    with pytest.raises(ValueError):
        bootstrap(directory, "production")
    assert not directory.exists()
    bootstrap(directory, "development")
    expected = {
        "postgres_password",
        "migrator_database_url",
        "runtime_database_url",
        "webhook_secret",
        "session_signing_secret",
    }
    assert {item.name for item in directory.iterdir()} == expected
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for path in directory.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
        content = Redacted(path.read_text(encoding="utf-8").rstrip("\n"))
        assert len(content.reveal()) >= 32
    before = {path.name: Redacted(path.read_text()) for path in directory.iterdir()}
    with pytest.raises(ValueError):
        bootstrap(directory, "development")
    unchanged = all(
        (directory / name).read_text(encoding="utf-8") == content.reveal()
        for name, content in before.items()
    )
    assert unchanged
    assert os.access(directory, os.W_OK)


def test_runtime_database_identity_validation_rejects_different_hosts_and_owners() -> None:
    secret = Redacted.random()
    owner = SecretStr(f"postgresql+psycopg://owner:{secret.reveal()}@database/soc")
    good = SecretStr(f"postgresql+psycopg://runtime:{secret.reveal()}@database/soc")
    admin_url, runtime_url = _validate_urls(owner, good)
    assert admin_url.username == "owner" and runtime_url.username == "runtime"
    for invalid in (
        f"postgresql+psycopg://runtime:{secret.reveal()}@other/soc",
        f"postgresql+psycopg://owner:{secret.reveal()}@database/soc",
        "postgresql+psycopg://runtime@database/soc",
        f"postgresql+psycopg://bad-name:{secret.reveal()}@database/soc",
        f"postgresql+psycopg://runtime:{secret.reveal()}@database/other",
    ):
        with pytest.raises(ProvisionError):
            _validate_urls(owner, SecretStr(invalid))


def test_compose_only_publishes_nginx_and_keeps_data_services_internal() -> None:
    import yaml

    config = yaml.safe_load(Path("infra/docker-compose.yml").read_text(encoding="utf-8"))
    services = config["services"]
    expected = {
        "postgres",
        "redis-broker",
        "redis-cache",
        "migrate",
        "backend",
        "celery-worker",
        "celery-beat",
        "nginx",
    }
    assert set(services) == expected | {"playwright"}
    assert [name for name, service in services.items() if "ports" in service] == ["nginx"]
    assert config["networks"]["internal"]["internal"] is True
    browser = services["playwright"]
    assert browser["profiles"] == ["e2e"]
    assert browser["networks"] == ["edge"]
    assert browser["user"] != "0:0" and "ALL" in browser["cap_drop"]
    assert set(browser["secrets"]) == {"webhook_secret"}
    for name in expected - {"nginx"}:
        assert services[name]["networks"] == ["internal"]
        assert services[name]["user"] != "0:0"
        assert "ALL" in services[name]["cap_drop"]
    for name in expected - {"migrate"}:
        assert "healthcheck" in services[name]
    proxy_ip = services["nginx"]["networks"]["internal"]["ipv4_address"]
    assert services["backend"]["environment"]["TRUSTED_PROXY_IPS"] == proxy_ip
    for service in ("backend", "celery-worker", "celery-beat"):
        mounted = set(services[service]["secrets"])
        assert mounted == {"runtime_database_url", "webhook_secret", "session_signing_secret"}
        assert "migrator_database_url" not in mounted
    assert set(services["migrate"]["secrets"]) == {"migrator_database_url", "runtime_database_url"}
    assert services["postgres"]["secrets"] == ["postgres_password"]
