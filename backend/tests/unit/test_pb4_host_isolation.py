"""Host isolation must fail closed, and positive controls cannot be skipped."""

import ast
import errno
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from scripts import check_compose_isolation as check

from tests.sensitive import Redacted


@pytest.fixture
def compose_config() -> dict:
    return {
        "networks": {
            "internal": {
                "name": "smart-soc_internal",
                "driver": "bridge",
                "internal": True,
                "enable_ipv6": False,
                "driver_opts": {check.GATEWAY_MODE: "isolated"},
                "ipam": {"config": [{"subnet": "172.30.42.0/24", "ip_range": "172.30.42.128/25"}]},
            }
        }
    }


@pytest.fixture
def network() -> dict:
    return {
        "Driver": "bridge",
        "Internal": True,
        "EnableIPv6": False,
        "Options": {check.GATEWAY_MODE: "isolated"},
        "IPAM": {"Config": [{"Subnet": "172.30.42.0/24", "IPRange": "172.30.42.128/25"}]},
    }


def test_host_script_supports_the_documented_python_version() -> None:
    source = Path("scripts/check_compose_isolation.py").read_text(encoding="utf-8")
    ast.parse(source, feature_version=(3, 10))


def test_engine_accepts_only_a_compatible_local_linux_docker_server() -> None:
    check._require_supported_engine(
        "28.0.0",
        "Docker Engine - Community",
        "Ubuntu",
        "unix:///var/run/docker.sock",
        "linux",
        "linux",
    )
    check._require_supported_engine(
        "29.3.2+vendor",
        "Docker Engine - Community",
        "Ubuntu",
        "unix:///run/docker.sock",
        "linux",
        "linux",
    )
    check._require_supported_engine(
        "28.2.2-0ubuntu1~24.04.1",
        "Docker Engine",
        "Ubuntu",
        "unix:///run/docker.sock",
        "linux",
        "linux",
    )
    for version, platform, system, endpoint, local, daemon in (
        ("27.9.9", "Docker Engine", "Ubuntu", "unix:///run/docker.sock", "linux", "linux"),
        ("28.0.0-rc.1", "Docker Engine", "Ubuntu", "unix:///run/docker.sock", "linux", "linux"),
        ("unknown", "Docker Engine", "Ubuntu", "unix:///run/docker.sock", "linux", "linux"),
        ("28.0.0", "Podman Engine", "Ubuntu", "unix:///run/docker.sock", "linux", "linux"),
        ("28.0.0", "Docker Engine", "Docker Desktop", "unix:///run/docker.sock", "linux", "linux"),
        ("28.0.0", "Docker Engine", "Ubuntu", "tcp://docker:2375", "linux", "linux"),
        ("28.0.0", "Docker Engine", "Ubuntu", "ssh://example", "linux", "linux"),
        ("28.0.0", "Docker Engine", "Ubuntu", "unix:///run/docker.sock", "darwin", "linux"),
        ("28.0.0", "Docker Engine", "Ubuntu", "unix:///run/docker.sock", "linux", "windows"),
    ):
        with pytest.raises(check.IsolationError):
            check._require_supported_engine(version, platform, system, endpoint, local, daemon)


def test_engine_preflight_rejects_ambiguous_context_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    monkeypatch.setenv("DOCKER_CONTEXT", "remote")

    def fake_run(command: list[str], failure: str) -> str:
        if "{{.Server.Version}}" in command:
            return "28.0.0"
        if "{{.Server.Platform.Name}}" in command:
            return "Docker Engine - Community"
        if "{{.Server.Os}}" in command:
            return "linux"
        if "{{.OperatingSystem}}" in command:
            return "Ubuntu"
        raise AssertionError("Unexpected Docker command")

    monkeypatch.setattr(check, "_run", fake_run)
    with pytest.raises(check.IsolationError, match="Unset either"):
        check._engine_preflight("/usr/bin/docker")


def test_compose_config_requires_the_isolated_ipv4_internal_bridge(compose_config: dict) -> None:
    assert check._compose_network_name(compose_config) == "smart-soc_internal"
    for key, value in (
        ("driver", "overlay"),
        ("internal", False),
        ("enable_ipv6", True),
        ("external", True),
        ("driver_opts", {}),
        ("name", "--invalid"),
    ):
        invalid = deepcopy(compose_config)
        invalid["networks"]["internal"][key] = value
        with pytest.raises(check.IsolationError):
            check._compose_network_name(invalid)


def test_existing_network_must_match_the_isolated_configuration(network: dict) -> None:
    check._require_isolated_network(network)
    for key, value in (
        ("Driver", "overlay"),
        ("Internal", False),
        ("EnableIPv6", True),
        ("Options", {}),
        ("Options", {check.GATEWAY_MODE: "nat"}),
    ):
        invalid = deepcopy(network)
        invalid[key] = value
        with pytest.raises(check.IsolationError, match="recreate it without deleting volumes"):
            check._require_isolated_network(invalid)


def test_preflight_rejects_an_existing_stale_bridge(
    compose_config: dict, network: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(check, "_engine_preflight", lambda docker: None)
    network["Options"] = {}

    def fake_run(command: list[str], failure: str) -> str:
        if "config" in command:
            return json.dumps(compose_config)
        if "ls" in command:
            return "smart-soc_internal"
        if "inspect" in command:
            return json.dumps(network)
        raise AssertionError("Unexpected Docker command")

    monkeypatch.setattr(check, "_run", fake_run)
    with pytest.raises(check.IsolationError, match="recreate it without deleting volumes"):
        check._preflight("/usr/bin/docker")


def test_preflight_rejects_stale_ipam_without_removing_the_network(
    compose_config: dict, network: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(check, "_engine_preflight", lambda docker: None)
    network["IPAM"]["Config"][0]["IPRange"] = "172.30.42.0/24"
    commands: list[list[str]] = []

    def fake_run(command: list[str], failure: str) -> str:
        commands.append(command)
        if "config" in command:
            return json.dumps(compose_config)
        if "ls" in command:
            return "smart-soc_internal"
        if "inspect" in command:
            return json.dumps(network)
        raise AssertionError("Unexpected Docker command")

    monkeypatch.setattr(check, "_run", fake_run)
    with pytest.raises(check.IsolationError, match="stale IPAM"):
        check._preflight("/usr/bin/docker")
    assert all("rm" not in command and "down" not in command for command in commands)


@pytest.mark.parametrize(
    "pools",
    [
        [],
        [{"Subnet": "172.30.42.0/24"}],
        [{"Subnet": "172.30.42.0/24", "IPRange": "172.30.43.0/25"}],
        [{"Subnet": "fd00::/64", "IPRange": "fd00::/80"}],
    ],
)
def test_data_network_requires_valid_ipv4_pools(pools: list[dict[str, str]]) -> None:
    with pytest.raises(check.IsolationError, match="valid IPv4 subnets and reserved ranges"):
        check._ipam_pools(pools, "Subnet", "IPRange")


def test_host_probe_checks_every_actual_data_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    addresses = {
        "postgres": ("172.30.42.130", 5432),
        "redis-broker": ("172.30.42.131", 6379),
        "redis-cache": ("172.30.42.132", 6379),
    }
    calls: list[tuple[str, int]] = []

    def blocked(address: str, port: int) -> bool:
        calls.append((address, port))
        return False

    monkeypatch.setattr(check, "_can_connect", blocked)
    check._require_host_isolation(addresses)
    assert set(calls) == set(addresses.values())
    monkeypatch.setattr(check, "_can_connect", lambda address, port: address.endswith("131"))
    with pytest.raises(check.IsolationError, match="redis-broker"):
        check._require_host_isolation(addresses)
    with pytest.raises(check.IsolationError, match="all three"):
        check._require_host_isolation({"postgres": addresses["postgres"]})


def test_data_addresses_are_actual_unpublished_internal_containers(
    network: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    identifiers = {name: str(index) * 64 for index, (name, _) in enumerate(check.DATA_SERVICES, 1)}
    container_addresses = {
        identifiers[name]: f"172.30.42.{130 + index}"
        for index, (name, _) in enumerate(check.DATA_SERVICES)
    }
    extra_network = False
    published = False
    published_automatically = False
    ipv6_address = False

    def fake_run(command: list[str], failure: str) -> str:
        if "ps" in command:
            return identifiers[command[-1]]
        if "{{json .NetworkSettings.Networks}}" in command:
            links = {"smart-soc_internal": {"IPAddress": container_addresses[command[-1]]}}
            if extra_network:
                links["edge"] = {"IPAddress": "172.31.0.10"}
            if ipv6_address:
                links["smart-soc_internal"]["GlobalIPv6Address"] = "fd00::2"
            return json.dumps(links)
        if "{{json .HostConfig.PortBindings}}" in command:
            return json.dumps({"6379/tcp": [{"HostPort": "6379"}]} if published else {})
        if "{{json .NetworkSettings.Ports}}" in command:
            return json.dumps(
                {"6379/tcp": [{"HostPort": "12345"}] if published_automatically else None}
            )
        raise AssertionError("Unexpected Docker command")

    monkeypatch.setattr(check, "_run", fake_run)
    addresses = check._data_addresses("/usr/bin/docker", "smart-soc_internal", network)
    assert len(addresses) == 3 and addresses["postgres"] == ("172.30.42.130", 5432)
    extra_network = True
    with pytest.raises(check.IsolationError, match="only to the expected network"):
        check._data_addresses("/usr/bin/docker", "smart-soc_internal", network)
    extra_network = False
    published = True
    with pytest.raises(check.IsolationError, match="published host ports"):
        check._data_addresses("/usr/bin/docker", "smart-soc_internal", network)
    published = False
    published_automatically = True
    with pytest.raises(check.IsolationError, match="published host ports"):
        check._data_addresses("/usr/bin/docker", "smart-soc_internal", network)
    published_automatically = False
    ipv6_address = True
    with pytest.raises(check.IsolationError, match="only to the expected network"):
        check._data_addresses("/usr/bin/docker", "smart-soc_internal", network)


def test_internal_positive_control_uses_the_same_actual_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    addresses = {
        "postgres": ("172.30.42.130", 5432),
        "redis-broker": ("172.30.42.131", 6379),
        "redis-cache": ("172.30.42.132", 6379),
    }
    commands: list[list[str]] = []
    monkeypatch.setattr(check, "_run", lambda command, failure: commands.append(command) or "")
    check._internal_positive_control("/usr/bin/docker", addresses)
    assert json.loads(commands[0][-1]) == [
        [name, *addresses[name]] for name, _ in check.DATA_SERVICES
    ]
    assert "for host in (name, address)" in commands[0][-2]


@pytest.mark.parametrize(
    "error",
    [
        OSError(errno.ECONNREFUSED, "refused"),
        OSError(errno.ENETUNREACH, "unreachable"),
        TimeoutError(),
    ],
)
def test_host_probe_recognizes_network_denials(
    error: OSError, monkeypatch: pytest.MonkeyPatch
) -> None:
    def blocked(*args: object, **kwargs: object) -> None:
        raise error

    monkeypatch.setattr(check.socket, "create_connection", blocked)
    assert check._can_connect("172.30.42.130", 5432) is False


def test_host_probe_fails_closed_on_resource_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def exhausted(*args: object, **kwargs: object) -> None:
        raise OSError(errno.EMFILE, "too many open files")

    monkeypatch.setattr(check.socket, "create_connection", exhausted)
    with pytest.raises(check.IsolationError, match="failed unexpectedly"):
        check._can_connect("172.30.42.130", 5432)


def test_host_control_requires_a_valid_reachable_published_nginx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert check._published_nginx_address("0.0.0.0:8080") == ("127.0.0.1", 8080)
    assert check._published_nginx_address("[::]:8080") == ("::1", 8080)
    with pytest.raises(check.IsolationError):
        check._published_nginx_address("not-an-ip:8080")
    monkeypatch.setattr(check, "_run", lambda command, failure: "127.0.0.1:8080")
    monkeypatch.setattr(check, "_can_connect", lambda address, port: False)
    with pytest.raises(check.IsolationError, match="Host positive control"):
        check._host_positive_control("/usr/bin/docker")


def test_runtime_verification_runs_positive_controls_around_host_probe(
    network: dict, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    events: list[str] = []
    monkeypatch.setattr(check.sys, "argv", ["check_compose_isolation.py", "verify"])
    monkeypatch.setattr(check.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(check, "_preflight", lambda docker: ("smart-soc_internal", network))
    monkeypatch.setattr(check, "_data_addresses", lambda docker, name, value: {})
    monkeypatch.setattr(
        check, "_internal_positive_control", lambda docker, addresses: events.append("internal")
    )
    monkeypatch.setattr(check, "_host_positive_control", lambda docker: events.append("host"))
    monkeypatch.setattr(
        check, "_require_host_isolation", lambda addresses: events.append("negative")
    )
    assert check.main() == 0
    assert events == ["internal", "host", "negative", "internal"]
    assert "internal and host controls passed" in capsys.readouterr().out


def test_full_verify_wires_inspection_and_both_controls(
    compose_config: dict, network: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    identifiers = {name: str(index) * 64 for index, (name, _) in enumerate(check.DATA_SERVICES, 1)}
    addresses = {
        identifier: f"172.30.42.{130 + index}"
        for index, identifier in enumerate(identifiers.values())
    }
    internal_probes: list[list[list[object]]] = []
    host_probes: list[tuple[str, int]] = []
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    monkeypatch.setattr(check.sys, "argv", ["check_compose_isolation.py", "verify"])
    monkeypatch.setattr(check.sys, "platform", "linux")
    monkeypatch.setattr(check.shutil, "which", lambda name: "/usr/bin/docker")

    def fake_run(command: list[str], failure: str) -> str:
        if "{{.Server.Version}}" in command:
            return "28.0.4"
        if "{{.Server.Platform.Name}}" in command:
            return "Docker Engine - Community"
        if "{{.Server.Os}}" in command:
            return "linux"
        if "{{.OperatingSystem}}" in command:
            return "Ubuntu"
        if "{{.Endpoints.docker.Host}}" in command:
            return "unix:///var/run/docker.sock"
        if "config" in command:
            return json.dumps(compose_config)
        if command[1:3] == ["network", "ls"]:
            return "smart-soc_internal"
        if command[1:3] == ["network", "inspect"]:
            return json.dumps(network)
        if "ps" in command:
            return identifiers[command[-1]]
        if "{{json .NetworkSettings.Networks}}" in command:
            return json.dumps({"smart-soc_internal": {"IPAddress": addresses[command[-1]]}})
        if "{{json .HostConfig.PortBindings}}" in command:
            return "{}"
        if "{{json .NetworkSettings.Ports}}" in command:
            return '{"5432/tcp": null}'
        if "exec" in command:
            internal_probes.append(json.loads(command[-1]))
            return ""
        if "port" in command:
            return "127.0.0.1:8080"
        raise AssertionError("Unexpected Docker command")

    def fake_connect(address: str, port: int) -> bool:
        host_probes.append((address, port))
        return (address, port) == ("127.0.0.1", 8080)

    monkeypatch.setattr(check, "_run", fake_run)
    monkeypatch.setattr(check, "_can_connect", fake_connect)
    assert check.main() == 0
    assert len(internal_probes) == 2
    assert (
        internal_probes[0]
        == internal_probes[1]
        == [[name, addresses[identifiers[name]], port] for name, port in check.DATA_SERVICES]
    )
    assert host_probes == [("127.0.0.1", 8080)] + [
        (addresses[identifiers[name]], port) for name, port in check.DATA_SERVICES
    ]


def test_failed_docker_commands_do_not_disclose_raw_output(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = Redacted.random()
    monkeypatch.setattr(
        check.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr=secret.reveal()),
    )
    with pytest.raises(check.IsolationError) as error:
        check._run(["/usr/bin/docker", "info"], "Docker inspection failed")
    assert secret.reveal() not in str(error.value)
    assert str(error.value) == "Docker inspection failed"
