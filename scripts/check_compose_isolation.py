"""Fail closed on unsupported Docker hosts and verify Compose network isolation.

The preflight is non-destructive and must run before starting the stack. The
runtime check makes only TCP connection probes; it never changes containers,
networks, volumes or data. Docker host/root administrators remain trusted.
"""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["compose", "-f", str(ROOT / "infra/docker-compose.yml")]
GATEWAY_MODE = "com.docker.network.bridge.gateway_mode_ipv4"
DATA_SERVICES = (("postgres", 5432), ("redis-broker", 6379), ("redis-cache", 6379))


class IsolationError(Exception):
    """The required host or network isolation cannot be established."""


def _run(command: list[str], failure: str) -> str:
    try:
        result = subprocess.run(  # noqa: S603 - fixed executable/arguments, no shell
            command, capture_output=True, text=True, check=False, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired):
        raise IsolationError(failure) from None
    if result.returncode:
        # Docker output can contain environment or paths; do not print it here.
        raise IsolationError(failure)
    return result.stdout.strip()


def _decode_json(value: str, failure: str) -> Any:
    try:
        return json.loads(value)
    except ValueError:
        raise IsolationError(failure) from None


def _require_supported_engine(
    version: str,
    platform: str,
    operating_system: str,
    endpoint: str,
    local_os: str,
    daemon_os: str,
) -> None:
    match = re.fullmatch(r"(\d+)\.(\d+)\.\d+(?:[-+~][A-Za-z0-9_.+~-]+)?", version)
    prerelease = re.search(r"(?:^|[-+.])(rc|beta|alpha|dev)(?:[.-]?\d|[.-]|$)", version, re.I)
    if match is None or (int(match.group(1)), int(match.group(2))) < (28, 0) or prerelease:
        raise IsolationError("A stable Docker Engine 28.0 or newer is required")
    if (
        local_os != "linux"
        or daemon_os != "linux"
        or not platform.casefold().startswith("docker engine")
        or "docker desktop" in operating_system.casefold()
    ):
        raise IsolationError("A native Linux Docker Engine is required for the host probe")
    try:
        parsed = urlsplit(endpoint)
        local_socket = (
            parsed.scheme == "unix"
            and not parsed.netloc
            and parsed.path.startswith("/")
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        local_socket = False
    if not local_socket:
        raise IsolationError("A local Docker Unix socket is required for the host probe")


def _engine_preflight(docker: str) -> None:
    version = _run([docker, "version", "--format", "{{.Server.Version}}"], "Docker version failed")
    platform = _run(
        [docker, "version", "--format", "{{.Server.Platform.Name}}"],
        "Docker server platform query failed",
    )
    daemon_os = _run(
        [docker, "version", "--format", "{{.Server.Os}}"], "Docker server OS query failed"
    )
    operating_system = _run(
        [docker, "info", "--format", "{{.OperatingSystem}}"], "Docker server information failed"
    )
    endpoint = os.environ.get("DOCKER_HOST")
    if endpoint and os.environ.get("DOCKER_CONTEXT"):
        raise IsolationError("Unset either DOCKER_HOST or DOCKER_CONTEXT before verification")
    if not endpoint:
        endpoint = _run(
            [docker, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
            "Docker context inspection failed",
        )
    _require_supported_engine(
        version, platform, operating_system, endpoint, sys.platform, daemon_os
    )


def _compose_network_name(config: Any) -> str:
    try:
        network = config["networks"]["internal"]
        name = network["name"]
        valid = (
            network["driver"] == "bridge"
            and network["internal"] is True
            and network["enable_ipv6"] is False
            and network["driver_opts"][GATEWAY_MODE] == "isolated"
            and not network.get("external", False)
            and isinstance(name, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", name) is not None
        )
    except (KeyError, TypeError):
        valid = False
        name = None
    if not valid or not isinstance(name, str):
        raise IsolationError("Compose must configure an IPv4-only isolated internal bridge")
    return name


def _require_isolated_network(network: Any) -> None:
    try:
        valid = (
            network["Driver"] == "bridge"
            and network["Internal"] is True
            and network["EnableIPv6"] is False
            and network["Options"][GATEWAY_MODE] == "isolated"
        )
    except (KeyError, TypeError):
        valid = False
    if not valid:
        raise IsolationError(
            "Existing data network is not isolated; recreate it without deleting volumes"
        )


def _inspect_network(docker: str, name: str) -> Any:
    value = _run(
        [docker, "network", "inspect", "--format", "{{json .}}", name],
        "Docker data-network inspection failed",
    )
    result = _decode_json(value, "Docker data-network inspection returned invalid JSON")
    _require_isolated_network(result)
    return result


def _ipam_pools(
    value: Any, subnet_key: str, range_key: str
) -> set[tuple[ipaddress.IPv4Network, ipaddress.IPv4Network]]:
    try:
        if not isinstance(value, list) or not value:
            raise ValueError("missing pools")
        result = set()
        for pool in value:
            subnet = ipaddress.ip_network(pool[subnet_key])
            dynamic_range = ipaddress.ip_network(pool[range_key])
            if (
                not isinstance(subnet, ipaddress.IPv4Network)
                or not isinstance(dynamic_range, ipaddress.IPv4Network)
                or not dynamic_range.subnet_of(subnet)
            ):
                raise ValueError("invalid IPv4 allocation range")
            result.add((subnet, dynamic_range))
        if len(result) != len(value):
            raise ValueError("duplicate pools")
        return result
    except (KeyError, TypeError, ValueError):
        raise IsolationError("Data network needs valid IPv4 subnets and reserved ranges") from None


def _preflight(docker: str) -> tuple[str, Any | None]:
    _engine_preflight(docker)
    config = _decode_json(
        _run([docker, *COMPOSE, "config", "--format", "json"], "Compose configuration failed"),
        "Compose configuration returned invalid JSON",
    )
    name = _compose_network_name(config)
    try:
        expected_pools = _ipam_pools(
            config["networks"]["internal"]["ipam"]["config"], "subnet", "ip_range"
        )
    except (KeyError, TypeError):
        raise IsolationError("Compose data network is missing its allocation range") from None
    names = _run(
        [docker, "network", "ls", "--format", "{{.Name}}"], "Docker network listing failed"
    )
    network = _inspect_network(docker, name) if name in names.splitlines() else None
    if network is not None:
        try:
            actual_pools = _ipam_pools(network["IPAM"]["Config"], "Subnet", "IPRange")
        except (KeyError, TypeError):
            raise IsolationError("Existing data network is missing its allocation range") from None
        if actual_pools != expected_pools:
            raise IsolationError(
                "Existing data network has stale IPAM; recreate it without deleting volumes"
            )
    return name, network


def _network_subnets(network: Any) -> list[ipaddress.IPv4Network]:
    try:
        return [subnet for subnet, _ in _ipam_pools(network["IPAM"]["Config"], "Subnet", "IPRange")]
    except (KeyError, TypeError):
        raise IsolationError("Docker data network has invalid subnets") from None


def _data_addresses(docker: str, name: str, network: Any) -> dict[str, tuple[str, int]]:
    subnets = _network_subnets(network)
    result: dict[str, tuple[str, int]] = {}
    for service, port in DATA_SERVICES:
        container = _run([docker, *COMPOSE, "ps", "-q", service], "Data service lookup failed")
        if re.fullmatch(r"[0-9a-f]{12,64}", container) is None:
            raise IsolationError("Expected one running container for each data service")
        links = _decode_json(
            _run(
                [docker, "inspect", "--format", "{{json .NetworkSettings.Networks}}", container],
                "Data service network inspection failed",
            ),
            "Data service network inspection returned invalid JSON",
        )
        try:
            if not isinstance(links, dict) or set(links) != {name}:
                raise ValueError("unexpected network attachment")
            attachment = links[name]
            address = ipaddress.ip_address(attachment["IPAddress"])
            if (
                not isinstance(address, ipaddress.IPv4Address)
                or not any(address in subnet for subnet in subnets)
                or attachment.get("GlobalIPv6Address")
            ):
                raise ValueError("invalid data service address")
        except (KeyError, TypeError, ValueError):
            raise IsolationError(
                "Data service is not attached only to the expected network"
            ) from None
        bindings = _decode_json(
            _run(
                [docker, "inspect", "--format", "{{json .HostConfig.PortBindings}}", container],
                "Data service port inspection failed",
            ),
            "Data service port inspection returned invalid JSON",
        )
        if bindings not in (None, {}):
            raise IsolationError("A data service has published host ports")
        actual_ports = _decode_json(
            _run(
                [docker, "inspect", "--format", "{{json .NetworkSettings.Ports}}", container],
                "Data service published-port inspection failed",
            ),
            "Data service published-port inspection returned invalid JSON",
        )
        if actual_ports is not None and (
            not isinstance(actual_ports, dict)
            or any(value not in (None, []) for value in actual_ports.values())
        ):
            raise IsolationError("A data service has published host ports")
        result[service] = (str(address), port)
    if len({address for address, _ in result.values()}) != len(DATA_SERVICES):
        raise IsolationError("Data services must have distinct internal addresses")
    return result


def _internal_positive_control(docker: str, addresses: dict[str, tuple[str, int]]) -> None:
    targets = [(name, *addresses[name]) for name, _ in DATA_SERVICES]
    code = (
        "import json, socket, sys\n"
        "for name, address, port in json.loads(sys.argv[1]):\n"
        "    for host in (name, address):\n"
        "        socket.create_connection((host, port), timeout=3).close()\n"
    )
    _run(
        [docker, *COMPOSE, "exec", "-T", "backend", "python", "-c", code, json.dumps(targets)],
        "Internal positive control could not reach all data services by name and address",
    )


def _can_connect(address: str, port: int) -> bool:
    try:
        with socket.create_connection((address, port), timeout=2):
            return True
    except OSError as error:
        # Refused, filtered, or unroutable is a negative probe; resource errors
        # and other unexpected failures must not masquerade as isolation.
        denied = {
            errno.EACCES,
            errno.EPERM,
            errno.ECONNREFUSED,
            errno.EHOSTUNREACH,
            errno.ENETUNREACH,
            errno.ETIMEDOUT,
        }
        if isinstance(error, TimeoutError) or error.errno in denied:
            return False
        raise IsolationError("Host TCP probe failed unexpectedly") from None


def _published_nginx_address(value: str) -> tuple[str, int]:
    try:
        lines = value.splitlines()
        if len(lines) != 1:
            raise ValueError("expected one published address")
        host, raw_port = lines[0].rsplit(":", 1)
        address = ipaddress.ip_address(host.strip("[]"))
        port = int(raw_port)
        if not 1 <= port <= 65535 or address.is_multicast:
            raise ValueError("invalid port")
        if address.is_unspecified:
            address = ipaddress.ip_address("127.0.0.1" if address.version == 4 else "::1")
        return str(address), port
    except ValueError:
        raise IsolationError("Unable to identify the published Nginx address") from None


def _host_positive_control(docker: str) -> None:
    address, port = _published_nginx_address(
        _run([docker, *COMPOSE, "port", "nginx", "8080"], "Nginx port inspection failed")
    )
    if not _can_connect(address, port):
        raise IsolationError("Host positive control could not reach published Nginx")


def _require_host_isolation(addresses: dict[str, tuple[str, int]]) -> None:
    if set(addresses) != {name for name, _ in DATA_SERVICES}:
        raise IsolationError("Host probe requires all three data services")
    for name, expected_port in DATA_SERVICES:
        address, port = addresses[name]
        if port != expected_port:
            raise IsolationError("Host probe has an unexpected data-service port")
        if _can_connect(address, port):
            raise IsolationError(f"Docker host can reach the internal {name} service")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("preflight", "verify"))
    args = parser.parse_args()
    try:
        docker = shutil.which("docker")
        if docker is None:
            raise IsolationError("Docker is required for Compose isolation checks")
        name, network = _preflight(docker)
        if args.stage == "verify":
            if network is None:
                raise IsolationError("Compose data network does not exist")
            addresses = _data_addresses(docker, name, network)
            _internal_positive_control(docker, addresses)
            _host_positive_control(docker)
            _require_host_isolation(addresses)
            _internal_positive_control(docker, addresses)
            print("Verified: host cannot reach data services; internal and host controls passed")
        else:
            print("Verified: compatible Docker engine and isolated Compose network configuration")
        return 0
    except IsolationError as error:
        message = f"Compose isolation check failed: {error}"
        print(message, file=sys.stderr)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::error title=Compose isolation::{message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
