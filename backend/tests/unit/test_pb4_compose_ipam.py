"""Keep statically assigned Compose addresses out of Docker's dynamic pools."""

from copy import deepcopy
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

import pytest
import yaml


def _compose() -> dict[str, Any]:
    return yaml.safe_load(Path("infra/docker-compose.yml").read_text(encoding="utf-8"))


def _assert_reserved_static_addresses(compose: dict[str, Any]) -> None:
    """Validate every statically addressed service network, not just nginx."""
    for service_name, service in compose["services"].items():
        attached = service.get("networks", {})
        if isinstance(attached, list):
            continue  # A list names networks but cannot specify a static address.
        for network_name, options in attached.items():
            if options is None:
                continue
            for field in ("ipv4_address", "ipv6_address"):
                if field not in options:
                    continue
                address = ip_address(options[field])
                pools = compose["networks"][network_name].get("ipam", {}).get("config", [])
                containing = [
                    pool
                    for pool in pools
                    if "subnet" in pool and address in ip_network(pool["subnet"])
                ]
                assert containing, f"{service_name} static address is outside configured subnets"
                for pool in containing:
                    subnet = ip_network(pool["subnet"])
                    assert "ip_range" in pool, f"{network_name} must reserve its static addresses"
                    dynamic = ip_network(pool["ip_range"])
                    assert dynamic.subnet_of(subnet), f"{network_name} dynamic range exceeds subnet"
                    assert address not in dynamic, (
                        f"{service_name} static address overlaps {network_name} dynamic range"
                    )

    nginx_address = compose["services"]["nginx"]["networks"]["internal"]["ipv4_address"]
    assert compose["services"]["backend"]["environment"]["TRUSTED_PROXY_IPS"] == nginx_address


def test_compose_reserves_static_addresses_and_trusts_only_the_nginx_peer() -> None:
    compose = _compose()
    _assert_reserved_static_addresses(compose)
    assert compose["networks"]["internal"]["ipam"]["config"][0]["ip_range"] == "172.30.42.128/25"
    assert compose["services"]["nginx"]["networks"]["internal"]["ipv4_address"] == "172.30.42.2"


@pytest.mark.parametrize("service", ["nginx", "backend"])
def test_static_address_in_dynamic_pool_is_rejected_for_any_service(service: str) -> None:
    compose = deepcopy(_compose())
    compose["services"][service]["networks"] = {"internal": {"ipv4_address": "172.30.42.130"}}
    with pytest.raises(AssertionError, match="static address overlaps"):
        _assert_reserved_static_addresses(compose)


@pytest.mark.parametrize(
    ("subnet", "dynamic_range", "field", "address"),
    [
        ("10.44.0.0/24", "10.44.0.128/25", "ipv4_address", "10.44.0.130"),
        ("fd17:cc00::/64", "fd17:cc00:0:0:8000::/65", "ipv6_address", "fd17:cc00:0:0:8000::10"),
    ],
)
def test_static_address_in_any_network_pool_is_rejected(
    subnet: str, dynamic_range: str, field: str, address: str
) -> None:
    compose = deepcopy(_compose())
    compose["networks"]["another-network"] = {
        "ipam": {"config": [{"subnet": subnet, "ip_range": dynamic_range}]}
    }
    compose["services"]["postgres"]["networks"] = {
        "internal": None,
        "another-network": {field: address},
    }
    with pytest.raises(AssertionError, match="static address overlaps"):
        _assert_reserved_static_addresses(compose)


def test_static_address_without_a_reserved_range_is_rejected() -> None:
    compose = deepcopy(_compose())
    del compose["networks"]["internal"]["ipam"]["config"][0]["ip_range"]
    with pytest.raises(AssertionError, match="must reserve its static addresses"):
        _assert_reserved_static_addresses(compose)


def test_trusted_proxy_must_equal_nginx_static_address() -> None:
    compose = deepcopy(_compose())
    compose["services"]["backend"]["environment"]["TRUSTED_PROXY_IPS"] = "172.30.42.3"
    with pytest.raises(AssertionError):
        _assert_reserved_static_addresses(compose)
