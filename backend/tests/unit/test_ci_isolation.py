"""CI refuses non-disposable services and any usable IP route."""

import argparse
import asyncio
import errno
import socket
from typing import Any

import pytest
from scripts import ci_isolated_checks


class Probe:
    def __init__(self, error: int | None, calls: list[object]) -> None:
        self.error = error
        self.calls = calls

    def __enter__(self) -> Probe:
        return self

    def __exit__(self, *args: object) -> None:
        pass

    def connect(self, address: object) -> None:
        self.calls.append(address)
        if self.error is not None:
            raise OSError(self.error, "probe failure")


def test_network_preflight_requires_both_ipv4_and_ipv6_to_be_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []

    def unreachable(*args: Any, **kwargs: Any) -> Probe:
        return Probe(errno.ENETUNREACH, calls)

    monkeypatch.setattr(socket, "socket", unreachable)
    ci_isolated_checks._assert_no_ip_routing()
    assert calls == [("127.0.0.1", 9), ("198.51.100.1", 9), ("::1", 9), ("2001:db8::1", 9)]


@pytest.mark.parametrize("error", [None, errno.EACCES])
def test_network_preflight_fails_closed_on_routable_or_unexpected_state(
    monkeypatch: pytest.MonkeyPatch, error: int | None
) -> None:
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: Probe(error, []))
    with pytest.raises(RuntimeError, match="network"):
        ci_isolated_checks._assert_no_ip_routing()


def test_ci_requires_explicit_disposable_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CI_DISPOSABLE_SERVICES", raising=False)
    with pytest.raises(RuntimeError, match="disposable"):
        asyncio.run(ci_isolated_checks._run(argparse.Namespace()))


def test_ci_refuses_non_test_database_and_duplicate_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CI_DISPOSABLE_SERVICES", "1")
    args = argparse.Namespace(database="production", postgres_port=1, broker_port=2, cache_port=3)
    with pytest.raises(ValueError, match="_test"):
        asyncio.run(ci_isolated_checks._run(args))
    args.database = "disposable_test"
    args.cache_port = args.broker_port
    with pytest.raises(ValueError, match="distinct"):
        asyncio.run(ci_isolated_checks._run(args))
