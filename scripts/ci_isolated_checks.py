"""Run application checks without IP networking, using fixed local service bridges.

The parent bridges three loopback-only service ports to temporary Unix sockets.
The child enters a fresh Linux network namespace, verifies IP routing is absent,
and runs the normal checks as the original unprivileged user.
"""

import argparse
import asyncio
import errno
import functools
import getpass
import os
import shutil
import socket
import sys
import tempfile
from contextlib import suppress
from pathlib import Path
from urllib.parse import quote


async def _copy(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
    try:
        while data := await source.read(65536):
            destination.write(data)
            await destination.drain()
    except OSError:
        pass
    finally:
        if destination.can_write_eof():
            with suppress(OSError):
                destination.write_eof()


async def _relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, port: int) -> None:
    upstream: asyncio.StreamWriter | None = None
    try:
        upstream_reader, upstream = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.gather(_copy(reader, upstream), _copy(upstream_reader, writer))
    except OSError:
        pass
    finally:
        writer.close()
        if upstream is not None:
            upstream.close()
        with suppress(OSError):
            await writer.wait_closed()
        if upstream is not None:
            with suppress(OSError):
                await upstream.wait_closed()


def _assert_no_ip_routing() -> None:
    """A UDP connect performs a local route lookup without sending a packet."""
    destinations = (
        (socket.AF_INET, "127.0.0.1"),
        (socket.AF_INET, "198.51.100.1"),
        (socket.AF_INET6, "::1"),
        (socket.AF_INET6, "2001:db8::1"),
    )
    unavailable = {
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
        errno.EADDRNOTAVAIL,
        errno.EAFNOSUPPORT,
        errno.EPROTONOSUPPORT,
    }
    for family, address in destinations:
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as probe:
                probe.connect((address, 9))
        except OSError as error:
            if error.errno not in unavailable:
                raise RuntimeError("Unable to verify test network isolation") from error
        else:
            raise RuntimeError("Test IP networking is not disabled")
    print("Verified: test namespace has no loopback or external IP route", flush=True)


def _inside() -> None:
    _assert_no_ip_routing()
    make = shutil.which("make")
    if make is None:
        raise RuntimeError("make is required for CI checks")
    # Fixed arguments and a resolved executable; there is no shell interpolation.
    os.execv(make, [make, "check", f"PYTHON={sys.executable}"])  # noqa: S606


async def _run(args: argparse.Namespace) -> int:
    if os.environ.get("CI_DISPOSABLE_SERVICES") != "1":
        raise RuntimeError(
            "Explicitly confirm that all CI services and the database cluster are disposable"
        )
    if not args.database.endswith("_test"):
        raise ValueError("CI database name must end in _test")
    if len({args.postgres_port, args.broker_port, args.cache_port}) != 3:
        raise ValueError("PostgreSQL, broker and cache need distinct service ports")
    for port in (args.postgres_port, args.broker_port, args.cache_port):
        if not 1 <= port <= 65535:
            raise ValueError("Invalid local service port")
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            raise RuntimeError("A required local CI service is unavailable") from None
        writer.close()
        await writer.wait_closed()
    with tempfile.TemporaryDirectory(prefix="soc-ci-") as directory:
        root = Path(directory)
        broker = root / "broker.sock"
        cache = root / "cache.sock"
        addresses = (
            (root / f".s.PGSQL.{args.postgres_port}", args.postgres_port),
            (broker, args.broker_port),
            (cache, args.cache_port),
        )
        servers: list[asyncio.AbstractServer] = []
        try:
            for path, port in addresses:
                servers.append(
                    await asyncio.start_unix_server(functools.partial(_relay, port=port), path=path)
                )
            database_url = (
                f"postgresql+psycopg://{quote(args.database_user, safe='')}@/"
                f"{quote(args.database, safe='')}?host={quote(directory, safe='')}"
                f"&port={args.postgres_port}"
            )
            variables = {
                "TEST_DATABASE_URL": database_url,
                "TEST_DATABASE_DISPOSABLE": "1",
                "TEST_PG_CLUSTER_DISPOSABLE": "1",
                "TEST_REDIS_DISPOSABLE": "1",
                "TEST_REDIS_BROKER_URL": f"redis+socket://{broker}?virtual_host=15",
                "TEST_REDIS_BROKER_CLIENT_URL": f"unix://{broker}?db=15",
                "TEST_REDIS_CACHE_URL": f"unix://{cache}?db=15",
                "PATH": os.environ.get("PATH", ""),
            }
            command = [
                "sudo",
                "-n",
                "unshare",
                "--net",
                "--",
                "runuser",
                "-u",
                getpass.getuser(),
                "--preserve-environment",
                "--",
                "env",
                *(f"{name}={value}" for name, value in variables.items()),
                sys.executable,
                str(Path(__file__).resolve()),
                "--inside",
            ]
            process = await asyncio.create_subprocess_exec(*command)
            return await process.wait()
        finally:
            for server in servers:
                server.close()
            await asyncio.gather(*(server.wait_closed() for server in servers))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--database-user", default="ci_test_user")
    parser.add_argument("--database", default="smart_soc_ci_test")
    parser.add_argument("--postgres-port", type=int, default=5432)
    parser.add_argument("--broker-port", type=int, default=6379)
    parser.add_argument("--cache-port", type=int, default=6380)
    args = parser.parse_args()
    if args.inside:
        _inside()
        return 1  # exec does not return on success
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
