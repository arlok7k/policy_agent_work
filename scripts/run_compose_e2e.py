"""Seed and test an explicitly disposable development Compose stack.

Passwords exist only in process environments and are redacted from child output.
The browser runs on the Compose edge network, not the internal data network.
This script never removes a volume, network, or secret file.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from collections import deque
from collections.abc import Mapping, Sequence
from pathlib import Path


class Redacted:
    """Ephemeral test secret whose representation cannot reveal its value."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not value:
            raise ValueError("An end-to-end test secret is empty")
        self._value = value

    @classmethod
    def random(cls) -> Redacted:
        return cls(secrets.token_urlsafe(32))

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Redacted(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


def redact_output(text: str, protected: Sequence[Redacted]) -> str:
    for secret in sorted(protected, key=lambda item: len(item.reveal()), reverse=True):
        text = text.replace(secret.reveal(), "<redacted>")
    text = re.sub(r"(?i)sha256=[0-9a-f]{64}", "sha256=<redacted>", text)
    return re.sub(
        r"(?im)(\b(?:cookie|set-cookie|authorization|x-csrf-token|"
        r"x-webhook-signature)[ \t]*:[ \t]*)[^\r\n]*",
        r"\1<redacted>",
        text,
    )


def require_disposable(environ: Mapping[str, str], *, confirmed: bool) -> None:
    if (
        not confirmed
        or environ.get("ENV") != "development"
        or environ.get("DEV_INSECURE_COOKIES", "").lower() != "true"
    ):
        raise ValueError(
            "End-to-end smoke requires --disposable, ENV=development and DEV_INSECURE_COOKIES=true"
        )


def _stream(command: list[str], environ: Mapping[str, str], protected: Sequence[Redacted]) -> int:
    # The executable and each argument are fixed data; no shell or secret arguments.
    with subprocess.Popen(  # noqa: S603
        command,
        env=environ,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    ) as process:
        if process.stdout is None:
            raise RuntimeError("Unable to capture end-to-end diagnostics")
        tail: deque[str] = deque(maxlen=30)
        for line in process.stdout:
            safe = redact_output(line, protected)
            print(safe, end="", flush=True)
            tail.append(safe)
        code = process.wait()
        if code and environ.get("GITHUB_ACTIONS") == "true":
            # Also expose the sanitized failure in check annotations when a CI
            # log-download host is unreachable. The normal full output remains.
            message = "".join(tail)[-10000:]
            escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::error title=Compose smoke::{escaped}", flush=True)
        return code


def _capture(command: list[str], environ: Mapping[str, str], protected: Sequence[Redacted]) -> str:
    # This command returns only container IDs or addresses, never credentials.
    result = subprocess.run(  # noqa: S603
        command, env=environ, check=False, capture_output=True, text=True
    )
    if result.returncode:
        print(redact_output(result.stderr, protected), file=sys.stderr, end="")
        raise RuntimeError(f"Docker inspection failed with exit code {result.returncode}")
    return result.stdout.strip()


def _internal_endpoints(
    docker: str, environ: Mapping[str, str], protected: Sequence[Redacted]
) -> dict[str, dict[str, object]]:
    compose = [docker, "compose", "-f", "infra/docker-compose.yml"]
    endpoints: dict[str, dict[str, object]] = {}
    for service, port in (("postgres", 5432), ("redis-broker", 6379), ("redis-cache", 6379)):
        container = _capture([*compose, "ps", "-q", service], environ, protected)
        if not re.fullmatch(r"[0-9a-f]{12,64}", container):
            raise ValueError(f"Expected one running {service} container")
        address = _capture(
            [
                docker,
                "inspect",
                "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                container,
            ],
            environ,
            protected,
        )
        parsed = ipaddress.ip_address(address)
        if parsed.version != 4 or parsed.is_loopback or parsed.is_unspecified:
            raise ValueError(f"Invalid internal address for {service}")
        endpoints[service] = {"host": str(parsed), "port": port}
    return endpoints


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--disposable", action="store_true", help="confirm this stack and its data are disposable"
    )
    args = parser.parse_args()
    protected: list[Redacted] = []
    try:
        require_disposable(os.environ, confirmed=args.disposable)
        docker = shutil.which("docker")
        if docker is None:
            raise RuntimeError("Docker is required for the Compose end-to-end smoke")
        secret_path = Path(
            os.environ.get("SOC_WEBHOOK_SECRET_FILE", "infra/secrets/dev/webhook_secret")
        )
        webhook = Redacted(secret_path.read_text(encoding="utf-8").rstrip("\r\n"))
        credentials = {
            "SEED_ADMIN_PASSWORD": Redacted.random(),
            "SEED_SENIOR_ANALYST_PASSWORD": Redacted.random(),
            "SEED_ANALYST_PASSWORD": Redacted.random(),
        }
        protected = [webhook, *credentials.values()]
        environ = dict(os.environ)
        environ.update({name: value.reveal() for name, value in credentials.items()})
        environ["SOC_E2E_DISPOSABLE"] = "1"
        compose = [docker, "compose", "-f", "infra/docker-compose.yml"]
        internal_probe = (
            "import socket\n"
            "for host, port in [('postgres', 5432), ('redis-broker', 6379), "
            "('redis-cache', 6379)]:\n"
            "    socket.create_connection((host, port), timeout=3).close()\n"
        )
        print("Checking data services from the internal network", flush=True)
        code = _stream(
            [*compose, "exec", "-T", "backend", "python", "-c", internal_probe], environ, protected
        )
        if code:
            return code
        seed_command = [*compose, "exec", "-T"]
        for name in credentials:
            seed_command.extend(["-e", name])
        seed_command.extend(["backend", "python", "scripts/seed_dev.py"])
        print("Seeding throwaway users into the empty disposable development database", flush=True)
        code = _stream(seed_command, environ, protected)
        if code:
            return code
        environ["SOC_E2E_INTERNAL_ENDPOINTS"] = json.dumps(
            _internal_endpoints(docker, environ, protected)
        )
        print("Running Playwright on the isolated Compose edge network", flush=True)
        return _stream(
            [*compose, "--profile", "e2e", "run", "--rm", "--no-deps", "--build", "playwright"],
            environ,
            protected,
        )
    except Exception as error:
        # Preserve the diagnostic without exposing test credentials or signatures.
        message = f"Compose end-to-end setup failed ({type(error).__name__}): {error}"
        print(redact_output(message, protected), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
