"""Create ignored throwaway Docker secret files for local development only."""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path


def bootstrap(directory: Path, environment: str) -> None:
    if environment != "development":
        raise ValueError("Development secrets require ENV=development")
    names = (
        "postgres_password",
        "migrator_database_url",
        "runtime_database_url",
        "webhook_secret",
        "session_signing_secret",
    )
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Secret directory must be a real directory")
    os.chmod(directory, 0o700)
    if any((directory / name).exists() or (directory / name).is_symlink() for name in names):
        raise ValueError("Secret files already exist; refusing to overwrite")
    owner_password = secrets.token_urlsafe(48)
    runtime_password = secrets.token_urlsafe(48)
    values = (
        owner_password,
        f"postgresql+psycopg://hpb_owner:{owner_password}@postgres:5432/smart_soc",
        f"postgresql+psycopg://hpb_runtime:{runtime_password}@postgres:5432/smart_soc",
        secrets.token_urlsafe(48),
        secrets.token_urlsafe(48),
    )
    for name, value in zip(names, values, strict=True):
        # Docker Compose's file-backed secrets are bind mounts and ignore uid/mode
        # remapping. Host directory traversal remains restricted to its owner.
        descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        try:
            os.fchmod(descriptor, 0o444)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                stream.write(value + "\n")
        finally:
            if descriptor != -1:
                os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory", type=Path, default=Path(__file__).resolve().parents[1] / "infra/secrets/dev"
    )
    args = parser.parse_args()
    try:
        bootstrap(args.directory, os.environ.get("ENV", ""))
    except (OSError, ValueError) as error:
        print(f"Development secret bootstrap refused ({type(error).__name__})", file=sys.stderr)
        return 1
    print("Throwaway development secret files created in the private directory")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
