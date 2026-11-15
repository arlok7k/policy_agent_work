"""Print Compose diagnostics after masking local throwaway secret values."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


def redact(log: str, directory: Path) -> str:
    if not directory.is_dir():
        raise ValueError("Secret directory is not available for log redaction")
    protected: set[str] = set()
    for path in directory.iterdir():
        if not path.is_file():
            continue
        value = path.read_text(encoding="utf-8").rstrip("\r\n")
        if not value:
            raise ValueError("A development secret file is empty")
        protected.add(value)
        parsed = urlsplit(value)
        if parsed.password:
            protected.add(unquote(parsed.password))
    if not protected:
        raise ValueError("No development secrets are available for log redaction")
    for value in sorted(protected, key=len, reverse=True):
        log = log.replace(value, "<redacted>")
    return log


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory", type=Path, default=Path(__file__).resolve().parents[1] / "infra/secrets/dev"
    )
    args = parser.parse_args()
    try:
        output = redact(sys.stdin.read(), args.directory)
    except OSError, UnicodeError, ValueError:
        print("Compose log redaction unavailable; refusing to print raw logs", file=sys.stderr)
        return 1
    print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
