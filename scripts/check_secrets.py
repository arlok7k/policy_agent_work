"""Fail CI on secret-scanner findings in tracked repository files.

Only file paths and line numbers are printed; potentially sensitive content is
never echoed. The scanner sees newly staged files as well as committed files.
"""

import json
import shutil
import subprocess
import sys


def main() -> int:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to enumerate tracked files")
    # A fixed executable and fixed arguments are passed without a shell.
    tracked = subprocess.run(  # noqa: S603
        [git, "ls-files", "-z"], check=True, capture_output=True
    ).stdout.decode("utf-8")
    paths = [path for path in tracked.split("\0") if path]
    if not paths:
        print("No tracked files to scan", file=sys.stderr)
        return 1
    # Paths are data after `--`, not executable options; no shell is used.
    scan = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "detect_secrets", "scan", "--", *paths],
        check=True,
        capture_output=True,
        text=True,
    )
    findings = json.loads(scan.stdout)["results"]
    for path, matches in findings.items():
        for match in matches:
            print(f"Potential secret: {path}:{match['line_number']} ({match['type']})")
    if findings:
        return 1
    print(f"Secret scan: {len(paths)} tracked files, no findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
