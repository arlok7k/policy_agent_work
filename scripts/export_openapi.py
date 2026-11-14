"""Write or check the deterministic PB1/PB2 host OpenAPI artifact."""

import argparse
import json
from pathlib import Path

from app.main import app

ARTIFACT = Path(__file__).resolve().parent.parent / "openapi.host.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the export is out of date")
    args = parser.parse_args()
    generated = json.dumps(app.openapi(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not ARTIFACT.is_file() or ARTIFACT.read_text(encoding="utf-8") != generated:
            print("Host OpenAPI export is missing or out of date")
            return 1
        print("Host OpenAPI export matches the application")
    else:
        ARTIFACT.write_text(generated, encoding="utf-8")
        print("Wrote openapi.host.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
