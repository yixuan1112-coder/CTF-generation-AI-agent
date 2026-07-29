from __future__ import annotations

import argparse
import json
from pathlib import Path

from .orchestrator import ChallengeFactory, FactoryError


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a validator-gated local CTF challenge")
    parser.add_argument("brief", help="Theme and learning objective")
    parser.add_argument("--output", type=Path, default=Path("generated"))
    args = parser.parse_args()
    try:
        bundle, reports = ChallengeFactory().generate(args.brief, args.output)
    except (FactoryError, OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps({"bundle": str(bundle), "gates": [r.__dict__ for r in reports]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

