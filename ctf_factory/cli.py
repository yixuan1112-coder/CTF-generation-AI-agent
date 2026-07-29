from __future__ import annotations

import argparse
import json
from pathlib import Path

from .catalog import list_templates
from .models import DIFFICULTIES
from .orchestrator import ChallengeFactory, FactoryError
from .arena import run_arena


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate validator-gated local CTF challenges")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="List reviewed challenge templates")
    generate = sub.add_parser("generate", help="Generate one challenge bundle")
    generate.add_argument("--category", choices=("web", "crypto", "forensics", "ai-ml"), required=True)
    generate.add_argument("--type", dest="challenge_type", required=True)
    generate.add_argument("--difficulty", choices=DIFFICULTIES, required=True)
    generate.add_argument("--theme", default="Local cyber range")
    generate.add_argument("--output", type=Path, default=Path("generated"))
    arena = sub.add_parser("arena", help="Run a local attack/defend/judge round for a Web bundle")
    arena.add_argument("bundle", type=Path)
    args = parser.parse_args()
    if args.command == "list":
        print(json.dumps([{"category": t.category, "type": t.challenge_type, "delivery": t.delivery} for t in list_templates()], indent=2))
        return 0
    if args.command == "arena":
        try:
            report = run_arena(args.bundle)
        except (OSError, ValueError, KeyError) as exc:
            parser.error(str(exc))
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    try:
        bundle, reports = ChallengeFactory().generate(
            category=args.category, challenge_type=args.challenge_type,
            difficulty=args.difficulty, theme=args.theme, output=args.output,
        )
    except (FactoryError, OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps({"bundle": str(bundle), "gates": [r.__dict__ for r in reports]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

