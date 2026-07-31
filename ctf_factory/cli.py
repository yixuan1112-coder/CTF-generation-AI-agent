from __future__ import annotations

import argparse
import json
from pathlib import Path

from .catalog import CATEGORY_INFO, list_templates, runtime_delivery
from .models import DIFFICULTIES
from .orchestrator import ChallengeFactory, FactoryError
from .arena import run_arena
from .operations import batch_generate, doctor, export_player_bundle
from .studio import serve_studio


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate validator-gated local CTF challenges")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="List reviewed challenge templates")
    sub.add_parser("doctor", help="Check Python, Docker, and optional model configuration")
    studio = sub.add_parser("studio", help="Launch the local visual challenge designer")
    studio.add_argument("--host", default="127.0.0.1")
    studio.add_argument("--port", type=int, default=8787)
    generate = sub.add_parser("generate", help="Generate one challenge bundle")
    generate.add_argument("--category", choices=tuple(CATEGORY_INFO), required=True)
    generate.add_argument("--type", dest="challenge_type", required=True)
    generate.add_argument("--difficulty", choices=DIFFICULTIES, required=True)
    generate.add_argument("--theme", default="Local cyber range")
    generate.add_argument("--output", type=Path, default=Path("generated"))
    generate.add_argument("--variant", default="default", help="Unique lowercase variant id")
    generate.add_argument("--seed", help="Optional reproducible generation seed")
    batch = sub.add_parser("batch", help="Generate a reproducible batch of challenges")
    batch.add_argument("--count", type=int, required=True)
    batch.add_argument("--categories", default="web,crypto,forensics,ai-ml")
    batch.add_argument("--difficulties", default="easy,medium,hard")
    batch.add_argument("--theme", default="Autonomous cyber range")
    batch.add_argument("--seed", default="ctf-batch")
    batch.add_argument("--output", type=Path, default=Path("generated"))
    export = sub.add_parser("export", help="Create a player-only ZIP without organizer secrets")
    export.add_argument("bundle", type=Path)
    export.add_argument("--output", type=Path, default=Path("exports"))
    arena = sub.add_parser("arena", help="Run a local attack/defend/judge round for a Web bundle")
    arena.add_argument("bundle", type=Path)
    args = parser.parse_args()
    if args.command == "list":
        print(json.dumps([{"category": t.category, "type": t.challenge_type,
                           "delivery": runtime_delivery(t.category, t.delivery)}
                          for t in list_templates()], indent=2))
        return 0
    if args.command == "doctor":
        report = doctor(); print(json.dumps(report, indent=2)); return 0 if report["ready"] else 1
    if args.command == "studio":
        serve_studio(host=args.host, port=args.port); return 0
    if args.command == "batch":
        try:
            results = batch_generate(count=args.count, categories=args.categories.split(","), difficulties=args.difficulties.split(","), theme=args.theme, output=args.output, seed=args.seed)
        except (OSError, ValueError, FactoryError) as exc:
            parser.error(str(exc))
        print(json.dumps({"count": len(results), "results": results}, indent=2)); return 0
    if args.command == "export":
        try: target = export_player_bundle(args.bundle, args.output)
        except (OSError, ValueError, KeyError) as exc: parser.error(str(exc))
        print(json.dumps({"player_bundle": str(target)}, indent=2)); return 0
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
            variant=args.variant, seed=args.seed,
        )
    except (FactoryError, OSError, ValueError, KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps({"bundle": str(bundle), "gates": [r.__dict__ for r in reports]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

