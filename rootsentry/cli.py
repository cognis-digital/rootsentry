"""rootsentry CLI.

    rootsentry eval evidence.json [--json] [--fail-on COMPROMISED]
    rootsentry catalog [--platform android|ios] [--json]

``eval`` reads a device telemetry snapshot (see examples/evidence.android.json)
and prints the posture verdict. ``--fail-on`` sets the exit-code threshold so it
can gate a backend attestation check.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from .catalog import Platform, for_platform
from .engine import Evidence, Posture, evaluate


def cmd_eval(args: argparse.Namespace) -> int:
    with open(args.evidence, "r", encoding="utf-8") as fh:
        ev = Evidence.from_dict(json.load(fh))
    verdict = evaluate(ev)
    if args.json:
        print(json.dumps(verdict.to_dict(), indent=2))
    else:
        print(f"posture: {verdict.posture.label}  (score {verdict.score}/100)")
        for s in verdict.fired:
            print(f"  [{s.weight:2}] {s.category.value:9} {s.id} — {s.description}")
        if not verdict.fired:
            print("  no indicators fired")
    threshold = Posture[args.fail_on] if args.fail_on else None
    if threshold is not None and verdict.posture >= threshold:
        return 1
    return 0


def cmd_catalog(args: argparse.Namespace) -> int:
    signals = for_platform(Platform(args.platform)) if args.platform else None
    from .catalog import CATALOG
    signals = signals if signals is not None else CATALOG
    if args.json:
        print(json.dumps([
            {"id": s.id, "platform": s.platform.value, "category": s.category.value,
             "kind": s.kind, "match": s.match, "weight": s.weight, "description": s.description}
            for s in signals
        ], indent=2))
    else:
        for s in signals:
            print(f"{s.id:32} {s.platform.value:7} {s.category.value:9} w{s.weight} — {s.description}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rootsentry", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="store_true")
    sub = parser.add_subparsers(dest="command")

    p_eval = sub.add_parser("eval", help="evaluate a device evidence snapshot")
    p_eval.add_argument("evidence")
    p_eval.add_argument("--json", action="store_true")
    p_eval.add_argument("--fail-on", choices=[p.name for p in Posture])
    p_eval.set_defaults(func=cmd_eval)

    p_cat = sub.add_parser("catalog", help="list indicator catalog")
    p_cat.add_argument("--platform", choices=["android", "ios"])
    p_cat.add_argument("--json", action="store_true")
    p_cat.set_defaults(func=cmd_catalog)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "version", False):
        from . import __version__
        print(__version__)
        return 0
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
