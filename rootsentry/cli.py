"""rootsentry CLI.

    rootsentry eval evidence.json [--json] [--fail-on COMPROMISED]
    rootsentry fleet snapshots.json [--json] [--devices] [--fail-rate 0.2]
    rootsentry catalog [--platform android|ios] [--json]
    rootsentry attack [--json]

``eval`` reads one device telemetry snapshot and prints the posture verdict.
``fleet`` ingests a batch (JSON array, or {"devices":[...]}) and reports the
population posture, indicator co-occurrence, attacker profiles and outliers.
``--fail-on`` / ``--fail-rate`` set exit-code thresholds for CI / attestation
gating.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from .catalog import Platform, for_platform, ATTACK_NAMES, for_technique
from .engine import Evidence, Posture, evaluate


def cmd_eval(args: argparse.Namespace) -> int:
    with open(args.evidence, "r", encoding="utf-8") as fh:
        ev = Evidence.from_dict(json.load(fh))
    verdict = evaluate(ev)
    from .fleet import classify_profiles
    profiles = classify_profiles(verdict)
    if args.json:
        out = verdict.to_dict()
        out["profiles"] = [
            {"id": p.id, "label": p.label, "severity": p.severity} for p in profiles
        ]
        print(json.dumps(out, indent=2))
    else:
        print(f"posture: {verdict.posture.label}  (score {verdict.score}/100)")
        for s in verdict.fired:
            tags = f"  [{','.join(s.attack)}]" if s.attack else ""
            print(f"  [{s.weight:2}] {s.category.value:9} {s.id} — {s.description}{tags}")
        if not verdict.fired:
            print("  no indicators fired")
        if verdict.techniques:
            print("ATT&CK: " + ", ".join(
                f"{t} {ATTACK_NAMES.get(t, '')}" for t in verdict.techniques))
        for p in profiles:
            print(f"PROFILE [{p.severity}] {p.label}")
    threshold = Posture[args.fail_on] if args.fail_on else None
    if threshold is not None and verdict.posture >= threshold:
        return 1
    return 0


def _load_snapshots(path: str) -> list:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("devices", data.get("snapshots", []))
    if not isinstance(data, list):
        raise ValueError("fleet input must be a JSON array or {'devices': [...]}")
    return data


def cmd_fleet(args: argparse.Namespace) -> int:
    from .fleet import analyze_fleet, PROFILES
    snaps = _load_snapshots(args.snapshots)
    report = analyze_fleet(snaps)
    if args.json:
        print(json.dumps(report.to_dict(include_devices=args.devices), indent=2))
    else:
        print(f"fleet: {report.total} devices  "
              f"compromised-rate {report.compromised_rate:.1%}")
        print("posture:")
        for p in Posture:
            print(f"  {p.label:11} {report.posture_counts.get(p.label, 0)}")
        if report.profile_counts:
            print("attacker profiles:")
            labels = {p.id: p.label for p in PROFILES}
            for pid, c in sorted(report.profile_counts.items(), key=lambda kv: -kv[1]):
                print(f"  [{c:4}] {labels.get(pid, pid)}")
        if report.cooccurrence:
            print("indicator co-occurrence (count, lift):")
            for a, b, c, lift in report.cooccurrence[:10]:
                print(f"  {c:4}x  lift {lift:4.1f}  {a} + {b}")
        if report.technique_counts:
            print("ATT&CK techniques:")
            for t, c in sorted(report.technique_counts.items(), key=lambda kv: -kv[1]):
                print(f"  [{c:4}] {t} {ATTACK_NAMES.get(t, '')}")
        if report.outliers:
            print("outliers (most indicators):")
            for did, sc, n in report.outliers[:10]:
                print(f"  {did:20} {n} signals  score {sc}")
        if args.devices:
            print("devices:")
            for r in report.devices:
                prof = ",".join(p.id for p in r.profiles)
                print(f"  {r.device_id:20} {r.verdict.posture.label:11} "
                      f"{r.verdict.score:3}  {prof}")
    if args.fail_rate is not None and report.compromised_rate >= args.fail_rate:
        return 1
    return 0


def cmd_attack(args: argparse.Namespace) -> int:
    rows = []
    for tid, name in sorted(ATTACK_NAMES.items()):
        sigs = for_technique(tid)
        rows.append((tid, name, [s.id for s in sigs]))
    if args.json:
        print(json.dumps(
            [{"id": t, "name": n, "signals": s} for t, n, s in rows], indent=2))
    else:
        for tid, name, sigs in rows:
            print(f"{tid:11} {name}")
            for sid in sigs:
                print(f"    - {sid}")
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

    p_fleet = sub.add_parser("fleet", help="analyze a batch of device snapshots")
    p_fleet.add_argument("snapshots")
    p_fleet.add_argument("--json", action="store_true")
    p_fleet.add_argument("--devices", action="store_true",
                         help="include per-device rows in the output")
    p_fleet.add_argument("--fail-rate", type=float, default=None,
                         help="exit 1 if compromised-rate >= this fraction (0-1)")
    p_fleet.set_defaults(func=cmd_fleet)

    p_cat = sub.add_parser("catalog", help="list indicator catalog")
    p_cat.add_argument("--platform", choices=["android", "ios"])
    p_cat.add_argument("--json", action="store_true")
    p_cat.set_defaults(func=cmd_catalog)

    p_atk = sub.add_parser("attack", help="show ATT&CK technique -> signal mapping")
    p_atk.add_argument("--json", action="store_true")
    p_atk.set_defaults(func=cmd_attack)
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
