"""Evaluate on-device evidence against the indicator catalog.

The app collects an :class:`Evidence` snapshot at runtime (which suspicious
files it can stat, which packages are installed, system properties, listening
ports, runtime flags) and the engine returns which signals fired, an aggregate
risk score (0-100), and a posture verdict. The scoring is saturating so a few
high-weight indicators are enough to reach a CRITICAL posture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from .catalog import (
    Signal, Platform, Category, CATALOG, for_platform, ATTACK_NAMES,
    FILE, PACKAGE, PROP, PORT, FLAG,
)


class Posture(IntEnum):
    TRUSTED = 0
    SUSPICIOUS = 1
    COMPROMISED = 2
    CRITICAL = 3

    @property
    def label(self) -> str:
        return self.name


@dataclass
class Evidence:
    """A device telemetry snapshot. All fields optional; absent => not observed."""
    platform: Platform
    present_files: list[str] = field(default_factory=list)
    installed_packages: list[str] = field(default_factory=list)
    system_props: dict = field(default_factory=dict)   # name -> value
    open_ports: list[int] = field(default_factory=list)
    runtime_flags: list[str] = field(default_factory=list)  # flags observed true

    @classmethod
    def from_dict(cls, d: dict) -> "Evidence":
        return cls(
            platform=Platform(d.get("platform", "android")),
            present_files=list(d.get("present_files", [])),
            installed_packages=list(d.get("installed_packages", [])),
            system_props={str(k): str(v) for k, v in d.get("system_props", {}).items()},
            open_ports=[int(p) for p in d.get("open_ports", [])],
            runtime_flags=list(d.get("runtime_flags", [])),
        )


@dataclass
class Verdict:
    posture: Posture
    score: int
    fired: list[Signal]

    @property
    def categories(self) -> dict:
        """Map of fired Category -> count (e.g. {'root': 2, 'hook': 1})."""
        out: dict = {}
        for s in self.fired:
            out[s.category.value] = out.get(s.category.value, 0) + 1
        return out

    @property
    def techniques(self) -> list[str]:
        """Sorted, de-duplicated ATT&CK for Mobile technique ids that fired."""
        seen: set = set()
        for s in self.fired:
            seen.update(s.attack)
        return sorted(seen)

    def to_dict(self) -> dict:
        return {
            "posture": self.posture.label,
            "score": self.score,
            "categories": self.categories,
            "techniques": [
                {"id": t, "name": ATTACK_NAMES.get(t, "")} for t in self.techniques
            ],
            "fired": [
                {"id": s.id, "category": s.category.value, "weight": s.weight,
                 "description": s.description, "attack": list(s.attack)}
                for s in self.fired
            ],
        }


def _matches(signal: Signal, ev: Evidence) -> bool:
    if signal.kind == FILE:
        return signal.match in ev.present_files
    if signal.kind == PACKAGE:
        return signal.match in ev.installed_packages
    if signal.kind == PORT:
        return int(signal.match) in ev.open_ports
    if signal.kind == FLAG:
        return signal.match in ev.runtime_flags
    if signal.kind == PROP:
        observed = ev.system_props.get(signal.match)
        if observed is None:
            return False
        return signal.prop_value.lower() in observed.lower()
    return False


def evaluate(ev: Evidence, catalog: list[Signal] | None = None) -> Verdict:
    signals = catalog if catalog is not None else for_platform(ev.platform)
    fired = [s for s in signals if _matches(s, ev)]

    # Saturating score: 100 * (1 - prod(1 - w/12)) keeps a single weight-10 hit
    # high (~83) while multiple indicators converge toward 100.
    survival = 1.0
    for s in fired:
        survival *= (1.0 - min(s.weight, 11) / 12.0)
    score = round(100 * (1.0 - survival))

    if score >= 80:
        posture = Posture.CRITICAL
    elif score >= 50:
        posture = Posture.COMPROMISED
    elif score > 0:
        posture = Posture.SUSPICIOUS
    else:
        posture = Posture.TRUSTED

    fired.sort(key=lambda s: -s.weight)
    return Verdict(posture=posture, score=score, fired=fired)
