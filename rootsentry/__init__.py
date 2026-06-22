"""rootsentry — mobile runtime-integrity detection (root/jailbreak/emulator/hook/tamper).

Defensive library: match on-device telemetry against a catalog of well-known
compromise indicators and produce a risk score + posture verdict your app can
act on. Pure standard library; embeddable reference checks for Android/iOS live
under ``reference/``.
"""

from .catalog import (
    Signal, Platform, Category, CATALOG, for_platform, for_technique,
    by_id, ATTACK_NAMES,
)
from .engine import Evidence, Verdict, Posture, evaluate
from .fleet import (
    Profile, PROFILES, classify_profiles,
    DeviceResult, FleetReport, analyze_fleet,
)

__all__ = [
    "Signal", "Platform", "Category", "CATALOG", "for_platform", "for_technique",
    "by_id", "ATTACK_NAMES",
    "Evidence", "Verdict", "Posture", "evaluate",
    "Profile", "PROFILES", "classify_profiles",
    "DeviceResult", "FleetReport", "analyze_fleet",
]

__version__ = "0.2.0"
