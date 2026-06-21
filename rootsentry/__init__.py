"""rootsentry — mobile runtime-integrity detection (root/jailbreak/emulator/hook/tamper).

Defensive library: match on-device telemetry against a catalog of well-known
compromise indicators and produce a risk score + posture verdict your app can
act on. Pure standard library; embeddable reference checks for Android/iOS live
under ``reference/``.
"""

from .catalog import Signal, Platform, Category, CATALOG, for_platform
from .engine import Evidence, Verdict, Posture, evaluate

__all__ = [
    "Signal", "Platform", "Category", "CATALOG", "for_platform",
    "Evidence", "Verdict", "Posture", "evaluate",
]

__version__ = "0.1.0"
