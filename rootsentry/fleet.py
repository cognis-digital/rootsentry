"""Fleet / cohort analysis for rootsentry.

A single-device verdict tells you whether *one* runtime can be trusted. When you
operate an app or an attestation backend at scale you get thousands of evidence
snapshots, and the interesting questions become *population* questions:

  * What share of the fleet is COMPROMISED/CRITICAL right now, and is it drifting?
  * Which indicators *co-occur*? Attacker toolkits leave correlated fingerprints
    (Magisk + Zygisk + frida = active dynamic instrumentation; goldfish + sdk
    model + qemu = an emulator farm). Co-occurrence is far harder to spoof than
    any single check, so it is the strongest signal you have.
  * Which devices are *outliers* — many low-weight oddities that no single rule
    flags as CRITICAL but together look engineered?
  * Which recognizable **attacker profiles** is the fleet exhibiting, so triage
    and response can be templated instead of done device-by-device?

This module is pure-stdlib and offline: it consumes the same :class:`Evidence`
snapshots the engine already scores. Defensive use only — it summarizes and
classifies your own telemetry; it never modifies a device.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations

from .catalog import Signal, Category, ATTACK_NAMES
from .engine import Evidence, Verdict, Posture, evaluate


# --------------------------------------------------------------------------- #
# Attacker profiles
# --------------------------------------------------------------------------- #
# A profile is recognized when ALL of its `requires_any` groups are satisfied:
# each group is an OR over signal ids, and the profile needs at least one hit in
# every group (AND across groups). This encodes "toolkit A and toolkit B were
# both present", which is the co-occurrence pattern that distinguishes a serious
# instrumentation setup from an incidentally-rooted daily driver.

@dataclass(frozen=True)
class Profile:
    id: str
    label: str
    severity: str                 # info | elevated | high | critical
    requires_any: tuple           # tuple of tuples; each inner tuple is an OR group
    description: str

    def matches(self, fired_ids: set) -> bool:
        return all(any(sid in fired_ids for sid in group) for group in self.requires_any)


PROFILES: list[Profile] = [
    Profile(
        "dynamic_instrumentation",
        "Active dynamic instrumentation (frida/hook)",
        "critical",
        (
            ("android.frida.port", "android.frida.lib", "android.frida.gadget",
             "android.frida.maps", "ios.frida.port", "android.xposed.pkg",
             "android.lsposed.pkg", "ios.mobilesubstrate", "ios.substitute",
             "ios.dyld.insert", "android.substrate"),
        ),
        "A hooking/instrumentation toolkit is live on the device. This is the "
        "signature of someone actively reverse-engineering or tampering with the "
        "running app, not a casual rooted user. Treat as targeted.",
    ),
    Profile(
        "rooted_and_hooked",
        "Rooted device running an instrumentation framework",
        "critical",
        (
            ("android.su.system_xbin", "android.su.system_bin", "android.su.sbin",
             "android.su.vendor", "android.magisk.pkg", "android.magisk.path",
             "ios.cydia.app", "ios.sileo.app", "ios.jailbreakd"),
            ("android.frida.port", "android.frida.lib", "android.frida.gadget",
             "android.frida.maps", "ios.frida.port", "android.xposed.pkg",
             "android.lsposed.pkg", "ios.mobilesubstrate", "android.substrate"),
        ),
        "Privilege escalation (root/jailbreak) AND a hooking framework together — "
        "the device is fully under operator control and being instrumented.",
    ),
    Profile(
        "emulator_farm",
        "Emulator / automation farm",
        "high",
        (
            ("android.emu.goldfish", "android.emu.ranchu", "android.emu.qemu",
             "android.emu.generic", "android.emu.genymotion", "android.emu.qemu_pipe"),
        ),
        "Runtime presents as an emulator. At fleet scale, a spike of identical "
        "emulator snapshots indicates a fraud/automation farm (account creation, "
        "promo abuse, scripted actions) rather than real users.",
    ),
    Profile(
        "repackaged_app",
        "Repackaged / cloned application",
        "critical",
        (
            ("any.signature.mismatch", "any.integrity.fail", "any.packer.detected"),
        ),
        "The running binary does not match the expected signing identity or failed "
        "an integrity check. The app was repackaged — trojanized clone, modded "
        "build, or a tampered copy used to bypass licensing/controls.",
    ),
    Profile(
        "mitm_analysis",
        "Traffic-interception / analysis setup",
        "high",
        (
            ("any.proxy.mitm", "any.user.ca", "any.debugger.attached",
             "android.ptrace.tracerpid"),
            ("android.frida.port", "android.frida.lib", "android.frida.maps",
             "ios.frida.port", "any.debugger.attached", "android.ptrace.tracerpid",
             "android.su.system_xbin", "android.magisk.pkg", "ios.cydia.app"),
        ),
        "A proxy/user-CA or attached debugger combined with elevated access — the "
        "classic setup for intercepting and rewriting the app's network traffic.",
    ),
    Profile(
        "evasive_root",
        "Root hidden behind detection-evasion",
        "high",
        (
            ("android.magisk.repackaged", "android.magisk.path", "android.selinux.permissive"),
        ),
        "Root present together with anti-detection measures (renamed Magisk, "
        "forced-permissive SELinux). The operator is specifically trying to defeat "
        "root detection — a deliberate, knowledgeable adversary.",
    ),
]


def classify_profiles(verdict: Verdict) -> list[Profile]:
    """Return the attacker profiles a single verdict matches, severest first."""
    fired_ids = {s.id for s in verdict.fired}
    order = {"critical": 0, "high": 1, "elevated": 2, "info": 3}
    hits = [p for p in PROFILES if p.matches(fired_ids)]
    hits.sort(key=lambda p: order.get(p.severity, 9))
    return hits


# --------------------------------------------------------------------------- #
# Fleet report
# --------------------------------------------------------------------------- #

@dataclass
class DeviceResult:
    device_id: str
    verdict: Verdict
    profiles: list[Profile] = field(default_factory=list)


@dataclass
class FleetReport:
    total: int
    posture_counts: dict                  # label -> count
    signal_counts: dict                   # signal id -> count
    category_counts: dict                 # category -> count
    technique_counts: dict                # ATT&CK id -> count
    profile_counts: dict                  # profile id -> count
    cooccurrence: list                    # [(idA, idB, count, lift), ...]
    outliers: list                        # [(device_id, score, n_signals), ...]
    devices: list = field(default_factory=list)

    @property
    def compromised_rate(self) -> float:
        bad = self.posture_counts.get("COMPROMISED", 0) + self.posture_counts.get("CRITICAL", 0)
        return (bad / self.total) if self.total else 0.0

    def to_dict(self, include_devices: bool = False) -> dict:
        d = {
            "total": self.total,
            "compromised_rate": round(self.compromised_rate, 4),
            "posture_counts": self.posture_counts,
            "category_counts": self.category_counts,
            "technique_counts": [
                {"id": t, "name": ATTACK_NAMES.get(t, ""), "count": c}
                for t, c in sorted(self.technique_counts.items(), key=lambda kv: -kv[1])
            ],
            "profile_counts": self.profile_counts,
            "top_signals": sorted(
                ({"id": k, "count": v} for k, v in self.signal_counts.items()),
                key=lambda x: -x["count"],
            )[:20],
            "cooccurrence": [
                {"a": a, "b": b, "count": c, "lift": round(lift, 2)}
                for (a, b, c, lift) in self.cooccurrence
            ],
            "outliers": [
                {"device_id": did, "score": sc, "signals": n}
                for (did, sc, n) in self.outliers
            ],
        }
        if include_devices:
            d["devices"] = [
                {
                    "device_id": r.device_id,
                    "posture": r.verdict.posture.label,
                    "score": r.verdict.score,
                    "profiles": [p.id for p in r.profiles],
                    "fired": [s.id for s in r.verdict.fired],
                }
                for r in self.devices
            ]
        return d


def _cooccurrence(per_device_ids: list, total: int, min_count: int = 2):
    """Pairwise co-occurrence with a lift score.

    lift = P(A and B) / (P(A) * P(B)). lift > 1 means the two indicators show up
    together more than chance would predict — i.e. they belong to the same
    toolkit/fingerprint. We surface only pairs seen at least ``min_count`` times.
    """
    single: dict = {}
    pair: dict = {}
    for ids in per_device_ids:
        uniq = sorted(set(ids))
        for sid in uniq:
            single[sid] = single.get(sid, 0) + 1
        for a, b in combinations(uniq, 2):
            pair[(a, b)] = pair.get((a, b), 0) + 1
    out = []
    for (a, b), c in pair.items():
        if c < min_count:
            continue
        pa = single[a] / total
        pb = single[b] / total
        pab = c / total
        lift = pab / (pa * pb) if pa and pb else 0.0
        out.append((a, b, c, lift))
    # strongest co-occurrence first: by count, then lift
    out.sort(key=lambda t: (-t[2], -t[3]))
    return out


def analyze_fleet(
    snapshots: list,
    *,
    outlier_min_signals: int = 3,
    cooccurrence_min_count: int = 2,
) -> FleetReport:
    """Score a batch of device snapshots and summarize the population.

    ``snapshots`` is a list of dicts. Each may carry an optional ``device_id``
    (or ``id``); the rest of the dict is parsed as :class:`Evidence`.
    """
    devices: list = []
    posture_counts: dict = {p.name: 0 for p in Posture}
    signal_counts: dict = {}
    category_counts: dict = {}
    technique_counts: dict = {}
    profile_counts: dict = {}
    per_device_ids: list = []

    for i, snap in enumerate(snapshots):
        did = str(snap.get("device_id") or snap.get("id") or f"device-{i}")
        ev = Evidence.from_dict(snap)
        verdict = evaluate(ev)
        profiles = classify_profiles(verdict)

        posture_counts[verdict.posture.label] += 1
        ids = [s.id for s in verdict.fired]
        per_device_ids.append(ids)
        for s in verdict.fired:
            signal_counts[s.id] = signal_counts.get(s.id, 0) + 1
        for cat, n in verdict.categories.items():
            category_counts[cat] = category_counts.get(cat, 0) + n
        for t in verdict.techniques:
            technique_counts[t] = technique_counts.get(t, 0) + 1
        for p in profiles:
            profile_counts[p.id] = profile_counts.get(p.id, 0) + 1

        devices.append(DeviceResult(did, verdict, profiles))

    total = len(snapshots)
    cooc = _cooccurrence(per_device_ids, total, min_count=cooccurrence_min_count) if total else []

    # Outliers: devices with many indicators but that did not already hit CRITICAL
    # on a single high-weight rule — i.e. "death by a thousand cuts" snapshots
    # that a per-rule threshold would under-rate. Ranked by signal count.
    outliers = []
    for r in devices:
        n = len(r.verdict.fired)
        if n >= outlier_min_signals:
            outliers.append((r.device_id, r.verdict.score, n))
    outliers.sort(key=lambda t: (-t[2], -t[1]))

    return FleetReport(
        total=total,
        posture_counts=posture_counts,
        signal_counts=signal_counts,
        category_counts=category_counts,
        technique_counts=technique_counts,
        profile_counts=profile_counts,
        cooccurrence=cooc,
        outliers=outliers,
        devices=devices,
    )
