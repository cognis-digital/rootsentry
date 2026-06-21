"""Catalog of mobile compromise indicators.

Each :class:`Signal` describes one observable indicator that a device is
rooted, jailbroken, emulated, or being instrumented/hooked. Signals are
data, not code: an app collects *evidence* (files it can see, packages
installed, system properties, listening ports) on-device and rootsentry's
engine matches that evidence against this catalog.

The catalog encodes well-known, publicly-documented indicators used by mobile
hardening libraries. It is defensive: the goal is for *your* app to recognize a
compromised runtime and react (degrade, warn, refuse high-risk actions).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Platform(str, Enum):
    ANDROID = "android"
    IOS = "ios"
    BOTH = "both"


class Category(str, Enum):
    ROOT = "root"
    JAILBREAK = "jailbreak"
    EMULATOR = "emulator"
    HOOK = "hook"
    DEBUGGER = "debugger"
    TAMPER = "tamper"


# evidence kinds a signal can match against
FILE = "file_present"
PACKAGE = "package_installed"
PROP = "system_prop"
PORT = "open_port"
FLAG = "runtime_flag"


@dataclass(frozen=True)
class Signal:
    id: str
    platform: Platform
    category: Category
    kind: str           # one of FILE / PACKAGE / PROP / PORT / FLAG
    match: str          # path, package id, "prop=value", port number, or flag name
    weight: int         # 1-10 contribution to risk score
    description: str
    prop_value: str = ""   # for PROP signals, the expected/suspicious value (substring)


def _s(*args, **kwargs) -> Signal:
    return Signal(*args, **kwargs)


CATALOG: list[Signal] = [
    # --- Android root ---
    _s("android.su.system_xbin", Platform.ANDROID, Category.ROOT, FILE, "/system/xbin/su", 9,
       "su binary present in /system/xbin (classic root)"),
    _s("android.su.system_bin", Platform.ANDROID, Category.ROOT, FILE, "/system/bin/su", 9,
       "su binary present in /system/bin"),
    _s("android.magisk.pkg", Platform.ANDROID, Category.ROOT, PACKAGE, "com.topjohnwu.magisk", 9,
       "Magisk manager installed"),
    _s("android.superuser.pkg", Platform.ANDROID, Category.ROOT, PACKAGE, "eu.chainfire.supersu", 8,
       "SuperSU installed"),
    _s("android.busybox", Platform.ANDROID, Category.ROOT, FILE, "/system/xbin/busybox", 6,
       "busybox present (common on rooted devices)"),
    _s("android.build.testkeys", Platform.ANDROID, Category.ROOT, PROP, "ro.build.tags", 7,
       "Build signed with test-keys rather than release-keys", prop_value="test-keys"),
    _s("android.ro.debuggable", Platform.ANDROID, Category.DEBUGGER, PROP, "ro.debuggable", 6,
       "System build is debuggable (ro.debuggable=1)", prop_value="1"),
    _s("android.ro.secure", Platform.ANDROID, Category.ROOT, PROP, "ro.secure", 7,
       "Non-secure system build (ro.secure=0)", prop_value="0"),

    # --- Android emulator ---
    _s("android.emu.goldfish", Platform.ANDROID, Category.EMULATOR, PROP, "ro.hardware", 5,
       "Emulator hardware (goldfish/ranchu)", prop_value="goldfish"),
    _s("android.emu.ranchu", Platform.ANDROID, Category.EMULATOR, PROP, "ro.hardware", 5,
       "Emulator hardware (ranchu)", prop_value="ranchu"),
    _s("android.emu.generic", Platform.ANDROID, Category.EMULATOR, PROP, "ro.product.model", 4,
       "Generic/emulator product model", prop_value="sdk"),
    _s("android.emu.qemu", Platform.ANDROID, Category.EMULATOR, PROP, "ro.kernel.qemu", 6,
       "QEMU kernel flag set", prop_value="1"),

    # --- Android hooking / instrumentation ---
    _s("android.frida.port", Platform.ANDROID, Category.HOOK, PORT, "27042", 8,
       "frida-server default control port open"),
    _s("android.frida.lib", Platform.ANDROID, Category.HOOK, FILE, "/data/local/tmp/frida-server", 8,
       "frida-server binary staged in /data/local/tmp"),
    _s("android.xposed.pkg", Platform.ANDROID, Category.HOOK, PACKAGE, "de.robv.android.xposed.installer", 8,
       "Xposed framework installed"),
    _s("android.substrate", Platform.ANDROID, Category.HOOK, FILE, "/system/lib/libsubstrate.so", 7,
       "Cydia Substrate library present"),

    # --- iOS jailbreak ---
    _s("ios.cydia.app", Platform.IOS, Category.JAILBREAK, FILE, "/Applications/Cydia.app", 9,
       "Cydia installed (classic jailbreak)"),
    _s("ios.sileo.app", Platform.IOS, Category.JAILBREAK, FILE, "/Applications/Sileo.app", 9,
       "Sileo package manager installed"),
    _s("ios.bash", Platform.IOS, Category.JAILBREAK, FILE, "/bin/bash", 7,
       "Shell present at /bin/bash (not on stock iOS)"),
    _s("ios.apt", Platform.IOS, Category.JAILBREAK, FILE, "/etc/apt", 7,
       "APT package directory present"),
    _s("ios.mobilesubstrate", Platform.IOS, Category.HOOK, FILE,
       "/Library/MobileSubstrate/MobileSubstrate.dylib", 8,
       "MobileSubstrate hooking library present"),
    _s("ios.sandbox.escape", Platform.IOS, Category.JAILBREAK, FLAG, "can_write_outside_sandbox", 9,
       "App could write outside its sandbox (fork/write test passed)"),
    _s("ios.fork.allowed", Platform.IOS, Category.JAILBREAK, FLAG, "fork_succeeded", 6,
       "fork() succeeded — stock iOS denies this to sandboxed apps"),
    _s("ios.frida.port", Platform.IOS, Category.HOOK, PORT, "27042", 8,
       "frida-server default control port open"),

    # --- Cross-platform tamper / debugger ---
    _s("any.debugger.attached", Platform.BOTH, Category.DEBUGGER, FLAG, "debugger_attached", 7,
       "A debugger is attached to the process"),
    _s("any.signature.mismatch", Platform.BOTH, Category.TAMPER, FLAG, "signature_mismatch", 10,
       "App signing certificate does not match the expected pin (repackaged)"),
    _s("any.integrity.fail", Platform.BOTH, Category.TAMPER, FLAG, "integrity_check_failed", 9,
       "Code/resource integrity check failed"),
]


def for_platform(platform: Platform) -> list[Signal]:
    return [s for s in CATALOG if s.platform in (platform, Platform.BOTH)]
