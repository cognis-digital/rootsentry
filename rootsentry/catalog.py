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
    attack: tuple = ()     # MITRE ATT&CK for Mobile technique IDs this maps to


def _s(*args, **kwargs) -> Signal:
    return Signal(*args, **kwargs)


# MITRE ATT&CK for Mobile technique IDs referenced below (real, documented):
#   T1630.003  Disguise Root/Jailbreak Indicators
#   T1617      Hooking
#   T1631      Process Injection ; T1631.001 Ptrace System Calls
#   T1633      Virtualization/Sandbox Evasion ; T1633.001 System Checks
#   T1406.002  Software Packing
#   T1577      Compromise Application Executable
#   T1404      Exploitation for Privilege Escalation
#   T1658      Exploitation for Client Execution
# See https://attack.mitre.org/matrices/mobile/ — used here for defensive
# enrichment/mapping only.


CATALOG: list[Signal] = [
    # --- Android root ---
    _s("android.su.system_xbin", Platform.ANDROID, Category.ROOT, FILE, "/system/xbin/su", 9,
       "su binary present in /system/xbin (classic root)", attack=("T1404",)),
    _s("android.su.system_bin", Platform.ANDROID, Category.ROOT, FILE, "/system/bin/su", 9,
       "su binary present in /system/bin", attack=("T1404",)),
    _s("android.su.sbin", Platform.ANDROID, Category.ROOT, FILE, "/sbin/su", 9,
       "su binary present in /sbin", attack=("T1404",)),
    _s("android.su.vendor", Platform.ANDROID, Category.ROOT, FILE, "/vendor/bin/su", 9,
       "su binary present in /vendor/bin", attack=("T1404",)),
    _s("android.magisk.pkg", Platform.ANDROID, Category.ROOT, PACKAGE, "com.topjohnwu.magisk", 9,
       "Magisk manager installed", attack=("T1404", "T1630.003")),
    _s("android.magisk.repackaged", Platform.ANDROID, Category.ROOT, PACKAGE, "io.github.huskydg.magisk", 9,
       "Repackaged/renamed Magisk (stub-rename to evade detection)", attack=("T1630.003",)),
    _s("android.magisk.path", Platform.ANDROID, Category.ROOT, FILE, "/sbin/.magisk", 9,
       "Magisk runtime directory present", attack=("T1404", "T1630.003")),
    _s("android.superuser.pkg", Platform.ANDROID, Category.ROOT, PACKAGE, "eu.chainfire.supersu", 8,
       "SuperSU installed", attack=("T1404",)),
    _s("android.kingroot.pkg", Platform.ANDROID, Category.ROOT, PACKAGE, "com.kingroot.kinguser", 8,
       "KingRoot/KingUser one-click root installed", attack=("T1404",)),
    _s("android.busybox", Platform.ANDROID, Category.ROOT, FILE, "/system/xbin/busybox", 6,
       "busybox present (common on rooted devices)"),
    _s("android.build.testkeys", Platform.ANDROID, Category.ROOT, PROP, "ro.build.tags", 7,
       "Build signed with test-keys rather than release-keys", prop_value="test-keys"),
    _s("android.ro.debuggable", Platform.ANDROID, Category.DEBUGGER, PROP, "ro.debuggable", 6,
       "System build is debuggable (ro.debuggable=1)", prop_value="1"),
    _s("android.ro.secure", Platform.ANDROID, Category.ROOT, PROP, "ro.secure", 7,
       "Non-secure system build (ro.secure=0)", prop_value="0"),
    _s("android.selinux.permissive", Platform.ANDROID, Category.ROOT, PROP, "ro.boot.selinux", 7,
       "SELinux forced permissive (enforcement disabled)", prop_value="permissive"),
    _s("android.bootloader.unlocked", Platform.ANDROID, Category.TAMPER, PROP, "ro.boot.verifiedbootstate", 7,
       "Verified-boot state not green (unlocked/tampered bootloader)", prop_value="orange"),
    _s("android.flash.locked_no", Platform.ANDROID, Category.TAMPER, PROP, "ro.boot.flash.locked", 6,
       "Flash partition unlocked (ro.boot.flash.locked=0)", prop_value="0"),

    # --- Android emulator ---
    _s("android.emu.goldfish", Platform.ANDROID, Category.EMULATOR, PROP, "ro.hardware", 5,
       "Emulator hardware (goldfish/ranchu)", prop_value="goldfish", attack=("T1633.001",)),
    _s("android.emu.ranchu", Platform.ANDROID, Category.EMULATOR, PROP, "ro.hardware", 5,
       "Emulator hardware (ranchu)", prop_value="ranchu", attack=("T1633.001",)),
    _s("android.emu.generic", Platform.ANDROID, Category.EMULATOR, PROP, "ro.product.model", 4,
       "Generic/emulator product model", prop_value="sdk", attack=("T1633.001",)),
    _s("android.emu.qemu", Platform.ANDROID, Category.EMULATOR, PROP, "ro.kernel.qemu", 6,
       "QEMU kernel flag set", prop_value="1", attack=("T1633.001",)),
    _s("android.emu.genymotion", Platform.ANDROID, Category.EMULATOR, FILE, "/dev/socket/genyd", 6,
       "Genymotion emulator control socket present", attack=("T1633.001",)),
    _s("android.emu.qemu_pipe", Platform.ANDROID, Category.EMULATOR, FILE, "/dev/qemu_pipe", 6,
       "QEMU pipe device present (emulator)", attack=("T1633.001",)),

    # --- Android hooking / instrumentation ---
    _s("android.frida.port", Platform.ANDROID, Category.HOOK, PORT, "27042", 8,
       "frida-server default control port open", attack=("T1617", "T1631")),
    _s("android.frida.lib", Platform.ANDROID, Category.HOOK, FILE, "/data/local/tmp/frida-server", 8,
       "frida-server binary staged in /data/local/tmp", attack=("T1617", "T1631")),
    _s("android.frida.gadget", Platform.ANDROID, Category.HOOK, FILE, "/data/local/tmp/libfrida-gadget.so", 8,
       "frida-gadget injectable library staged", attack=("T1617", "T1631")),
    _s("android.frida.maps", Platform.ANDROID, Category.HOOK, FLAG, "frida_in_memory_maps", 8,
       "frida-agent/gum strings found in /proc/self/maps (in-process injection)",
       attack=("T1617", "T1631.001")),
    _s("android.xposed.pkg", Platform.ANDROID, Category.HOOK, PACKAGE, "de.robv.android.xposed.installer", 8,
       "Xposed framework installed", attack=("T1617",)),
    _s("android.lsposed.pkg", Platform.ANDROID, Category.HOOK, PACKAGE, "org.lsposed.manager", 8,
       "LSPosed (Zygisk-based Xposed) manager installed", attack=("T1617",)),
    _s("android.substrate", Platform.ANDROID, Category.HOOK, FILE, "/system/lib/libsubstrate.so", 7,
       "Cydia Substrate library present", attack=("T1617",)),
    _s("android.ptrace.tracerpid", Platform.ANDROID, Category.DEBUGGER, FLAG, "tracerpid_nonzero", 7,
       "TracerPid != 0 in /proc/self/status (process is being ptraced)",
       attack=("T1631.001",)),

    # --- iOS jailbreak ---
    _s("ios.cydia.app", Platform.IOS, Category.JAILBREAK, FILE, "/Applications/Cydia.app", 9,
       "Cydia installed (classic jailbreak)", attack=("T1404",)),
    _s("ios.sileo.app", Platform.IOS, Category.JAILBREAK, FILE, "/Applications/Sileo.app", 9,
       "Sileo package manager installed", attack=("T1404",)),
    _s("ios.zebra.app", Platform.IOS, Category.JAILBREAK, FILE, "/Applications/Zebra.app", 9,
       "Zebra package manager installed", attack=("T1404",)),
    _s("ios.bash", Platform.IOS, Category.JAILBREAK, FILE, "/bin/bash", 7,
       "Shell present at /bin/bash (not on stock iOS)", attack=("T1404",)),
    _s("ios.sh", Platform.IOS, Category.JAILBREAK, FILE, "/bin/sh", 7,
       "Shell present at /bin/sh (not on stock iOS)", attack=("T1404",)),
    _s("ios.apt", Platform.IOS, Category.JAILBREAK, FILE, "/etc/apt", 7,
       "APT package directory present", attack=("T1404",)),
    _s("ios.jailbreakd", Platform.IOS, Category.JAILBREAK, FILE, "/var/jb/usr/bin/jailbreakd", 9,
       "jailbreakd present under rootless /var/jb (Dopamine/rootless JB)", attack=("T1404",)),
    _s("ios.mobilesubstrate", Platform.IOS, Category.HOOK, FILE,
       "/Library/MobileSubstrate/MobileSubstrate.dylib", 8,
       "MobileSubstrate hooking library present", attack=("T1617",)),
    _s("ios.substitute", Platform.IOS, Category.HOOK, FILE,
       "/usr/lib/substitute-inserter.dylib", 8,
       "Substitute hooking framework present", attack=("T1617",)),
    _s("ios.dyld.insert", Platform.IOS, Category.HOOK, FLAG, "dyld_insert_libraries_set", 8,
       "DYLD_INSERT_LIBRARIES env var set (dylib injection)", attack=("T1617", "T1631")),
    _s("ios.sandbox.escape", Platform.IOS, Category.JAILBREAK, FLAG, "can_write_outside_sandbox", 9,
       "App could write outside its sandbox (fork/write test passed)", attack=("T1404",)),
    _s("ios.fork.allowed", Platform.IOS, Category.JAILBREAK, FLAG, "fork_succeeded", 6,
       "fork() succeeded — stock iOS denies this to sandboxed apps", attack=("T1404",)),
    _s("ios.frida.port", Platform.IOS, Category.HOOK, PORT, "27042", 8,
       "frida-server default control port open", attack=("T1617", "T1631")),

    # --- Cross-platform tamper / debugger ---
    _s("any.debugger.attached", Platform.BOTH, Category.DEBUGGER, FLAG, "debugger_attached", 7,
       "A debugger is attached to the process", attack=("T1631.001",)),
    _s("any.signature.mismatch", Platform.BOTH, Category.TAMPER, FLAG, "signature_mismatch", 10,
       "App signing certificate does not match the expected pin (repackaged)",
       attack=("T1577", "T1661")),
    _s("any.integrity.fail", Platform.BOTH, Category.TAMPER, FLAG, "integrity_check_failed", 9,
       "Code/resource integrity check failed", attack=("T1577",)),
    _s("any.packer.detected", Platform.BOTH, Category.TAMPER, FLAG, "packer_detected", 7,
       "Executable is packed/obfuscated (signature-evasion packer)", attack=("T1406.002",)),
    _s("any.proxy.mitm", Platform.BOTH, Category.TAMPER, FLAG, "system_proxy_active", 5,
       "System HTTP proxy configured (possible interception/MITM during analysis)"),
    _s("any.user.ca", Platform.BOTH, Category.TAMPER, FLAG, "user_ca_installed", 6,
       "User-installed CA in trust store (TLS interception setup)"),
]


# Human-readable names for the ATT&CK for Mobile techniques referenced above.
ATTACK_NAMES: dict[str, str] = {
    "T1404": "Exploitation for Privilege Escalation",
    "T1406.002": "Software Packing",
    "T1577": "Compromise Application Executable",
    "T1617": "Hooking",
    "T1630.003": "Disguise Root/Jailbreak Indicators",
    "T1631": "Process Injection",
    "T1631.001": "Ptrace System Calls",
    "T1633.001": "System Checks",
    "T1661": "Application Versioning",
}


def for_platform(platform: Platform) -> list[Signal]:
    return [s for s in CATALOG if s.platform in (platform, Platform.BOTH)]


def by_id(signal_id: str) -> Signal | None:
    for s in CATALOG:
        if s.id == signal_id:
            return s
    return None


def for_technique(technique: str) -> list[Signal]:
    """All catalog signals that map to a given ATT&CK technique id."""
    return [s for s in CATALOG if technique in s.attack]
