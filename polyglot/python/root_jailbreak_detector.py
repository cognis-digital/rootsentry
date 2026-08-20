"""
polyglot/python/root_jailbreak_detector.py

Mobile runtime-integrity detection: root/jailbreak/emulator/hook/tamper indicators 
with a scored posture verdict (RASP-style, zero deps).

Provides a single function `detect_root_jailbreak()` that returns structured results.
"""

import os
import sys
import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DetectionResult:
    """Structured result from the integrity check."""
    
    is_rooted: bool = False
    is_jailbroken: bool = False
    is_emulator: bool = False
    is_tampered: bool = False
    
    root_indicators: list[str] = None
    jailbreak_indicators: list[str] = None
    emulator_indicators: list[str] = None
    tamper_indicators: list[str] = None
    
    confidence_score: int = 0  # 0-100
    verdict: str = "CLEAN"
    
    def __post_init__(self):
        if self.root_indicators is None:
            object.__setattr__(self, 'root_indicators', [])
        if self.jailbreak_indicators is None:
            object.__setattr__(self, 'jailbreak_indicators', [])
        if self.emulator_indicators is None:
            object.__setattr__(self, 'emulator_indicators', [])
        if self.tamper_indicators is None:
            object.__setattr__(self, 'tamper_indicators', [])


def _safe_read_file(path: str) -> str | None:
    """Read file contents safely, return None on failure."""
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if len(content) > 4096:
                content = content[:4096] + "..."
            return content
    except (OSError, IOError):
        return None


def _safe_run_command(cmd: list[str], timeout: int = 5) -> str | None:
    """Run shell command safely, return output or None on failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, 
            timeout=timeout, env=os.environ.copy()
        )
        if result.returncode == 0:
            return result.stdout.strip()
        elif result.stderr and "No such file" not in result.stderr:
            # Command exists but failed (e.g., needs root)
            return result.stderr[:200].strip()
    except subprocess.TimeoutExpired:
        pass
    except OSError:
        pass
    return None


def _check_android_root_binaries() -> list[str]:
    """Check for Android-specific root binaries and paths."""
    indicators = []
    
    # Check /system/bin/su (classic root)
    if os.path.exists("/system/bin/su"):
        indicators.append("system/bin/su exists")
    
    # Check /data/local/su or /data/data/com.termux/files/usr/bin/su
    for path in ["/data/local/su", "/data/data/com.termux/files/usr/bin/su"]:
        if os.path.exists(path):
            indicators.append(f"data/{path.split('/')[-1]} exists")
    
    # Check busybox with su capability (common on rooted devices)
    if _safe_run_command(["which", "su"]):
        indicators.append("su found in PATH via which")
    
    # Check for Magisk-specific artifacts
    magisk_paths = [
        "/data/adb/magisk",
        "/data/adb/magisk.prop",
        "/system/bin/.magisk",
        "/system/etc/init/magisk.rc",
    ]
    for path in magisk_paths:
        if os.path.exists(path):
            indicators.append(f"Magisk artifact at {path}")
    
    # Check for KernelSU artifacts
    kernelsu_paths = [
        "/data/adb/kernelsu",
        "/system/bin/.kernelsu",
    ]
    for path in kernelsu_paths:
        if os.path.exists(path):
            indicators.append(f"KernelSU artifact at {path}")
    
    # Check for proot (user-space root)
    proot_indicators = ["/data/local/proot", "/system/bin/proot"]
    for path in proot_indicators:
        if os.path.exists(path):
            indicators.append(f"proot binary at {path}")
    
    return indicators


def _check_android_env_vars() -> list[str]:
    """Check Android-specific environment variables that indicate root."""
    indicators = []
    
    env_keys_to_check = [
        "PREFIX",  # Often set by proot/termux
        "TERMUX_VERSION",  # Termux indicator
        "ANDROID_ROOT",  # Sometimes set when rooted
    ]
    
    for key in env_keys_to_check:
        value = os.environ.get(key)
        if value:
            indicators.append(f"env {key}={value}")
    
    return indicators


def _check_android_emulator() -> list[str]:
    """Check for Android emulator artifacts."""
    indicators = []
    
    # Check emulator-specific files
    emulator_files = [
        "/system/etc/init/hw/android.d/emulator.rc",
        "/data/local.prop",  # Emulator often sets properties here
        "/data/adb/emulator",
    ]
    
    for path in emulator_files:
        if os.path.exists(path):
            indicators.append(f"emulator artifact at {path}")
    
    # Check device properties that indicate emulator
    prop_indicators = [
        "ro.product.model=Android SDK built for x86",
        "ro.product.model=SDK Phone",
        "ro.product.model=Google SDK Pixel Emulator",
        "ro.build.fingerprint=Android SDK/",
    ]
    
    # Read /proc/device-tree/com/google/android/emulator if available
    emulator_tree = "/proc/device-tree/com/google/android/emulator"
    if os.path.exists(emulator_tree):
        indicators.append("emulator device tree node present")
    
    return indicators


def _check_ios_jailbreak() -> list[str]:
    """Check for iOS jailbreak artifacts."""
    indicators = []
    
    # Check common jailbreak binary paths
    jailbreak_binaries = [
        "/usr/libexec/su",  # Common su location on jailbroken devices
        "/var/jb/",  # Sileo/Zeppelin storage
        "/Library/Jailbreak/",  # Cydia storage
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
    ]
    
    for path in jailbreak_binaries:
        if os.path.exists(path):
            indicators.append(f"jailbreak app at {path}")
    
    # Check environment variables
    env_indicators = [
        "SHARED_LIB_DIR",  # Often set by Cydia Substrate
        "DYLD_INSERT_LIBRARIES",  # Hook injection indicator
        "SUBSTRATE",  # Substrate framework
    ]
    
    for key in env_indicators:
        if os.environ.get(key):
            indicators.append(f"env {key} is set")
    
    return indicators


def _check_ios_emulator() -> list[str]:
    """Check for iOS Simulator artifacts."""
    indicators = []
    
    # Check simulator-specific paths
    simulator_paths = [
        "/Applications/Xcode.app/Contents/Developer/Applications/Simulator.app",
        "/Library/Developer/CoreSimulator/",
        "/var/folders/*/CoreSimulator-*.app",  # Dynamic path
    ]
    
    for path in simulator_paths:
        if os.path.exists(path):
            indicators.append(f"simulator artifact at {path}")
    
    return indicators


def _check_hooking_artifacts() -> list[str]:
    """Check for common hooking libraries and tampering."""
    indicators = []
    
    # Check for Frida artifacts
    frida_paths = [
        "/data/data/com.frida.server/",  # Android Frida server
        "/var/folders/*/frida-server",  # iOS Frida
    ]
    
    for path in frida_paths:
        if os.path.exists(path):
            indicators.append(f"possible Frida artifact at {path}")
    
    # Check for Xposed/Posix hooks
    xposed_indicators = [
        "/data/data/de.robv.android.xposed.installer/",
        "/system/lib/xposed",  # Android Xposed framework
    ]
    
    for path in xposed_indicators:
        if os.path.exists(path):
            indicators.append(f"Xposed artifact at {path}")
    
    # Check for LLDB/Debug symbols (often used by jailbreaks)
    lldb_paths = [
        "/usr/libexec/debugserver",  # iOS debug server
        "/data/data/com.apple.dt.xcode/",  # Xcode artifacts
    ]
    
    for path in lldb_paths:
        if os.path.exists(path):
            indicators.append(f"debug artifact at {path}")
    
    return indicators


def _calculate_confidence(indicators: list[str]) -> int:
    """Calculate confidence score based on number and type of indicators."""
    # Base score per indicator, with diminishing returns
    base_score = min(len(indicators) * 5, 40)
    
    # Bonus for "strong" indicators (binaries exist vs just env vars)
    strong_count = sum(1 for i in indicators if "exists" in i or ".app" in i or "/system/" in i)
    bonus = min(strong_count * 3, 20)
    
    # Bonus for multiple categories
    categories = set()
    for i in indicators:
        if "magisk" in i.lower():
            categories.add("root")
        elif "sileo" in i.lower() or "cydia" in i.lower():
            categories.add("jailbreak")
        elif "emulator" in i.lower():
            categories.add("emulator")
    
    category_bonus = min(len(categories) * 10, 25)
    
    return min(base_score + bonus + category_bonus, 100)


def _determine_verdict(score: int, root: bool, jailbreak: bool, emulator: bool, tamper: bool) -> str:
    """Determine human-readable verdict based on results."""
    if score >= 80 and (root or jailbreak):
        return "HIGHLY_SUSPECTED"
    elif score >= 50 and (root or jailbreak):
        return "SUSPECTED"
    elif score >= 30:
        return "POSSIBLY_TAMPERED"
    elif emulator:
        return "EMULATOR_DETECTED"
    elif tamper:
        return "TAMPER_INDICATORS_FOUND"
    else:
        return "CLEAN"


def detect_root_jailbreak() -> DetectionResult:
    """
    Main entry point for runtime integrity detection.
    
    Returns a DetectionResult with all findings and a confidence score.
    """
    root_indicators = []
    jailbreak_indicators = []
    emulator_indicators = []
    tamper_indicators = []
    
    # Android-specific checks
    android_root = _check_android_root_binaries()
    if android_root:
        root_indicators.extend(android_root)
    
    android_env = _check_android_env_vars()
    if android_env:
        root_indicators.extend(android_env)
    
    android_emulator = _check_android_emulator()
    if android_emulator:
        emulator_indicators.extend(android_emulator)
    
    # iOS-specific checks
    ios_jailbreak = _check_ios_jailbreak()
    if ios_jailbreak:
        jailbreak_indicators.extend(ios_jailbreak)
    
    ios_emulator = _check_ios_emulator()
    if ios_emulator:
        emulator_indicators.extend(ios_emulator)
    
    # Cross-platform hooking/tamper checks
    hook_artifacts = _check_hooking_artifacts()
    tamper_indicators.extend(hook_artifacts)
    
    # Calculate scores and verdicts
    all_indicators = root_indicators + jailbreak_indicators + emulator_indicators + tamper_indicators
    
    confidence = _calculate_confidence(all_indicators)
    verdict = _determine_verdict(
        confidence,
        len(root_indicators) > 0,
        len(jailbreak_indicators) > 0,
        len(emulator_indicators) > 0,
        len(tamper_indicators) > 0
    )
    
    return DetectionResult(
        is_rooted=len(root_indicators) > 0,
        is_jailbroken=len(jailbreak_indicators) > 0,
        is_emulator=len(emulator_indicators) > 0,
        is_tampered=len(tamper_indicators) > 0,
        root_indicators=root_indicators[:10],  # Limit output size
        jailbreak_indicators=jailbreak_indicators[:10],
        emulator_indicators=emulator_indicators[:10],
        tamper_indicators=tamper_indicators[:10],
        confidence_score=confidence,
        verdict=verdict,
    )


# =============================================================================
# Demo / Self-test when run as main module
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("ROOT/JAILBREAK/EMULATOR DETECTOR - Quick Check")
    print("=" * 60)
    
    result = detect_root_jailbreak()
    
    # Print summary
    print(f"\nVerdict: {result.verdict}")
    print(f"Confidence Score: {result.confidence_score}/100")
    print(f"Rooted: {result.is_rooted}")
    print(f"Jailbroken: {result.is_jailbroken}")
    print(f"Emulator: {result.is_emulator}")
    print(f"Tampered: {result.is_tampered}")
    
    # Print detailed indicators if any found
    if result.root_indicators or result.jailbreak_indicators:
        print("\n--- Root/Jailbreak Indicators ---")
        for i, ind in enumerate((result.root_indicators + result.jailbreak_indicators)[:15], 1):
            print(f"  {i}. {ind}")
    
    if result.emulator_indicators:
        print("\n--- Emulator Indicators ---")
        for i, ind in enumerate(result.emulator_indicators[:10], 1):
            print(f"  {i}. {ind}")
    
    if result.tamper_indicators:
        print("\n--- Tamper/Hook Indicators ---")
        for i, ind in enumerate(result.tamper_indicators[:10], 1):
            print(f"  {i}. {ind}")
    
    # Exit with appropriate code
    if result.confidence_score >= 50:
        sys.exit(1)  # Non-zero indicates potential compromise
    else:
        sys.exit(0)  # Zero indicates clean