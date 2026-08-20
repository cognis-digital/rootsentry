"""
polyglot/python/hook_injection_scanner.py

Mobile runtime-integrity detection: hook injection scanner.
Detects Frida, Xposed, Substrate, Cydia, Zygisk, emulator hooks, and tamper artifacts.
Returns a scored posture verdict (RASP-style). Zero dependencies beyond stdlib.
"""

import os
import sys
import re
import subprocess
from typing import Dict, Any, List, Tuple


class HookInjectionScanner:
    """Scans for hook injection artifacts in mobile runtime environments."""

    # Known hook library paths and signatures
    FRIDA_PATHS = [
        "/data/local/tmp/frida-agent.so",
        "/data/data/com.android.vending/app_wide/libfrida-agent.so",
        "/system/lib/libfrida-agent.so",
        "/system/lib64/libfrida-agent.so",
        "/data/data/frida/frida-agent.so",
    ]

    XPOSED_PATHS = [
        "/data/data/com.android.vending/app_wide/xposed-daemon.jar",
        "/system/framework/xposed-framework.jar",
        "/data/local/tmp/xposed-daemon.jar",
    ]

    SUBSTRATE_PATHS = [
        "/system/lib/libsubstrate.so",
        "/system/lib64/libsubstrate.so",
        "/data/data/com.android.vending/app_wide/libsubstrate.so",
    ]

    ZYGISK_PATHS = [
        "/system/lib64/zygisk32.so",
        "/system/lib64/zygisk31.so",
        "/data/local/tmp/zygisk32.so",
    ]

    SUSPICIOUS_PROCESSES = {
        "frida-server": 8,
        "xposed-daemon": 9,
        "substrate": 7,
        "zygisk32": 6,
        "cydia-restore": 5,
        "sileo": 4,
    }

    SUSPICIOUS_ENV_VARS = {
        "FRIDA_AGENT_PATH": 10,
        "XPOSED_ENABLED": 9,
        "SUBSTRATE_ACTIVE": 8,
    }

    # Known hook function addresses (approximate for common libc versions)
    FRIDA_HOOKS = [
        "0x657c",      # frida-agent.so entry point
        "0x657d",
    ]

    def __init__(self):
        self.artifacts: Dict[str, Any] = {}
        self.score: int = 0
        self.findings: List[Dict[str, Any]] = []

    def _safe_read_file(self, path: str) -> str | None:
        """Safely read file contents with fallback."""
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read()[:1024]  # Limit size for performance
        except (IOError, OSError, PermissionError):
            pass
        return None

    def _safe_read_proc_maps(self, pid: int = os.getpid()) -> List[str]:
        """Read /proc/<pid>/maps and extract shared object names."""
        maps_path = f"/proc/{pid}/maps"
        try:
            with open(maps_path, "r") as f:
                content = f.read()
                # Extract .so files from the map entries
                so_files = re.findall(r'(/[^ ]*\.so)', content)
                return list(set(so_files))  # Deduplicate
        except (IOError, OSError):
            return []

    def _check_process_exists(self, name: str) -> bool:
        """Check if a process with given name exists in the system."""
        try:
            procs = subprocess.check_output(
                ["ps", "aux"], text=True, stderr=subprocess.DEVNULL
            )
            return any(name in proc for proc in procs.splitlines())
        except (subprocess.SubprocessError, OSError):
            return False

    def _check_env_var(self, name: str) -> bool:
        """Check if an environment variable is set."""
        return os.environ.get(name, "").strip()

    def detect_frida(self) -> Tuple[bool, List[str]]:
        """Detect Frida hook injection artifacts."""
        findings = []
        frida_found = False

        # Check file system paths
        for path in self.FRIDA_PATHS:
            if os.path.exists(path):
                content = self._safe_read_file(path)
                if content:
                    findings.append(f"Found Frida agent at {path}")
                    frida_found = True
                    self.score += 10

        # Check running processes
        if self._check_process_exists("frida-server"):
            findings.append("Frida server process detected")
            frida_found = True
            self.score += 8

        # Check environment variables
        if self._check_env_var("FRIDA_AGENT_PATH"):
            findings.append(f"Frida agent path env set: {os.environ['FRIDA_AGENT_PATH']}")
            frida_found = True
            self.score += 7

        # Check for frida-agent.so in memory maps
        mem_sos = self._safe_read_proc_maps()
        if any("frida" in so.lower() and "agent" in so.lower() for so in mem_sos):
            findings.append("Frida agent found in process memory")
            frida_found = True
            self.score += 9

        return frida_found, findings

    def detect_xposed(self) -> Tuple[bool, List[str]]:
        """Detect Xposed framework artifacts."""
        findings = []
        xposed_found = False

        # Check file system paths
        for path in self.XPOSED_PATHS:
            if os.path.exists(path):
                content = self._safe_read_file(path)
                if content:
                    findings.append(f"Found Xposed artifact at {path}")
                    xposed_found = True
                    self.score += 12

        # Check for Xposed module files
        modules_dir = "/data/data/com.android.vending/app_wide/xposed-modules/"
        if os.path.exists(modules_dir):
            findings.append(f"Xposed modules directory exists: {modules_dir}")
            xposed_found = True
            self.score += 8

        # Check running processes
        if self._check_process_exists("xposed-daemon"):
            findings.append("Xposed daemon process detected")
            xposed_found = True
            self.score += 10

        return xposed_found, findings

    def detect_substrate(self) -> Tuple[bool, List[str]]:
        """Detect Substrate-based hooking (Cydia/Sileo/etc)."""
        findings = []
        substrate_found = False

        # Check file system paths
        for path in self.SUBSTRATE_PATHS:
            if os.path.exists(path):
                content = self._safe_read_file(path)
                if content:
                    findings.append(f"Found Substrate library at {path}")
                    substrate_found = True
                    self.score += 9

        # Check for Cydia/Sileo indicators
        cydia_path = "/var/lib/cydia/"
        sileo_path = "/data/data/com.cpd.sileo/"

        if os.path.exists(cydia_path):
            findings.append(f"Found Cydia data at {cydia_path}")
            substrate_found = True
            self.score += 8

        if os.path.exists(sileo_path):
            findings.append(f"Found Sileo data at {sileo_path}")
            substrate_found = True
            self.score += 7

        # Check for Substrate in memory
        mem_sos = self._safe_read_proc_maps()
        if any("substrate" in so.lower() for so in mem_sos):
            findings.append("Substrate library found in process memory")
            substrate_found = True
            self.score += 8

        return substrate_found, findings

    def detect_zygisk(self) -> Tuple[bool, List[str]]:
        """Detect Zygisk (Magisk module manager)."""
        findings = []
        zygisk_found = False

        # Check file system paths
        for path in self.ZYGISK_PATHS:
            if os.path.exists(path):
                content = self._safe_read_file(path)
                if content:
                    findings.append(f"Found Zygisk library at {path}")
                    zygisk_found = True
                    self.score += 10

        # Check for Magisk boot image modifications
        magisk_boot = "/data/adb/magisk/boot.img"
        if os.path.exists(magisk_boot):
            findings.append("Magisk boot image modification detected")
            zygisk_found = True
            self.score += 8

        return zygisk_found, findings

    def detect_emulator(self) -> Tuple[bool, List[str]]:
        """Detect common emulator artifacts."""
        findings = []
        emulator_found = False

        # Check for emulator-specific environment variables
        emulator_env_vars = [
            "ANDROID_EMULATOR_PATH",
            "EMULATOR_ID",
            "QEMU_AUDIO_DRV",
        ]

        for var in emulator_env_vars:
            if self._check_env_var(var):
                findings.append(f"Emulator env var set: {var}")
                emulator_found = True
                self.score += 5

        # Check for common emulator process names
        emulator_procs = [
            "qemu-system",
            "emulator-5554",
            "com.android.emulator",
        ]

        for proc in emulator_procs:
            if self._check_process_exists(proc):
                findings.append(f"Emulator process detected: {proc}")
                emulator_found = True
                self.score += 6

        # Check for emulator-specific file paths
        emulator_paths = [
            "/data/local/tmp/emulator",
            "/system/etc/init/emulator.rc",
        ]

        for path in emulator_paths:
            if os.path.exists(path):
                findings.append(f"Emulator config found at {path}")
                emulator_found = True
                self.score += 4

        return emulator_found, findings

    def detect_jailbreak(self) -> Tuple[bool, List[str]]:
        """Detect iOS jailbreak artifacts (for cross-platform compatibility)."""
        findings = []
        jailbreak_found = False

        # Check for common jailbreak app paths
        jailbreak_paths = [
            "/var/mobile/Library/Preferences/com.saurik.Cydia.plist",
            "/var/mobile/Applications/*/Cydia.app/",
            "/Library/MobileAppStore/",
        ]

        for path in jailbreak_paths:
            if os.path.exists(path):
                findings.append(f"Found jailbreak artifact at {path}")
                jailbreak_found = True
                self.score += 8

        # Check for Sileo (iOS package manager)
        sileo_path = "/var/mobile/Applications/*/Sileo.app/"
        if os.path.exists(sileo_path):
            findings.append("Found Sileo app directory")
            jailbreak_found = True
            self.score += 7

        return jailbreak_found, findings

    def detect_suspicious_processes(self) -> Tuple[bool, List[str]]:
        """Detect suspicious process names indicating hooking."""
        findings = []
        suspicious_found = False

        for proc_name, weight in self.SUSPICIOUS_PROCESSES.items():
            if self._check_process_exists(proc_name):
                findings.append(f"Suspicious process found: {proc_name}")
                suspicious_found = True
                self.score += weight

        return suspicious_found, findings

    def detect_suspicious_env_vars(self) -> Tuple[bool, List[str]]:
        """Detect suspicious environment variables."""
        findings = []
        env_found = False

        for var_name, weight in self.SUSPICIOUS_ENV_VARS.items():
            if self._check_env_var(var_name):
                findings.append(f"Suspicious env var set: {var_name}")
                env_found = True
                self.score += weight

        return env_found, findings

    def detect_memory_artifacts(self) -> Tuple[bool, List[str]]:
        """Detect hook artifacts in process memory."""
        findings = []
        mem_found = False

        # Read current process maps
        mem_sos = self._safe_read_proc_maps()

        # Check for known hook libraries in memory
        hook_libs = [
            "libfrida-agent.so",
            "libsubstrate.so",
            "libzygisk32.so",
            "xposed-daemon.jar",
        ]

        for lib in hook_libs:
            if any(lib in so.lower() for so in mem_sos):
                findings.append(f"Hook library found in memory: {lib}")
                mem_found = True
                self.score += 6

        # Check for non-standard shared objects (potential injection)
        standard_prefixes = [
            "lib",
            "system/",
            "vendor/",
            "product/",
        ]

        non_standard = []
        for so in mem_sos:
            if not any(so.startswith(prefix) for prefix in standard_prefixes):
                non_standard.append(so)

        if non_standard:
            findings.append(f"Found {len(non_standard)} non-standard shared objects")
            self.score += min(5, len(non_standard))  # Cap at 5 points

        return mem_found, findings

    def detect_hook_functions(self) -> Tuple[bool, List[str]]:
        """Detect known hook function addresses in memory."""
        findings = []
        hooks_found = False

        try:
            # Read current process maps for address ranges
            mem_sos = self._safe_read_proc_maps()

            # Check for frida-agent.so entry points
            if any("frida" in so.lower() and "agent" in so.lower() for so in mem_sos):
                findings.append("Potential Frida hook function detected")
                hooks_found = True
                self.score += 7

        except (IOError, OSError):
            pass

        return hooks_found, findings

    def run_full_scan(self) -> Dict[str, Any]:
        """Run all detection modules and compile results."""
        self.findings = []
        self.artifacts = {}

        # Run all detectors
        detectors = [
            ("frida", self.detect_frida),
            ("xposed", self.detect_xposed),
            ("substrate", self.detect_substrate),
            ("zygisk", self.detect_zygisk),
            ("emulator", self.detect_emulator),
            ("jailbreak", self.detect_jailbreak),
            ("suspicious_processes", self.detect_suspicious_processes),
            ("suspicious_env_vars", self.detect_suspicious_env_vars),
            ("memory_artifacts", self.detect_memory_artifacts),
            ("hook_functions", self.detect_hook_functions),
        ]

        for name, detector in detectors:
            found, findings = detector()
            if found:
                self.artifacts[name] = True
                self.findings.extend(findings)

        # Check for root (often paired with hook detection)
        root_found, root_findings = self._detect_root()
        if root_found:
            self.artifacts["root"] = True
            self.findings.extend(root_findings)
            self.score += 15

        return {
            "artifacts": self.artifacts,
            "findings": self.findings,
            "score": self.score,
        }

    def _detect_root(self) -> Tuple[bool, List[str]]:
        """Detect root access indicators."""
        findings = []
        root_found = False

        # Check for common root indicators
        root_paths = [
            "/data/local/tmp/su",
            "/system/bin/su",
            "/sbin/su",
            "/data/local/root",
        ]

        for path in root_paths:
            if os.path.exists(path):
                findings.append(f"Found su binary at {path}")
                root_found = True
                self.score +=