"""
polyglot/python/emulator_avd_spoof_detector.py

Mobile runtime-integrity detection: emulator/AVD spoof detector.
RASP-style, zero deps, scored posture verdict.
"""

import os
import re
from typing import Dict, Any, Optional


class AVDSpoofDetector:
    """Detect Android Virtual Device (AVD) / emulator artifacts."""

    # Known AVD filesystem signatures
    AVD_FILE_SIGNATURES = {
        r'/data/local/tmp/avd\.ini',
        r'/data/local/tmp/avd\.ini\.backup',
        r'/data/.android-avd/',
        r'/data/data/com\.android\.vndk\.(current|legacy)/lib/x86/libandroid_runtime\.so',
    }

    # Known AVD process signatures
    AVD_PROCESS_SIGNATURES = {
        r'com\.android\.vndk\.(current|legacy)',
        r'Android SDK built for x86',
        r'AVD',
    }

    # Known AVD memory/library signatures
    AVD_LIB_SIGNATURES = [
        b'libandroid_runtime.so',
        b'libavd.so',
        b'com.android.vndk',
    ]

    # Bootloader/kernel parameters indicating AVD
    AVD_BOOT_PARAMS = {
        r'androidboot\.avd=',
        r'sdk\.gphone\.(x86|x86_64)',
    }

    def __init__(self):
        self._results: Dict[str, Any] = {}

    def _safe_read(self, path: str) -> Optional[bytes]:
        """Read file safely with fallback."""
        try:
            if not os.path.exists(path):
                return None
            with open(path, 'rb') as f:
                content = f.read(4096)  # Read first 4KB
                return content
        except (IOError, OSError):
            return None

    def _check_filesystem(self) -> Dict[str, Any]:
        """Check filesystem artifacts."""
        results = {'score': 0.0, 'evidence': []}

        # Check for avd.ini files
        for sig in self.AVD_FILE_SIGNATURES:
            match = re.search(sig, '/data/')
            if match:
                results['score'] += 15.0
                results['evidence'].append(f'AVD file pattern found: {match.group(0)}')

        # Check /proc/self/status for Model field
        status_content = self._safe_read('/proc/self/status')
        if status_content:
            model_match = re.search(rb'Model:\s*(.*)', status_content)
            if model_match:
                model_str = model_match.group(1).decode('utf-8', errors='ignore').lower()
                if 'sdk' in model_str or 'x86' in model_str or 'avd' in model_str:
                    results['score'] += 20.0
                    results['evidence'].append(f'Suspicious Model field: {model_str}')

        # Check /proc/self/maps for emulator libraries
        maps_content = self._safe_read('/proc/self/maps')
        if maps_content:
            for lib in self.AVD_LIB_SIGNATURES:
                if lib in maps_content:
                    results['score'] += 10.0
                    results['evidence'].append(f'AVD library found in memory: {lib.decode()}')

        return results

    def _check_processes(self) -> Dict[str, Any]:
        """Check running processes for AVD artifacts."""
        results = {'score': 0.0, 'evidence': []}

        try:
            # Read /proc/self/cmdline
            cmdline_content = self._safe_read('/proc/self/cmdline')
            if cmdline_content:
                cmdline_str = cmdline_content.decode('utf-8', errors='ignore').lower()
                
                for sig in self.AVD_PROCESS_SIGNATURES:
                    if re.search(sig, cmdline_str):
                        results['score'] += 15.0
                        results['evidence'].append(f'AVD process pattern found: {sig}')

            # Check /proc/self/status for Android-specific fields
            status_content = self._safe_read('/proc/self/status')
            if status_content:
                # Look for Android SDK in environment or cmdline
                env_match = re.search(rb'(?:Android|SDK).*?(?:x86|x86_64)', status_content)
                if env_match:
                    results['score'] += 10.0
                    results['evidence'].append('Android SDK detected in process state')

        except (IOError, OSError):
            pass

        return results

    def _check_network(self) -> Dict[str, Any]:
        """Check network artifacts for AVD indicators."""
        results = {'score': 0.0, 'evidence': []}

        try:
            # Check /proc/net/route or /proc/net/arp for SDK DNS entries
            route_content = self._safe_read('/proc/net/route')
            arp_content = self._safe_read('/proc/net/arp')

            if route_content and b'sdk.gphone' in route_content:
                results['score'] += 15.0
                results['evidence'].append('SDK DNS route found')

            if arp_content and b'sdk.gphone' in arp_content:
                results['score'] += 15.0
                results['evidence'].append('SDK ARP entry found')

        except (IOError, OSError):
            pass

        return results

    def _check_boot_params(self) -> Dict[str, Any]:
        """Check bootloader/kernel parameters."""
        results = {'score': 0.0, 'evidence': []}

        try:
            # Check /proc/cmdline for AVD boot params
            cmdline_content = self._safe_read('/proc/cmdline')
            if cmdline_content:
                cmdline_str = cmdline_content.decode('utf-8', errors='ignore').lower()

                for pattern in self.AVD_BOOT_PARAMS:
                    if re.search(pattern, cmdline_str):
                        results['score'] += 20.0
                        results['evidence'].append(f'AVD boot parameter found: {pattern}')

        except (IOError, OSError):
            pass

        return results

    def _check_memory(self) -> Dict[str, Any]:
        """Check memory-mapped files for AVD artifacts."""
        results = {'score': 0.0, 'evidence': []}

        try:
            # Check /proc/self/maps for avd-named shared libraries
            maps_content = self._safe_read('/proc/self/maps')
            if maps_content:
                # Look for avd-specific shared memory or files
                if b'avd' in maps_content.lower():
                    results['score'] += 10.0
                    results['evidence'].append('AVD-related memory mapping found')

        except (IOError, OSError):
            pass

        return results

    def _check_hostname(self) -> Dict[str, Any]:
        """Check hostname for AVD indicators."""
        results = {'score': 0.0, 'evidence': []}

        try:
            # Read /proc/self/status for hostname
            status_content = self._safe_read('/proc/self/status')
            if status_content:
                hostname_match = re.search(rb'Hostname:\s*(.*)', status_content)
                if hostname_match:
                    hostname_str = hostname_match.group(1).decode('utf-8', errors='ignore').lower()
                    
                    # Check for SDK/AVD in hostname
                    if any(term in hostname_str for term in ['sdk', 'avd', 'x86']):
                        results['score'] += 15.0
                        results['evidence'].append(f'Suspicious hostname: {hostname_str}')

        except (IOError, OSError):
            pass

        return results

    def _calculate_total_score(self, components: list) -> float:
        """Calculate weighted total score."""
        weights = {
            'filesystem': 2.0,
            'processes': 1.5,
            'network': 1.5,
            'boot_params': 2.0,
            'memory': 1.0,
            'hostname': 1.0,
        }

        total = 0.0
        for name, result in components.items():
            if isinstance(result, dict):
                weighted = result['score'] * weights.get(name, 1.0)
                total += weighted
            else:
                total += result

        return min(total, 100.0)  # Cap at 100%

    def detect(self) -> Dict[str, Any]:
        """Run all detection components and return verdict."""
        self._results = {
            'components': {},
            'total_score': 0.0,
            'verdict': 'UNKNOWN',
            'confidence': 0.0,
            'evidence': [],
        }

        # Run all detection components
        components = [
            ('filesystem', self._check_filesystem()),
            ('processes', self._check_processes()),
            ('network', self._check_network()),
            ('boot_params', self._check_boot_params()),
            ('memory', self._check_memory()),
            ('hostname', self._check_hostname()),
        ]

        # Collect all evidence
        for name, result in components:
            if isinstance(result, dict):
                self._results['components'][name] = result
                self._results['evidence'].extend(result.get('evidence', []))

        # Calculate total score
        self._results['total_score'] = self._calculate_total_score(components)

        # Determine verdict and confidence
        score = self._results['total_score']
        
        if score >= 80:
            self._results['verdict'] = 'HIGH_PROBABILITY'
            self._results['confidence'] = min(score / 100, 1.0) * 0.95 + 0.05
        elif score >= 60:
            self._results['verdict'] = 'MODERATE_PROBABILITY'
            self._results['confidence'] = min(score / 100, 1.0) * 0.75 + 0.25
        elif score >= 40:
            self._results['verdict'] = 'LOW_PROBABILITY'
            self._results['confidence'] = score / 100 * 0.5 + 0.3
        else:
            self._results['verdict'] = 'LIKELY_NATIVE'
            self._results['confidence'] = max(0.0, (40 - score) / 60)

        # Remove duplicate evidence entries
        seen = set()
        unique_evidence = []
        for item in self._results['evidence']:
            if item not in seen:
                seen.add(item)
                unique_evidence.append(item)
        self._results['evidence'] = unique_evidence

        return self._results


def main():
    """Demo/runnable entry point."""
    detector = AVDSpoofDetector()
    result = detector.detect()

    print("=" * 60)
    print("AVD SPOOF DETECTOR RESULTS")
    print("=" * 60)
    print(f"Verdict: {result['verdict']}")
    print(f"Total Score: {result['total_score']:.1f}/100")
    print(f"Confidence: {result['confidence']:.2%}")
    print("-" * 60)

    if result['evidence']:
        print("EVIDENCE FOUND:")
        for i, item in enumerate(result['evidence'], 1):
            print(f"  [{i}] {item}")
    else:
        print("No specific evidence found.")

    print("-" * 60)
    
    # Component breakdown
    if result.get('components'):
        print("COMPONENT BREAKDOWN:")
        for name, comp in result['components'].items():
            score = comp.get('score', 0.0)
            evidence = comp.get('evidence', [])
            status = "✓" if score > 0 else "○"
            print(f"  {status} {name:15s}: {score:.1f}/100")

    print("=" * 60)


if __name__ == '__main__':
    main()