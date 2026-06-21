# rootsentry

**Mobile runtime-integrity detection — root, jailbreak, emulator, hooking, tamper.**

`rootsentry` decides whether a mobile device's runtime can be trusted. An app
collects a small telemetry snapshot on-device — suspicious files, installed
packages, system properties, open ports, runtime flags — and `rootsentry`
scores it against a catalog of well-known compromise indicators, returning a
**posture verdict** (`TRUSTED` → `SUSPICIOUS` → `COMPROMISED` → `CRITICAL`) your
app or backend can act on.

Pure standard library, zero dependencies. Defensive by design: the point is for
*your* app to recognize a rooted/jailbroken/instrumented runtime and react —
degrade gracefully, warn, or refuse high-risk actions.

## How it works

```
catalog.py   data-only list of indicators (su binaries, Magisk, Cydia,
             frida-server ports, test-keys builds, MobileSubstrate, …)
engine.py    match an Evidence snapshot -> fired signals + saturating score 0-100
reference/   embeddable on-device collectors (Kotlin / Swift)
```

Scoring saturates: a single weight-10 indicator (e.g. a signing-cert mismatch)
already reaches `CRITICAL`, while several medium indicators converge toward 100
— so you don't get fooled by one cheap check passing.

## Install

```bash
pip install -e .          # or ".[dev]" for tests
```

## Use

```bash
# Evaluate a device snapshot (see examples/evidence.android.json)
rootsentry eval evidence.json
# posture: CRITICAL  (score 97/100)
#   [ 9] root      android.su.system_xbin — su binary present in /system/xbin
#   [ 9] root      android.magisk.pkg — Magisk manager installed
#   [ 8] hook      android.frida.port — frida-server default control port open
#   ...

# Gate a backend attestation check (exit 1 at/above threshold)
rootsentry eval evidence.json --fail-on COMPROMISED

# Inspect the indicator catalog
rootsentry catalog --platform ios
```

### As a library

```python
from rootsentry import Evidence, Platform, evaluate

ev = Evidence(platform=Platform.ANDROID,
              present_files=["/system/xbin/su"],
              installed_packages=["com.topjohnwu.magisk"])
verdict = evaluate(ev)
print(verdict.posture.label, verdict.score)   # COMPROMISED 75
```

## On-device collection

`reference/android_RootCheck.kt` and `reference/ios_JailbreakCheck.swift` show
how to gather the `Evidence` snapshot on each platform. Recommended pattern:
collect on-device, attest + send to your backend (inside Play Integrity /
DeviceCheck where possible), and evaluate server-side so the decision isn't made
solely in an environment the attacker controls.

## Indicator coverage

Root (su, Magisk, SuperSU, busybox, test-keys, ro.secure), emulator
(goldfish/ranchu/qemu), hooking (frida-server, Xposed, Substrate), iOS jailbreak
(Cydia, Sileo, bash/apt, sandbox-escape, fork), and cross-platform tamper
(signature mismatch, integrity failure, attached debugger).

## Scope of use

Defensive runtime self-protection (RASP-style) for apps you own/operate, plus
device-posture analysis during authorized assessments. Detection only —
`rootsentry` does not modify the device.

## License

Cognis Open Collaboration License (COCL) v1.0. See [LICENSE](LICENSE).
