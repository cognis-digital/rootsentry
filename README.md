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


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ rootsentry --help
usage: rootsentry [-h] [--version] {eval,fleet,catalog,attack} ...

rootsentry CLI.

positional arguments:
  {eval,fleet,catalog,attack}
    eval                evaluate a device evidence snapshot
    fleet               analyze a batch of device snapshots
    catalog             list indicator catalog
    attack              show ATT&CK technique -> signal mapping

options:
  -h, --help            show this help message and exit
  --version
```

```console
$ rootsentry catalog
android.su.system_xbin           android root      w9 — su binary present in /system/xbin (classic root)
android.su.system_bin            android root      w9 — su binary present in /system/bin
android.su.sbin                  android root      w9 — su binary present in /sbin
android.su.vendor                android root      w9 — su binary present in /vendor/bin
android.magisk.pkg               android root      w9 — Magisk manager installed
android.magisk.repackaged        android root      w9 — Repackaged/renamed Magisk (stub-rename to evade detection)
android.magisk.path              android root      w9 — Magisk runtime directory present
android.superuser.pkg            android root      w8 — SuperSU installed
android.kingroot.pkg             android root      w8 — KingRoot/KingUser one-click root installed
android.busybox                  android root      w6 — busybox present (common on rooted devices)
android.build.testkeys           android root      w7 — Build signed with test-keys rather than release-keys
android.ro.debuggable            android debugger  w6 — System build is debuggable (ro.debuggable=1)
android.ro.secure                android root      w7 — Non-secure system build (ro.secure=0)
android.selinux.permissive       android root      w7 — SELinux forced permissive (enforcement disabled)
android.bootloader.unlocked      android tamper    w7 — Verified-boot state not green (unlocked/tampered bootloader)
android.flash.locked_no          android tamper    w6 — Flash partition unlocked (ro.boot.flash.locked=0)
android.emu.goldfish             android emulator  w5 — Emulator hardware (goldfish/ranchu)
android.emu.ranchu               android emulator  w5 — Emulator hardware (ranchu)
android.emu.generic              android emulator  w4 — Generic/emulator product model
android.emu.qemu                 android emulator  w6 — QEMU kernel flag set
android.emu.genymotion           android emulator  w6 — Genymotion emulator control socket present
android.emu.qemu_pipe            android emulator  w6 — QEMU pipe device present (emulator)
android.frida.port               android hook      w8 — frida-server default control port open
android.frida.lib                android hook      w8 — frida-server binary staged in /data/local/tmp
android.frida.gadget             android hook      w8 — frida-gadget injectable library staged
android.frida.maps     
```

> Blocks above are real `rootsentry` output — reproduce them from a clone.

<!-- cognis:example:end -->

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

# Each fired indicator now carries its MITRE ATT&CK for Mobile technique(s)
# and the verdict names any recognized attacker profile:
#   ATT&CK: T1404 Exploitation for Privilege Escalation, T1617 Hooking, ...
#   PROFILE [critical] Rooted device running an instrumentation framework

# Gate a backend attestation check (exit 1 at/above threshold)
rootsentry eval evidence.json --fail-on COMPROMISED

# Fleet / cohort analysis: posture distribution, indicator co-occurrence (with
# lift), attacker profiles, ATT&CK rollup, and outliers over a batch of devices
rootsentry fleet examples/fleet.android.json
rootsentry fleet fleet.json --json --devices > fleet.json   # SIEM-ready
rootsentry fleet canary.json --fail-rate 0.2                 # CI/canary gate

# ATT&CK technique -> indicator crosswalk
rootsentry attack

# Inspect the indicator catalog
rootsentry catalog --platform ios
```

### Fleet analysis (the big new capability)

A single verdict trusts one device; a **fleet** report finds campaigns. When you
operate an attestation backend at scale, `rootsentry fleet` ingests a batch of
snapshots and surfaces the population-level signal:

- **Posture distribution** and a single `compromised-rate` you can trend or gate.
- **Indicator co-occurrence with lift** — attacker toolkits leave *correlated*
  fingerprints, and correlation is far harder to spoof than any one check.
- **Attacker profiles** (`dynamic_instrumentation`, `rooted_and_hooked`,
  `emulator_farm`, `repackaged_app`, `mitm_analysis`, `evasive_root`) so triage
  is templated, not per-device.
- **Outliers** — devices with many low-weight oddities a per-rule threshold
  under-rates.

Full walkthrough, frank threat/defensive context, and the ATT&CK mapping live in
[`docs/FLEET_ANALYSIS.md`](docs/FLEET_ANALYSIS.md).

```python
from rootsentry import analyze_fleet, classify_profiles, evaluate, Evidence, Platform

report = analyze_fleet(list_of_snapshot_dicts)
print(report.compromised_rate, report.profile_counts)
print(report.cooccurrence[:5])            # [(idA, idB, count, lift), ...]
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

## Offline / air-gap feeds

The bundled `datafeeds.py` + `data_feeds_2026.json` ship a keyless, cache-first
ingester. rootsentry wires the **MITRE ATT&CK for Mobile** feed (`attack-mobile`)
so an air-gapped deployment can refresh the technique catalog over sneakernet:

```python
from rootsentry import datafeeds
bundle = datafeeds.get("attack-mobile", offline=True)   # serves the local cache
```

All tests stay offline via a committed STIX fixture; the network is never
touched during `pytest`.

## Indicator coverage

Root (su across system/vendor/sbin, Magisk + renamed/repackaged Magisk, SuperSU,
KingRoot, busybox, test-keys, ro.secure, permissive SELinux, unlocked verified
boot), emulator (goldfish/ranchu/qemu, Genymotion, qemu_pipe), hooking
(frida-server/gadget + in-memory maps, Xposed/LSPosed, Substrate, ptrace
TracerPid), iOS jailbreak (Cydia, Sileo, Zebra, bash/sh, apt, rootless
`/var/jb` jailbreakd, sandbox-escape, fork, DYLD_INSERT_LIBRARIES, Substitute),
and cross-platform tamper (signature mismatch, integrity failure, packer,
user-CA, system proxy, attached debugger). Every indicator is annotated with its
MITRE ATT&CK for Mobile technique.

## Scope of use

Defensive runtime self-protection (RASP-style) for apps you own/operate, plus
device-posture analysis during authorized assessments. Detection only —
`rootsentry` does not modify the device.

## License

Cognis Open Collaboration License (COCL) v1.0. See [LICENSE](LICENSE).
