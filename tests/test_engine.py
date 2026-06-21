from rootsentry.catalog import Platform, CATALOG, for_platform
from rootsentry.engine import Evidence, Posture, evaluate


def test_clean_device_is_trusted():
    ev = Evidence(platform=Platform.ANDROID, system_props={"ro.build.tags": "release-keys"})
    v = evaluate(ev)
    assert v.posture == Posture.TRUSTED
    assert v.score == 0
    assert v.fired == []


def test_rooted_device_critical():
    ev = Evidence(
        platform=Platform.ANDROID,
        present_files=["/system/xbin/su", "/data/local/tmp/frida-server"],
        installed_packages=["com.topjohnwu.magisk"],
        system_props={"ro.build.tags": "test-keys", "ro.debuggable": "1"},
        open_ports=[27042],
    )
    v = evaluate(ev)
    assert v.posture == Posture.CRITICAL
    assert v.score >= 80
    ids = {s.id for s in v.fired}
    assert "android.su.system_xbin" in ids
    assert "android.magisk.pkg" in ids
    assert "android.frida.port" in ids


def test_single_high_weight_is_compromised_not_critical():
    ev = Evidence(platform=Platform.ANDROID, present_files=["/system/xbin/su"])
    v = evaluate(ev)
    # one weight-9 indicator -> ~75 -> COMPROMISED
    assert v.posture == Posture.COMPROMISED
    assert 50 <= v.score < 80


def test_prop_substring_match():
    ev = Evidence(platform=Platform.ANDROID, system_props={"ro.hardware": "ranchu"})
    v = evaluate(ev)
    assert any(s.id == "android.emu.ranchu" for s in v.fired)


def test_prop_value_must_match():
    # ro.build.tags present but with release-keys must NOT fire test-keys signal
    ev = Evidence(platform=Platform.ANDROID, system_props={"ro.build.tags": "release-keys"})
    v = evaluate(ev)
    assert not any(s.id == "android.build.testkeys" for s in v.fired)


def test_ios_jailbreak():
    ev = Evidence(
        platform=Platform.IOS,
        present_files=["/Applications/Cydia.app", "/bin/bash"],
        runtime_flags=["can_write_outside_sandbox"],
    )
    v = evaluate(ev)
    assert v.posture in (Posture.COMPROMISED, Posture.CRITICAL)
    assert any(s.id == "ios.cydia.app" for s in v.fired)


def test_platform_filter_excludes_other_os():
    ev = Evidence(platform=Platform.IOS, present_files=["/system/xbin/su"])
    v = evaluate(ev)
    # android su path should not be in the iOS catalog
    assert not any(s.id == "android.su.system_xbin" for s in v.fired)


def test_cross_platform_tamper_signal():
    ev = Evidence(platform=Platform.ANDROID, runtime_flags=["signature_mismatch"])
    v = evaluate(ev)
    assert any(s.id == "any.signature.mismatch" for s in v.fired)
    assert v.posture == Posture.CRITICAL  # weight 10


def test_fired_sorted_by_weight():
    ev = Evidence(
        platform=Platform.ANDROID,
        present_files=["/system/xbin/busybox", "/system/xbin/su"],
    )
    v = evaluate(ev)
    weights = [s.weight for s in v.fired]
    assert weights == sorted(weights, reverse=True)


def test_evidence_from_dict():
    ev = Evidence.from_dict({
        "platform": "android",
        "present_files": ["/system/bin/su"],
        "open_ports": ["27042"],
    })
    assert ev.platform == Platform.ANDROID
    assert 27042 in ev.open_ports


def test_catalog_platform_scoping():
    android = for_platform(Platform.ANDROID)
    assert all(s.platform in (Platform.ANDROID, Platform.BOTH) for s in android)
    assert len(android) < len(CATALOG)
