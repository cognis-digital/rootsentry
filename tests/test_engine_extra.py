"""Extra engine tests: scoring monotonicity, verdict enrichment, edge cases."""

import pytest

from rootsentry.catalog import Platform, CATALOG, ATTACK_NAMES
from rootsentry.engine import Evidence, Posture, Verdict, evaluate


def _ev(**kw):
    return Evidence(platform=Platform.ANDROID, **kw)


def test_score_bounds():
    for ev in [
        _ev(),
        _ev(present_files=["/system/xbin/su"]),
        _ev(present_files=["/system/xbin/su", "/system/bin/su", "/sbin/su"],
            installed_packages=["com.topjohnwu.magisk"], open_ports=[27042]),
    ]:
        v = evaluate(ev)
        assert 0 <= v.score <= 100


def test_score_is_monotone_with_more_indicators():
    base = evaluate(_ev(present_files=["/system/xbin/su"])).score
    more = evaluate(_ev(present_files=["/system/xbin/su"],
                        installed_packages=["com.topjohnwu.magisk"])).score
    assert more >= base


def test_posture_thresholds():
    assert evaluate(_ev()).posture == Posture.TRUSTED
    # a single weight-6 indicator => SUSPICIOUS or COMPROMISED, never TRUSTED
    v = evaluate(_ev(present_files=["/system/xbin/busybox"]))
    assert v.posture != Posture.TRUSTED


def test_posture_ordering_intenum():
    assert Posture.TRUSTED < Posture.SUSPICIOUS < Posture.COMPROMISED < Posture.CRITICAL


def test_verdict_categories_property():
    v = evaluate(_ev(present_files=["/system/xbin/su"],
                     installed_packages=["com.topjohnwu.magisk"],
                     open_ports=[27042]))
    cats = v.categories
    assert cats.get("root", 0) >= 2
    assert cats.get("hook", 0) >= 1
    assert sum(cats.values()) == len(v.fired)


def test_verdict_techniques_property_sorted_unique():
    v = evaluate(_ev(present_files=["/system/xbin/su"],
                     installed_packages=["com.topjohnwu.magisk"]))
    t = v.techniques
    assert t == sorted(set(t))
    assert "T1404" in t
    assert all(x in ATTACK_NAMES for x in t)


def test_verdict_to_dict_shape():
    v = evaluate(_ev(present_files=["/system/xbin/su"]))
    d = v.to_dict()
    assert set(d) >= {"posture", "score", "categories", "techniques", "fired"}
    assert isinstance(d["techniques"], list)
    assert all("id" in t and "name" in t for t in d["techniques"])
    assert all("attack" in f for f in d["fired"])


def test_clean_verdict_to_dict_empty_collections():
    d = evaluate(_ev()).to_dict()
    assert d["fired"] == []
    assert d["techniques"] == []
    assert d["categories"] == {}


def test_prop_substring_case_insensitive():
    v = evaluate(_ev(system_props={"ro.hardware": "GOLDFISH-X"}))
    assert any(s.id == "android.emu.goldfish" for s in v.fired)


def test_prop_missing_does_not_fire():
    v = evaluate(_ev(system_props={"ro.product.brand": "acme"}))
    assert v.posture == Posture.TRUSTED


def test_port_match_int_and_str_inputs():
    v1 = evaluate(_ev(open_ports=[27042]))
    v2 = evaluate(Evidence.from_dict({"platform": "android", "open_ports": ["27042"]}))
    assert any(s.id == "android.frida.port" for s in v1.fired)
    assert any(s.id == "android.frida.port" for s in v2.fired)


def test_custom_catalog_subset():
    sub = [s for s in CATALOG if s.id == "android.magisk.pkg"]
    v = evaluate(_ev(present_files=["/system/xbin/su"],
                     installed_packages=["com.topjohnwu.magisk"]),
                 catalog=sub)
    assert {s.id for s in v.fired} == {"android.magisk.pkg"}


def test_empty_catalog_is_trusted():
    v = evaluate(_ev(present_files=["/system/xbin/su"]), catalog=[])
    assert v.posture == Posture.TRUSTED
    assert v.score == 0


def test_selinux_permissive_fires():
    v = evaluate(_ev(system_props={"ro.boot.selinux": "permissive"}))
    assert any(s.id == "android.selinux.permissive" for s in v.fired)


def test_verifiedboot_orange_fires():
    v = evaluate(_ev(system_props={"ro.boot.verifiedbootstate": "orange"}))
    assert any(s.id == "android.bootloader.unlocked" for s in v.fired)


def test_tracerpid_flag_fires():
    v = evaluate(_ev(runtime_flags=["tracerpid_nonzero"]))
    assert any(s.id == "android.ptrace.tracerpid" for s in v.fired)


def test_packer_flag_maps_to_software_packing():
    v = evaluate(Evidence(platform=Platform.ANDROID,
                          runtime_flags=["packer_detected"]))
    assert "T1406.002" in v.techniques


def test_ios_rootless_jailbreakd():
    v = evaluate(Evidence(platform=Platform.IOS,
                          present_files=["/var/jb/usr/bin/jailbreakd"]))
    assert any(s.id == "ios.jailbreakd" for s in v.fired)


def test_dyld_insert_libraries_ios():
    v = evaluate(Evidence(platform=Platform.IOS,
                          runtime_flags=["dyld_insert_libraries_set"]))
    assert any(s.id == "ios.dyld.insert" for s in v.fired)


def test_evidence_from_dict_defaults_android():
    ev = Evidence.from_dict({})
    assert ev.platform == Platform.ANDROID
    assert ev.present_files == []


def test_evidence_from_dict_coerces_prop_values():
    ev = Evidence.from_dict({"platform": "android",
                             "system_props": {"ro.debuggable": 1}})
    assert ev.system_props["ro.debuggable"] == "1"


def test_signature_mismatch_is_critical_alone():
    v = evaluate(Evidence(platform=Platform.ANDROID,
                          runtime_flags=["signature_mismatch"]))
    assert v.posture == Posture.CRITICAL


@pytest.mark.parametrize("flag,sig", [
    ("system_proxy_active", "any.proxy.mitm"),
    ("user_ca_installed", "any.user.ca"),
    ("debugger_attached", "any.debugger.attached"),
])
def test_crossplatform_flags(flag, sig):
    v = evaluate(Evidence(platform=Platform.IOS, runtime_flags=[flag]))
    assert any(s.id == sig for s in v.fired)
