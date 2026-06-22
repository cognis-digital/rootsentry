"""Catalog integrity + ATT&CK mapping tests."""

import pytest

from rootsentry.catalog import (
    CATALOG, Signal, Platform, Category, ATTACK_NAMES,
    FILE, PACKAGE, PROP, PORT, FLAG,
    for_platform, for_technique, by_id,
)

VALID_KINDS = {FILE, PACKAGE, PROP, PORT, FLAG}


def test_catalog_nonempty_and_grew():
    assert len(CATALOG) >= 40


def test_signal_ids_unique():
    ids = [s.id for s in CATALOG]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("s", CATALOG, ids=[s.id for s in CATALOG])
def test_signal_wellformed(s):
    assert isinstance(s, Signal)
    assert s.id and isinstance(s.id, str)
    assert isinstance(s.platform, Platform)
    assert isinstance(s.category, Category)
    assert s.kind in VALID_KINDS
    assert s.match
    assert 1 <= s.weight <= 10
    assert s.description
    assert isinstance(s.attack, tuple)


@pytest.mark.parametrize("s", CATALOG, ids=[s.id for s in CATALOG])
def test_prop_signals_have_prop_value(s):
    if s.kind == PROP:
        assert s.prop_value, f"{s.id} is a PROP signal but has no prop_value"


@pytest.mark.parametrize("s", CATALOG, ids=[s.id for s in CATALOG])
def test_port_signals_are_numeric(s):
    if s.kind == PORT:
        assert s.match.isdigit()


@pytest.mark.parametrize("s", CATALOG, ids=[s.id for s in CATALOG])
def test_attack_ids_are_known(s):
    for tid in s.attack:
        assert tid in ATTACK_NAMES, f"{s.id} maps to unknown technique {tid}"


@pytest.mark.parametrize("s", CATALOG, ids=[s.id for s in CATALOG])
def test_attack_id_format(s):
    for tid in s.attack:
        assert tid.startswith("T")
        body = tid[1:].replace(".", "")
        assert body.isdigit()


def test_every_attack_name_used_at_least_once():
    used = set()
    for s in CATALOG:
        used.update(s.attack)
    # every name we publish should be referenced by some signal
    for tid in ATTACK_NAMES:
        assert tid in used, f"{tid} declared in ATTACK_NAMES but no signal uses it"


def test_for_technique_roundtrip():
    for tid in ATTACK_NAMES:
        sigs = for_technique(tid)
        assert sigs, f"no signals for {tid}"
        for s in sigs:
            assert tid in s.attack


def test_for_technique_unknown_returns_empty():
    assert for_technique("T9999") == []


def test_by_id_found_and_missing():
    assert by_id("android.magisk.pkg") is not None
    assert by_id("does.not.exist") is None


def test_for_platform_android_excludes_ios():
    a = for_platform(Platform.ANDROID)
    assert all(s.platform in (Platform.ANDROID, Platform.BOTH) for s in a)
    assert any(s.platform == Platform.BOTH for s in a)


def test_for_platform_ios_excludes_android():
    i = for_platform(Platform.IOS)
    assert all(s.platform in (Platform.IOS, Platform.BOTH) for s in i)
    assert not any(s.id.startswith("android.") for s in i)


def test_both_platform_signals_in_both_lists():
    both = [s for s in CATALOG if s.platform == Platform.BOTH]
    a = for_platform(Platform.ANDROID)
    i = for_platform(Platform.IOS)
    for s in both:
        assert s in a and s in i


@pytest.mark.parametrize("cat", list(Category))
def test_each_category_represented(cat):
    assert any(s.category == cat for s in CATALOG), f"no signal for category {cat}"


def test_signal_is_frozen():
    s = CATALOG[0]
    with pytest.raises(Exception):
        s.weight = 1  # type: ignore[misc]


def test_new_indicators_present():
    ids = {s.id for s in CATALOG}
    for expected in [
        "android.su.sbin", "android.magisk.repackaged", "android.lsposed.pkg",
        "android.frida.gadget", "android.frida.maps", "android.ptrace.tracerpid",
        "android.selinux.permissive", "ios.jailbreakd", "ios.dyld.insert",
        "any.packer.detected", "any.user.ca",
    ]:
        assert expected in ids, f"missing new indicator {expected}"
