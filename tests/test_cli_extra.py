"""CLI tests for fleet / attack / enriched eval and edge cases."""

import json
from pathlib import Path

import pytest

from rootsentry.cli import main, build_parser, _load_snapshots

FLEET_EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "fleet.android.json"


# ---- eval enrichment -------------------------------------------------------

def _write(tmp_path, obj):
    p = tmp_path / "in.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def test_eval_shows_attack_and_profile(tmp_path, capsys):
    ev = {"platform": "android",
          "present_files": ["/system/xbin/su", "/data/local/tmp/frida-server"],
          "installed_packages": ["com.topjohnwu.magisk"], "open_ports": [27042]}
    main(["eval", _write(tmp_path, ev)])
    out = capsys.readouterr().out
    assert "ATT&CK" in out
    assert "PROFILE" in out
    assert "T1404" in out


def test_eval_json_has_profiles_and_techniques(tmp_path, capsys):
    ev = {"platform": "android", "present_files": ["/system/xbin/su"]}
    main(["eval", _write(tmp_path, ev), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert "profiles" in data
    assert "techniques" in data
    assert data["posture"] == "COMPROMISED"


def test_eval_clean_no_profiles(tmp_path, capsys):
    ev = {"platform": "android", "system_props": {"ro.build.tags": "release-keys"}}
    rc = main(["eval", _write(tmp_path, ev)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "no indicators fired" in out
    assert "PROFILE" not in out


def test_eval_fail_on_critical(tmp_path):
    ev = {"platform": "android", "runtime_flags": ["signature_mismatch"]}
    assert main(["eval", _write(tmp_path, ev), "--fail-on", "CRITICAL"]) == 1


def test_eval_fail_on_not_reached(tmp_path):
    ev = {"platform": "android", "present_files": ["/system/xbin/busybox"]}
    assert main(["eval", _write(tmp_path, ev), "--fail-on", "CRITICAL"]) == 0


# ---- fleet -----------------------------------------------------------------

def test_fleet_human(capsys):
    rc = main(["fleet", str(FLEET_EXAMPLE)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "fleet:" in out
    assert "compromised-rate" in out
    assert "attacker profiles:" in out
    assert "co-occurrence" in out


def test_fleet_json(capsys):
    main(["fleet", str(FLEET_EXAMPLE), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["total"] >= 10
    assert "cooccurrence" in data
    assert "devices" not in data


def test_fleet_json_devices(capsys):
    main(["fleet", str(FLEET_EXAMPLE), "--json", "--devices"])
    data = json.loads(capsys.readouterr().out)
    assert "devices" in data
    assert len(data["devices"]) == data["total"]


def test_fleet_devices_human(capsys):
    main(["fleet", str(FLEET_EXAMPLE), "--devices"])
    out = capsys.readouterr().out
    assert "devices:" in out
    assert "clean-01" in out


def test_fleet_fail_rate_trips(capsys):
    rc = main(["fleet", str(FLEET_EXAMPLE), "--fail-rate", "0.2"])
    assert rc == 1


def test_fleet_fail_rate_not_tripped(capsys):
    rc = main(["fleet", str(FLEET_EXAMPLE), "--fail-rate", "0.99"])
    assert rc == 0


def test_fleet_accepts_bare_array(tmp_path, capsys):
    arr = [{"platform": "android", "present_files": ["/system/xbin/su"]}]
    p = tmp_path / "arr.json"
    p.write_text(json.dumps(arr), encoding="utf-8")
    rc = main(["fleet", str(p)])
    assert rc == 0


def test_load_snapshots_dict_devices(tmp_path):
    p = tmp_path / "d.json"
    p.write_text(json.dumps({"devices": [{"platform": "android"}]}), encoding="utf-8")
    assert len(_load_snapshots(str(p))) == 1


def test_load_snapshots_dict_snapshots_key(tmp_path):
    p = tmp_path / "d.json"
    p.write_text(json.dumps({"snapshots": [{"platform": "ios"}]}), encoding="utf-8")
    assert len(_load_snapshots(str(p))) == 1


def test_load_snapshots_rejects_scalar(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(123), encoding="utf-8")
    with pytest.raises(ValueError):
        _load_snapshots(str(p))


# ---- attack ----------------------------------------------------------------

def test_attack_human(capsys):
    rc = main(["attack"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "T1617" in out
    assert "Hooking" in out
    assert "android.frida.port" in out


def test_attack_json(capsys):
    main(["attack", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert any(row["id"] == "T1404" for row in data)
    for row in data:
        assert "name" in row and "signals" in row
        assert row["signals"]


# ---- catalog (regression for attack/new signals) ---------------------------

def test_catalog_json_includes_new_signals(capsys):
    main(["catalog", "--json"])
    data = json.loads(capsys.readouterr().out)
    ids = {row["id"] for row in data}
    assert "android.lsposed.pkg" in ids
    assert "ios.jailbreakd" in ids


def test_catalog_android_only(capsys):
    main(["catalog", "--platform", "android"])
    out = capsys.readouterr().out
    assert "android.su.sbin" in out
    assert "ios.cydia.app" not in out


# ---- top-level -------------------------------------------------------------

def test_version_updated(capsys):
    main(["--version"])
    assert capsys.readouterr().out.strip() == "0.2.0"


def test_no_command_prints_help_and_returns_1(capsys):
    rc = main([])
    assert rc == 1


def test_parser_has_all_subcommands():
    parser = build_parser()
    # argparse stores choices on the subparsers action
    actions = [a for a in parser._actions if hasattr(a, "choices") and a.choices]
    names = set()
    for a in actions:
        try:
            names.update(a.choices.keys())
        except AttributeError:
            pass
    assert {"eval", "fleet", "catalog", "attack"} <= names
