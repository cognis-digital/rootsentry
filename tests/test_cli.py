import json

from rootsentry.cli import main


def test_eval_human(tmp_path, capsys):
    ev = {"platform": "android", "present_files": ["/system/xbin/su"],
          "installed_packages": ["com.topjohnwu.magisk"]}
    p = tmp_path / "ev.json"
    p.write_text(json.dumps(ev), encoding="utf-8")
    rc = main(["eval", str(p)])
    out = capsys.readouterr().out
    assert "posture:" in out
    assert "magisk" in out.lower()
    assert rc == 0  # no --fail-on


def test_eval_fail_on(tmp_path, capsys):
    ev = {"platform": "android", "present_files": ["/system/xbin/su"],
          "installed_packages": ["com.topjohnwu.magisk"], "open_ports": [27042]}
    p = tmp_path / "ev.json"
    p.write_text(json.dumps(ev), encoding="utf-8")
    rc = main(["eval", str(p), "--fail-on", "COMPROMISED"])
    assert rc == 1


def test_eval_json(tmp_path, capsys):
    p = tmp_path / "ev.json"
    p.write_text(json.dumps({"platform": "android"}), encoding="utf-8")
    main(["eval", str(p), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["posture"] == "TRUSTED"


def test_catalog_listing(capsys):
    main(["catalog", "--platform", "ios"])
    out = capsys.readouterr().out
    assert "ios.cydia.app" in out
    assert "android.su.system_xbin" not in out


def test_version(capsys):
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip()
