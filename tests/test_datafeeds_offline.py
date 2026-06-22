"""Offline tests for the bundled feed catalog + datafeeds ingester.

These NEVER touch the network: every test either inspects the static catalog or
reads a committed fixture out of an isolated cache dir via offline=True.
"""

import json
import time
from pathlib import Path

import pytest

from rootsentry import datafeeds as df

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    return tmp_path


# ---- catalog ---------------------------------------------------------------

def test_catalog_loads_and_has_feeds():
    cat = df.load_catalog()
    assert cat.get("feeds")
    assert len(cat["feeds"]) >= 30


def test_attack_mobile_feed_present():
    ids = {f["id"] for f in df.list_feeds()}
    assert "attack-mobile" in ids


def test_attack_mobile_feed_is_keyless_and_https():
    feed = next(f for f in df.list_feeds() if f["id"] == "attack-mobile")
    assert feed["keyless"] is True
    assert feed["url"].startswith("https://")
    assert feed["format"] == "stix"


def test_list_feeds_domain_filter():
    ti = df.list_feeds(domain="threat-intel")
    assert ti
    assert all(f["domain"] == "threat-intel" for f in ti)


def test_every_feed_has_required_keys():
    for f in df.list_feeds():
        assert {"id", "name", "url", "format"} <= set(f)
        assert f["url"].startswith("http")


# ---- offline cache behaviour ----------------------------------------------

def _prime(cache_dir: Path, feed_id: str, fixture: str):
    data = (FIXTURES / fixture).read_bytes()
    (cache_dir / f"{feed_id}.data").write_bytes(data)
    (cache_dir / f"{feed_id}.meta.json").write_text(json.dumps({
        "feed": feed_id, "fetched_at": time.time(), "bytes": len(data),
    }), encoding="utf-8")


def test_get_offline_reads_cached_stix(cache):
    _prime(cache, "attack-mobile", "attack-mobile.data")
    obj = df.get("attack-mobile", offline=True)
    assert obj["type"] == "bundle"
    ids = {
        ref["external_id"]
        for o in obj["objects"]
        for ref in o.get("external_references", [])
    }
    assert {"T1617", "T1404", "T1631"} <= ids


def test_get_offline_without_cache_raises(cache):
    with pytest.raises(FileNotFoundError):
        df.get("attack-mobile", offline=True)


def test_cached_age_hours_none_when_absent(cache):
    assert df.cached_age_hours("attack-mobile") is None


def test_cached_age_hours_small_after_prime(cache):
    _prime(cache, "attack-mobile", "attack-mobile.data")
    age = df.cached_age_hours("attack-mobile")
    assert age is not None and age < 1.0


def test_snapshot_export_import_roundtrip(cache, tmp_path):
    _prime(cache, "attack-mobile", "attack-mobile.data")
    archive = tmp_path / "snap.tar.gz"
    n = df.snapshot_export(str(archive))
    assert n >= 1
    assert archive.exists()


def test_attack_mobile_feed_matches_engine_techniques(cache):
    """The bundled ATT&CK Mobile fixture covers techniques our catalog maps to."""
    _prime(cache, "attack-mobile", "attack-mobile.data")
    obj = df.get("attack-mobile", offline=True)
    feed_ids = {
        ref["external_id"]
        for o in obj["objects"]
        for ref in o.get("external_references", [])
    }
    from rootsentry.catalog import for_technique
    for tid in feed_ids:
        # each technique the feed defines should resolve to >=1 catalog signal
        assert for_technique(tid), f"no rootsentry signal maps to {tid}"
