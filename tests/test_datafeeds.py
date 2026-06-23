"""Offline tests for the edge/air-gap datafeeds layer.

These never touch the network: the fetch function is monkeypatched, and the
cache is redirected to a tmp dir. They verify catalog integrity, cache
read/write, freshness, offline semantics, and the air-gap snapshot round-trip.
"""

import json
import pathlib

import pytest

import cisbench.datafeeds as df

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "cisbench" / "data_feeds_2026.json"


@pytest.fixture(autouse=True)
def _tmp_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    yield


def test_catalog_file_parses_and_has_feeds():
    data = json.loads(CATALOG.read_text(encoding="utf-8"))
    assert isinstance(data.get("feeds"), list)
    assert len(data["feeds"]) >= 1


def test_catalog_includes_the_oscal_feed_cisbench_consumes():
    feeds = {f["id"] for f in df.load_catalog().get("feeds", [])}
    assert "oscal-800-53-rev5-catalog" in feeds


def test_every_feed_has_required_fields():
    for f in df.load_catalog().get("feeds", []):
        assert f.get("id")
        assert f.get("url", "").startswith("http")
        assert f.get("format")


def test_list_feeds_filters_by_domain():
    compliance = df.list_feeds(domain="compliance")
    ids = {f["id"] for f in compliance}
    assert "oscal-800-53-rev5-catalog" in ids
    # a non-compliance feed must not show up under the compliance filter
    assert all(f.get("domain") == "compliance" for f in compliance)


def test_update_writes_cache_and_meta(monkeypatch):
    payload = json.dumps({"catalog": {"groups": []}}).encode()
    monkeypatch.setattr(df, "fetch", lambda *a, **k: payload)
    path = df.update("oscal-800-53-rev5-catalog")
    assert path.exists()
    assert path.read_bytes() == payload
    age = df.cached_age_hours("oscal-800-53-rev5-catalog")
    assert age is not None and age >= 0.0


def test_get_offline_without_cache_raises():
    with pytest.raises(FileNotFoundError):
        df.get("oscal-800-53-rev5-catalog", offline=True)


def test_get_offline_serves_cache(monkeypatch):
    payload = json.dumps({"catalog": {"metadata": {"title": "x"}}}).encode()
    monkeypatch.setattr(df, "fetch", lambda *a, **k: payload)
    df.update("oscal-800-53-rev5-catalog")
    # break the network so offline must use the cache
    monkeypatch.setattr(df, "fetch", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("network used in offline mode")))
    data = df.get("oscal-800-53-rev5-catalog", offline=True)
    assert data["catalog"]["metadata"]["title"] == "x"


def test_update_unknown_feed_raises():
    with pytest.raises(KeyError):
        df.update("no-such-feed-xyz")


def test_snapshot_export_import_roundtrip(monkeypatch, tmp_path):
    payload = json.dumps({"catalog": {"groups": []}}).encode()
    monkeypatch.setattr(df, "fetch", lambda *a, **k: payload)
    df.update("oscal-800-53-rev5-catalog")
    archive = tmp_path / "snap.tar.gz"
    n = df.snapshot_export(str(archive))
    assert n >= 1 and archive.exists()

    # fresh cache dir, import the snapshot, serve offline
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "enclave"))
    imported = df.snapshot_import(str(archive))
    assert imported >= 1
    data = df.get("oscal-800-53-rev5-catalog", offline=True)
    assert "catalog" in data
