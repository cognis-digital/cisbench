"""Offline tests for the NIST 800-53 rev5 crosswalk enrichment.

These tests are strictly OFFLINE: they point ``COGNIS_FEEDS_CACHE`` at a
small, trimmed OSCAL fixture committed under ``tests/fixtures/feeds-cache``
and call the feed layer with ``offline=True``, so they never touch the
network. The fixture contains only the control families/controls that the
built-in cisbench profile maps to.
"""

import json
import os
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURE_CACHE = ROOT / "tests" / "fixtures" / "feeds-cache"


@pytest.fixture(autouse=True)
def _offline_cache(monkeypatch):
    """Force the feed layer to read the committed fixture, never the network."""
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIXTURE_CACHE))
    # Belt and braces: make any accidental network fetch explode loudly.
    import cisbench.datafeeds as df

    def _no_net(*a, **k):  # pragma: no cover - guard
        raise AssertionError("network fetch attempted in an offline test")

    monkeypatch.setattr(df, "fetch", _no_net)
    yield


def test_fixture_is_present_and_parseable():
    data = json.loads((FIXTURE_CACHE / "oscal-800-53-rev5-catalog.data")
                      .read_text(encoding="utf-8"))
    assert "catalog" in data
    assert data["catalog"]["groups"]


def test_load_catalog_offline_serves_fixture():
    from cisbench.crosswalk import load_catalog

    cat = load_catalog(offline=True)
    assert cat["catalog"]["metadata"]["title"]


def test_build_index_resolves_authoritative_titles():
    from cisbench.crosswalk import build_index, load_catalog

    index = build_index(load_catalog(offline=True))
    # Authoritative NIST 800-53 rev5 titles (verbatim from the OSCAL catalog).
    assert index["sc-8"].title == "Transmission Confidentiality and Integrity"
    assert index["sc-8"].label == "SC-8"
    assert index["sc-8"].family == "System and Communications Protection"
    assert index["ia-5.1"].title == "Password-based Authentication"
    assert index["ia-5.1"].label == "IA-5(1)"
    assert index["ac-2"].title == "Account Management"
    assert index["si-11"].title == "Error Handling"


def test_normalize_and_label_render_enhancements():
    from cisbench.crosswalk import _normalize, _oscal_label

    assert _normalize("SC-8(1)") == "sc-8.1"
    assert _oscal_label("sc-8.1") == "SC-8(1)"
    assert _oscal_label("ac-2") == "AC-2"


def test_enrich_builtin_profile_maps_every_check_offline():
    from cisbench.crosswalk import enrich_profile
    from cisbench.profile import Profile

    rows = enrich_profile(Profile.builtin(), offline=True)
    assert len(rows) == len(Profile.builtin().checks)
    # Every built-in check is tagged with at least one 800-53 control, and
    # every tagged control resolves against the catalog (no UNRESOLVED).
    for row in rows:
        assert row["controls"], f"{row['check_id']} has no NIST mapping"
        for c in row["controls"]:
            assert c["resolved"] is True, f"{row['check_id']} -> {c}"
            assert c["title"]


def test_enrich_includes_real_family_names():
    from cisbench.crosswalk import enrich_profile
    from cisbench.profile import Profile

    rows = {r["check_id"]: r for r in
            enrich_profile(Profile.builtin(), offline=True)}
    tls = rows["CDB-1.1"]
    assert "System and Communications Protection" in tls["families"]
    labels = {c["label"] for c in tls["controls"]}
    assert {"SC-8", "SC-8(1)"} <= labels


def test_resolve_marks_unknown_control_unresolved():
    from cisbench.crosswalk import build_index, load_catalog, resolve

    index = build_index(load_catalog(offline=True))
    out = resolve(["sc-8", "zz-99"], index)
    assert out["sc-8"] is not None
    assert out["zz-99"] is None


def test_offline_with_empty_cache_raises(monkeypatch, tmp_path):
    """offline=True with nothing cached must fail rather than hit the network."""
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path))
    from cisbench.crosswalk import load_catalog

    with pytest.raises(FileNotFoundError):
        load_catalog(offline=True)
