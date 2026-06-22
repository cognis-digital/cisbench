"""Offline tests for the `feeds` and `crosswalk` CLI commands.

All tests run with ``COGNIS_FEEDS_CACHE`` pointed at the committed trimmed
OSCAL fixture and force ``offline`` semantics, so no network access occurs.
"""

import json
import pathlib

import pytest

from cisbench.cli import main

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURE_CACHE = ROOT / "tests" / "fixtures" / "feeds-cache"


@pytest.fixture(autouse=True)
def _offline_cache(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIXTURE_CACHE))
    import cisbench.datafeeds as df

    def _no_net(*a, **k):  # pragma: no cover - guard
        raise AssertionError("network fetch attempted in an offline test")

    monkeypatch.setattr(df, "fetch", _no_net)
    yield


def test_feeds_list_shows_only_relevant_feed(capsys):
    rc = main(["feeds", "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "oscal-800-53-rev5-catalog" in out
    assert "usnistgov" in out or "nist" in out.lower()
    # cisbench must not advertise feeds it doesn't consume.
    assert "opensky" not in out
    assert "ofac" not in out


def test_feeds_get_offline_summarizes_catalog(capsys):
    rc = main(["feeds", "get", "oscal-800-53-rev5-catalog", "--offline"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "controls indexed:" in out
    assert "families:" in out


def test_feeds_get_rejects_irrelevant_feed(capsys):
    rc = main(["feeds", "get", "opensky-states", "--offline"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not a feed cisbench consumes" in err


def test_feeds_update_rejects_irrelevant_feed(capsys):
    rc = main(["feeds", "update", "ofac-sdn"])
    assert rc == 2
    assert "not a feed cisbench consumes" in capsys.readouterr().err


def test_crosswalk_offline_table(capsys):
    rc = main(["crosswalk", "--offline", "--no-color"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "NIST SP 800-53 rev5 crosswalk" in out
    assert "Transmission Confidentiality and Integrity" in out
    assert "SC-8(1)" in out
    assert "12/12 checks carry 800-53 mappings" in out


def test_crosswalk_offline_json(capsys):
    rc = main(["crosswalk", "--offline", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["profile"]
    assert len(data["checks"]) == 12
    cdb11 = next(c for c in data["checks"] if c["check_id"] == "CDB-1.1")
    titles = {c.get("title") for c in cdb11["controls"]}
    assert "Transmission Confidentiality and Integrity" in titles


def test_crosswalk_fail_on_unmapped_is_clean_for_builtin(capsys):
    # Every built-in control resolves, so the gate stays green.
    rc = main(["crosswalk", "--offline", "--no-color", "--fail-on-unmapped"])
    assert rc == 0
