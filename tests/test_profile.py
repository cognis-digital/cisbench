"""Tests for profile loading and scoring."""

import json

import pytest

from cisbench.profile import (
    Profile,
    ProfileError,
    load_inventory,
    scan,
)


def test_builtin_profile_loads():
    prof = Profile.builtin()
    assert prof.name == "cognis-db-baseline"
    assert len(prof.checks) >= 12
    # ids are unique
    ids = [c.id for c in prof.checks]
    assert len(ids) == len(set(ids))


def test_builtin_every_check_has_remediation_and_reference():
    prof = Profile.builtin()
    for chk in prof.checks:
        assert chk.remediation, f"{chk.id} missing remediation"
        assert chk.reference, f"{chk.id} missing reference"


def test_profile_from_dict_requires_checks():
    with pytest.raises(ProfileError):
        Profile.from_dict({"name": "empty", "checks": []})


def test_profile_rejects_duplicate_ids():
    data = {
        "name": "dup",
        "checks": [
            {"id": "A", "path": "x", "operator": "is_true"},
            {"id": "A", "path": "y", "operator": "is_true"},
        ],
    }
    with pytest.raises(ProfileError):
        Profile.from_dict(data)


def test_profile_load_from_file(tmp_path):
    data = {
        "name": "f",
        "checks": [{"id": "A", "path": "x", "operator": "is_true"}],
    }
    p = tmp_path / "prof.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    prof = Profile.load(p)
    assert prof.get("A") is not None
    assert prof.get("missing") is None


def test_profile_load_missing_file():
    with pytest.raises(ProfileError):
        Profile.load("does-not-exist.json")


def test_profile_load_bad_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ProfileError):
        Profile.load(p)


# ---- scoring -------------------------------------------------------------
def _tiny_profile():
    return Profile.from_dict({
        "name": "tiny",
        "checks": [
            {"id": "P", "path": "a", "operator": "is_true", "severity": "low"},
            {"id": "Q", "path": "b", "operator": "is_true",
             "severity": "critical"},
        ],
    })


def test_score_all_pass():
    prof = _tiny_profile()
    rep = scan(prof, {"a": True, "b": True})
    assert rep.passed == 2
    assert rep.failed == 0
    assert rep.score == 100.0
    assert rep.weighted_score == 100.0


def test_score_half_pass():
    prof = _tiny_profile()
    rep = scan(prof, {"a": True, "b": False})
    assert rep.passed == 1
    assert rep.failed == 1
    assert rep.score == 50.0
    # low weight=1 passes, critical weight=4 fails -> 1/5 = 20%
    assert rep.weighted_score == 20.0


def test_score_none_pass():
    prof = _tiny_profile()
    rep = scan(prof, {"a": False, "b": False})
    assert rep.score == 0.0
    assert rep.weighted_score == 0.0
    assert len(rep.failures) == 2


def test_report_to_dict_shape():
    prof = _tiny_profile()
    rep = scan(prof, {"a": True, "b": False})
    d = rep.to_dict()
    assert d["summary"]["total"] == 2
    assert d["summary"]["passed"] == 1
    assert len(d["results"]) == 2
    # failed results carry remediation in dict, passed do not
    statuses = {r["id"]: r["status"] for r in d["results"]}
    assert statuses["P"] == "PASS"
    assert statuses["Q"] == "FAIL"


# ---- inventory loading ---------------------------------------------------
def test_load_inventory_unwraps_settings(tmp_path):
    p = tmp_path / "inv.json"
    p.write_text(json.dumps({"settings": {"a": 1}, "meta": "x"}),
                 encoding="utf-8")
    inv = load_inventory(p)
    assert inv == {"a": 1}


def test_load_inventory_plain(tmp_path):
    p = tmp_path / "inv.json"
    p.write_text(json.dumps({"a": 1}), encoding="utf-8")
    assert load_inventory(p) == {"a": 1}


def test_load_inventory_rejects_non_object(tmp_path):
    p = tmp_path / "inv.json"
    p.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(ProfileError):
        load_inventory(p)


def test_builtin_against_example_inventory():
    """The shipped example inventory should produce a mix of pass/fail."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    inv = load_inventory(root / "examples" / "inventory.json")
    rep = scan(Profile.builtin(), inv)
    assert rep.failed > 0  # example is intentionally not fully hardened
    assert rep.passed > 0


def test_builtin_against_hardened_inventory():
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    inv = load_inventory(root / "examples" / "inventory_hardened.json")
    rep = scan(Profile.builtin(), inv)
    assert rep.failed == 0
    assert rep.score == 100.0
