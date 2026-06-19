"""Tests for the check evaluation engine."""

import pytest

from cisbench.engine import (
    Check,
    CheckError,
    evaluate_check,
    resolve_path,
)


def make_check(**kw):
    base = dict(id="T-1", title="t", path="a.b", operator="equals", expected=1)
    base.update(kw)
    return Check(**base)


# ---- path resolution -----------------------------------------------------
def test_resolve_nested_path():
    inv = {"a": {"b": {"c": 5}}}
    assert resolve_path(inv, "a.b.c") == 5


def test_resolve_list_index():
    inv = {"users": [{"name": "x"}, {"name": "y"}]}
    assert resolve_path(inv, "users.1.name") == "y"


def test_resolve_missing_returns_sentinel():
    from cisbench.engine import _MISSING
    inv = {"a": {"b": 1}}
    assert resolve_path(inv, "a.z") is _MISSING
    assert resolve_path(inv, "a.b.c") is _MISSING  # b is not a dict


# ---- operator pass/fail --------------------------------------------------
@pytest.mark.parametrize("op,expected,observed,result", [
    ("equals", 5, 5, True),
    ("equals", 5, 4, False),
    ("not_equals", "0.0.0.0", "10.0.0.1", True),
    ("not_equals", "0.0.0.0", "0.0.0.0", False),
    ("gte", 14, 16, True),
    ("gte", 14, 12, False),
    ("lte", 10, 5, True),
    ("lte", 10, 25, False),
    ("gt", 0, 1, True),
    ("lt", 5, 3, True),
    ("in", [1, 2, 3], 2, True),
    ("in", [1, 2, 3], 9, False),
    ("not_in", ["root", "admin"], "dbuser", True),
    ("contains", "secure", "sec", False),  # value 'sec' contains expected? no
])
def test_operators(op, expected, observed, result):
    chk = make_check(operator=op, expected=expected, path="x")
    inv = {"x": observed}
    assert evaluate_check(chk, inv).passed is result


def test_contains_on_list():
    chk = make_check(operator="contains", expected="ssl", path="modules")
    assert evaluate_check(chk, {"modules": ["ssl", "audit"]}).passed is True
    assert evaluate_check(chk, {"modules": ["audit"]}).passed is False


def test_is_true_is_false():
    t = make_check(operator="is_true", expected=None, path="flag")
    f = make_check(operator="is_false", expected=None, path="flag")
    assert evaluate_check(t, {"flag": True}).passed is True
    assert evaluate_check(t, {"flag": False}).passed is False
    assert evaluate_check(f, {"flag": False}).passed is True
    assert evaluate_check(f, {"flag": 0}).passed is True


# ---- presence operators --------------------------------------------------
def test_present_operator():
    chk = make_check(operator="present", expected=None, path="audit.enabled")
    assert evaluate_check(chk, {"audit": {"enabled": True}}).passed is True
    assert evaluate_check(chk, {"audit": {}}).passed is False


def test_absent_operator():
    chk = make_check(operator="absent", expected=None, path="debug.backdoor")
    assert evaluate_check(chk, {"debug": {}}).passed is True
    assert evaluate_check(chk, {"debug": {"backdoor": True}}).passed is False


# ---- missing values fail value-operators ---------------------------------
def test_missing_value_fails():
    chk = make_check(operator="gte", expected=14, path="auth.len")
    res = evaluate_check(chk, {"auth": {}})
    assert res.passed is False
    assert "missing" in res.evidence


# ---- type errors are handled, not raised ---------------------------------
def test_numeric_op_on_string_fails_gracefully():
    chk = make_check(operator="gte", expected=14, path="x")
    res = evaluate_check(chk, {"x": "not a number"})
    assert res.passed is False
    assert "could not evaluate" in res.evidence


def test_bool_is_not_numeric():
    chk = make_check(operator="gte", expected=1, path="x")
    res = evaluate_check(chk, {"x": True})
    assert res.passed is False


# ---- evidence is populated -----------------------------------------------
def test_evidence_present():
    chk = make_check(operator="equals", expected=1, path="x")
    res = evaluate_check(chk, {"x": 1})
    assert res.evidence
    assert "x" in res.evidence


# ---- check validation ----------------------------------------------------
def test_invalid_operator_rejected():
    with pytest.raises(CheckError):
        Check(id="X", title="t", path="a", operator="bogus", expected=1)


def test_invalid_severity_rejected():
    with pytest.raises(CheckError):
        Check(id="X", title="t", path="a", operator="equals", expected=1,
              severity="apocalyptic")


def test_missing_expected_rejected_for_comparison():
    with pytest.raises(CheckError):
        Check(id="X", title="t", path="a", operator="equals")


def test_from_dict_rejects_unknown_field():
    with pytest.raises(CheckError):
        Check.from_dict({"id": "X", "path": "a", "operator": "is_true",
                         "bogus_field": 1})


def test_weight_follows_severity():
    low = make_check(operator="is_true", expected=None, severity="low")
    crit = make_check(operator="is_true", expected=None, severity="critical")
    assert crit.weight > low.weight
