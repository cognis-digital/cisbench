"""Check evaluation engine for cisbench.

A *check* is a declarative description of one hardening expectation. Each check
carries an id, a title, an authored control reference, a rule that is evaluated
against a value pulled from the inventory, the expected value, a severity, and
remediation text.

Rules are intentionally small and composable so that profiles can be authored
as plain JSON without any executable code. The supported operators are:

    equals            value == expected
    not_equals        value != expected
    gte               value >= expected   (numeric)
    lte               value <= expected   (numeric)
    gt                value >  expected   (numeric)
    lt                value <  expected   (numeric)
    in                value in expected   (expected is a list)
    not_in            value not in expected
    contains          expected in value   (value is a list/str)
    not_contains      expected not in value
    is_true           value is truthy     (expected ignored)
    is_false          value is falsy      (expected ignored)
    present           the key exists in the inventory
    absent            the key does not exist in the inventory

The value is located with a dotted path (e.g. "tls.required") so nested
inventory snapshots can be addressed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Sentinel used to distinguish "key missing" from "key present but None".
_MISSING = object()

# Severities ordered from least to most serious; used for weighting and sorting.
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_SEVERITY = "medium"

# Operators that do not consume an "expected" value.
_NO_EXPECTED_OPS = {"is_true", "is_false", "present", "absent"}

# Operators that require the located value to exist.
_NEEDS_VALUE_OPS = {
    "equals", "not_equals", "gte", "lte", "gt", "lt",
    "in", "not_in", "contains", "not_contains", "is_true", "is_false",
}


class CheckError(ValueError):
    """Raised when a check definition is malformed."""


@dataclass
class Check:
    """A single declarative hardening check."""

    id: str
    title: str
    path: str
    operator: str
    expected: Any = None
    reference: str = ""
    severity: str = DEFAULT_SEVERITY
    remediation: str = ""
    description: str = ""
    nist_controls: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id:
            raise CheckError("check is missing an 'id'")
        if not self.path:
            raise CheckError(f"check '{self.id}' is missing a 'path'")
        if self.operator not in _ALL_OPERATORS:
            raise CheckError(
                f"check '{self.id}' uses unknown operator '{self.operator}'"
            )
        if self.severity not in SEVERITY_ORDER:
            raise CheckError(
                f"check '{self.id}' has invalid severity '{self.severity}'"
            )
        if self.operator not in _NO_EXPECTED_OPS and self.expected is None:
            # Allow explicit null only for operators that accept it; for the
            # comparison operators a None expected almost always means the
            # author forgot to set it.
            raise CheckError(
                f"check '{self.id}' with operator '{self.operator}' "
                "requires an 'expected' value"
            )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Check":
        known = {
            "id", "title", "path", "operator", "expected", "reference",
            "severity", "remediation", "description", "nist_controls",
        }
        unknown = set(data) - known
        if unknown:
            raise CheckError(
                f"check '{data.get('id', '?')}' has unknown field(s): "
                + ", ".join(sorted(unknown))
            )
        return cls(
            id=data["id"],
            title=data.get("title", data["id"]),
            path=data["path"],
            operator=data["operator"],
            expected=data.get("expected"),
            reference=data.get("reference", ""),
            severity=data.get("severity", DEFAULT_SEVERITY),
            remediation=data.get("remediation", ""),
            description=data.get("description", ""),
            nist_controls=list(data.get("nist_controls", []) or []),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "path": self.path,
            "operator": self.operator,
            "expected": self.expected,
            "reference": self.reference,
            "severity": self.severity,
            "remediation": self.remediation,
            "description": self.description,
            "nist_controls": list(self.nist_controls),
        }

    @property
    def weight(self) -> int:
        """Severity-derived weight used by weighted scoring."""
        return SEVERITY_ORDER[self.severity]


@dataclass
class CheckResult:
    """Outcome of evaluating one check against an inventory."""

    check: Check
    passed: bool
    observed: Any
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.check.id,
            "title": self.check.title,
            "reference": self.check.reference,
            "severity": self.check.severity,
            "status": "PASS" if self.passed else "FAIL",
            "observed": _jsonable(self.observed),
            "expected": self.check.expected,
            "evidence": self.evidence,
            "remediation": "" if self.passed else self.check.remediation,
        }


def _jsonable(value: Any) -> Any:
    """Return value if it is JSON-serializable, otherwise its repr."""
    if value is _MISSING:
        return None
    if isinstance(value, (str, int, float, bool, type(None), list, dict)):
        return value
    return repr(value)


def resolve_path(inventory: dict[str, Any], path: str) -> Any:
    """Resolve a dotted path against the inventory.

    Returns the sentinel _MISSING when any segment is absent. List indexing is
    supported with integer-looking segments (e.g. "users.0.name").
    """
    current: Any = inventory
    for segment in path.split("."):
        if isinstance(current, dict):
            if segment in current:
                current = current[segment]
            else:
                return _MISSING
        elif isinstance(current, list):
            try:
                idx = int(segment)
            except ValueError:
                return _MISSING
            if -len(current) <= idx < len(current):
                current = current[idx]
            else:
                return _MISSING
        else:
            return _MISSING
    return current


def _as_number(value: Any) -> float:
    if isinstance(value, bool):  # bool is an int subclass; reject explicitly.
        raise TypeError("boolean is not a valid number for comparison")
    if isinstance(value, (int, float)):
        return float(value)
    raise TypeError(f"value {value!r} is not numeric")


def _op_equals(v, e):       return v == e
def _op_not_equals(v, e):   return v != e
def _op_gte(v, e):          return _as_number(v) >= _as_number(e)
def _op_lte(v, e):          return _as_number(v) <= _as_number(e)
def _op_gt(v, e):           return _as_number(v) > _as_number(e)
def _op_lt(v, e):           return _as_number(v) < _as_number(e)
def _op_in(v, e):           return v in e
def _op_not_in(v, e):       return v not in e
def _op_contains(v, e):     return e in v
def _op_not_contains(v, e): return e not in v
def _op_is_true(v, e):      return bool(v)
def _op_is_false(v, e):     return not bool(v)


_ALL_OPERATORS = {
    "equals": _op_equals,
    "not_equals": _op_not_equals,
    "gte": _op_gte,
    "lte": _op_lte,
    "gt": _op_gt,
    "lt": _op_lt,
    "in": _op_in,
    "not_in": _op_not_in,
    "contains": _op_contains,
    "not_contains": _op_not_contains,
    "is_true": _op_is_true,
    "is_false": _op_is_false,
    "present": None,   # handled specially (operates on presence, not value)
    "absent": None,    # handled specially
}


def evaluate_check(check: Check, inventory: dict[str, Any]) -> CheckResult:
    """Evaluate a single check against an inventory snapshot."""
    observed = resolve_path(inventory, check.path)
    present = observed is not _MISSING

    # Presence operators short-circuit before value handling.
    if check.operator == "present":
        passed = present
        ev = (
            f"setting '{check.path}' is present"
            if passed
            else f"setting '{check.path}' is missing from the inventory"
        )
        return CheckResult(check, passed, observed if present else None, ev)

    if check.operator == "absent":
        passed = not present
        ev = (
            f"setting '{check.path}' is absent (as required)"
            if passed
            else f"setting '{check.path}' is present but should be absent "
            f"(observed: {_jsonable(observed)!r})"
        )
        return CheckResult(check, passed, observed if present else None, ev)

    # Value operators require the setting to exist.
    if not present:
        ev = (
            f"setting '{check.path}' is missing; cannot satisfy "
            f"'{check.operator}' check (treated as FAIL)"
        )
        return CheckResult(check, False, None, ev)

    fn = _ALL_OPERATORS[check.operator]
    try:
        passed = bool(fn(observed, check.expected))
    except TypeError as exc:
        ev = (
            f"could not evaluate '{check.operator}' on '{check.path}': {exc} "
            f"(observed: {_jsonable(observed)!r})"
        )
        return CheckResult(check, False, observed, ev)

    ev = _build_evidence(check, observed, passed)
    return CheckResult(check, passed, observed, ev)


def _build_evidence(check: Check, observed: Any, passed: bool) -> str:
    obs = _jsonable(observed)
    if check.operator in _NO_EXPECTED_OPS:
        cond = check.operator.replace("_", " ")
        return f"'{check.path}' = {obs!r} ({'satisfies' if passed else 'violates'} {cond})"
    rel = "matches" if passed else "does not match"
    return (
        f"'{check.path}' = {obs!r} {rel} expectation "
        f"({check.operator} {check.expected!r})"
    )
