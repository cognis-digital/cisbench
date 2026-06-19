"""Profile and scoring logic for cisbench.

A *profile* is an ordered collection of checks plus metadata. Profiles can be
loaded from JSON files; if none is supplied, the built-in default profile of
authored DB-hardening checks is used.

Scoring computes both a plain pass-rate and a severity-weighted score so that
failing a critical control costs more than failing a low one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .defaults import DEFAULT_PROFILE
from .engine import Check, CheckError, CheckResult, evaluate_check


class ProfileError(ValueError):
    """Raised when a profile is malformed or cannot be loaded."""


@dataclass
class Profile:
    """A named, ordered collection of checks."""

    name: str
    checks: list[Check] = field(default_factory=list)
    version: str = "1.0"
    description: str = ""

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for chk in self.checks:
            if chk.id in seen:
                raise ProfileError(f"duplicate check id '{chk.id}' in profile")
            seen.add(chk.id)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Profile":
        if not isinstance(data, dict):
            raise ProfileError("profile must be a JSON object")
        raw_checks = data.get("checks")
        if not isinstance(raw_checks, list) or not raw_checks:
            raise ProfileError("profile must contain a non-empty 'checks' list")
        checks: list[Check] = []
        for entry in raw_checks:
            if not isinstance(entry, dict):
                raise ProfileError("each check must be a JSON object")
            try:
                checks.append(Check.from_dict(entry))
            except CheckError as exc:
                raise ProfileError(str(exc)) from exc
        return cls(
            name=data.get("name", "custom"),
            version=str(data.get("version", "1.0")),
            description=data.get("description", ""),
            checks=checks,
        )

    @classmethod
    def load(cls, path: str | Path) -> "Profile":
        p = Path(path)
        if not p.is_file():
            raise ProfileError(f"profile file not found: {p}")
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ProfileError(f"profile is not valid JSON: {exc}") from exc
        return cls.from_dict(data)

    @classmethod
    def builtin(cls) -> "Profile":
        return cls.from_dict(DEFAULT_PROFILE)

    def get(self, check_id: str) -> Check | None:
        for chk in self.checks:
            if chk.id == check_id:
                return chk
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class ScanReport:
    """Aggregated results of evaluating a profile against an inventory."""

    profile: Profile
    results: list[CheckResult]

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return self.total - self.passed

    @property
    def score(self) -> float:
        """Plain pass-rate as a percentage (0.0 - 100.0)."""
        if self.total == 0:
            return 0.0
        return round(100.0 * self.passed / self.total, 1)

    @property
    def weighted_score(self) -> float:
        """Severity-weighted score as a percentage (0.0 - 100.0)."""
        total_weight = sum(r.check.weight for r in self.results)
        if total_weight == 0:
            return 0.0
        earned = sum(r.check.weight for r in self.results if r.passed)
        return round(100.0 * earned / total_weight, 1)

    @property
    def failures(self) -> list[CheckResult]:
        return [r for r in self.results if not r.passed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile.name,
            "profile_version": self.profile.version,
            "summary": {
                "total": self.total,
                "passed": self.passed,
                "failed": self.failed,
                "score": self.score,
                "weighted_score": self.weighted_score,
            },
            "results": [r.to_dict() for r in self.results],
        }


def scan(profile: Profile, inventory: dict[str, Any]) -> ScanReport:
    """Evaluate every check in the profile against the inventory."""
    results = [evaluate_check(chk, inventory) for chk in profile.checks]
    return ScanReport(profile=profile, results=results)


def load_inventory(path: str | Path) -> dict[str, Any]:
    """Load an inventory snapshot JSON file."""
    p = Path(path)
    if not p.is_file():
        raise ProfileError(f"inventory file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProfileError(f"inventory is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ProfileError("inventory must be a JSON object")
    # Allow an optional "settings" wrapper so snapshots can carry metadata.
    if "settings" in data and isinstance(data["settings"], dict):
        return data["settings"]
    return data
