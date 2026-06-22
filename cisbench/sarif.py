"""SARIF 2.1.0 export for cisbench scan reports.

SARIF (Static Analysis Results Interchange Format, OASIS standard, version
2.1.0) is the lingua franca for ingesting analysis findings into code-scanning
dashboards — GitHub code scanning, Azure DevOps, and many SAST aggregators all
read it. Emitting SARIF lets a cisbench scan show up alongside other security
findings in those tools without any bespoke glue.

This module turns a :class:`~cisbench.profile.ScanReport` into a SARIF log.
Mapping:

* one ``run`` whose ``tool.driver`` describes cisbench and registers every
  check in the scanned profile as a reusable ``rule`` (with id, name, the
  authored control reference, full description, and remediation as help text);
* one ``result`` per **failing** check (SARIF results are findings, so passing
  checks are not emitted as problems); each result carries the rule id, a
  severity ``level``, a human-readable message built from the evidence, and a
  logical location naming the inventory setting path that was evaluated.

Severity is mapped to the SARIF ``level`` enum and also preserved exactly via
the ``security-severity`` property used by GitHub code scanning:

    cisbench severity   SARIF level   security-severity
    -----------------   -----------   -----------------
    critical            error         9.0
    high                error         7.0
    medium              warning       5.0
    low                 note          3.0

The output is plain, deterministic JSON (no timestamps), so it is safe to diff
in CI and reproducible across runs.
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .profile import ScanReport

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/cognis-digital/cisbench"

# cisbench severity -> (SARIF level, GitHub security-severity score)
_LEVEL_MAP: dict[str, tuple[str, str]] = {
    "critical": ("error", "9.0"),
    "high": ("error", "7.0"),
    "medium": ("warning", "5.0"),
    "low": ("note", "3.0"),
}


def _level_for(severity: str) -> str:
    return _LEVEL_MAP.get(severity, ("warning", "5.0"))[0]


def _security_severity_for(severity: str) -> str:
    return _LEVEL_MAP.get(severity, ("warning", "5.0"))[1]


def _rule_for_check(chk) -> dict[str, Any]:
    """Build a SARIF reportingDescriptor (rule) from a check."""
    full = chk.description or chk.title
    help_text = full
    if chk.remediation:
        help_text = f"{full}\n\nRemediation: {chk.remediation}"
    rule: dict[str, Any] = {
        "id": chk.id,
        "name": chk.id.replace("-", "").replace(".", ""),
        "shortDescription": {"text": chk.title},
        "fullDescription": {"text": full},
        "help": {"text": help_text},
        "defaultConfiguration": {"level": _level_for(chk.severity)},
        "properties": {
            "tags": ["security", "hardening", "configuration"],
            "security-severity": _security_severity_for(chk.severity),
            "cisbench-severity": chk.severity,
            "cisbench-reference": chk.reference,
        },
    }
    return rule


def _result_for(check_result) -> dict[str, Any]:
    """Build a SARIF result for a single failing check."""
    chk = check_result.check
    message = f"{chk.title}: {check_result.evidence}"
    if chk.remediation:
        message += f" Remediation: {chk.remediation}"
    return {
        "ruleId": chk.id,
        "level": _level_for(chk.severity),
        "message": {"text": message},
        "locations": [
            {
                "logicalLocations": [
                    {
                        "name": chk.path,
                        "fullyQualifiedName": chk.path,
                        "kind": "member",
                    }
                ]
            }
        ],
        "properties": {
            "cisbench-reference": chk.reference,
            "cisbench-severity": chk.severity,
        },
    }


def to_sarif(report: ScanReport) -> dict[str, Any]:
    """Convert a scan report into a SARIF 2.1.0 log (as a dict)."""
    rules = [_rule_for_check(chk) for chk in report.profile.checks]
    results = [_result_for(r) for r in report.results if not r.passed]

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "cisbench",
                "version": __version__,
                "informationUri": INFORMATION_URI,
                "organization": "Cognis Digital",
                "shortDescription": {
                    "text": (
                        "Offline CIS-benchmark-style configuration checker "
                        "for database hardening settings."
                    )
                },
                "rules": rules,
            }
        },
        "results": results,
        "properties": {
            "profile": report.profile.name,
            "profileVersion": report.profile.version,
            "score": report.score,
            "weightedScore": report.weighted_score,
            "total": report.total,
            "passed": report.passed,
            "failed": report.failed,
        },
    }

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }
