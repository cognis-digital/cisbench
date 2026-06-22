"""Tests for SARIF 2.1.0 export."""

import json
import pathlib

import pytest

from cisbench.cli import main
from cisbench.profile import Profile, load_inventory, scan
from cisbench.sarif import SARIF_VERSION, to_sarif

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXAMPLE = str(ROOT / "examples" / "inventory.json")
HARDENED = str(ROOT / "examples" / "inventory_hardened.json")


def _report(inventory_path):
    inv = load_inventory(inventory_path)
    return scan(Profile.builtin(), inv)


def test_sarif_top_level_shape():
    log = to_sarif(_report(EXAMPLE))
    assert log["version"] == SARIF_VERSION == "2.1.0"
    assert log["$schema"].endswith("sarif-schema-2.1.0.json")
    assert isinstance(log["runs"], list) and len(log["runs"]) == 1


def test_sarif_driver_metadata():
    run = to_sarif(_report(EXAMPLE))["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "cisbench"
    assert driver["organization"] == "Cognis Digital"
    assert driver["informationUri"].startswith("https://")


def test_sarif_registers_every_check_as_a_rule():
    prof = Profile.builtin()
    run = to_sarif(scan(prof, load_inventory(EXAMPLE)))["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == len(prof.checks)
    rule_ids = {r["id"] for r in rules}
    assert {c.id for c in prof.checks} == rule_ids


def test_sarif_results_are_only_failures():
    report = _report(EXAMPLE)
    run = to_sarif(report)["runs"][0]
    results = run["results"]
    assert len(results) == report.failed
    # every result references a real rule and a failing check
    failing_ids = {r.check.id for r in report.results if not r.passed}
    assert {res["ruleId"] for res in results} == failing_ids


def test_sarif_hardened_has_no_results():
    run = to_sarif(_report(HARDENED))["runs"][0]
    assert run["results"] == []
    # but rules are still registered
    assert len(run["tool"]["driver"]["rules"]) >= 12


def test_sarif_severity_level_mapping():
    run = to_sarif(_report(EXAMPLE))["runs"][0]
    by_rule = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    # CDB-1.1 is critical -> error; CDB-7.1 is low -> note
    assert by_rule["CDB-1.1"]["defaultConfiguration"]["level"] == "error"
    assert by_rule["CDB-7.1"]["defaultConfiguration"]["level"] == "note"
    assert by_rule["CDB-2.2"]["defaultConfiguration"]["level"] == "warning"


def test_sarif_security_severity_property():
    run = to_sarif(_report(EXAMPLE))["runs"][0]
    by_rule = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    # GitHub code-scanning reads this property; must be a numeric string.
    score = by_rule["CDB-1.1"]["properties"]["security-severity"]
    assert score == "9.0"
    float(score)  # parses as a number


def test_sarif_result_has_logical_location():
    run = to_sarif(_report(EXAMPLE))["runs"][0]
    res = run["results"][0]
    loc = res["locations"][0]["logicalLocations"][0]
    assert loc["name"]  # the inventory setting path
    assert "kind" in loc


def test_sarif_summary_properties():
    report = _report(EXAMPLE)
    props = to_sarif(report)["runs"][0]["properties"]
    assert props["total"] == report.total
    assert props["failed"] == report.failed
    assert props["score"] == report.score
    assert props["profile"] == report.profile.name


def test_sarif_is_deterministic():
    a = to_sarif(_report(EXAMPLE))
    b = to_sarif(_report(EXAMPLE))
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ---- CLI wiring ----------------------------------------------------------
def test_cli_sarif_flag_emits_valid_json(capsys):
    rc = main(["scan", EXAMPLE, "--sarif"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "cisbench"


def test_cli_sarif_respects_gate(capsys):
    # SARIF output should not change exit-code gating behaviour.
    rc = main(["scan", EXAMPLE, "--sarif", "--fail-on-any"])
    assert rc == 1
    json.loads(capsys.readouterr().out)  # still valid JSON on stdout


def test_cli_sarif_custom_profile(capsys):
    prof = str(ROOT / "demos" / "05-pci-custom-profile" / "profile_payments.json")
    inv = str(ROOT / "demos" / "05-pci-custom-profile" / "inventory.json")
    rc = main(["scan", inv, "--profile", prof, "--sarif"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    rule_ids = {r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]}
    assert "PAY-1" in rule_ids
