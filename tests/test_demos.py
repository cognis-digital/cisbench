"""Tests that every shipped demo actually loads and scans as documented.

These guard against a demo inventory drifting out of sync with the engine
(e.g. an unparseable file, or a profile that no longer loads).
"""

import json
import pathlib

import pytest

from cisbench.profile import Profile, load_inventory, scan

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEMOS = ROOT / "demos"


def _demo_inventories():
    return sorted(DEMOS.glob("*/inventory*.json"))


def test_demos_directory_exists_and_is_populated():
    dirs = [p for p in DEMOS.iterdir() if p.is_dir()]
    assert len(dirs) >= 8


@pytest.mark.parametrize("inv_path", _demo_inventories(),
                         ids=lambda p: f"{p.parent.name}/{p.name}")
def test_every_demo_inventory_scans(inv_path):
    inv = load_inventory(inv_path)
    report = scan(Profile.builtin(), inv)
    # A scan always produces one result per baseline check.
    assert report.total == len(Profile.builtin().checks)
    assert 0.0 <= report.score <= 100.0


@pytest.mark.parametrize("inv_path", _demo_inventories(),
                         ids=lambda p: f"{p.parent.name}/{p.name}")
def test_every_demo_has_a_scenario(inv_path):
    scenario = inv_path.parent / "SCENARIO.md"
    assert scenario.is_file(), f"{inv_path.parent.name} is missing SCENARIO.md"
    assert scenario.read_text(encoding="utf-8").strip()


def test_demo_custom_profile_loads_and_scans():
    prof_path = DEMOS / "05-pci-custom-profile" / "profile_payments.json"
    inv_path = DEMOS / "05-pci-custom-profile" / "inventory.json"
    prof = Profile.load(prof_path)
    assert prof.name == "cognis-payments-db"
    report = scan(prof, load_inventory(inv_path))
    # Documented outcome: passes baseline but fails two payments controls.
    assert report.failed == 2


def test_demo_known_scores():
    """Spot-check the headline scores cited in the SCENARIO files."""
    expectations = {
        "01-postgres-prod-audit/inventory.json": (9, 12),
        "02-mysql-dev-exposed/inventory.json": (0, 12),
        "07-legacy-onprem-remediation/inventory.json": (1, 12),
        "07-legacy-onprem-remediation/inventory_after_phase1.json": (9, 12),
        "08-airgapped-review/inventory.json": (10, 12),
    }
    for rel, (exp_passed, exp_total) in expectations.items():
        inv = load_inventory(DEMOS / rel)
        report = scan(Profile.builtin(), inv)
        assert report.passed == exp_passed, rel
        assert report.total == exp_total, rel
