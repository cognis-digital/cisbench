"""Tests for the CLI, especially exit-code gates."""

import json
import pathlib

import pytest

from cisbench.cli import main

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXAMPLE = str(ROOT / "examples" / "inventory.json")
HARDENED = str(ROOT / "examples" / "inventory_hardened.json")
PROFILE = str(ROOT / "examples" / "profile_minimal.json")


def test_scan_runs_clean_exit(capsys):
    rc = main(["scan", EXAMPLE, "--no-color"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PASS" in out and "FAIL" in out
    assert "score" in out


def test_scan_json_output(capsys):
    rc = main(["scan", EXAMPLE, "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["total"] >= 12
    assert "results" in data


def test_fail_on_any_gate_trips_on_example(capsys):
    # The example inventory has failures -> gate should return 1.
    rc = main(["scan", EXAMPLE, "--fail-on-any", "--no-color"])
    assert rc == 1


def test_fail_on_any_passes_on_hardened():
    rc = main(["scan", HARDENED, "--fail-on-any", "--no-color"])
    assert rc == 0


def test_fail_on_score_threshold(capsys):
    # Hardened scores 100; threshold 90 should pass.
    assert main(["scan", HARDENED, "--fail-on", "90", "--no-color"]) == 0
    # Example scores below 100; threshold 100 should fail.
    assert main(["scan", EXAMPLE, "--fail-on", "100", "--no-color"]) == 1


def test_list_command(capsys):
    rc = main(["list", "--no-color"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CDB-1.1" in out


def test_list_json(capsys):
    rc = main(["list", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["checks"]) >= 12


def test_check_single_pass(capsys):
    # CDB-1.1 (require_tls) passes on the example inventory.
    rc = main(["check", "CDB-1.1", EXAMPLE, "--no-color"])
    assert rc == 0
    assert "PASS" in capsys.readouterr().out


def test_check_single_fail_gate(capsys):
    # CDB-4.2 (default_admin_renamed) is false in the example -> FAIL.
    rc = main(["check", "CDB-4.2", EXAMPLE, "--no-color", "--fail-on-fail"])
    assert rc == 1


def test_check_unknown_id(capsys):
    rc = main(["check", "NOPE", EXAMPLE, "--no-color"])
    assert rc == 2
    assert "no check with id" in capsys.readouterr().err


def test_custom_profile_used(capsys):
    rc = main(["scan", EXAMPLE, "--profile", PROFILE, "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["profile"] == "minimal-tls-profile"
    assert data["summary"]["total"] == 2


def test_missing_inventory_file_is_usage_error(capsys):
    rc = main(["scan", "no-such-file.json", "--no-color"])
    assert rc == 2
    assert "not found" in capsys.readouterr().err
