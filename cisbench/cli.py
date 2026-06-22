"""Command-line interface for cisbench.

Subcommands:
    scan    evaluate a profile against an inventory and report results
    list    print the catalog of checks in a profile
    check   evaluate a single check by id against an inventory

Exit codes:
    0   success / all gates satisfied
    1   a CI gate failed (--fail-on / --fail-on-any threshold not met)
    2   usage or input error (bad file, unknown check id, etc.)
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import __version__
from .engine import evaluate_check
from .profile import (
    Profile,
    ProfileError,
    ScanReport,
    load_inventory,
    scan,
)
from .sarif import to_sarif

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_USAGE = 2

# ANSI colours, only applied when stdout is a TTY.
_GREEN = "\033[32m"
_RED = "\033[31m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _color(text: str, code: str, enable: bool) -> str:
    return f"{code}{text}{_RESET}" if enable else text


def _load_profile(args: argparse.Namespace) -> Profile:
    if getattr(args, "profile", None):
        return Profile.load(args.profile)
    return Profile.builtin()


# --------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------
def cmd_scan(args: argparse.Namespace) -> int:
    profile = _load_profile(args)
    inventory = load_inventory(args.inventory)
    report = scan(profile, inventory)

    if getattr(args, "sarif", False):
        print(json.dumps(to_sarif(report), indent=2))
    elif args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_scan_table(report, color=_use_color(args))

    return _apply_gate(args, report)


def _use_color(args: argparse.Namespace) -> bool:
    if getattr(args, "no_color", False):
        return False
    return sys.stdout.isatty()


def _print_scan_table(report: ScanReport, color: bool) -> None:
    print()
    print(_color(f"cisbench scan — profile: {report.profile.name} "
                 f"(v{report.profile.version})", _BOLD, color))
    print("=" * 72)
    id_w = max((len(r.check.id) for r in report.results), default=2)
    id_w = max(id_w, 2)
    for r in report.results:
        if r.passed:
            status = _color("PASS", _GREEN, color)
        else:
            status = _color("FAIL", _RED, color)
        print(f"[{status}] {r.check.id:<{id_w}}  {r.check.title}")
        print(f"        ref={r.check.reference}  severity={r.check.severity}")
        print(f"        evidence: {r.evidence}")
        if not r.passed and r.check.remediation:
            print(f"        remediation: {r.check.remediation}")
    print("-" * 72)
    summary = (
        f"{report.passed}/{report.total} passed  |  "
        f"score {report.score}%  |  weighted {report.weighted_score}%"
    )
    code = _GREEN if report.failed == 0 else _RED
    print(_color(summary, code, color))
    if report.failed:
        print(f"{report.failed} check(s) failed.")
    print()


def _apply_gate(args: argparse.Namespace, report: ScanReport) -> int:
    """Return the process exit code based on CI gate flags."""
    if getattr(args, "fail_on_any", False) and report.failed > 0:
        return EXIT_GATE_FAILED
    threshold = getattr(args, "fail_on", None)
    if threshold is not None and report.score < threshold:
        return EXIT_GATE_FAILED
    return EXIT_OK


# --------------------------------------------------------------------------
# list
# --------------------------------------------------------------------------
def cmd_list(args: argparse.Namespace) -> int:
    profile = _load_profile(args)
    if args.json:
        print(json.dumps(profile.to_dict(), indent=2))
        return EXIT_OK
    color = _use_color(args)
    print()
    print(_color(f"Profile: {profile.name} (v{profile.version}) — "
                 f"{len(profile.checks)} checks", _BOLD, color))
    if profile.description:
        print(profile.description)
    print("=" * 72)
    for chk in profile.checks:
        print(f"{chk.id:<10} [{chk.severity:<8}] {chk.title}")
        print(f"           ref={chk.reference}  path={chk.path}  "
              f"op={chk.operator}"
              + (f"  expected={chk.expected!r}" if chk.expected is not None else ""))
    print()
    return EXIT_OK


# --------------------------------------------------------------------------
# check
# --------------------------------------------------------------------------
def cmd_check(args: argparse.Namespace) -> int:
    profile = _load_profile(args)
    chk = profile.get(args.check_id)
    if chk is None:
        print(f"error: no check with id '{args.check_id}' in profile "
              f"'{profile.name}'", file=sys.stderr)
        return EXIT_USAGE
    inventory = load_inventory(args.inventory)
    result = evaluate_check(chk, inventory)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        color = _use_color(args)
        status = (_color("PASS", _GREEN, color) if result.passed
                  else _color("FAIL", _RED, color))
        print(f"[{status}] {chk.id}  {chk.title}")
        print(f"  reference:   {chk.reference}")
        print(f"  severity:    {chk.severity}")
        print(f"  evidence:    {result.evidence}")
        if not result.passed and chk.remediation:
            print(f"  remediation: {chk.remediation}")

    if args.fail_on_fail and not result.passed:
        return EXIT_GATE_FAILED
    return EXIT_OK


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cisbench",
        description="Offline CIS-benchmark-style configuration checker for "
                    "database settings. Operates only on a provided inventory "
                    "JSON; it never connects to a database.",
    )
    parser.add_argument("--version", action="version",
                        version=f"cisbench {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="evaluate a profile against an "
                                         "inventory snapshot")
    p_scan.add_argument("inventory", help="path to inventory JSON file")
    p_scan.add_argument("--profile", help="path to a custom profile JSON "
                                          "(defaults to built-in baseline)")
    p_scan.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON instead of a table")
    p_scan.add_argument("--sarif", action="store_true",
                        help="emit a SARIF 2.1.0 log of failing checks "
                             "(for GitHub code scanning and SAST dashboards)")
    p_scan.add_argument("--no-color", action="store_true",
                        help="disable ANSI colour output")
    p_scan.add_argument("--fail-on", type=float, metavar="SCORE",
                        help="exit non-zero if the score is below SCORE "
                             "(0-100)")
    p_scan.add_argument("--fail-on-any", action="store_true",
                        help="exit non-zero if any check fails")
    p_scan.set_defaults(func=cmd_scan)

    # list
    p_list = sub.add_parser("list", help="list the checks in a profile")
    p_list.add_argument("--profile", help="path to a custom profile JSON")
    p_list.add_argument("--json", action="store_true",
                        help="emit the profile as JSON")
    p_list.add_argument("--no-color", action="store_true",
                        help="disable ANSI colour output")
    p_list.set_defaults(func=cmd_list)

    # check
    p_check = sub.add_parser("check", help="evaluate a single check by id")
    p_check.add_argument("check_id", help="id of the check to evaluate")
    p_check.add_argument("inventory", help="path to inventory JSON file")
    p_check.add_argument("--profile", help="path to a custom profile JSON")
    p_check.add_argument("--json", action="store_true",
                         help="emit machine-readable JSON")
    p_check.add_argument("--no-color", action="store_true",
                         help="disable ANSI colour output")
    p_check.add_argument("--fail-on-fail", action="store_true",
                         help="exit non-zero if the check fails")
    p_check.set_defaults(func=cmd_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ProfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
