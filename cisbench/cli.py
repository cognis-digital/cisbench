"""Command-line interface for cisbench.

Subcommands:
    scan         evaluate a profile against an inventory and report results
    list         print the catalog of checks in a profile
    check        evaluate a single check by id against an inventory
    crosswalk    map each check to authoritative NIST 800-53 rev5 controls
    feeds        manage the edge/air-gap data-feed cache (list/update/get)
    active-scan  OPTIONAL, authorization-gated read-only probe of an
                 allowlisted host (off by default; passive scan is the default)

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

from . import __version__, datafeeds
from .active import (
    ActiveError,
    ActiveScanner,
    Allowlist,
    RateLimiter,
    merge_evidence,
    parse_target,
)
from .crosswalk import FEED_ID, build_index, enrich_profile, load_catalog
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
# crosswalk  (real enrichment: map checks -> authoritative NIST 800-53 rev5)
# --------------------------------------------------------------------------
def cmd_crosswalk(args: argparse.Namespace) -> int:
    profile = _load_profile(args)
    try:
        rows = enrich_profile(profile, offline=args.offline)
    except FileNotFoundError:
        print("error: NIST 800-53 catalog is not cached. Run "
              "'cisbench feeds update' while online, or import an air-gap "
              "snapshot, before using --offline.", file=sys.stderr)
        return EXIT_USAGE
    except ConnectionError as exc:
        print(f"error: could not fetch the 800-53 catalog: {exc}\n"
              "       use --offline once the cache is populated.",
              file=sys.stderr)
        return EXIT_USAGE

    if args.json:
        print(json.dumps({"profile": profile.name, "checks": rows}, indent=2))
        return EXIT_OK

    color = _use_color(args)
    print()
    print(_color(f"NIST SP 800-53 rev5 crosswalk — profile: {profile.name}",
                 _BOLD, color))
    print(_color("source: usnistgov/oscal-content (authoritative OSCAL "
                 "catalog)", _BOLD, color))
    print("=" * 72)
    unmapped = 0
    for row in rows:
        print(f"{row['check_id']:<10} [{row['severity']:<8}] {row['title']}")
        if not row["controls"]:
            print("           (no NIST 800-53 controls tagged)")
            continue
        for c in row["controls"]:
            if c["resolved"]:
                print(f"           -> {c['label']:<10} {c['title']}  "
                      f"[{c['family']}]")
            else:
                unmapped += 1
                print(f"           -> {c['requested']:<10} "
                      + _color("UNRESOLVED in catalog", _RED, color))
    print("-" * 72)
    mapped_checks = sum(1 for r in rows if r["controls"])
    print(f"{mapped_checks}/{len(rows)} checks carry 800-53 mappings; "
          f"{unmapped} control id(s) unresolved.")
    print()
    return EXIT_GATE_FAILED if (args.fail_on_unmapped and unmapped) else EXIT_OK


# --------------------------------------------------------------------------
# feeds  (edge/air-gap data-feed cache management)
# --------------------------------------------------------------------------

# cisbench only consumes these feed ids from the shared catalog.
RELEVANT_FEEDS = [FEED_ID]


def _relevant_or_error(feed_id: str) -> bool:
    if feed_id not in RELEVANT_FEEDS:
        print(f"error: '{feed_id}' is not a feed cisbench consumes. "
              f"Relevant feeds: {', '.join(RELEVANT_FEEDS)}", file=sys.stderr)
        return False
    return True


def cmd_feeds(args: argparse.Namespace) -> int:
    action = args.feeds_action
    catalog = datafeeds.load_catalog()
    by_id = {f["id"]: f for f in catalog.get("feeds", [])}

    if action == "list":
        print()
        print("cisbench data feeds (edge/air-gap ingestion):")
        print("=" * 72)
        for fid in RELEVANT_FEEDS:
            meta = by_id.get(fid, {})
            age = datafeeds.cached_age_hours(fid)
            fresh = "uncached" if age is None else f"cached {age:.1f}h ago"
            print(f"  {fid}")
            print(f"      {meta.get('name', '')}")
            print(f"      domain={meta.get('domain', '')}  "
                  f"format={meta.get('format', '')}  [{fresh}]")
            print(f"      url={meta.get('url', '')}")
        print()
        return EXIT_OK

    if action == "update":
        rc = EXIT_OK
        for fid in (args.ids or RELEVANT_FEEDS):
            if not _relevant_or_error(fid):
                rc = EXIT_USAGE
                continue
            try:
                pth = datafeeds.update(fid)
                print(f"  updated {fid} -> {pth} "
                      f"({pth.stat().st_size} bytes)")
            except (KeyError, ConnectionError) as exc:
                print(f"  {fid}: {exc}", file=sys.stderr)
                rc = EXIT_USAGE
        return rc

    if action == "get":
        if not _relevant_or_error(args.id):
            return EXIT_USAGE
        try:
            data = datafeeds.get(args.id, offline=args.offline)
        except (KeyError, FileNotFoundError, ConnectionError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE
        if args.id == FEED_ID:
            # Print a compact summary rather than the 10 MB catalog.
            index = build_index(data)
            families = sorted({c.family_id for c in index.values()})
            print(f"feed: {args.id}")
            print(f"controls indexed: {len(index)}")
            print(f"families: {len(families)} ({', '.join(families)})")
        else:  # pragma: no cover - only one relevant feed today
            text = json.dumps(data, indent=2) if isinstance(data, (dict, list)) \
                else str(data)
            print(text[:4000])
        return EXIT_OK

    return EXIT_USAGE


# --------------------------------------------------------------------------
# active-scan  (OPTIONAL, authorization-gated, read-only probe)
# --------------------------------------------------------------------------
def cmd_active_scan(args: argparse.Namespace) -> int:
    """Read-only probe of an allowlisted host, then score it passively.

    Off by default at every layer: requires --authorized AND an explicit
    target allowlist; paces probes with a rate limiter; probes are read-only
    (TCP connect + banner only). The probe evidence is merged into a base
    inventory and scored by the ordinary passive engine.
    """
    # Build the allowlist from --allow and/or --allow-file.
    entries: list[str] = list(args.allow or [])
    try:
        if args.allow_file:
            file_allow = Allowlist.from_file(args.allow_file)
            entries.extend(file_allow.entries)
        allowlist = Allowlist.from_iterable(entries)
    except ActiveError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if not args.authorized:
        print("refused: active probing is OFF by default. Re-run with "
              "--authorized and an explicit --allow/--allow-file target "
              "allowlist for hosts you are authorized to assess.",
              file=sys.stderr)
        return EXIT_USAGE
    if len(allowlist) == 0:
        print("refused: --authorized requires a non-empty target allowlist "
              "(use --allow HOST or --allow-file FILE).", file=sys.stderr)
        return EXIT_USAGE

    try:
        targets = [parse_target(t, default_port=args.port) for t in args.targets]
    except ActiveError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    scanner = ActiveScanner(
        authorized=True,
        allowlist=allowlist,
        limiter=RateLimiter(rate=args.rate, capacity=args.rate),
        timeout=args.timeout,
    )

    try:
        results = scanner.probe_all(targets)
    except ActiveError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_USAGE

    base: dict[str, Any] = {}
    if args.from_inventory:
        base = load_inventory(args.from_inventory)
    inventory = merge_evidence(base, results)

    if args.emit_inventory:
        print(json.dumps(inventory, indent=2))
        return EXIT_OK

    profile = _load_profile(args)
    report = scan(profile, inventory)
    if getattr(args, "sarif", False):
        print(json.dumps(to_sarif(report), indent=2))
    elif args.json:
        out = report.to_dict()
        out["active_probes"] = [r.to_dict() for r in results]
        print(json.dumps(out, indent=2))
    else:
        color = _use_color(args)
        print()
        print(_color("cisbench active-scan (read-only, authorized) — "
                     f"{len(results)} target(s) probed", _BOLD, color))
        for r in results:
            state = "reachable" if r.reachable else "unreachable"
            line = f"  {r.target.host}:{r.target.port}  {state}"
            if r.banner:
                line += f"  banner={r.banner!r}"
            if r.error:
                line += f"  error={r.error}"
            print(line)
        _print_scan_table(report, color=color)
    return _apply_gate(args, report)


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

    # crosswalk
    p_xw = sub.add_parser(
        "crosswalk",
        help="map each check to authoritative NIST 800-53 rev5 controls")
    p_xw.add_argument("--profile", help="path to a custom profile JSON")
    p_xw.add_argument("--json", action="store_true",
                      help="emit machine-readable JSON")
    p_xw.add_argument("--no-color", action="store_true",
                      help="disable ANSI colour output")
    p_xw.add_argument("--offline", action="store_true",
                      help="resolve from the cached catalog only "
                           "(air-gap mode; never touches the network)")
    p_xw.add_argument("--fail-on-unmapped", action="store_true",
                      help="exit non-zero if any tagged control is "
                           "unresolved in the catalog")
    p_xw.set_defaults(func=cmd_crosswalk)

    # feeds
    p_feeds = sub.add_parser(
        "feeds",
        help="manage the edge/air-gap data-feed cache cisbench consumes")
    feeds_sub = p_feeds.add_subparsers(dest="feeds_action", required=True)
    fl = feeds_sub.add_parser("list", help="list the feeds cisbench consumes")
    fl.set_defaults(func=cmd_feeds)
    fu = feeds_sub.add_parser("update",
                              help="fetch + cache the relevant feed(s)")
    fu.add_argument("ids", nargs="*",
                    help="feed id(s) to update (default: all relevant)")
    fu.set_defaults(func=cmd_feeds)
    fg = feeds_sub.add_parser("get", help="show a cached feed summary")
    fg.add_argument("id", help="feed id to retrieve")
    fg.add_argument("--offline", action="store_true",
                    help="serve from cache only (never touch the network)")
    fg.set_defaults(func=cmd_feeds)

    # active-scan (OPTIONAL, authorization-gated, read-only)
    p_act = sub.add_parser(
        "active-scan",
        help="OPTIONAL authorization-gated read-only probe of an allowlisted "
             "host (OFF by default; the passive 'scan' is the default mode)",
        description="Read-only active probe. OFF by default: requires "
                    "--authorized AND an explicit target allowlist. Probes are "
                    "read-only (TCP connect + banner); no auth, no payloads, no "
                    "writes. Evidence is merged into an inventory and scored by "
                    "the same passive engine.")
    p_act.add_argument("targets", nargs="+",
                       help="host[:port] target(s) to probe (must be allowlisted)")
    p_act.add_argument("--authorized", action="store_true",
                       help="REQUIRED to enable active probing; asserts you are "
                            "authorized to assess the allowlisted targets")
    p_act.add_argument("--allow", action="append", metavar="HOST",
                       help="add a host to the authorization allowlist "
                            "(repeatable)")
    p_act.add_argument("--allow-file", metavar="FILE",
                       help="file of allowlisted hosts (one per line, # comments)")
    p_act.add_argument("--port", type=int, default=5432,
                       help="default port when a target omits one (default 5432)")
    p_act.add_argument("--rate", type=float, default=2.0,
                       help="max probe attempts per second (rate limiter; "
                            "default 2.0)")
    p_act.add_argument("--timeout", type=float, default=3.0,
                       help="per-probe TCP timeout in seconds (default 3.0)")
    p_act.add_argument("--from", dest="from_inventory", metavar="INVENTORY",
                       help="base inventory JSON to merge probe evidence into")
    p_act.add_argument("--emit-inventory", action="store_true",
                       help="print the merged inventory and exit (do not score)")
    p_act.add_argument("--profile", help="path to a custom profile JSON")
    p_act.add_argument("--json", action="store_true",
                       help="emit machine-readable JSON")
    p_act.add_argument("--sarif", action="store_true",
                       help="emit a SARIF 2.1.0 log of failing checks")
    p_act.add_argument("--no-color", action="store_true",
                       help="disable ANSI colour output")
    p_act.add_argument("--fail-on", type=float, metavar="SCORE",
                       help="exit non-zero if the score is below SCORE")
    p_act.add_argument("--fail-on-any", action="store_true",
                       help="exit non-zero if any check fails")
    p_act.set_defaults(func=cmd_active_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ProfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ActiveError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
