# cisbench

**cisbench** is an offline, CIS-benchmark-style configuration checker for
database hardening settings. It evaluates a set of declarative checks against a
**provided inventory snapshot** (a settings JSON) and reports `PASS`/`FAIL` with
evidence, a compliance score, and remediation guidance.

cisbench is **offline only**. It never connects to a database. You give it a
JSON snapshot of the configuration you want to audit, and it reasons purely over
that file. This makes it safe to run anywhere — in CI, on an air-gapped review
workstation, or against an exported configuration dump.

- Maintainer: **Cognis Digital**
- License: **COCL 1.0**
- Python 3.10+
- Standard library only — no third-party runtime dependencies.

## Why offline?

Many configuration-assessment tools require live credentials and network access
to the system under test. cisbench deliberately does the opposite: it works
against a captured snapshot. The team that exports the configuration never has
to hand out database credentials, and the audit is fully reproducible.

## Install

```bash
pip install -e .
```

This installs the `cisbench` console command.

## Concepts

- **Inventory** — a JSON object describing the configuration to audit. Settings
  are addressed with dotted paths (e.g. `network.require_tls`). An optional
  top-level `settings` wrapper is supported so snapshots can carry metadata.
- **Check** — a single declarative expectation: an id, a title, an authored
  control reference, a rule (operator + path + expected value), a severity, and
  remediation text.
- **Profile** — an ordered collection of checks. A built-in baseline profile
  (`cognis-db-baseline`, 12 checks) ships with the tool; you can also supply
  your own with `--profile`.
- **Score** — the plain pass-rate, plus a severity-**weighted** score so that
  failing a `critical` control costs more than failing a `low` one.

## Usage

### Scan an inventory

```bash
cisbench scan examples/inventory.json
```

```
cisbench scan — profile: cognis-db-baseline (v1.0)
========================================================================
[PASS] CDB-1.1   Transport encryption is required for client connections
        ref=CDB-NET-1  severity=critical
        evidence: 'network.require_tls' = True (satisfies is true)
[FAIL] CDB-2.1   Password minimum length meets baseline
        ref=CDB-AUTH-1  severity=high
        evidence: 'auth.password_min_length' = 12 does not match expectation (gte 14)
        remediation: Set the password policy minimum length to at least 14 ...
...
------------------------------------------------------------------------
9/12 passed  |  score 75.0%  |  weighted 71.4%
3 check(s) failed.
```

Add `--json` for machine-readable output:

```bash
cisbench scan examples/inventory.json --json
```

### List the checks in a profile

```bash
cisbench list
cisbench list --profile examples/profile_minimal.json
```

### Evaluate a single check

```bash
cisbench check CDB-1.1 examples/inventory.json
```

### Use in CI (exit-code gates)

cisbench returns a non-zero exit code when a gate is not satisfied, so it can
fail a pipeline:

```bash
# Fail if any check fails:
cisbench scan inventory.json --fail-on-any

# Fail if the score drops below a threshold:
cisbench scan inventory.json --fail-on 90
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0`  | success / all gates satisfied |
| `1`  | a CI gate failed (`--fail-on` / `--fail-on-any`) |
| `2`  | usage or input error (missing file, unknown check id) |

## Authoring a custom profile

A profile is plain JSON. Each check uses one of the supported operators below.

```json
{
  "name": "minimal-tls-profile",
  "version": "1.0",
  "description": "Checks transport security only.",
  "checks": [
    {
      "id": "MIN-1",
      "title": "TLS is required for client connections",
      "path": "network.require_tls",
      "operator": "is_true",
      "reference": "MIN-NET-1",
      "severity": "critical",
      "remediation": "Enable mandatory TLS at the listener."
    }
  ]
}
```

### Supported operators

| Operator | Meaning |
|----------|---------|
| `equals` / `not_equals` | value equals / does not equal `expected` |
| `gte` / `lte` / `gt` / `lt` | numeric comparisons against `expected` |
| `in` / `not_in` | membership of value in the `expected` list |
| `contains` / `not_contains` | `expected` is / is not in the value (list or string) |
| `is_true` / `is_false` | value is truthy / falsy (`expected` ignored) |
| `present` / `absent` | the setting key exists / does not exist |

### Severities

`low`, `medium`, `high`, `critical` — these drive the weighted score (weights
1, 2, 3, 4 respectively).

## Built-in baseline profile

The `cognis-db-baseline` profile ships 12 vendor-neutral checks covering
transport encryption, authentication policy, audit logging, account hygiene,
network exposure, data-at-rest encryption, and diagnostic information leakage.
All control identifiers (the `CDB-*` namespace) and wording are authored for
cisbench; they are not copied from any external benchmark document.

Run `cisbench list` to see the full catalogue.

## Development

```bash
python -m pytest
```

On Windows, set `PYTHONUTF8=1` for the tests:

```bash
PYTHONUTF8=1 python -m pytest
```

## Scope

cisbench is a **defensive, analytical** tool. It reads configuration snapshots
and reports on hardening posture. It performs no exploitation, no network
activity, and no changes to any system.
