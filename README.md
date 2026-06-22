# cisbench

**cisbench** is an offline, CIS-benchmark-style configuration checker for
database hardening settings. It evaluates a set of declarative checks against a
**provided inventory snapshot** (a settings JSON) and reports `PASS`/`FAIL` with
evidence, a compliance score, and remediation guidance.

cisbench **never connects to a database**. You give it a JSON snapshot of the
configuration you want to audit, and it reasons purely over that file. This
makes it safe to run anywhere — in CI, on an air-gapped review workstation, or
against an exported configuration dump. The optional `crosswalk` enrichment can
fetch the authoritative NIST 800-53 OSCAL catalog once, then run fully offline
(or fully air-gapped via a snapshot); see [Data feeds](#data-feeds-edge--air-gap-ingestion).

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

### Export findings as SARIF 2.1.0

cisbench can emit a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) log so
its findings drop straight into a code-scanning dashboard (GitHub code
scanning, Azure DevOps, or any SARIF-aware aggregator) alongside your other
security results:

```bash
cisbench scan examples/inventory.json --sarif > cisbench.sarif
```

Every check in the scanned profile is registered as a reusable SARIF `rule`
(carrying its control reference and remediation as help text), and each
**failing** check becomes a `result` with:

- the rule id,
- a SARIF `level` (`error` for critical/high, `warning` for medium, `note` for
  low) plus a GitHub `security-severity` score,
- a logical location naming the exact inventory setting path, and
- the evidence and remediation in the message.

The output is deterministic (no timestamps), so it is safe to diff in CI. To
publish to GitHub code scanning:

```yaml
- run: cisbench scan inventory.json --sarif > cisbench.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: cisbench.sarif
```

### Crosswalk findings to NIST SP 800-53 rev5 (real control titles)

Every baseline check is tagged with the NIST SP 800-53 rev5 controls it
supports. `cisbench crosswalk` resolves those control ids against the
**authoritative** NIST OSCAL machine-readable catalog and prints each control's
official **title** and **family** — so a database finding is traceable to a
federal control, with provenance:

```bash
cisbench crosswalk            # online: fetches + caches the catalog if needed
cisbench crosswalk --offline  # air-gap: resolves from the cache only
```

```
NIST SP 800-53 rev5 crosswalk — profile: cognis-db-baseline
source: usnistgov/oscal-content (authoritative OSCAL catalog)
========================================================================
CDB-1.1    [critical] Transport encryption is required for client connections
           -> SC-8       Transmission Confidentiality and Integrity  [System and Communications Protection]
           -> SC-8(1)    Cryptographic Protection  [System and Communications Protection]
...
12/12 checks carry 800-53 mappings; 0 control id(s) unresolved.
```

Add `--json` for machine-readable output, or `--fail-on-unmapped` to gate a
pipeline when a tagged control cannot be resolved in the catalog.

### Data feeds (edge / air-gap ingestion)

The crosswalk is powered by a bundled, **standard-library-only** data-feed
layer (`cisbench/datafeeds.py`). It fetches authoritative feeds over HTTPS,
caches them to disk, and re-serves them **offline** so the tool keeps working on
a disconnected or air-gapped enclave. cisbench consumes exactly one feed from
the shared catalog:

| Feed id | Source | Used for |
|---------|--------|----------|
| `oscal-800-53-rev5-catalog` | [`usnistgov/oscal-content`](https://github.com/usnistgov/oscal-content) — `nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json` | resolving check tags to authoritative 800-53 rev5 control titles/families |

```bash
cisbench feeds list                                   # show the feed(s) + cache status
cisbench feeds update                                 # fetch + cache (online, one-time)
cisbench feeds get oscal-800-53-rev5-catalog --offline  # cached summary, no network
```

The cache location is `COGNIS_FEEDS_CACHE` (default `~/.cache/cognis-feeds`).

#### Air-gap workflow (sneakernet)

On a connected host, populate the cache and export a snapshot; carry it to the
enclave and import it. Everything after that runs with `--offline`:

```bash
# connected host
cisbench feeds update
python -m cisbench.datafeeds snapshot-export oscal.tar.gz

# air-gapped enclave (after transferring oscal.tar.gz)
export COGNIS_FEEDS_CACHE=/opt/cognis-feeds
python -m cisbench.datafeeds snapshot-import oscal.tar.gz
cisbench crosswalk --offline
```

The bundled tests run **fully offline** against a small trimmed OSCAL fixture
committed under [`tests/fixtures/feeds-cache`](tests/fixtures/feeds-cache/);
they never touch the network.

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

## Demos

The [`demos/`](demos/) directory contains worked, real-use-case scenarios. Each
demo is a self-contained folder with a realistic inventory snapshot (and, where
relevant, a custom profile) plus a `SCENARIO.md` explaining where the data came
from, what to expect, the exact command to run, and how to act on the result.

| Demo | Scenario |
|------|----------|
| [`01-postgres-prod-audit`](demos/01-postgres-prod-audit/) | Quarterly hardening review of a production PostgreSQL primary (3 findings). |
| [`02-mysql-dev-exposed`](demos/02-mysql-dev-exposed/) | An exposed, unhardened MySQL dev box found in a network sweep (0/12) — used as a hard CI gate. |
| [`03-cloud-managed-sqldb`](demos/03-cloud-managed-sqldb/) | A managed PaaS database: shared-responsibility review where only tenant-owned controls fail. |
| [`04-ci-release-gate`](demos/04-ci-release-gate/) | A release pipeline catching an IaC regression with `--fail-on`. |
| [`05-pci-custom-profile`](demos/05-pci-custom-profile/) | The same DB scored against the baseline (100%) vs. a stricter custom payments profile (75%). |
| [`06-sarif-code-scanning`](demos/06-sarif-code-scanning/) | Emitting SARIF 2.1.0 and uploading to a code-scanning dashboard. |
| [`07-legacy-onprem-remediation`](demos/07-legacy-onprem-remediation/) | Driving a remediation project with before/after snapshots (8.3% → 75.0%). |
| [`08-airgapped-review`](demos/08-airgapped-review/) | An offline audit of an incomplete export, showing the conservative "missing → FAIL" behaviour. |
| [`09-nist-800-53-crosswalk`](demos/09-nist-800-53-crosswalk/) | Crosswalking the baseline to authoritative NIST 800-53 rev5 control titles/families, fully offline. |

Try one:

```bash
cisbench scan demos/01-postgres-prod-audit/inventory.json
```

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
      "remediation": "Enable mandatory TLS at the listener.",
      "nist_controls": ["sc-8", "sc-8.1"]
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

The optional `nist_controls` field on a check is a list of NIST 800-53 rev5
control ids (OSCAL form, e.g. `"sc-8"`, `"ia-5.1"`) that `cisbench crosswalk`
resolves to authoritative titles.

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
and reports on hardening posture. It performs no exploitation and makes no
changes to any system. The only network activity is the optional, opt-in fetch
of the authoritative NIST OSCAL catalog for `crosswalk`/`feeds update`; that
catalog is cached and can be served entirely offline (and air-gapped via
snapshot), so scanning never requires network access.
