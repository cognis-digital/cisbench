# cisbench

[![CI](https://github.com/cognis-digital/cisbench/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/cisbench/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![stdlib only](https://img.shields.io/badge/runtime%20deps-none-success)
![License: COCL 1.0](https://img.shields.io/badge/license-COCL%201.0-lightgrey)
![Passive by default](https://img.shields.io/badge/scan-passive%20by%20default-success)
![SARIF 2.1.0](https://img.shields.io/badge/output-SARIF%202.1.0-orange)
![NIST 800-53 rev5](https://img.shields.io/badge/crosswalk-NIST%20800--53%20rev5-informational)

**cisbench** is an offline, CIS-benchmark-style configuration checker for
database hardening settings. It evaluates a set of declarative checks against a
**provided inventory snapshot** (a settings JSON) and reports `PASS`/`FAIL` with
evidence, a compliance score, and remediation guidance.

At a glance:

- **Passive & offline by default** — scores a configuration snapshot you
  provide; the default path never opens a socket.
- **Real, traceable enrichment** — crosswalks every finding to the
  **authoritative** NIST SP 800-53 rev5 OSCAL catalog (official control titles
  and families), fetched once and then served fully offline / air-gapped.
- **Dashboard-ready output** — emits **SARIF 2.1.0** for GitHub code scanning
  and SAST aggregators, plus plain JSON.
- **Edge / air-gap data feeds** — a stdlib-only feed ingester
  (`cisbench/datafeeds.py`) caches authoritative feeds and re-serves them on a
  disconnected enclave via a sneakernet snapshot.
- **Optional, tightly-gated active mode** — an authorization-gated, rate-limited,
  **read-only** probe of an explicit target allowlist (off by default; see
  [Active mode](#active-mode-optional-authorization-gated-read-only)).
- **Four implementations** — a Python reference plus Go, Rust, and
  TypeScript/Node ports of the core scan surface (see [Language ports](#language-ports)).

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


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ cisbench --version
cisbench 0.1.0
```

```console
$ cisbench --help
usage: cisbench [-h] [--version]
                {scan,list,check,crosswalk,feeds,active-scan} ...

Offline CIS-benchmark-style configuration checker for database settings.
Operates only on a provided inventory JSON; it never connects to a database.

positional arguments:
  {scan,list,check,crosswalk,feeds,active-scan}
    scan                evaluate a profile against an inventory snapshot
    list                list the checks in a profile
    check               evaluate a single check by id
    crosswalk           map each check to authoritative NIST 800-53 rev5
                        controls
    feeds               manage the edge/air-gap data-feed cache cisbench
                        consumes
    active-scan         OPTIONAL authorization-gated read-only probe of an
                        allowlisted host (OFF by default; the passive 'scan'
                        is the default mode)

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

```console
$ cisbench list
Profile: cognis-db-baseline (v1.0) — 12 checks
Cognis Database Baseline: a vendor-neutral set of offline configuration-hardening checks for relational database deployments.
========================================================================
CDB-1.1    [critical] Transport encryption is required for client connections
           ref=CDB-NET-1  path=network.require_tls  op=is_true
CDB-1.2    [high    ] Minimum TLS protocol version is 1.2 or higher
           ref=CDB-NET-2  path=network.min_tls_version  op=gte  expected=1.2
CDB-2.1    [high    ] Password minimum length meets baseline
           ref=CDB-AUTH-1  path=auth.password_min_length  op=gte  expected=14
CDB-2.2    [medium  ] Password complexity enforcement is enabled
           ref=CDB-AUTH-2  path=auth.password_complexity_enabled  op=is_true
CDB-2.3    [medium  ] Failed-login lockout threshold is configured
           ref=CDB-AUTH-3  path=auth.failed_login_lockout_threshold  op=lte  expected=10
CDB-3.1    [high    ] Audit logging is enabled
           ref=CDB-AUD-1  path=audit.logging_enabled  op=is_true
CDB-3.2    [medium  ] Audit log retention meets baseline
           ref=CDB-AUD-2  path=audit.retention_days  op=gte  expected=90
CDB-4.1    [critical] Anonymous or guest login is disabled
           ref=CDB-ACC-1  path=auth.anonymous_login_enabled  op=is_false
CDB-4.2    [medium  ] Default administrative account has been renamed
           ref=CDB-ACC-2  path=accounts.default_admin_renamed  op=is_true
CDB-5.1    [high    ] Listener is not bound to all interfaces
           ref=CDB-NET-3  path=network.bind_address  op=not_equals  expected='0.0.0.0'
CDB-6.1    [high    ] Data-at-rest encryption is enabled
           ref=CDB-DAT-1  path=storage.encryption_at_rest  op=is_true
CDB-7.1    [low     ] Verbose error messages are not exposed to clients
           ref=CDB-DIA-1  path=diagnostics.verbose_client_errors  op=is_false
```

> Blocks above are real `cisbench` output — reproduce them from a clone.

<!-- cognis:example:end -->

## Why offline?

Many configuration-assessment tools require live credentials and network access
to the system under test. cisbench deliberately does the opposite: it works
against a captured snapshot. The team that exports the configuration never has
to hand out database credentials, and the audit is fully reproducible.

## Install

From a clone (recommended for the full repo, demos, and ports):

```bash
git clone https://github.com/cognis-digital/cisbench
cd cisbench
pip install -e .
```

Or install the package directly with pip:

```bash
pip install cognis-cisbench
```

This installs the `cisbench` console command. There are **no third-party
runtime dependencies** — cisbench is standard-library only, so it drops into a
minimal or air-gapped environment cleanly.

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
a disconnected or air-gapped enclave. The bundled catalog
(`cisbench/data_feeds_2026.json`) is the shared Cognis edge-feed catalog (35
real, mostly-keyless feeds across vuln, threat-intel, compliance, cloud and
OSINT domains — e.g. CISA KEV, EPSS, OSV, NVD, MITRE ATT&CK STIX, NIST OSCAL).
For its own operation, **cisbench consumes exactly one feed** and the
`cisbench feeds` command intentionally exposes only that one:

| Feed id | Source | Used for |
|---------|--------|----------|
| `oscal-800-53-rev5-catalog` | [`usnistgov/oscal-content`](https://github.com/usnistgov/oscal-content) — `nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json` | resolving check tags to authoritative 800-53 rev5 control titles/families |

The wider catalog is available to the underlying ingester (`python -m
cisbench.datafeeds list`) for operators who want to enrich an air-gapped
toolchain — including bulk CVE harvest (`python -m cisbench.datafeeds bulk
nvd-cve`) that paginates a CVE source to the edge cache without bundling
gigabytes into git. All feeds are keyless/offline-capable and carry their own
licensing/attribution; no fabricated intelligence is shipped.

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

## Active mode (optional, authorization-gated, read-only)

cisbench is **passive and offline by default** — nothing in the default path
touches a live system. For operators who need to gather configuration evidence
from a host they are **explicitly authorized to assess**, there is an optional
`active-scan` subcommand. It is locked down behind **four independent
guardrails, all of which must be satisfied**:

1. **Authorization flag** — nothing runs without `--authorized`. Off by default.
2. **Target allowlist** — every target must be named explicitly via `--allow`
   (repeatable) or `--allow-file`. A host that is not on the allowlist is
   refused before any socket is opened.
3. **Rate limiter** — a token bucket (`--rate`, default 2/s) paces probes so the
   tool cannot be turned into a sweeper.
4. **Read-only probes only** — the built-in probe is a TCP connect + banner
   read. It sends **nothing**: no authentication, no exploit payloads, no
   state-changing traffic. It cannot log in, cannot bypass auth, and cannot
   modify the target.

The probe yields *evidence* (reachability/banner), which is merged into an
inventory snapshot and then scored by the **same passive engine** — so active
and passive runs are scored identically.

```bash
# Off by default — this is refused (exit 2):
cisbench active-scan db.internal:5432 --allow db.internal

# Authorized + allowlisted + paced + read-only:
cisbench active-scan db.internal:5432 \
    --authorized --allow db.internal --rate 1 \
    --from exported_settings.json
```

```
cisbench active-scan (read-only, authorized) — 1 target(s) probed
  db.internal:5432  reachable  banner='...'
... (passive scan table over the merged inventory) ...
```

Use `--emit-inventory` to capture the merged evidence as JSON without scoring,
or `--from BASE.json` to layer probe evidence on top of an exported config.
**This mode is for authorized, defensive assessment only.** cisbench performs
no exploitation and makes no changes to any system.

## Language ports

The core passive scan surface is available in four implementations, all sharing
an identical scoring contract (the same inventory yields the same score in each):

| Port | Path | Commands | Test |
|------|------|----------|------|
| **Python** (reference) | [`cisbench/`](cisbench/) | `scan` `list` `check` `crosswalk` `feeds` `active-scan` | `python -m pytest` |
| **Go** | [`ports/go/`](ports/go/) | `scan` `list` | `go test ./...` |
| **Rust** | [`ports/rust/`](ports/rust/) | `scan` `list` | `cargo test` |
| **TypeScript / Node** | [`ports/node/`](ports/node/) | `scan` `list` | `npm test` |

```bash
# Go
cd ports/go && go run ./cmd/cisbench scan ../../examples/inventory_hardened.json
# Rust
cd ports/rust && cargo run -- scan ../../examples/inventory_hardened.json
# Node (TypeScript, native type-stripping; Node >= 22)
cd ports/node && node --experimental-strip-types src/cli.ts scan ../../examples/inventory_hardened.json
```

Every port is built and tested in CI on push, so they are real and verifiable —
see [`.github/workflows/ci.yml`](.github/workflows/ci.yml) and
[`ports/README.md`](ports/README.md). The ports implement the passive surface
only; the authorization-gated active probe lives in the Python reference.

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

## Scope, authorization & safety

cisbench is a **defensive, analytical** tool. It reads configuration snapshots
and reports on hardening posture. It performs **no exploitation** and makes
**no changes** to any system.

- **Passive scanning is the default and is fully offline.** The `scan`, `list`,
  `check`, and (with a populated cache) `crosswalk` commands open no network
  sockets.
- **The only default network activity** is the optional, opt-in fetch of the
  authoritative NIST OSCAL catalog for `crosswalk` / `feeds update`; that
  catalog is cached and can be served entirely offline (and air-gapped via
  snapshot), so scanning never requires network access.
- **Active probing is OFF by default** and, when enabled, is hemmed in by four
  independent guardrails — `--authorized`, an explicit target allowlist, a rate
  limiter, and read-only-only probes (no auth, no payloads, no writes). See
  [Active mode](#active-mode-optional-authorization-gated-read-only). Only probe
  systems you are explicitly authorized to assess.
- **No fabricated data.** All control titles come from the authoritative NIST
  OSCAL catalog; the bundled feed catalog references only real, attributable
  sources. cisbench never invents CVEs, fingerprints, or intelligence.

License: **COCL 1.0** (see [`LICENSE`](LICENSE) / [`NOTICE`](NOTICE)).
