# Demo 06 — Upload cisbench findings to a code-scanning dashboard (SARIF)

## Where the data came from
An offline database snapshot reviewed in CI. The team wants cisbench findings
to appear in their **code-scanning dashboard** (GitHub code scanning, Azure
DevOps, or any SARIF-aware aggregator) next to their other security results,
instead of living only in build logs.

cisbench can emit **SARIF 2.1.0** with `--sarif`.

## What to expect
The configuration has two gaps:

- **CDB-2.1** — password minimum length is 12 (below 14), high severity.
- **CDB-5.1** — listener is bound to **0.0.0.0**, high severity.

Human-readable view:
```bash
cisbench scan demos/06-sarif-code-scanning/inventory.json
# 10/12 passed | score 83.3%
```

SARIF view (one `result` per failing check, every profile check registered as a
reusable `rule`):
```bash
cisbench scan demos/06-sarif-code-scanning/inventory.json --sarif > cisbench.sarif
```

Each result carries:
- the rule id (`CDB-2.1`, `CDB-5.1`),
- a SARIF `level` (`error` for critical/high, `warning` for medium, `note` for
  low) plus a GitHub `security-severity` score,
- a logical location naming the exact inventory setting path,
- the evidence and remediation in the message.

## How to act — wire it into GitHub Actions
```yaml
- name: cisbench hardening scan
  run: cisbench scan inventory.json --sarif > cisbench.sarif
- name: Upload to code scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: cisbench.sarif
```

The two findings show up in the Security tab as code-scanning alerts, with
severity, location, and remediation already populated — no custom glue needed.
