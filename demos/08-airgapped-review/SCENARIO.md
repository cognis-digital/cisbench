# Demo 08 — Air-gapped audit with an incomplete export

## Where the data came from
An auditor received a configuration dump on removable media to review on an
**air-gapped** workstation — exactly the situation cisbench is built for: no
database connection, no credentials, fully reproducible from the file alone.

The export was incomplete. Whoever produced it never captured the `storage` and
`diagnostics` sections, so those settings are simply absent from the snapshot.

## What to expect
cisbench treats a missing value-operator setting as a **FAIL with explicit
evidence**, rather than silently passing or crashing:

```bash
cisbench scan demos/08-airgapped-review/inventory.json
# 10/12 passed | score 83.3%
```

The two failures call out the gap directly:

- **CDB-6.1** — `setting 'storage.encryption_at_rest' is missing; cannot
  satisfy 'is_true' check (treated as FAIL)`
- **CDB-7.1** — `setting 'diagnostics.verbose_client_errors' is missing; cannot
  satisfy 'is_false' check (treated as FAIL)`

This is the conservative, audit-friendly default: an unevidenced control is not
a passing control.

## See what evidence is required up front
Before requesting a re-export, list every control and the exact path it reads,
so the export can be made complete in one round-trip:
```bash
cisbench list
```

## How to act
1. Note that 10 controls are genuinely satisfied by the captured evidence.
2. The two "missing" findings are an **export gap, not necessarily a real
   weakness** — request a complete export that includes `storage` and
   `diagnostics`, then re-scan.
3. Because cisbench is fully offline and deterministic, the auditor can re-run
   the identical command on the new export and diff the two reports.
