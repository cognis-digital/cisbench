# Demo 03 — Managed cloud SQL database (shared-responsibility review)

## Where the data came from
A configuration export for a managed (PaaS) cloud SQL database, production
tenant, taken on 2026-06-18. The snapshot carries metadata alongside the
`settings` block (`environment`, `platform`, `snapshot_taken`); cisbench
transparently unwraps the `settings` wrapper and ignores the extra metadata.

This demo illustrates the **shared-responsibility model**: the platform
provides transport and at-rest encryption by default, so those controls pass
out of the box. The gaps live in the **customer-owned** policy controls.

## What to expect
**10/12 passed, score 83.3% (weighted 87.5%)**. Two findings remain, both
tenant responsibilities:

- **CDB-3.2** — audit retention is **45 days**, below the 90-day baseline.
- **CDB-4.2** — the default administrative account has **not** been renamed.

## Run it
```bash
cisbench scan demos/03-cloud-managed-sqldb/inventory.json
```

Just the failing controls, as JSON, for an automated tracker:
```bash
cisbench scan demos/03-cloud-managed-sqldb/inventory.json --json
```

## How to act
1. Raise the managed audit/diagnostic-log retention setting to 90+ days (often
   a single platform setting or a sink/retention policy on the log store).
2. Create a dedicated named administrator and disable or rename the shipped
   default admin where the platform allows it.

The platform-owned controls need no action — that is the point of the review:
it separates "the provider already covers this" from "we still owe this."
