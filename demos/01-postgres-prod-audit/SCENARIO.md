# Demo 01 — Quarterly hardening review of a production PostgreSQL primary

## Where the data came from
The DBA team exported the running configuration of a production PostgreSQL 16
primary during the quarterly security review and hand-mapped the relevant
settings onto the cisbench inventory schema. cisbench never touched the
database — it only reads `inventory.json`.

## What to expect
This server is *mostly* hardened. Three controls fail:

- **CDB-1.2** — the listener still negotiates **TLS 1.1** (`min_tls_version`
  = 1.1), below the 1.2 baseline.
- **CDB-2.1** — the password minimum length is **10**, below the required 14.
- **CDB-3.2** — audit logs are kept only **30 days**, below the 90-day floor.

Overall: **9/12 passed, score 75.0%**.

## Run it
```bash
cisbench scan demos/01-postgres-prod-audit/inventory.json
```

Machine-readable for a ticketing integration:
```bash
cisbench scan demos/01-postgres-prod-audit/inventory.json --json
```

## How to act
1. Raise `ssl_min_protocol_version` to `TLSv1.2` (ideally `TLSv1.3`) in
   `postgresql.conf` and reload.
2. Increase the password policy minimum length to 14+ (e.g. via your
   `passwordcheck`/`credcheck` extension policy).
3. Extend audit log retention to at least 90 days to meet the baseline.

Re-run the scan after the change window; the three findings should clear.
