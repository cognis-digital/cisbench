# Demo 07 — Driving a remediation project on a legacy on-prem database

## Where the data came from
A legacy on-prem database that predates the current hardening standard. The
team captured an offline snapshot (`inventory.json`) at the start of a
remediation project, then a second snapshot (`inventory_after_phase1.json`)
after the first fix window. This demo shows cisbench as a **progress tracker**.

## Phase 0 — baseline the damage
```bash
cisbench scan demos/07-legacy-onprem-remediation/inventory.json
# 1/12 passed | score 8.3% (weighted 12.5%)
```
Almost everything fails. Use the weighted score to prioritise: critical and
high controls (TLS, 0.0.0.0 binding, audit logging, at-rest encryption) hurt
the weighted number the most, so they go first.

## Inspect one control in detail
Before touching the listener, confirm exactly what cisbench wants and why:
```bash
cisbench check CDB-1.1 demos/07-legacy-onprem-remediation/inventory.json
# FAIL — 'network.require_tls' = False (violates is true)
# remediation: Enable mandatory TLS for all client connections...
```

## Phase 1 — fix the high-impact controls, then re-scan
After enabling TLS 1.2, moving off 0.0.0.0, turning on audit logging with a
90-day retention, and tightening the password policy:
```bash
cisbench scan demos/07-legacy-onprem-remediation/inventory_after_phase1.json
# 9/12 passed | score 75.0% (weighted 81.2%)
```
The score jumps from **8.3% to 75.0%**. Three lower-priority controls remain
for phase 2:

- **CDB-4.2** — rename the default admin account.
- **CDB-6.1** — enable data-at-rest encryption.
- **CDB-7.1** — stop exposing verbose client errors.

## How to act
Run the scan at the end of each remediation window and track the score over
time. The weighted score is the honest one to report to leadership because it
reflects how much *risk* has actually been retired, not just how many checkboxes
were ticked.
