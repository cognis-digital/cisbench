# Demo 02 — Exposed MySQL dev instance found in a network sweep

## Where the data came from
A security engineer running an internal network sweep found a MySQL 8.0
instance that a team stood up for a sprint and never hardened. The relevant
settings were captured offline into `inventory.json` for triage — no
credentials were used against the box.

## What to expect
This is a worst-case configuration. **Every** baseline control fails
(**0/12 passed, score 0.0%**), including all four critical/high transport and
access controls:

- TLS is not required and the minimum version is **1.0**.
- The listener is bound to **0.0.0.0** (all interfaces).
- **Anonymous login is enabled** — the most serious finding.
- No audit logging, no data-at-rest encryption, verbose client errors on,
  weak password policy, default admin not renamed.

## Run it
```bash
cisbench scan demos/02-mysql-dev-exposed/inventory.json
```

Use it as a hard CI gate so this never ships:
```bash
cisbench scan demos/02-mysql-dev-exposed/inventory.json --fail-on-any
echo "exit code: $?"   # 1 — gate tripped
```

## How to act
Treat as an incident-adjacent finding, not a slow remediation:

1. **Immediately** restrict network reachability (firewall / security group)
   so the instance is not on a routable path while it is in this state.
2. Disable anonymous login and require authenticated sessions.
3. Enable mandatory TLS 1.2+, bind to a specific trusted interface, turn on
   audit logging and at-rest encryption, and tighten the password policy.

Re-scan; the score should climb out of 0% as each control is addressed.
