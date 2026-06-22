# Demo 04 — CI release gate catches a regression before promotion

## Where the data came from
This `inventory.json` was rendered from the database role of an
infrastructure-as-code plan inside a release pipeline. The pipeline runs
cisbench as a promotion gate: the change is only deployed to production if the
hardening posture clears the org's threshold.

A recent edit to the IaC module accidentally flipped data-at-rest encryption
off, so this release candidate carries a single regression.

## What to expect
**11/12 passed, score 91.7%**, with one finding:

- **CDB-6.1** — data-at-rest encryption is disabled (`storage.encryption_at_rest`
  = false), a high-severity control.

## Run it as a gate

Strict org policy: require a 95% score to promote. This gate **fails**, so the
release is blocked:
```bash
cisbench scan demos/04-ci-release-gate/inventory.json --fail-on 95
echo "exit code: $?"   # 1 — below threshold, promotion blocked
```

Block on *any* failing control (zero-tolerance gate) — also fails here:
```bash
cisbench scan demos/04-ci-release-gate/inventory.json --fail-on-any
echo "exit code: $?"   # 1
```

A looser 90% gate would have let this slip through (`--fail-on 90` returns 0),
which is exactly why the threshold is a policy decision.

## How to act
1. Fix the IaC module so data-at-rest encryption is re-enabled.
2. Re-run the pipeline; the gate clears and the change promotes.

Wire the exact command into your pipeline step and let the non-zero exit code
stop the deploy automatically.
