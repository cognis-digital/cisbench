# Demo 05 — Same database, two bars: baseline vs. a stricter payments profile

## Where the data came from
This database backs a payments service. The DBA captured an offline snapshot
for review. The point of this demo is to show how the **same inventory** scores
very differently depending on the profile you hold it to.

`profile_payments.json` is a custom, stricter profile authored for cisbench
(the `PAY-*` control namespace is our own — it is not copied from any external
standard). It raises the bar where a regulated payments environment typically
demands more: 16-character passwords and 365-day audit retention.

## What to expect

Against the **built-in baseline** the server is clean:
```bash
cisbench scan demos/05-pci-custom-profile/inventory.json
# 12/12 passed | score 100.0%
```

Against the **stricter payments profile** two controls fail:
```bash
cisbench scan demos/05-pci-custom-profile/inventory.json \
  --profile demos/05-pci-custom-profile/profile_payments.json
# 6/8 passed | score 75.0%
```

- **PAY-3** — password minimum length is 14, below the payments bar of 16.
- **PAY-7** — audit retention is 90 days, below the payments bar of 365.

## How to act
"Passes the baseline" is not the same as "meets our regulated bar." For the
payments-scope system:

1. Raise the password minimum length to 16+.
2. Extend audit retention to at least one year.

Use `cisbench list --profile demos/05-pci-custom-profile/profile_payments.json`
to review every control in the custom profile, and adapt the thresholds to your
own policy.
