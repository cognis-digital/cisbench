# cisbench language ports

These are faithful ports of **cisbench's core passive surface** — load an
offline inventory snapshot, evaluate it against the `cognis-db-baseline`
profile (the same 12 CDB-* checks as the Python reference), and report
PASS/FAIL with a plain and a severity-weighted score.

All ports are **passive and offline**: they only read the inventory JSON you
give them and never connect to a database. The optional, authorization-gated
*active* probe is intentionally implemented only in the Python reference tool.

| Port | Path | Commands | Test command |
|------|------|----------|--------------|
| Python (reference) | [`../cisbench/`](../cisbench/) | `scan` `list` `check` `crosswalk` `feeds` `active-scan` | `python -m pytest` |
| Go | [`go/`](go/) | `scan` `list` | `go test ./...` |
| Rust | [`rust/`](rust/) | `scan` `list` | `cargo test` |
| TypeScript / Node | [`node/`](node/) | `scan` `list` | `npm test` |

Each port shares an identical scoring contract, so the same inventory produces
the same score across all four implementations. Every port is built and tested
in CI on push (see [`../.github/workflows/ci.yml`](../.github/workflows/ci.yml)).

## Quickstart per port

```bash
# Go
cd ports/go && go run ./cmd/cisbench scan ../../examples/inventory_hardened.json

# Rust
cd ports/rust && cargo run -- scan ../../examples/inventory_hardened.json

# Node (TypeScript, native type-stripping; Node >= 22)
cd ports/node && node --experimental-strip-types src/cli.ts scan ../../examples/inventory_hardened.json
```

Each emits machine-readable output with `--json`.
