# Demo 09 — NIST SP 800-53 rev5 crosswalk (air-gap ready)

## What this shows
Every check in the cisbench baseline is tagged with the NIST SP 800-53 rev5
controls it supports. The `crosswalk` command resolves those control ids
against the **authoritative** NIST OSCAL machine-readable catalog
(`usnistgov/oscal-content`) to recover each control's official **title** and
**family** — so a database hardening finding is traceable to a federal control,
with provenance.

The catalog is consumed through cisbench's bundled edge data-feed layer
(feed id `oscal-800-53-rev5-catalog`). It is fetched once, cached to disk, and
served **offline** thereafter — ideal for disconnected / air-gapped review.

## One-time online step (or import an air-gap snapshot)
```bash
cisbench feeds update            # fetch + cache the 800-53 catalog
# air-gap alternative, on a connected host:
#   python -m cisbench.datafeeds snapshot-export oscal.tar.gz
# then on the enclave:
#   python -m cisbench.datafeeds snapshot-import oscal.tar.gz
```

## Run the crosswalk (works offline once cached)
```bash
cisbench crosswalk --offline
```

Expected (abridged):

```
NIST SP 800-53 rev5 crosswalk — profile: cognis-db-baseline
CDB-1.1     [critical] Transport encryption is required for client connections
           -> SC-8       Transmission Confidentiality and Integrity  [System and Communications Protection]
           -> SC-8(1)    Cryptographic Protection  [System and Communications Protection]
...
12/12 checks carry 800-53 mappings; 0 control id(s) unresolved.
```

## Reproduce headline numbers
```bash
python demos/09-nist-800-53-crosswalk/run.py
```
