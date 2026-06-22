#!/usr/bin/env python3
"""Demo: crosswalk the cisbench baseline to NIST 800-53 rev5, fully offline.

Points the feed cache at the committed trimmed OSCAL fixture so the demo runs
on a disconnected machine with no setup. In production you would instead run
``cisbench feeds update`` once (or import an air-gap snapshot) and then call
``cisbench crosswalk --offline``.
"""

import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
# Use the committed fixture so the demo is self-contained and offline.
os.environ.setdefault(
    "COGNIS_FEEDS_CACHE",
    str(ROOT / "tests" / "fixtures" / "feeds-cache"),
)

from cisbench.crosswalk import enrich_profile  # noqa: E402
from cisbench.profile import Profile  # noqa: E402


def main() -> int:
    rows = enrich_profile(Profile.builtin(), offline=True)
    mapped = sum(1 for r in rows if r["controls"])
    families = sorted({fam for r in rows for fam in r["families"]})

    print("cisbench -> NIST SP 800-53 rev5 crosswalk (offline)\n")
    for r in rows:
        print(f"{r['check_id']:<10} {r['title']}")
        for c in r["controls"]:
            print(f"    {c['label']:<10} {c['title']}  [{c['family']}]")
    print()
    print(f"{mapped}/{len(rows)} checks carry authoritative 800-53 mappings")
    print(f"control families touched: {len(families)}")
    for fam in families:
        print(f"  - {fam}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
