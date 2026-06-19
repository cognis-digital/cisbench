"""cisbench - an offline CIS-benchmark-style configuration checker for databases.

cisbench evaluates declarative hardening checks against an offline inventory
snapshot (a settings JSON). It never connects to a database; it only reads the
inventory you give it and reports PASS/FAIL with evidence, a compliance score,
and remediation guidance.

Maintainer: Cognis Digital
License: COCL 1.0
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
