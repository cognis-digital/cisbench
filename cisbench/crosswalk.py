"""NIST SP 800-53 rev5 crosswalk for cisbench.

This module is the *real enrichment* layer: it takes the abstract NIST 800-53
control ids that each cisbench check is tagged with (e.g. ``sc-8``, ``ia-5.1``)
and resolves them against the **authoritative** NIST OSCAL machine-readable
catalog to recover the official control *title* and control *family*. The
crosswalk lets a hardening report state, with provenance, exactly which
federal controls a failing database setting maps to.

The catalog is consumed through the bundled :mod:`cisbench.datafeeds` edge
ingestion layer (feed id ``oscal-800-53-rev5-catalog``). It is fetched once,
cached to disk, and thereafter served **offline** so the crosswalk works on a
disconnected / air-gapped enclave. Tests point ``COGNIS_FEEDS_CACHE`` at a
trimmed committed fixture so they never touch the network.

Source: https://github.com/usnistgov/oscal-content
        nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

from . import datafeeds

# Only this feed is relevant to cisbench; we never let the tool reach for
# unrelated feeds in the shared catalog.
FEED_ID = "oscal-800-53-rev5-catalog"


@dataclass(frozen=True)
class ControlInfo:
    """Resolved metadata for one NIST 800-53 rev5 control."""

    id: str            # normalized OSCAL id, e.g. "sc-8" or "sc-8.1"
    label: str         # human label, e.g. "SC-8" or "SC-8(1)"
    title: str         # authoritative control title
    family_id: str     # e.g. "sc"
    family: str        # e.g. "System and Communications Protection"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "title": self.title,
            "family_id": self.family_id,
            "family": self.family,
        }


def _normalize(control_id: str) -> str:
    """Normalize a control id to OSCAL form: lowercase, '(n)' -> '.n'."""
    cid = control_id.strip().lower().replace("(", ".").replace(")", "")
    return cid


def _oscal_label(control_id: str) -> str:
    """Render an OSCAL id as the conventional NIST label (sc-8.1 -> SC-8(1))."""
    cid = _normalize(control_id)
    if "." in cid:
        base, enh = cid.split(".", 1)
        return f"{base.upper()}({enh})"
    return cid.upper()


def load_catalog(*, offline: bool = False) -> dict[str, Any]:
    """Return the parsed OSCAL 800-53 rev5 catalog dict via the feed layer.

    Honors ``offline`` (serve cache only, never touch the network). Raises
    ``FileNotFoundError`` if offline and nothing is cached.
    """
    return datafeeds.get(FEED_ID, offline=offline)


def build_index(catalog: dict[str, Any]) -> dict[str, ControlInfo]:
    """Flatten the OSCAL catalog into ``{normalized id -> ControlInfo}``.

    Walks every group (family) and recurses into nested control enhancements.
    """
    index: dict[str, ControlInfo] = {}
    root = catalog.get("catalog", catalog)
    for group in root.get("groups", []):
        family_id = str(group.get("id", "")).lower()
        family = group.get("title", "")
        _walk_controls(group.get("controls", []), family_id, family, index)
    return index


def _walk_controls(controls: Iterable[dict[str, Any]], family_id: str,
                   family: str, index: dict[str, ControlInfo]) -> None:
    for ctrl in controls:
        cid = _normalize(str(ctrl.get("id", "")))
        if cid:
            index[cid] = ControlInfo(
                id=cid,
                label=_oscal_label(cid),
                title=ctrl.get("title", ""),
                family_id=family_id,
                family=family,
            )
        # Control enhancements are nested under "controls".
        nested = ctrl.get("controls")
        if nested:
            _walk_controls(nested, family_id, family, index)


def resolve(control_ids: Iterable[str], index: dict[str, ControlInfo]
            ) -> dict[str, Optional[ControlInfo]]:
    """Resolve each requested control id against the catalog index.

    Returns ``{requested_id -> ControlInfo or None}`` preserving the caller's
    original (un-normalized) ids as keys.
    """
    out: dict[str, Optional[ControlInfo]] = {}
    for raw in control_ids:
        out[raw] = index.get(_normalize(raw))
    return out


def enrich_profile(profile, *, offline: bool = False,
                   index: Optional[dict[str, ControlInfo]] = None
                   ) -> list[dict[str, Any]]:
    """Crosswalk every check in a profile to authoritative 800-53 controls.

    For each check carrying ``nist_controls``, resolve those ids to their
    official titles and families from the OSCAL catalog. Returns one row per
    check; unmapped checks come back with an empty ``controls`` list.

    This is the substantive enrichment: it turns cisbench's internal CDB
    control ids into federally-traceable 800-53 rev5 references.
    """
    if index is None:
        index = build_index(load_catalog(offline=offline))

    rows: list[dict[str, Any]] = []
    for chk in profile.checks:
        resolved = resolve(chk.nist_controls, index)
        controls = []
        families: list[str] = []
        for raw, info in resolved.items():
            if info is None:
                controls.append({"requested": raw, "resolved": False})
            else:
                controls.append({"requested": raw, "resolved": True,
                                 **info.to_dict()})
                if info.family not in families:
                    families.append(info.family)
        rows.append({
            "check_id": chk.id,
            "title": chk.title,
            "severity": chk.severity,
            "reference": chk.reference,
            "nist_controls": list(chk.nist_controls),
            "families": families,
            "controls": controls,
        })
    return rows
