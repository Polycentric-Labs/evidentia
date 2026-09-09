"""Helpers for generating bundled catalog JSONs from compact Python definitions.

The per-framework generator scripts in this directory each define a set
of controls (or obligations, or techniques) as Python data, then invoke
one of the ``emit_*`` helpers here to write a catalog JSON to the right
tier-partitioned directory under ``packages/evidentia-core/src/
evidentia_core/catalogs/data/``.

This is the v0.2.0 authoring path. The v0.2.x refresh CI will eventually
replace these hand-authored definitions with live upstream fetches
(see scripts/catalogs/upstream/).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_ROOT = REPO_ROOT / "packages" / "evidentia-core" / "src" / "evidentia_core" / "catalogs" / "data"


Tier = Literal["A", "B", "C", "D"]


def _tier_dir(tier: Tier, subdir: str | None = None) -> Path:
    """Resolve the on-disk directory for a given tier."""
    if subdir is not None:
        return DATA_ROOT / subdir
    # Defaults by tier if no explicit subdir is given
    return (
        DATA_ROOT
        / {
            "A": "us-federal",
            "B": "threats",
            "C": "stubs",
            "D": "international",
        }[tier]
    )


def emit_control_catalog(
    *,
    framework_id: str,
    framework_name: str,
    version: str,
    source: str,
    families: list[str],
    controls: list[dict[str, Any]],
    tier: Tier,
    subdir: str | None = None,
    placeholder: bool = False,
    license_required: bool = False,
    license_terms: str | None = None,
    license_url: str | None = None,
    status: str | None = None,
    notes: str | None = None,
    verified_on: str | None = None,
    superseded_by: str | None = None,
    audit_contexts: dict[str, dict[str, Any]] | None = None,
    publication_notices: list[dict[str, Any]] | None = None,
) -> Path:
    """Write a ControlCatalog JSON for a control-type framework."""
    out: dict[str, Any] = {
        "framework_id": framework_id,
        "framework_name": framework_name,
        "version": version,
        "source": source,
        "tier": tier,
        "category": "control",
        "placeholder": placeholder,
        "families": families,
        "controls": controls,
    }
    if license_required:
        out["license_required"] = True
    if license_terms:
        out["license_terms"] = license_terms
    if license_url:
        out["license_url"] = license_url

    for key, value in {
        "status": status,
        "notes": notes,
        "verified_on": verified_on,
        "superseded_by": superseded_by,
        "audit_contexts": audit_contexts,
        "publication_notices": publication_notices,
    }.items():
        if value is not None:
            out[key] = value

    target_dir = _tier_dir(tier, subdir)
    target_dir.mkdir(parents=True, exist_ok=True)
    out_path = target_dir / f"{framework_id}.json"
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    return out_path


def make_stub_control(
    ctrl_id: str,
    title: str,
    family: str,
    license_url: str,
    placeholder_text: str = "[Licensed content — see license_url for authoritative text.]",
) -> dict[str, Any]:
    """Build a Tier-C stub control entry with placeholder description."""
    return {
        "id": ctrl_id,
        "title": title,
        "description": placeholder_text,
        "family": family,
        "placeholder": True,
        "tier": "C",
        "license_required": True,
        "license_url": license_url,
    }


def emit_obligation_catalog(
    *,
    framework_id: str,
    framework_name: str,
    version: str,
    source: str,
    regime: dict[str, Any],
    obligations: list[dict[str, Any]],
    tier: Tier,
    subdir: str | None = None,
    placeholder: bool = False,
    license_required: bool = False,
    license_terms: str | None = None,
    license_url: str | None = None,
) -> Path:
    """Write an ObligationCatalog JSON for a privacy law."""
    out: dict[str, Any] = {
        "framework_id": framework_id,
        "framework_name": framework_name,
        "version": version,
        "source": source,
        "tier": tier,
        "category": "obligation",
        "placeholder": placeholder,
        "regime": regime,
        "obligations": obligations,
    }
    if license_required:
        out["license_required"] = True
    if license_terms:
        out["license_terms"] = license_terms
    if license_url:
        out["license_url"] = license_url

    target_dir = _tier_dir(tier, subdir)
    target_dir.mkdir(parents=True, exist_ok=True)
    out_path = target_dir / f"{framework_id}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    return out_path


def emit_technique_catalog(
    *,
    framework_id: str,
    framework_name: str,
    version: str,
    source: str,
    techniques: list[dict[str, Any]],
    tactics: list[str] | None = None,
    tier: Tier,
    subdir: str | None = None,
    placeholder: bool = False,
    license_terms: str | None = None,
) -> Path:
    """Write a TechniqueCatalog JSON for a threat framework (ATT&CK/CWE/CAPEC)."""
    out: dict[str, Any] = {
        "framework_id": framework_id,
        "framework_name": framework_name,
        "version": version,
        "source": source,
        "tier": tier,
        "category": "technique",
        "placeholder": placeholder,
        "techniques": techniques,
    }
    if tactics:
        out["tactics"] = tactics
    if license_terms:
        out["license_terms"] = license_terms

    target_dir = _tier_dir(tier, subdir)
    target_dir.mkdir(parents=True, exist_ok=True)
    out_path = target_dir / f"{framework_id}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    return out_path


def emit_vulnerability_catalog(
    *,
    framework_id: str,
    framework_name: str,
    version: str,
    source: str,
    vulnerabilities: list[dict[str, Any]],
    tier: Tier,
    subdir: str | None = None,
    placeholder: bool = False,
    license_terms: str | None = None,
) -> Path:
    """Write a VulnerabilityCatalog JSON (CISA KEV, etc)."""
    out: dict[str, Any] = {
        "framework_id": framework_id,
        "framework_name": framework_name,
        "version": version,
        "source": source,
        "tier": tier,
        "category": "vulnerability",
        "placeholder": placeholder,
        "vulnerabilities": vulnerabilities,
    }
    if license_terms:
        out["license_terms"] = license_terms

    target_dir = _tier_dir(tier, subdir)
    target_dir.mkdir(parents=True, exist_ok=True)
    out_path = target_dir / f"{framework_id}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    return out_path
