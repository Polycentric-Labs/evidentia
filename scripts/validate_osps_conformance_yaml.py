#!/usr/bin/env python3
"""Validate ``.local/pre-release-review/osps-conformance.yaml`` schema.

Schema (v1):

- Top-level required fields:
  ``schema_version``, ``conformance_target``, ``conformance_level``,
  ``attested_at``, ``attestation_method``, ``controls``.
- ``controls`` MUST be a list of mappings, each with:
  - ``id`` (required) — the upstream OSPS Baseline assessment-requirement
    ID (``OSPS-XX-NN`` or ``OSPS-XX-NN.MM``).
  - ``verdict`` (required) — one of ``PASS`` / ``FAIL`` / ``HONEST_GAP``.
  - ``rationale`` (optional) — free-form text; required for ``HONEST_GAP``
    but enforcement is at the conformance-doc layer (this script does
    not gate on rationale presence).
  - ``evidence`` (optional for non-PASS) — list of ``{type, url}`` pairs.

Companion to :doc:`/OSPS-CONFORMANCE.md`. The CI gate at
``.github/workflows/verify-osps-conformance.yml`` calls this script on
every push to ``main``; the YAML companion is gitignored so the script
emits a soft warning (non-error) when the file is absent on fresh
clones.

Usage::

    python scripts/validate_osps_conformance_yaml.py <path-to-yaml>

Exit codes:

- ``0`` — valid.
- ``1`` — schema violation(s); error(s) printed to stderr.
- ``2`` — argv / file-not-found / yaml-parse error.

Per the publishing-authority protocol (~/.claude/CLAUDE.md), this
script is read-only — it never edits, pushes, tags, or publishes.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

REQUIRED_TOP_LEVEL = {
    "schema_version",
    "conformance_target",
    "conformance_level",
    "attested_at",
    "attestation_method",
    "controls",
}

VALID_VERDICTS = {"PASS", "FAIL", "HONEST_GAP"}


def validate(path: Path) -> list[str]:
    """Return a list of validation errors; empty list means valid."""
    errors: list[str] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"]

    if not isinstance(data, dict):
        return ["Top-level must be a mapping"]

    missing = REQUIRED_TOP_LEVEL - data.keys()
    if missing:
        errors.append(f"Missing required top-level fields: {sorted(missing)}")

    controls = data.get("controls", [])
    if not isinstance(controls, list):
        errors.append("`controls` must be a list")
        return errors

    for idx, control in enumerate(controls):
        if not isinstance(control, dict):
            errors.append(f"controls[{idx}]: must be a mapping")
            continue
        if "id" not in control:
            errors.append(f"controls[{idx}]: missing `id`")
        verdict = control.get("verdict")
        if verdict not in VALID_VERDICTS:
            errors.append(
                f"controls[{idx}] ({control.get('id', '?')}): "
                f"verdict={verdict!r} not in {sorted(VALID_VERDICTS)}"
            )

    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print(
            "Usage: validate_osps_conformance_yaml.py <path>",
            file=sys.stderr,
        )
        return 2

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        return 2

    errors = validate(path)
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    print(f"OK: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
