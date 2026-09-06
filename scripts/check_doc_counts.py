#!/usr/bin/env python3
"""README capability-count drift gate (Evidentia v0.10.12 Wave 0).

The README "capabilities at a glance" table claims four headline counts —
framework catalogs, inter-framework crosswalks, evidence collectors, MCP tools.
These drift silently as catalogs / crosswalks / collectors / tools are added.
This gate derives each count from the live registries / schema and fails if the
README table disagrees.

Derivations (canonical sources — all pure filesystem, no package import, so the
gate fits the fast ``consistency`` scope alongside the other doc-staleness
guards):
  catalogs    count of ``frameworks:`` entries in the catalogs manifest
              (evidentia_core catalogs/data/frameworks.yaml) — every bundled
              catalog (real + placeholder). This is exactly the list
              ``FrameworkRegistry.list_frameworks()`` returns, matching how the
              README counts "bundled catalogs".
  crosswalks  count of ``*.json`` in evidentia_core catalogs/data/mappings.
  collectors  count of credentialed ``POST /api/collectors/<name>/collect``
              ops in openapi.json — the credentialed cloud/SaaS collectors.
              The OCSF ingest path (``/api/collectors/ocsf/collect``, added in
              v0.10.12 to mirror the ``evidentia collect ocsf`` CLI verb) shares
              the ``/collect`` verb but is intentionally excluded — it ingests
              already-collected OCSF (file/URL, no credentials); it is an
              importer, not an evidence-collection agent.
  mcp_tools   count of ``@server.tool()`` registrations in evidentia_mcp
              server.py.

The PURE functions (parse_readme_counts, compare_counts, count_crosswalk_files,
count_mcp_tools, count_collector_endpoints) take inputs and return values, so
they unit-test against tiny fixtures; load_code_counts() derives the real inputs.

Exit codes:
    0 — PASS (README counts match code)
    1 — FAIL (a count drifted, or a source could not be read)
    2 — argparse usage error

Usage:
    python scripts/check_doc_counts.py
    python scripts/check_doc_counts.py --json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent

README_PATH = REPO_ROOT / "README.md"
OPENAPI_PATH = REPO_ROOT / "packages" / "evidentia-ui" / "openapi.json"
_CATALOGS_DATA = (
    REPO_ROOT
    / "packages"
    / "evidentia-core"
    / "src"
    / "evidentia_core"
    / "catalogs"
    / "data"
)
MANIFEST_PATH = _CATALOGS_DATA / "frameworks.yaml"
MAPPINGS_DIR = _CATALOGS_DATA / "mappings"
MCP_SERVER_PATH = (
    REPO_ROOT
    / "packages"
    / "evidentia-mcp"
    / "src"
    / "evidentia_mcp"
    / "server.py"
)

# Canonical count keys + the README-table label substring that identifies each.
# The substrings are mutually exclusive across the four real rows
# ("Inter-framework crosswalks" matches "crosswalk", not "catalog").
KEYS = ("catalogs", "crosswalks", "collectors", "mcp_tools")
_LABEL_MATCHERS: tuple[tuple[str, str], ...] = (
    ("catalog", "catalogs"),
    ("crosswalk", "crosswalks"),
    ("collector", "collectors"),
    ("mcp", "mcp_tools"),
)

# A markdown table row "| label | <int> |" — the separator row "|---|---|" and
# prose numbers (not pipe-delimited) do not match.
_TABLE_ROW = re.compile(r"^\|\s*([^|]+?)\s*\|\s*([0-9][0-9,]*)\s*\|")


# ───────────────────────── pure functions ────────────────────────────────


def parse_readme_counts(text: str) -> dict[str, int]:
    """Extract the four headline counts from the README at-a-glance table.

    Reads ``| label | int |`` rows whose label names a known capability; prose
    numbers (not in a pipe-delimited row) are ignored. First match per key wins.
    """
    counts: dict[str, int] = {}
    for line in text.splitlines():
        m = _TABLE_ROW.match(line.strip())
        if not m:
            continue
        label = m.group(1).strip().lower()
        value = int(m.group(2).replace(",", ""))
        for substr, key in _LABEL_MATCHERS:
            if substr in label and key not in counts:
                counts[key] = value
                break
    return counts


def compare_counts(code: dict[str, int], readme: dict[str, int]) -> list[str]:
    """One error per drifted or missing count; empty list when all agree."""
    errors: list[str] = []
    for key in KEYS:
        if key not in code:
            errors.append(f"{key}: could not derive code count")
            continue
        if key not in readme:
            errors.append(
                f"{key}: README has no at-a-glance row (code says {code[key]})"
            )
            continue
        if code[key] != readme[key]:
            errors.append(
                f"{key}: README says {readme[key]} but code derives "
                f"{code[key]} — update the README capabilities table"
            )
    return errors


def count_crosswalk_files(mappings_dir: Path) -> int:
    """Count ``*.json`` crosswalk definitions in the mappings directory."""
    return len(list(mappings_dir.glob("*.json")))


def count_mcp_tools(server_text: str) -> int:
    """Count ``@server.tool()`` registrations (line-anchored; skips comments)."""
    return len(re.findall(r"(?m)^\s*@server\.tool\(", server_text))


# Collector keys whose ``/collect`` endpoint is NOT a credentialed agent:
# the OCSF ingest path shares the ``/collect`` verb but is an importer, not
# a credentialed evidence-collection agent, so it is excluded from the count.
# ``nessus`` and ``greenbone`` (v0.13 V13-05) are the same shape: they
# ingest an already-produced vulnerability-scan XML export (file/text, no
# credentials, no network) rather than reaching out to a credentialed
# source, so both are excluded too. Per the cadence-assertion-layer design
# (docs/designs/cadence-assertion-layer-design.md section 2.6): file-import
# collectors do not raise the README's credentialed-collector count; API
# pollers do.
_NON_COLLECTOR_INGEST = frozenset({"ocsf", "nessus", "greenbone"})


def count_collector_endpoints(openapi: dict[str, Any]) -> int:
    """Count credentialed ``POST /api/collectors/<name>/collect`` operations.

    The OCSF ingest path (``/api/collectors/ocsf/collect``) shares the
    ``/collect`` verb — it mirrors the ``evidentia collect ocsf`` CLI verb —
    but ingests already-collected OCSF JSON (file/URL, no credentials) rather
    than reaching out to a credentialed source. It is an importer, not an
    evidence-collection agent, and is excluded from this count by design (see
    ``_NON_COLLECTOR_INGEST``). The Nessus and Greenbone ingest paths
    (``/api/collectors/nessus/collect``, ``/api/collectors/greenbone/collect``)
    are excluded for the identical reason: a Nessus v2 XML export or a
    Greenbone GMP report XML export is already-collected third-party
    output, ingested as text with no credentials and no network access.
    """
    paths = openapi.get("paths") or {}
    total = 0
    for op_path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        m = re.match(r"^/api/collectors/(.+)/collect$", op_path)
        if not m or "post" not in {k.lower() for k in methods}:
            continue
        if m.group(1) in _NON_COLLECTOR_INGEST:
            continue
        total += 1
    return total


def count_catalogs(manifest_path: Path) -> int:
    """Count bundled framework catalogs (``frameworks:`` entries in the manifest).

    Parses the YAML manifest directly (rather than importing the registry) so the
    gate stays a pure-filesystem check with no evidentia package dependency.
    """
    import yaml  # type: ignore[import-untyped]

    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    frameworks = (data or {}).get("frameworks") or []
    return len(frameworks)


# ─────────────────────────── loaders ─────────────────────────────────────


def load_code_counts() -> dict[str, int]:
    """Derive all four counts from the committed catalogs / schema / source."""
    openapi = json.loads(OPENAPI_PATH.read_text(encoding="utf-8"))
    return {
        "catalogs": count_catalogs(MANIFEST_PATH),
        "crosswalks": count_crosswalk_files(MAPPINGS_DIR),
        "collectors": count_collector_endpoints(openapi),
        "mcp_tools": count_mcp_tools(MCP_SERVER_PATH.read_text(encoding="utf-8")),
    }


# ─────────────────────────────── main ────────────────────────────────────


_PARITY_BADGE_RE = re.compile(
    r"CLI%E2%86%94GUI%20parity-(?P<pct>\d+(?:\.\d+)?)%25"
)


def check_parity_badge(readme_text: str) -> list[str]:
    """Assert the README's CLI<->GUI parity badge matches the live parity number.

    The badge is a hand-written literal in the README header. It was set to 93%
    during the pre-v0.11.0 claim sweep, when parity really was 93.4%. Parity
    reached 100% in v0.12 batch 2 and the badge did not move, because nothing
    compared the two: this script gated catalogs, crosswalks, collectors and MCP
    tools, and ``check_parity.py`` never looked at the README. So the most
    prominent number on the project's most public surface understated a shipped
    capability by seven points, silently, for a full release.

    That is the same defect class the v0.12.0 review was written to catch, so it
    gets the same treatment: the claim is derived from the code and compared,
    rather than trusted because someone typed it once.

    Rounding: the badge carries whole percent (``100%``), while
    ``check_parity.py`` reports a float (``100.0``). Compare on the rounded
    integer so a 93.4 -> 93 badge stays legal.
    """
    m = _PARITY_BADGE_RE.search(readme_text)
    if m is None:
        return [
            "README.md has no CLI<->GUI parity badge matching the expected "
            "shields.io pattern; the badge was removed or reformatted, so the "
            "gate can no longer verify it"
        ]

    # Derive from docs/cli-gui-parity.yaml, the same source of truth
    # check_parity.py uses. NOT from docs/parity-coverage.md: that file is
    # generated on demand and is itself drift-gated by nothing, so comparing
    # to it would chain one ungated claim to another.
    try:
        spec = importlib.util.spec_from_file_location(
            "check_parity_for_badge", SCRIPTS_DIR / "check_parity.py"
        )
        if spec is None or spec.loader is None:  # pragma: no cover - import guard
            raise ImportError("cannot load scripts/check_parity.py")
        parity = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(parity)
        rows = parity.load_manifest()["commands"]
        live = parity.coverage_pct(parity.status_counts(rows))
    except Exception as exc:  # pragma: no cover - import/IO guard
        return [f"cannot compute live parity coverage for the badge check: {exc}"]

    badge = float(m.group("pct"))
    if round(badge) != round(live):
        return [
            f"README parity badge says {m.group('pct')}%, but check_parity.py "
            f"reports {live:.1f}%. Update the badge in README.md (and re-run "
            "scripts/wiki/sync_mirrors.py if a mirror carries it)."
        ]
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    args = parser.parse_args(argv)

    code = load_code_counts()
    readme = parse_readme_counts(README_PATH.read_text(encoding="utf-8"))
    readme_text = README_PATH.read_text(encoding="utf-8")
    errors = compare_counts(code, readme) + check_parity_badge(readme_text)

    if args.json:
        print(
            json.dumps(
                {"ok": not errors, "code": code, "readme": readme, "errors": errors},
                indent=2,
            )
        )
        return 0 if not errors else 1

    print("README capability-count check:")
    for key in KEYS:
        cval = code.get(key, "?")
        rval = readme.get(key, "?")
        print(f"  {key:<11} code={cval!s:>4}  readme={rval!s:>4}")
    badge = _PARITY_BADGE_RE.search(readme_text)
    print(f"  {'parity badge':<11} readme={badge.group('pct') + '%' if badge else '?':>5}")
    print()
    if errors:
        print(f"check_doc_counts: FAIL ({len(errors)} issue(s)).")
        for err in errors:
            print(f"  - {err}")
        return 1
    print("check_doc_counts: PASS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
