#!/usr/bin/env python3
"""FedRAMP upstream drift probe (the ``fedramp-schema-watch`` sentinel).

Compares the live ``FedRAMP/rules`` + ``FedRAMP/schemas`` repos against
the pins in ``packages/evidentia-core/src/evidentia_core/fedramp/schemas/
UPSTREAM.json`` (the same provenance file the vendored SDR schemas and
``scripts/catalogs/gen_fedramp_ksi.py`` are built from). Both upstream
repos are "2026 Public Preview" drafts that move frequently; the KSI
emitter's correctness rests on these pins, so drift must surface on a
cadence, not at the next release.

Severity model (drives the workflow's red/notice split):

- **MAJOR** — the emit target itself moved: the KSI section's content
  hash changed; any tracked schema's ``$schemaVersion`` took a MAJOR
  bump; the CR26 dated fileset changed (a file disappeared, or a new
  dated set appeared — upstream policy cuts a NEW dated set for a new
  ruleset, e.g. CR27). The workflow turns the run red after filing the
  tracking issue.
- **NOTICE** — everything else worth a nudge: minor/patch
  ``$schemaVersion`` bumps, vendored-file blob drift (e.g. the upstream
  ``$ref``-defect fix PR merging — time to drop our local delta),
  dataset version bumps that leave the KSI section untouched.

Exit codes: 0 = clean or findings written (the workflow greps severity);
3 = a probe failed (network/API) — the run goes red rather than
false-green.

Usage:
    python3 scripts/check_fedramp_upstream_drift.py --output findings.md

Stdlib-only by design (the sentinel runs on a bare runner without
``uv sync``). Sends ``GITHUB_TOKEN`` when present; anonymous works too
(≈14 requests per run against a 60/hr unauthenticated limit).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
PIN_PATH = (
    REPO_ROOT
    / "packages"
    / "evidentia-core"
    / "src"
    / "evidentia_core"
    / "fedramp"
    / "schemas"
    / "UPSTREAM.json"
)

API_ROOT = "https://api.github.com"
SCHEMA_FILE_PREFIX = "fedramp-"
SCHEMA_FILE_SUFFIX = ".json"


def _request(url: str, *, raw: bool = False) -> bytes:
    """GET a GitHub API URL (optionally raw content).

    Prefers the ``gh`` CLI (preinstalled on runners; authenticated, and
    reliable for large payloads through proxies), falling back to plain
    urllib with one retry. Every ``gh`` call is an argument list — no
    shell.
    """
    accept = (
        "application/vnd.github.raw+json" if raw else "application/vnd.github+json"
    )
    if shutil.which("gh"):
        result = subprocess.run(
            ["gh", "api", url.removeprefix(API_ROOT + "/"), "-H", f"Accept: {accept}"],
            capture_output=True,
            check=True,
        )
        return result.stdout

    headers = {
        "Accept": accept,
        "User-Agent": "evidentia-fedramp-schema-watch",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    last_error: Exception | None = None
    for _attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                data: bytes = response.read()
            return data
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"GET {url} failed after retry: {last_error}")


def _get_json(url: str) -> Any:
    return json.loads(_request(url).decode("utf-8"))


def _semver_major(version: str) -> str:
    return version.split(".", 1)[0]


def probe_rules(pin: dict[str, Any], findings: list[tuple[str, str]]) -> None:
    """Probe FedRAMP/rules: dataset version + KSI section content hash."""
    rules = pin["rules"]
    raw = _request(
        f"{API_ROOT}/repos/{rules['repo']}/contents/{rules['file']}",
        raw=True,
    )
    dataset = json.loads(raw.decode("utf-8"))

    live_version = dataset.get("info", {}).get("version", "<missing>")
    ksi_canonical = json.dumps(
        dataset.get("KSI", {}), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    live_ksi_hash = hashlib.sha256(ksi_canonical).hexdigest()

    if live_ksi_hash != rules["ksi_section_sha256"]:
        findings.append(
            (
                "MAJOR",
                f"`{rules['repo']}` KSI section CHANGED (content hash "
                f"`{live_ksi_hash[:12]}…` vs pinned "
                f"`{rules['ksi_section_sha256'][:12]}…`; live dataset "
                f"version {live_version}, pinned "
                f"{rules['dataset_version']}). The bundled fedramp-ksi-2026 "
                f"catalog + crosswalk are stale — re-verify the KSI shape, "
                f"bump UPSTREAM.json, re-run scripts/catalogs/"
                f"gen_fedramp_ksi.py + regenerate_manifest.py.",
            )
        )
    elif live_version != rules["dataset_version"]:
        findings.append(
            (
                "NOTICE",
                f"`{rules['repo']}` dataset version moved "
                f"{rules['dataset_version']} → {live_version} with the KSI "
                f"section unchanged (non-KSI rules churn). No action "
                f"required; bump the pin at the next deliberate re-sync.",
            )
        )


def probe_schemas(pin: dict[str, Any], findings: list[tuple[str, str]]) -> None:
    """Probe FedRAMP/schemas: fileset, $schemaVersion, vendored blobs."""
    schemas = pin["schemas"]
    repo = schemas["repo"]
    ruleset_date = schemas["ruleset_date"]
    baseline: dict[str, str] = schemas["schema_versions"]

    listing = _get_json(f"{API_ROOT}/repos/{repo}/contents/")
    live_files = {
        item["name"]: item["sha"]
        for item in listing
        if item["type"] == "file"
        and item["name"].startswith(SCHEMA_FILE_PREFIX)
        and item["name"].endswith(SCHEMA_FILE_SUFFIX)
    }

    removed = sorted(set(baseline) - set(live_files))
    for name in removed:
        findings.append(
            (
                "MAJOR",
                f"`{repo}` no longer publishes `{name}` — the CR26 fileset "
                f"changed under the pin.",
            )
        )

    new_dated = sorted(
        name
        for name in set(live_files) - set(baseline)
        if ruleset_date not in name
    )
    if new_dated:
        findings.append(
            (
                "MAJOR",
                f"`{repo}` published schema file(s) outside the pinned "
                f"{ruleset_date} ruleset date: {', '.join(new_dated)}. "
                f"Upstream policy cuts a NEW dated fileset for a new "
                f"ruleset — this looks like the next CR revision. "
                f"Re-verify the emit target before the next release.",
            )
        )
    new_undated = sorted(
        name
        for name in set(live_files) - set(baseline)
        if ruleset_date in name
    )
    if new_undated:
        findings.append(
            (
                "NOTICE",
                f"`{repo}` added schema file(s) within the {ruleset_date} "
                f"ruleset: {', '.join(new_undated)}. The submission "
                f"surface grew; assess whether Evidentia should cover it.",
            )
        )

    for name, pinned_version in sorted(baseline.items()):
        if name not in live_files:
            continue  # already reported as removed
        live_schema = json.loads(
            _request(
                f"{API_ROOT}/repos/{repo}/contents/{name}", raw=True
            ).decode("utf-8")
        )
        live_version = str(live_schema.get("$schemaVersion", "<missing>"))
        if live_version == pinned_version:
            continue
        severity = (
            "MAJOR"
            if _semver_major(live_version) != _semver_major(pinned_version)
            else "NOTICE"
        )
        findings.append(
            (
                severity,
                f"`{name}` $schemaVersion moved {pinned_version} → "
                f"{live_version}.",
            )
        )

    for name, vendored in schemas["vendored"].items():
        live_blob = live_files.get(name)
        if live_blob is not None and live_blob != vendored["blob_sha"]:
            delta_note = (
                " Our copy carries a documented local delta (the "
                "cross-document $ref fragment fix, upstream PR #4) — if "
                "this drift IS that fix merging, re-vendor byte-identical "
                "and clear the delta note."
                if vendored.get("local_delta")
                else ""
            )
            findings.append(
                (
                    "NOTICE",
                    f"Vendored schema `{name}` drifted upstream (blob "
                    f"`{live_blob[:12]}…` vs pinned "
                    f"`{vendored['blob_sha'][:12]}…`). Diff and re-sync per "
                    f"evidentia_core/fedramp/schemas/README.md.{delta_note}",
                )
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="markdown findings file (empty file = no drift)",
    )
    args = parser.parse_args()

    with open(PIN_PATH, encoding="utf-8") as f:
        pin = json.load(f)

    findings: list[tuple[str, str]] = []
    try:
        probe_rules(pin, findings)
        probe_schemas(pin, findings)
    except Exception as exc:
        print(f"probe failed: {exc}", file=sys.stderr)
        args.output.write_text("", encoding="utf-8")
        return 3

    if not findings:
        args.output.write_text("", encoding="utf-8")
        print(
            "OK: FedRAMP upstream matches the UPSTREAM.json pins "
            f"(verified {pin['verified_at']})."
        )
        return 0

    lines = [
        "FedRAMP upstream drift against the pins in "
        "`packages/evidentia-core/src/evidentia_core/fedramp/schemas/"
        "UPSTREAM.json` (weekly `fedramp-schema-watch` sentinel):",
        "",
    ]
    lines.extend(f"- **{severity}**: {text}" for severity, text in findings)
    lines += [
        "",
        "Re-sync procedure: `evidentia_core/fedramp/schemas/README.md`. "
        "MAJOR findings red the sentinel run until the pins are "
        "deliberately re-verified and bumped.",
    ]
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    for severity, text in findings:
        print(f"{severity}: {text}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
