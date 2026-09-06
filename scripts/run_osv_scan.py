#!/usr/bin/env python3
"""Generate the CycloneDX SBOM and scan it with osv-scanner (v0.9.9 P2).

The Evidentia supply-chain pre-push gate. Invoked identically by CI
(the ``osv-scan`` job in ``.github/workflows/test.yml``) and pre-tag by
the release checklist (``docs/release-checklist.md`` Step 5) -- one
shared entry point so the CI gate and its documented counterpart
cannot drift.

Why this exists: the v0.9.8 16-row pre-push gate's Row 14 read
Dependabot alerts, which suppress DISPUTED CVEs, so a disputed pyjwt
advisory (PYSEC-2025-183) surfaced only post-tag. osv-scanner reports
transitive AND disputed advisories. Accepted / non-actionable findings
are allowlisted in ``osv-scanner.toml`` (repo root), each with a reason
and a re-validation date.

The SBOM is generated with the exact command ``release.yml`` uses, so
the gate scans the same artifact the release publishes and attaches.

Exit codes:
    0 -- no un-allowlisted vulnerabilities
    1 -- osv-scanner reported un-allowlisted vulnerabilities
    2 -- SBOM generation failed, or osv-scanner is missing / errored

Prerequisites:
    * ``osv-scanner`` on PATH. CI installs a pinned, checksum-verified
      v2.4.0 binary; operators install it once (see
      ``docs/release-checklist.md`` Step 5).
    * Run via ``uv run`` against a synced workspace so the SBOM
      reflects the full dependency closure.

Usage:
    uv run --no-sync python scripts/run_osv_scan.py
    uv run --no-sync python scripts/run_osv_scan.py --skip-sbom-gen
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tomllib
from datetime import date, timedelta
from pathlib import Path

SBOM_PATH = Path("evidentia-sbom.cdx.json")
CONFIG_PATH = Path("osv-scanner.toml")

# v0.10.4 B5: warn when any [[IgnoredVulns]] entry's `ignoreUntil` is
# within this window of expiring. Picked at 30 days so a normal
# 2-week release cadence has time to re-affirm or remove the entry
# before the gate starts failing — without being so noisy that
# entries 6+ months out generate alarm fatigue.
_ALLOWLIST_EXPIRY_WARN_WINDOW = timedelta(days=30)

# Cobra (osv-scanner's CLI framework) emits these when an invocation
# form is wrong. Used to fall through to the next candidate form so the
# gate survives osv-scanner CLI changes across major versions.
_USAGE_ERROR_MARKERS = ("unknown command", "unknown flag", "unknown shorthand")


def generate_sbom(sbom_path: Path) -> bool:
    """Generate the CycloneDX SBOM -- identical command to release.yml.

    ``sys.executable`` is the workspace venv interpreter when this
    script is run via ``uv run`` (the documented invocation), which is
    exactly what release.yml passes to ``cyclonedx-py environment``.
    """
    print(f"Generating CycloneDX SBOM at {sbom_path} ...")
    try:
        result = subprocess.run(
            [
                "uvx",
                "--from",
                "cyclonedx-bom",
                "cyclonedx-py",
                "environment",
                "-o",
                str(sbom_path),
                "--of",
                "JSON",
                "--sv",
                "1.7",
                "--pyproject",
                "packages/evidentia-core/pyproject.toml",
                sys.executable,
            ],
            check=False,
        )
    except FileNotFoundError as exc:
        print(f"ERROR: could not run cyclonedx-py via uvx ({exc}).", file=sys.stderr)
        return False
    return result.returncode == 0


def run_osv_scanner(sbom_path: Path, config_path: Path) -> int:
    """Scan the SBOM with osv-scanner.

    Returns osv-scanner's exit code, or a negative sentinel: -1 if
    osv-scanner is not on PATH, -2 if no invocation form was accepted.
    """
    if shutil.which("osv-scanner") is None:
        print(
            "ERROR: osv-scanner not found on PATH. Install it first; see docs/release-checklist.md Step 5.",
            file=sys.stderr,
        )
        return -1

    cfg = ["--config", str(config_path)]
    if not config_path.is_file():
        print(f"WARNING: {config_path} not found; scanning with no allowlist.")
        cfg = []

    # osv-scanner's CLI surface for SBOM scanning shifted across
    # v1 -> v2. Try the known forms in order; skip any the installed
    # version rejects as a usage error.
    candidates = [
        ["osv-scanner", *cfg, "--sbom", str(sbom_path)],
        ["osv-scanner", "scan", *cfg, "--sbom", str(sbom_path)],
        ["osv-scanner", "scan", "source", *cfg, str(sbom_path)],
    ]
    last_output = ""
    for cmd in candidates:
        print(f"Running: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if any(marker in (proc.stdout + proc.stderr).lower() for marker in _USAGE_ERROR_MARKERS):
            last_output = proc.stdout + proc.stderr
            print("  osv-scanner rejected this invocation form; trying the next.")
            continue
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        return proc.returncode

    print("ERROR: no osv-scanner invocation form was accepted.", file=sys.stderr)
    sys.stderr.write(last_output)
    return -2


def check_allowlist_expiry(config_path: Path, today: date | None = None) -> list[str]:
    """Inspect [[IgnoredVulns]] entries; return WARN strings for any
    entry whose ``ignoreUntil`` is within ``_ALLOWLIST_EXPIRY_WARN_WINDOW``
    of today (or already expired).

    v0.10.4 B5 hygiene: surfaces stale allowlist entries earlier than
    the actual gate failure. An expired entry is treated as a
    one-line WARN because osv-scanner itself will fail the gate on
    the next run after expiry — this is the early warning, not a
    second gate. Returned strings are written to stderr by the
    caller.
    """
    if today is None:
        today = date.today()
    if not config_path.is_file():
        return []
    try:
        with config_path.open("rb") as fp:
            data = tomllib.load(fp)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return [f"WARN: could not parse {config_path}: {exc!r}"]

    warnings: list[str] = []
    for entry in data.get("IgnoredVulns", []):
        vuln_id = entry.get("id", "<unknown>")
        ignore_until = entry.get("ignoreUntil")
        if ignore_until is None:
            warnings.append(
                f"WARN: allowlist entry {vuln_id!r} has no ignoreUntil; "
                "add a re-validation date (v0.10.4 B5 hygiene policy)."
            )
            continue
        # tomllib parses TOML date literals to datetime.date.
        if not isinstance(ignore_until, date):
            warnings.append(
                f"WARN: allowlist entry {vuln_id!r} ignoreUntil is not a "
                f"date (got {type(ignore_until).__name__}); skipping expiry check."
            )
            continue
        days_remaining = (ignore_until - today).days
        if days_remaining < 0:
            warnings.append(
                f"WARN: allowlist entry {vuln_id!r} expired "
                f"{-days_remaining} day(s) ago (ignoreUntil={ignore_until.isoformat()}). "
                "osv-scanner will fail the gate; re-affirm or remove the entry."
            )
        elif timedelta(days=days_remaining) <= _ALLOWLIST_EXPIRY_WARN_WINDOW:
            warnings.append(
                f"WARN: allowlist entry {vuln_id!r} expires in {days_remaining} day(s) "
                f"(ignoreUntil={ignore_until.isoformat()}). "
                "Re-affirm by editing osv-scanner.toml before the gate starts failing."
            )
    return warnings


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--sbom",
        type=Path,
        default=SBOM_PATH,
        help="SBOM path to generate and scan (default: evidentia-sbom.cdx.json).",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=CONFIG_PATH,
        help="osv-scanner allowlist (default: osv-scanner.toml).",
    )
    parser.add_argument(
        "--skip-sbom-gen",
        action="store_true",
        help="Scan an existing --sbom file instead of regenerating it.",
    )
    args = parser.parse_args()

    # v0.10.4 B5: surface expiring allowlist entries BEFORE running
    # the gate so the warning isn't drowned by gate output.
    for warning in check_allowlist_expiry(args.config):
        print(warning, file=sys.stderr)

    if not args.skip_sbom_gen and not generate_sbom(args.sbom):
        print("ERROR: SBOM generation failed.", file=sys.stderr)
        return 2

    if not args.sbom.is_file():
        print(f"ERROR: SBOM not found at {args.sbom}.", file=sys.stderr)
        return 2

    rc = run_osv_scanner(args.sbom, args.config)
    print()
    if rc == 0:
        print("PASS: osv-scanner found no un-allowlisted vulnerabilities.")
        return 0
    if rc == 1:
        print(
            "FAIL: osv-scanner reported un-allowlisted vulnerabilities (above).\n"
            "Resolution: upgrade the affected dependency, or -- if the finding\n"
            "is accepted -- add an [[IgnoredVulns]] entry to osv-scanner.toml\n"
            "with a reason traceable to a security-review disposition."
        )
        return 1
    print(f"ERROR: osv-scanner did not complete (code {rc}).", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
