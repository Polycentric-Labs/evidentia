#!/usr/bin/env python3
"""FIXABLE-only policy gate for the post-publish container rescan (#6).

``osv-scanner`` v2 has NO native fixable/severity gate -- it exits non-zero
on *any* reportable advisory. Run against a published container image that
sits on a full Debian base, that means the rescan goes permanently RED on
day-N base-OS CVEs marked "No fix available" (a dispatch on v0.10.13 found
81 such advisories, only 4 actually fixable). A chronically-red gate is the
project's own anti-pattern -- it trains everyone to ignore a red signal
(docs/engineering-practices.md, "Fail closed" + lesson #2).

This step re-architects the rescan into an *actionable* gate: parse
``osv-scanner ... --format json`` and fail ONLY when a detected
vulnerability has an *applicable* fix ("a fix is now available -> rebuild");
the unfixable base-OS CVEs are notify-only, still rendered for full
visibility on a green run. Surface reduction (a minimal glibc base + a
scheduled rebuild) is the companion roadmap item; this keeps the signal
honest until then.

The matched-affected rule (established empirically against real osv-scanner
v2.3.8 output on the published image): an OSV record lists ``affected[]``
entries for *every* Debian release and even unrelated source packages that
share a CVE. A fix is applicable ONLY when the ``affected`` entry whose
``package.ecosystem`` + ``package.name`` match the *detected* package
carries a ``fixed`` event. Matching any ``fixed`` event anywhere
over-reports ~25x (110 vs the real 4).

The allowlist is NOT re-implemented here: the rescan runs osv-scanner with
``--config osv-scanner.toml``, which suppresses ``[[IgnoredVulns]]`` ids
(with their ``ignoreUntil`` expiry) from the JSON entirely -- so this gate
parses the post-allowlist set and the allowlist keeps a single definition
(one place, no drift). Use ``[[IgnoredVulns]]`` only for time-bound,
documented exceptions; never to blanket-ignore the unfixable base-OS noise
(that is exactly what notify-only handles).

Exit codes:
    0 -- no fixable advisories (gate passes; unfixable CVEs reported)
    1 -- one or more fixable advisories (rebuild the published image)
    2 -- the scan JSON is missing / malformed (fail-closed: a gate that
         cannot read its input is a FAILURE, not a skip)

Usage:
    python scripts/check_osv_fixable.py rescan.json
    python scripts/check_osv_fixable.py rescan.json --image ghcr.io/...:vX \\
        --summary-file "$GITHUB_STEP_SUMMARY"
    python scripts/check_osv_fixable.py rescan.json --no-fail   # visibility only
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

_BAND_ORDER = ("Critical", "High", "Medium", "Low", "Unknown")


class ScanLoadError(Exception):
    """The osv-scanner JSON could not be read or is not a scan result."""


@dataclass(frozen=True)
class Finding:
    """One deduped advisory against one detected package."""

    vuln_id: str
    source_package: str
    os_package: str
    ecosystem: str
    installed_version: str
    fixed_versions: tuple[str, ...]
    max_severity: str | None
    aliases: tuple[str, ...]

    @property
    def is_fixable(self) -> bool:
        return bool(self.fixed_versions)


def load_scan(path: Path | str) -> dict:
    """Load + minimally validate osv-scanner ``--format json`` output.

    Raises ``ScanLoadError`` (caller maps to exit 2) for any unreadable,
    unparseable, or non-scan input -- the fail-closed boundary.
    """
    p = Path(path)
    if not p.is_file():
        raise ScanLoadError(f"osv-scanner JSON not found at {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanLoadError(f"could not parse {p}: {exc}") from exc
    if not isinstance(data, dict) or "results" not in data:
        raise ScanLoadError(f"{p} is not osv-scanner JSON output (no 'results' key)")
    return data


def fixed_versions_for(package_info: dict, vuln: dict) -> list[str]:
    """Fixed versions applicable to the DETECTED package, in order.

    Only ``affected[]`` entries whose package ecosystem AND name equal the
    detected package's are considered -- a ``fixed`` event on a different
    release or an unrelated source package that merely shares the CVE is not a
    fix for THIS package. The match is exact *including the release suffix*
    (``Debian:13``, not the ``Debian`` family) on purpose: a fix released for
    ``Debian:12`` does not apply to a ``Debian:13`` install, so relaxing to the
    family would over-flag. This mirrors osv-scanner's own per-package
    "Fix available" determination -- empirically it reproduces its exact fixable
    count (matching any shared-CVE entry over-reports by an order of magnitude).
    An empty ``fixed`` string carries no upgrade target, so it does not count.
    """
    eco = package_info.get("ecosystem")
    name = package_info.get("name")
    fixes: list[str] = []
    for aff in vuln.get("affected", []):
        ap = aff.get("package", {})
        if ap.get("ecosystem") != eco or ap.get("name") != name:
            continue
        for rng in aff.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed and fixed not in fixes:
                    fixes.append(fixed)
    return fixes


def severity_band(max_severity: str | None) -> str:
    """Map a numeric CVSS string (osv-scanner group ``max_severity``) to a band."""
    try:
        score = float(max_severity)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Unknown"


def _severity_for(groups: list[dict], vuln_id: str) -> str | None:
    for group in groups:
        if vuln_id in group.get("ids", []):
            return group.get("max_severity")
    return None


def classify(data: dict) -> tuple[list[Finding], list[Finding]]:
    """Return ``(fixable, unfixable)`` Findings, deduped by advisory id.

    The same advisory can appear on several package records (e.g. util-linux
    resolved under three installed versions). It is fixable if ANY of its
    records carries an applicable fix; the deduped Finding is then fixable.
    """
    by_id: dict[str, Finding] = {}
    for result in data.get("results", []):
        for pkg in result.get("packages", []):
            pkg_info = pkg.get("package", {})
            groups = pkg.get("groups", [])
            for vuln in pkg.get("vulnerabilities", []):
                vuln_id = vuln.get("id")
                if not vuln_id:
                    continue
                fixes = fixed_versions_for(pkg_info, vuln)
                finding = Finding(
                    vuln_id=vuln_id,
                    source_package=pkg_info.get("name", ""),
                    os_package=pkg_info.get("os_package_name", pkg_info.get("name", "")),
                    ecosystem=pkg_info.get("ecosystem", ""),
                    installed_version=pkg_info.get("version", ""),
                    fixed_versions=tuple(fixes),
                    max_severity=_severity_for(groups, vuln_id),
                    aliases=tuple(vuln.get("aliases") or ()),
                )
                existing = by_id.get(vuln_id)
                # Promote to the fixable record if any occurrence is fixable.
                if existing is None or (finding.is_fixable and not existing.is_fixable):
                    by_id[vuln_id] = finding

    fixable = sorted((f for f in by_id.values() if f.is_fixable), key=lambda f: f.vuln_id)
    unfixable = sorted((f for f in by_id.values() if not f.is_fixable), key=lambda f: f.vuln_id)
    return fixable, unfixable


def _band_summary(findings: list[Finding]) -> str:
    counts = Counter(severity_band(f.max_severity) for f in findings)
    return ", ".join(f"{counts[b]} {b}" for b in _BAND_ORDER if counts[b])


def render_markdown(fixable: list[Finding], unfixable: list[Finding], *, image: str | None = None) -> str:
    """Render a GitHub-flavoured markdown report for ``$GITHUB_STEP_SUMMARY``."""
    total = len(fixable) + len(unfixable)
    head = "# Post-publish container rescan — fixable-only policy"
    if image:
        head += f"\n\n**Image:** `{image}`"
    lines = [head, ""]
    lines.append(
        f"**{total}** advisories after allowlist · "
        f"**{len(fixable)} fixable** · {len(unfixable)} unfixable (no upstream fix)."
    )
    lines.append("")

    if fixable:
        lines.append("## ❌ Fixable — a fix is available; rebuild the image")
        lines.append("")
        lines.append("| Advisory | Package | Installed | Fixed in | Severity |")
        lines.append("|---|---|---|---|---|")
        for f in fixable:
            sev = f"{f.max_severity or '—'} ({severity_band(f.max_severity)})"
            lines.append(
                f"| {f.vuln_id} | {f.source_package} | {f.installed_version} | {', '.join(f.fixed_versions)} | {sev} |"
            )
        lines.append("")
        lines.append(
            "> **Action:** rebuild + republish the container on a fresh base to clear the fixable advisories above."
        )
    else:
        lines.append("## ✅ No fixable advisories — gate passes")
    lines.append("")

    if unfixable:
        lines.append(
            f"<details><summary>{len(unfixable)} unfixable base-OS advisories "
            f"— notify-only ({_band_summary(unfixable)})</summary>"
        )
        lines.append("")
        lines.append("| Advisory | Package | Installed | Severity |")
        lines.append("|---|---|---|---|")
        for f in unfixable:
            sev = f"{f.max_severity or '—'} ({severity_band(f.max_severity)})"
            lines.append(f"| {f.vuln_id} | {f.source_package} | {f.installed_version} | {sev} |")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    return "\n".join(lines) + "\n"


def _print_console(fixable: list[Finding], unfixable: list[Finding], *, no_fail: bool) -> None:
    print(f"osv-scanner rescan policy: {len(fixable)} fixable / {len(unfixable)} unfixable (no upstream fix)")
    if fixable:
        print("\nFIXABLE — a fix is available; rebuild the published image:")
        for f in fixable:
            print(
                f"  [{severity_band(f.max_severity)} "
                f"{f.max_severity or '—'}] {f.vuln_id}  "
                f"{f.source_package} {f.installed_version} -> "
                f"{', '.join(f.fixed_versions)}"
            )
    if unfixable:
        print(f"\nUnfixable base-OS advisories (notify-only): {_band_summary(unfixable)}")

    print()
    if fixable and not no_fail:
        print(
            f"FAIL: {len(fixable)} fixable advisory(ies) in the published image. "
            "Rebuild + republish the container on a fresh base."
        )
    elif fixable and no_fail:
        print(f"NOTE (--no-fail): {len(fixable)} fixable advisory(ies) present; not failing (visibility mode).")
    else:
        print(
            "PASS: no fixable advisories. Unfixable base-OS CVEs are notify-only — see the report for full visibility."
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "scan_json",
        type=Path,
        help="osv-scanner --format json output to evaluate.",
    )
    parser.add_argument(
        "--image",
        default=None,
        help="Image reference, for the report header (optional).",
    )
    parser.add_argument(
        "--summary-file",
        type=Path,
        default=None,
        help="Also write a markdown report here (e.g. $GITHUB_STEP_SUMMARY).",
    )
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Report only; never exit non-zero on fixable advisories.",
    )
    args = parser.parse_args(argv)

    try:
        data = load_scan(args.scan_json)
    except ScanLoadError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print(
            "Fail-closed: a rescan gate that cannot read its scan is a FAILURE, not a skip.",
            file=sys.stderr,
        )
        return 2

    fixable, unfixable = classify(data)
    _print_console(fixable, unfixable, no_fail=args.no_fail)

    if args.summary_file:
        try:
            args.summary_file.write_text(
                render_markdown(fixable, unfixable, image=args.image),
                encoding="utf-8",
            )
        except OSError as exc:
            print(
                f"WARNING: could not write summary file {args.summary_file}: {exc}",
                file=sys.stderr,
            )

    if fixable and not args.no_fail:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
