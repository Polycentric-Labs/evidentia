#!/usr/bin/env python3
"""Detect version drift between uv.lock and docker/requirements.txt (v0.9.3 P4.1).

Flags when docker/requirements.txt pins a different version than uv.lock
for security-sensitive packages. This catches the class of bug where
Dependabot or manual updates touch one file but not the other (as
happened with urllib3 2.4.0 → 2.7.0 across the v0.9.0 → v0.9.2 cycle).

Note: docker/requirements.txt is regenerated at release time via G4 Path 2
(pip-compile against PyPI's just-published wheels). During development,
minor drift is expected and the script reports it as a WARNING by default.
Use --strict to fail on any drift (intended for the release workflow or
pre-tag checks).

Exit codes:
    0 — no drift detected, or drift is non-strict (warning mode)
    1 — drift detected in strict mode
    2 — parse error or missing uv.lock

Usage (CI step — advisory):
    uv run python scripts/check_requirements_drift.py

Usage (pre-release gate — strict):
    uv run python scripts/check_requirements_drift.py --strict

Usage (with custom package list):
    uv run python scripts/check_requirements_drift.py --packages urllib3 requests cryptography
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SECURITY_SENSITIVE_PACKAGES = [
    "urllib3",
    "requests",
    "cryptography",
    "paramiko",
    "aiohttp",
    "httpx",
    "certifi",
    "pyopenssl",
]

UV_LOCK_PATH = Path("uv.lock")
DOCKER_REQS_PATH = Path("docker/requirements.txt")


def parse_uv_lock(path: Path, packages: list[str]) -> dict[str, str]:
    """Extract package versions from uv.lock (TOML-like format)."""
    if not path.is_file():
        return {}

    content = path.read_text(encoding="utf-8")
    versions: dict[str, str] = {}

    current_name: str | None = None
    for line in content.splitlines():
        name_match = re.match(r'^name\s*=\s*"([^"]+)"', line)
        if name_match:
            current_name = name_match.group(1).lower().replace("-", "_")
        elif current_name and current_name.replace("_", "-") in packages:
            ver_match = re.match(r'^version\s*=\s*"([^"]+)"', line)
            if ver_match:
                normalized = current_name.replace("_", "-")
                versions[normalized] = ver_match.group(1)
                current_name = None

    return versions


def parse_requirements_txt(path: Path, packages: list[str]) -> dict[str, str]:
    """Extract pinned versions from pip-compile output."""
    if not path.is_file():
        return {}

    content = path.read_text(encoding="utf-8")
    versions: dict[str, str] = {}

    pkg_pattern = re.compile(
        r"^([a-zA-Z0-9_-]+)==([^\s\\]+)", re.MULTILINE
    )
    for match in pkg_pattern.finditer(content):
        name = match.group(1).lower().replace("_", "-")
        if name in packages:
            versions[name] = match.group(2)

    return versions


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--packages",
        nargs="+",
        default=SECURITY_SENSITIVE_PACKAGES,
        help="Packages to check for drift (default: security-sensitive set).",
    )
    parser.add_argument(
        "--uv-lock",
        type=Path,
        default=UV_LOCK_PATH,
        help="Path to uv.lock (default: uv.lock).",
    )
    parser.add_argument(
        "--requirements",
        type=Path,
        default=DOCKER_REQS_PATH,
        help="Path to docker/requirements.txt (default: docker/requirements.txt).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Exit 1 on any drift (for pre-release gates). "
        "Default: advisory-only (exit 0 with WARNING).",
    )
    args = parser.parse_args()

    normalized_packages = [p.lower().replace("_", "-") for p in args.packages]

    if not args.uv_lock.is_file():
        print(f"ERROR: uv.lock not found at {args.uv_lock}", file=sys.stderr)
        return 2

    if not args.requirements.is_file():
        print(f"SKIP: {args.requirements} does not exist (no drift check needed)")
        return 0

    uv_versions = parse_uv_lock(args.uv_lock, normalized_packages)
    req_versions = parse_requirements_txt(args.requirements, normalized_packages)

    if not uv_versions:
        print("WARNING: no security-sensitive packages found in uv.lock")
        return 0

    print(f"Checking {len(normalized_packages)} security-sensitive packages...")
    print(f"  uv.lock: {args.uv_lock}")
    print(f"  requirements: {args.requirements}")
    print()

    drifts: list[tuple[str, str, str]] = []
    for pkg in sorted(normalized_packages):
        uv_ver = uv_versions.get(pkg)
        req_ver = req_versions.get(pkg)

        if uv_ver is None and req_ver is None:
            continue
        elif uv_ver is None:
            print(f"  {pkg}: in requirements ({req_ver}) but NOT in uv.lock")
        elif req_ver is None:
            print(f"  {pkg}: in uv.lock ({uv_ver}) but NOT in requirements")
        elif uv_ver != req_ver:
            drifts.append((pkg, uv_ver, req_ver))
            print(f"  {pkg}: DRIFT — uv.lock={uv_ver}, requirements={req_ver}")
        else:
            print(f"  {pkg}: OK ({uv_ver})")

    print()
    if drifts:
        severity = "FAIL" if args.strict else "WARNING"
        print(f"{severity}: version drift detected in security-sensitive packages:")
        for pkg, uv_ver, req_ver in drifts:
            print(f"  - {pkg}: uv.lock pins {uv_ver}, docker/requirements.txt pins {req_ver}")
        print()
        print("Resolution: re-run the G4 Path 2 regeneration step in release.yml,")
        print("or manually refresh docker/requirements.txt via:")
        print("  pip-compile --generate-hashes --no-emit-find-links \\")
        print("      --output-file=docker/requirements.txt docker/requirements.in")
        if not args.strict:
            print()
            print("(advisory mode — use --strict to make this a hard failure)")
        return 1 if args.strict else 0
    else:
        print("PASS: no version drift detected")
        return 0


if __name__ == "__main__":
    sys.exit(main())
