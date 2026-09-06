"""Regenerate the Meridian v2 baseline + pr-branch gap snapshots.

Used by the `examples/WALKTHROUGH.md` demo flow. Run from anywhere —
the script resolves paths relative to the repo root.

Usage::

    python scripts/demo/generate_snapshot_pair.py

Writes:
    examples/meridian-fintech-v2/snapshots/baseline.json
    examples/meridian-fintech-v2/snapshots/pr-branch.json
    examples/meridian-fintech-v2/snapshots/pr-diff.md

After a catalog refresh (NIST update, etc.) the absolute numbers in
the snapshots will shift — re-run this script and commit the
refreshed files so the README's "Expect: +1 opened, -3 closed, …"
counts stay accurate.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger("generate_snapshot_pair")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCENARIO_DIR = REPO_ROOT / "examples" / "meridian-fintech-v2"
SNAPSHOTS_DIR = SCENARIO_DIR / "snapshots"

FRAMEWORKS = "nist-800-53-rev5-moderate,soc2-tsc"


def _run(args: list[str], cwd: Path) -> None:
    """Run a Evidentia CLI command, surfacing output on failure."""
    logger.info("exec: %s", " ".join(args))
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        logger.error("stdout: %s", result.stdout)
        logger.error("stderr: %s", result.stderr)
        raise SystemExit(f"Command failed ({result.returncode}): {' '.join(args)}")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)

    logger.info("Generating baseline.json from my-controls.yaml")
    _run(
        [
            "evidentia",
            "gap",
            "analyze",
            "--inventory",
            "my-controls.yaml",
            "--frameworks",
            FRAMEWORKS,
            "--output",
            str(SNAPSHOTS_DIR / "baseline.json"),
            "--format",
            "json",
        ],
        cwd=SCENARIO_DIR,
    )

    logger.info("Generating pr-branch.json from my-controls-pr.yaml")
    _run(
        [
            "evidentia",
            "gap",
            "analyze",
            "--inventory",
            "my-controls-pr.yaml",
            "--frameworks",
            FRAMEWORKS,
            "--output",
            str(SNAPSHOTS_DIR / "pr-branch.json"),
            "--format",
            "json",
        ],
        cwd=SCENARIO_DIR,
    )

    logger.info("Rendering pr-diff.md from the two snapshots")
    _run(
        [
            "evidentia",
            "gap",
            "diff",
            "--base",
            str(SNAPSHOTS_DIR / "baseline.json"),
            "--head",
            str(SNAPSHOTS_DIR / "pr-branch.json"),
            "--format",
            "markdown",
            "--output",
            str(SNAPSHOTS_DIR / "pr-diff.md"),
        ],
        cwd=SCENARIO_DIR,
    )

    # Summary the user can paste into a CHANGELOG or commit body
    base = json.loads((SNAPSHOTS_DIR / "baseline.json").read_text(encoding="utf-8"))
    head = json.loads((SNAPSHOTS_DIR / "pr-branch.json").read_text(encoding="utf-8"))
    logger.info("---")
    logger.info("Baseline: %d gaps, %.1f%% coverage", base["total_gaps"], base["coverage_percentage"])
    logger.info("PR:       %d gaps, %.1f%% coverage", head["total_gaps"], head["coverage_percentage"])
    logger.info("Outputs written to: %s", SNAPSHOTS_DIR)


if __name__ == "__main__":
    sys.exit(main())
