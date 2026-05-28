"""Single source of truth for the pinned upstream OpenSSF OSPS Baseline commit.

The 5 osps-baseline_to_*.json crosswalks in this directory are
auto-extracted from ossf/security-baseline at this commit. When bumping
to a new upstream OSPS Baseline revision, update OSPS_BASELINE_COMMIT_SHA
here and re-run scripts/catalogs/gen_osps_crosswalks.py to regenerate the
JSONs deterministically.

This module is a *data-adjacent constant module*: it lives in the same
directory as the generated JSON artifacts (which cannot carry a Python
constant) so that the pin is co-located with what it pins. It is read by
the regeneration tooling and by any Python that needs to know which
upstream revision the shipped crosswalks were extracted from. The JSON
files keep their literal SHA strings (they are generated artifacts); this
module is where the SHA lives canonically for the regenerator.
"""

OSPS_BASELINE_COMMIT_SHA = "ac6bbec8aecf51dce41f62712745f7949ab6bdeb"
OSPS_BASELINE_VERSION = "osps-baseline-2026.02.19"
OSPS_BASELINE_REPO = "ossf/security-baseline"
