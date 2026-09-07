"""Build the vendored FedRAMP Rev 5 baseline provenance file.

Produces ``scripts/catalogs/upstream/fedramp-rev5-baselines.json``: the four
FedRAMP Rev 5 baselines (Low, Moderate, High, LI-SaaS) as ordered control id
lists, the LI-SaaS per-control FedRAMP Tailored method properties, and the
provenance block naming where the data came from. ``gen_fedramp_cmmc.py``
reads this file; it does not compute membership itself.

The source is the FedRAMP PMO's own OSCAL profiles, republished at
OSCAL-Foundation/fedramp-resources (the original GSA/fedramp-automation
publication was taken down). Membership is EXTRACTED from those profiles
rather than hand-authored: through v0.11.2 the Low and LI-SaaS lists were
derived by truncating Moderate, which silently dropped six control families
(see the history note at the top of ``gen_fedramp_cmmc.py``). Deriving
membership mechanically, from the same source every time and checked against
the same invariants every time, is what turns that class of error into a
build failure instead of a typo nobody notices.

Three ways to run this:

  1. ``python build_fedramp_baselines.py`` fetches the four profiles from
     SOURCE_URL and rewrites the vendored file in place.
  2. ``python build_fedramp_baselines.py --from-dir DIR`` reads the profiles
     from local files instead of the network (DIR holds the four
     ``FedRAMP_rev5_*-baseline_profile.json`` files, named as upstream names
     them).
  3. ``python build_fedramp_baselines.py --check`` (with either source)
     derives the document and compares it against the file at ``--out``
     without writing anything, exiting 1 on a mismatch. Run it before a
     re-vendor; the weekly ``fedramp-schema-watch`` sentinel performs the
     same extraction against the live republisher on its own schedule.

Either mode refuses to vendor a profile whose sha256 no longer matches the
pin already recorded at ``--out``, unless ``--allow-upstream-change`` is
given: an upstream change should be reviewed, never silently absorbed.

Two dates are recorded. ``retrieved`` is when the profile bytes now vendored
were first pulled: a rebuild from byte-identical profiles keeps it, and a
rebuild that accepts changed profiles resets it to today (or ``--retrieved``).
``reverified`` is the date of the last successful derivation, which every
build sets to today (or ``--reverified``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SOURCE_URL = "https://raw.githubusercontent.com/OSCAL-Foundation/fedramp-resources/main/baselines/rev5/json/"

# Canonical key order, shared by PROFILE_FILES, provenance.files and baselines.
PROFILE_FILES = {
    "low": "FedRAMP_rev5_LOW-baseline_profile.json",
    "moderate": "FedRAMP_rev5_MODERATE-baseline_profile.json",
    "high": "FedRAMP_rev5_HIGH-baseline_profile.json",
    "li-saas": "FedRAMP_rev5_LI-SaaS-baseline_profile.json",
}
BASELINE_KEYS = tuple(PROFILE_FILES)

# Published FedRAMP Rev 5 counts, from the PMO's own OSCAL profiles. A test
# monkeypatches this constant to exercise the invariant gate on synthetic data.
EXPECTED_COUNTS: dict[str, int] = {"low": 156, "moderate": 323, "high": 410, "li-saas": 156}

# NIST SP 800-53 Rev 5 withdrawn controls that must never appear in a baseline.
WITHDRAWN = {"CM-8(5)", "CP-2(4)", "SA-12", "SC-13(1)"}

_ID_RE = re.compile(r"^[A-Z]{2}-\d+(\(\d+\))?$")

DEFAULT_OUT = Path(__file__).resolve().parent / "upstream" / "fedramp-rev5-baselines.json"

# Prose carried verbatim from the vendored file's provenance and notes blocks.
# These are administrative text, not derived data, so build_document copies
# them unchanged except for the three fields the module docstring calls out.
_COMMENT = (
    "Vendored FedRAMP Rev 5 baseline membership. Source of truth for "
    "scripts/catalogs/gen_fedramp_cmmc.py. Do NOT hand-edit: regenerate with the builder "
    "described in provenance.builder. The four baselines nest strictly (low == li-saas as "
    "sets; low < moderate < high; union == high), which the generator asserts at build time."
)
_SOURCE_NAME = "FedRAMP Rev 5 baselines, OSCAL profiles authored by the FedRAMP PMO"
_REPUBLISHER = "OSCAL-Foundation/fedramp-resources (GSA/fedramp-automation was taken down; HTTP 404)"
_VALIDATION_BASE = (
    "Membership cross-validated three ways by the research pass (profile with-ids, "
    "resolved-catalog walk, and Internet Archive copies of the deleted GSA originals, "
    "identical in set and order), then independently re-extracted here from the profiles and "
    "re-checked against every invariant."
)
_VALIDATION_ADDENDUM = (
    " The in-repo extractor named in builder re-derives this file from the same profiles; "
    "reverified is the date of its last run, and --check repeats the derivation and compares."
)
_BUILDER = (
    "scripts/catalogs/build_fedramp_baselines.py (in-repo extractor: fetches the source_url "
    "profiles, or reads them from --from-dir, re-derives this file and re-checks every "
    "invariant; --check compares a fresh derivation against the vendored copy)"
)
_SHELF_LIFE = (
    "Rev 5 is on FedRAMP's legacy track (20x and CR26 lead). The upstream that would have "
    "signalled change (GSA/fedramp-automation) no longer exists, so any freshness sentinel "
    "must point at OSCAL-Foundation/fedramp-resources."
)
_NOTE_PM_PT_EXCLUDED = (
    "SP 800-53B Table 3-13 (PM) and Table 3-15 (PT): not allocated to the security control "
    "baselines. Neither family appears in any FedRAMP baseline."
)
_NOTE_LI_SAAS = (
    "LI-SaaS selects exactly the same 156 control ids as Low, in the same order. The FedRAMP "
    "Tailored tailoring is NOT a smaller control set: it is the per-control `method` property "
    "carried in li_saas_methods below. A catalog that stores only ids cannot express "
    "attest-versus-assess."
)
_NOTE_WITHDRAWN = (
    "CM-8(5), CP-2(4), SA-12 and SC-13(1) are withdrawn in NIST SP 800-53 Rev 5 and must never appear in a baseline."
)


def oscal_to_repo_id(oscal_id: str) -> str:
    """Convert an OSCAL control id (``ac-2.1``) to repo form (``AC-2(1)``)."""
    if "." in oscal_id:
        base, _, enhancement = oscal_id.partition(".")
        return f"{base.upper()}({enhancement})"
    return oscal_id.upper()


def membership(profile: dict[str, Any]) -> list[str]:
    """Ordered, de-duplicated control ids across every import's include-controls."""
    ids: list[str] = []
    seen: set[str] = set()
    for imp in profile["profile"].get("imports", []):
        for include in imp.get("include-controls", []):
            for oscal_id in include.get("with-ids", []):
                repo_id = oscal_to_repo_id(oscal_id)
                if repo_id not in seen:
                    seen.add(repo_id)
                    ids.append(repo_id)
    return ids


def li_saas_methods(profile: dict[str, Any]) -> dict[str, list[str]]:
    """Per-control FedRAMP Tailored ``method`` props, sorted by control id.

    The structure is ``modify.alters[].adds[].props[]`` (an OSCAL ``add``
    carrying the prop), not ``alters[].props[]`` directly. A control whose
    alteration adds some other prop (``IA-2(12)`` adds only a
    ``response-point``) contributes no entry.
    """
    methods: dict[str, list[str]] = {}
    for alter in profile["profile"].get("modify", {}).get("alters", []):
        repo_id = oscal_to_repo_id(alter.get("control-id", ""))
        values = [
            prop.get("value")
            for add in alter.get("adds", [])
            for prop in add.get("props", [])
            if prop.get("name") == "method" and prop.get("value")
        ]
        if not values:
            continue
        bucket = methods.setdefault(repo_id, [])
        for value in values:
            if value not in bucket:
                bucket.append(value)
    return {key: methods[key] for key in sorted(methods)}


def git_blob_sha(raw: bytes) -> str:
    """Git's content-addressed blob id: ``sha1("blob <len>\\0" + content)``.

    Depends only on the bytes, not on any repository state, so it can be
    computed locally and compared against a blob sha read from the GitHub
    API without cloning anything.
    """
    header = f"blob {len(raw)}\0".encode("ascii")
    return hashlib.sha1(header + raw).hexdigest()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def assert_invariants(
    baselines: dict[str, list[str]],
    methods: dict[str, list[str]],
    *,
    expected_counts: dict[str, int],
) -> None:
    """Raise ``RuntimeError`` on the first violated invariant.

    Mirrors ``gen_fedramp_cmmc.py::_assert_baseline_invariants`` (that
    function re-asserts the same properties at catalog-build time against
    whatever this script last wrote, so a hand-edited vendored file still
    fails the catalog build even if this gate is skipped). Adds one check
    that function does not need: every LI-SaaS method key must name an
    LI-SaaS control.

    Raises ``RuntimeError`` rather than using a bare ``assert``: this gate
    must survive ``python -O``, which compiles assert statements away.
    """

    def _require(condition: bool, message: str) -> None:
        if not condition:
            raise RuntimeError(f"baseline invariant violated: {message}")

    actual_counts = {name: len(ids) for name, ids in baselines.items()}
    _require(actual_counts == expected_counts, f"baseline counts changed: {actual_counts} != {expected_counts}")

    for name, ids in baselines.items():
        _require(len(ids) == len(set(ids)), f"{name} contains duplicate control ids")

    low, moderate = set(baselines["low"]), set(baselines["moderate"])
    high, li_saas = set(baselines["high"]), set(baselines["li-saas"])
    every = low | moderate | high | li_saas

    _require(low == li_saas, "LI-SaaS membership must equal Low")
    _require(low < moderate, "Low must be a strict subset of Moderate")
    _require(moderate < high, "Moderate must be a strict subset of High")
    _require(every == high, "the union of all baselines must equal High")

    pm = sorted(i for i in every if i.startswith("PM-"))
    pt = sorted(i for i in every if i.startswith("PT-"))
    _require(not pm, f"PM controls are not allocated to security baselines (SP 800-53B Table 3-13): {pm}")
    _require(not pt, f"PT controls are not allocated to security baselines (SP 800-53B Table 3-15): {pt}")

    withdrawn = sorted(every & WITHDRAWN)
    _require(not withdrawn, f"withdrawn Rev 5 controls cannot appear in a baseline: {withdrawn}")

    bad_format = sorted(i for i in every if not _ID_RE.match(i))
    _require(not bad_format, f"control ids do not match the repo id format: {bad_format}")

    stray_methods = sorted(set(methods) - li_saas)
    _require(not stray_methods, f"method props reference controls outside LI-SaaS: {stray_methods}")


def methods_note(baselines: dict[str, list[str]], methods: dict[str, list[str]]) -> str:
    """Build the ``notes.li_saas_methods`` sentence describing the method distribution."""
    li_saas = baselines["li-saas"]
    total = len(li_saas)
    with_method = len(methods)
    distribution = Counter(value for values in methods.values() for value in values)
    dist_text = ", ".join(
        f"{name} {count}" for name, count in sorted(distribution.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    two_or_more = sum(1 for values in methods.values() if len(values) > 1)

    sentence = (
        f"{with_method} of the {total} LI-SaaS controls carry at least one FedRAMP Tailored "
        f"method ({dist_text}); {two_or_more} carry two."
    )
    missing = sorted(set(li_saas) - set(methods))
    if missing:
        controls = ", ".join(missing)
        possessive = "its profile alteration adds" if len(missing) == 1 else "their profile alterations add"
        sentence += f" Controls with no method prop: {controls} ({possessive} no method)."
    return sentence


def build_document(profiles: dict[str, bytes], *, retrieved: str, reverified: str) -> dict[str, Any]:
    """Parse the four profiles, extract and validate, and assemble the vendored document.

    ``retrieved`` and ``reverified`` are the two dates the module docstring
    describes; ``main`` decides them, this function only records them.
    Returns the document in exactly the vendored file's key order:
    ``_comment``, ``provenance``, ``notes``, ``baselines``, ``li_saas_methods``.
    """
    parsed = {key: json.loads(raw) for key, raw in profiles.items()}
    baselines = {key: membership(parsed[key]) for key in BASELINE_KEYS}
    methods = li_saas_methods(parsed["li-saas"])
    assert_invariants(baselines, methods, expected_counts=EXPECTED_COUNTS)

    files: dict[str, dict[str, Any]] = {}
    for key in BASELINE_KEYS:
        raw = profiles[key]
        meta = parsed[key]["profile"]["metadata"]
        files[key] = {
            "file": PROFILE_FILES[key],
            "sha256": sha256(raw),
            "bytes": len(raw),
            "git_blob_sha": git_blob_sha(raw),
            "oscal_version": meta.get("oscal-version"),
            "profile_version": meta.get("version"),
        }
    published = parsed[BASELINE_KEYS[0]]["profile"]["metadata"].get("published")

    return {
        "_comment": _COMMENT,
        "provenance": {
            "source_name": _SOURCE_NAME,
            "source_url": SOURCE_URL,
            "republisher": _REPUBLISHER,
            "published": published,
            "retrieved": retrieved,
            "reverified": reverified,
            "validation": _VALIDATION_BASE + _VALIDATION_ADDENDUM,
            "builder": _BUILDER,
            "files": files,
            "shelf_life": _SHELF_LIFE,
        },
        "notes": {
            "pm_pt_excluded": _NOTE_PM_PT_EXCLUDED,
            "li_saas": _NOTE_LI_SAAS,
            "withdrawn": _NOTE_WITHDRAWN,
            "li_saas_methods": methods_note(baselines, methods),
        },
        "baselines": baselines,
        "li_saas_methods": methods,
    }


def _fetch(url: str) -> bytes:
    """GET url with one retry; network hiccups should not fail the whole run."""
    last_error: Exception | None = None
    for _attempt in range(2):
        try:
            with urllib.request.urlopen(url, timeout=120) as response:
                return response.read()
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"GET {url} failed after retry: {last_error}")


def load_profiles(from_dir: Path | None) -> dict[str, bytes]:
    """Read the four baseline profiles from a directory, or fetch them from SOURCE_URL."""
    if from_dir is not None:
        return {key: (from_dir / filename).read_bytes() for key, filename in PROFILE_FILES.items()}
    return {key: _fetch(f"{SOURCE_URL}{filename}") for key, filename in PROFILE_FILES.items()}


def content_sections(doc: dict[str, Any]) -> dict[str, Any]:
    """The parts a ``--check`` run compares: derived data, not the dated provenance strings.

    ``provenance.retrieved`` defaults to today and would make ``--check`` fail
    every day for no reason; the rest of ``provenance`` besides ``files`` is
    administrative prose that a deliberate hand edit, not this gate, should
    catch.
    """
    return {
        "baselines": doc["baselines"],
        "li_saas_methods": doc["li_saas_methods"],
        "notes": doc["notes"],
        "provenance.files": doc["provenance"]["files"],
    }


def _describe_dict_diff(fresh: dict[str, Any], vendored: dict[str, Any]) -> list[str]:
    """One readable line per key that differs between two comparably-shaped dicts."""
    lines: list[str] = []
    for key in sorted(set(fresh) | set(vendored)):
        fresh_value, vendored_value = fresh.get(key), vendored.get(key)
        if fresh_value == vendored_value:
            continue
        if isinstance(fresh_value, list) and isinstance(vendored_value, list):
            added = [item for item in fresh_value if item not in vendored_value]
            removed = [item for item in vendored_value if item not in fresh_value]
            detail = [part for part in (f"+{added}" if added else "", f"-{removed}" if removed else "") if part]
            lines.append(f"  {key}: {'; '.join(detail) if detail else 'reordered'}")
        else:
            lines.append(f"  {key}: {vendored_value!r} -> {fresh_value!r}")
    return lines


def _diff_summary(fresh: dict[str, Any], vendored: dict[str, Any]) -> list[str]:
    """A readable per-section report of how a fresh derivation differs from --out."""
    lines: list[str] = []
    for section in ("baselines", "li_saas_methods", "notes", "provenance.files"):
        if fresh[section] != vendored[section]:
            lines.append(f"{section}:")
            lines.extend(_describe_dict_diff(fresh[section], vendored[section]))
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--from-dir",
        type=Path,
        default=None,
        help="read the four profiles from this directory instead of fetching them",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="path to write (default: the vendored file)")
    parser.add_argument(
        "--retrieved",
        default=None,
        help=(
            "retrieval date to record, YYYY-MM-DD (default: the date already recorded at --out when the "
            "profiles are byte-identical to the pins, otherwise today, UTC)"
        ),
    )
    parser.add_argument(
        "--reverified", default=None, help="re-derivation date to record, YYYY-MM-DD (default: today, UTC)"
    )
    parser.add_argument("--check", action="store_true", help="do not write; compare a fresh derivation against --out")
    parser.add_argument(
        "--allow-upstream-change",
        action="store_true",
        help="proceed even if a profile's sha256 no longer matches the pin recorded at --out",
    )
    args = parser.parse_args(argv)

    today = datetime.now(UTC).strftime("%Y-%m-%d")
    profiles = load_profiles(args.from_dir)

    existing: dict[str, Any] | None = None
    if args.out.exists():
        existing = json.loads(args.out.read_text(encoding="utf-8"))

    changed: list[tuple[str, str, str]] = []
    if existing is not None:
        for key, raw in profiles.items():
            pinned = existing["provenance"]["files"][key]["sha256"]
            live = sha256(raw)
            if live != pinned:
                changed.append((PROFILE_FILES[key], pinned, live))
    if changed and not args.allow_upstream_change:
        print(f"error: upstream profile(s) changed since {args.out} was last vendored:", file=sys.stderr)
        for filename, pinned, live in changed:
            print(f"  {filename}: sha256 {pinned} -> {live}", file=sys.stderr)
        print("Re-run with --allow-upstream-change to review and re-vendor deliberately.", file=sys.stderr)
        return 2

    # Byte-identical profiles keep the date they were first retrieved; changed
    # (and therefore accepted) profiles were retrieved now.
    if args.retrieved:
        retrieved = args.retrieved
    elif existing is not None and not changed:
        retrieved = existing["provenance"]["retrieved"]
    else:
        retrieved = today
    reverified = args.reverified or today

    document = build_document(profiles, retrieved=retrieved, reverified=reverified)

    if args.check:
        if existing is None:
            print(f"error: nothing to check against, {args.out} does not exist", file=sys.stderr)
            return 1
        fresh_sections = content_sections(document)
        vendored_sections = content_sections(existing)
        if fresh_sections != vendored_sections:
            print(f"MISMATCH: a fresh derivation differs from {args.out}:", file=sys.stderr)
            for line in _diff_summary(fresh_sections, vendored_sections):
                print(line, file=sys.stderr)
            return 1
        print("OK")
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    # newline="\n" keeps the vendored file LF on every platform; without it a
    # Windows run would write CRLF and git would have to normalize on commit.
    args.out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
