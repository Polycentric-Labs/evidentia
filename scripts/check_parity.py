#!/usr/bin/env python3
"""CLI<->GUI feature-parity gate (Evidentia v0.10.8 Phase C-2).

The ``openapi-drift`` gate keeps the frontend *types* in lockstep with the
API, but it enforces no *feature* parity: a control can have a CLI verb and a
REST endpoint while the web UI never surfaces it, and the drift gate is happy.
This gate closes that blind spot. It reads the declarative manifest
``docs/cli-gui-parity.yaml`` (one row per CLI leaf) and asserts five
invariants against LIVE state:

  1. completeness   — every live CLI leaf (walked from the Typer app) has a
                      manifest row, and every manifest row names a real leaf.
                      A new verb can't land unclassified.
  2. api-existence  — every row's non-null ``api`` ("METHOD /path") resolves to
                      a real operation in ``packages/evidentia-ui/openapi.json``.
  3. gui-existence  — every ``full`` row's ``gui`` route is present in
                      ``App.tsx`` AND its endpoint is actually wired through the
                      runtime client (lib/api.ts + route pages/hooks, EXCLUDING
                      the generated ``src/types`` surface). This catches the
                      "types-only illusion": a route that compiles against the
                      generated types but calls nothing.
  4. debt-ratchet   — the live ``cli-only`` count never exceeds the manifest's
                      ``baseline.cli_only`` floor. New CLI-only debt is blocked;
                      the floor only moves DOWN (via ``--update-baseline`` when a
                      screen ships and a row flips ``cli-only`` -> ``*``).
  5. inverse-       — every live API operation (openapi.json) is either claimed
     completeness     by some CLI-leaf row's ``api`` OR listed in the manifest's
                      ``api_extra`` allowlist (API surface intentionally beyond
                      the CLI — GUI read drill-downs, chrome/health, computed
                      read-only behaviors, multi-dialect fan-out). The inverse of
                      check 1: a new endpoint can't land unclassified, and a
                      stale ``api_extra`` entry (matching no live op) is flagged.

The five ``check_*`` functions are PURE (inputs in, list-of-error-strings out)
so they unit-test against tiny fixtures; the ``load_*`` functions derive the
real inputs.

Exit codes:
    0 — PASS (all four checks clean)
    1 — FAIL (a check produced errors, or the manifest is missing/unparseable)
    2 — argparse usage error

Usage:
    python scripts/check_parity.py
    python scripts/check_parity.py --json
    python scripts/check_parity.py --emit-coverage-md   # write docs/parity-coverage.md
    python scripts/check_parity.py --update-baseline     # lower the ratchet floor
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent

MANIFEST_PATH = REPO_ROOT / "docs" / "cli-gui-parity.yaml"
OPENAPI_PATH = REPO_ROOT / "packages" / "evidentia-ui" / "openapi.json"
APP_TSX_PATH = REPO_ROOT / "packages" / "evidentia-ui" / "src" / "App.tsx"
UI_SRC_DIR = REPO_ROOT / "packages" / "evidentia-ui" / "src"
COVERAGE_MD_PATH = REPO_ROOT / "docs" / "parity-coverage.md"

VALID_STATUSES = {"full", "api-only", "cli-only", "exempt"}

# The frontend subtree that holds GENERATED OpenAPI types. Excluded from the
# "wired" surface: it enumerates every path, so counting it would defeat the
# gui-existence guard (the types-only illusion the gate exists to catch).
_GENERATED_TYPES_PREFIX = "types/"

# HTTP methods that count as real operations in the OpenAPI document.
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


# ───────────────────────── pure check functions ──────────────────────────


def check_completeness(
    cli_leaves: set[str], manifest_clis: set[str]
) -> list[str]:
    """Every live CLI leaf must have a manifest row, and vice versa.

    Returns one error per (a) live leaf missing from the manifest and (b)
    manifest row that names no live leaf (a stale row after a verb removal).
    """
    errors: list[str] = []
    for leaf in sorted(cli_leaves - manifest_clis):
        errors.append(
            f"completeness: live CLI leaf {leaf!r} is not in the manifest — "
            f"add a row to docs/cli-gui-parity.yaml"
        )
    for leaf in sorted(manifest_clis - cli_leaves):
        errors.append(
            f"completeness: manifest row {leaf!r} names no live CLI leaf — "
            f"remove the stale row from docs/cli-gui-parity.yaml"
        )
    return errors


def check_api_existence(
    rows: list[dict[str, Any]], openapi_ops: set[str]
) -> list[str]:
    """Every row's non-null ``api`` must resolve to a real OpenAPI operation."""
    errors: list[str] = []
    for row in rows:
        api = row.get("api")
        if not api:
            continue
        if api not in openapi_ops:
            errors.append(
                f"api-existence: row {row.get('cli')!r} declares api {api!r} "
                f"which is not an operation in openapi.json"
            )
    return errors


def check_gui_existence(
    rows: list[dict[str, Any]],
    app_routes: set[str],
    api_ts_paths: set[str],
) -> list[str]:
    """Every ``full`` row must have a real, wired GUI surface.

    For a row marked ``full``:
      * ``gui`` must be non-null;
      * its route (leading slash stripped for comparison) must appear in
        ``app_routes`` (the ``<Route path="…">`` set from App.tsx);
      * if the row names an ``api``, that endpoint's static path prefix must
        appear in ``api_ts_paths`` (the runtime-wired ``/api/…`` literals,
        EXCLUDING the generated types surface) — otherwise the route renders
        against types but calls nothing.
    """
    errors: list[str] = []
    for row in rows:
        if row.get("status") != "full":
            continue
        cli = row.get("cli")
        gui = row.get("gui")
        if not gui:
            errors.append(
                f"gui-existence: row {cli!r} is status:full but has no gui route"
            )
            continue
        if _norm_route(gui) not in app_routes:
            errors.append(
                f"gui-existence: row {cli!r} (status:full) names gui route "
                f"{gui!r} which is not a <Route path=…> in App.tsx"
            )
        api = row.get("api")
        if api:
            api_path = _api_path_of(api)
            if api_path is not None and not _path_is_wired(api_path, api_ts_paths):
                errors.append(
                    f"gui-existence: row {cli!r} (status:full) endpoint "
                    f"{api_path!r} is not wired in the runtime client "
                    f"(lib/api.ts / route pages) — the route is types-only"
                )
    return errors


def check_debt_ratchet(current_cli_only: int, baseline_cli_only: int) -> list[str]:
    """The live ``cli-only`` count must not exceed the baseline floor."""
    if current_cli_only > baseline_cli_only:
        return [
            f"debt-ratchet: cli-only count rose to {current_cli_only} "
            f"(baseline {baseline_cli_only}). New CLI-only debt is blocked; "
            f"give the new verb an API+GUI, or — if a screen legitimately "
            f"shipped and debt DROPPED — run "
            f"`python scripts/check_parity.py --update-baseline`."
        ]
    return []


def check_inverse_completeness(
    openapi_ops: set[str], claimed_apis: set[str], api_extra: set[str]
) -> list[str]:
    """Every live API operation must be classified — the inverse of check 1.

    An operation is classified when it is either (a) claimed by some CLI-leaf
    row's ``api`` ("this endpoint backs a CLI verb"), or (b) listed in the
    manifest's ``api_extra`` allowlist ("this endpoint is intentionally beyond
    the CLI" — GUI read drill-downs, chrome/health, computed read-only
    behaviors, multi-dialect fan-out). Any live op that is neither is flagged so
    a NEW endpoint cannot land unclassified. Stale ``api_extra`` entries (which
    match no live op) are flagged too, so the allowlist can't rot.
    """
    errors: list[str] = []
    for op in sorted(openapi_ops - claimed_apis - api_extra):
        errors.append(
            f"inverse-completeness: live API op {op!r} is neither claimed by a "
            f"CLI-leaf row's 'api' nor listed in 'api_extra' — classify it in "
            f"docs/cli-gui-parity.yaml (give a CLI row this api, or add an "
            f"api_extra entry with a reason)"
        )
    for extra in sorted(api_extra - openapi_ops):
        errors.append(
            f"inverse-completeness: api_extra entry {extra!r} matches no live "
            f"API operation — remove the stale entry from docs/cli-gui-parity.yaml"
        )
    return errors


# ─────────────────────────── small helpers ───────────────────────────────


def _norm_route(route: str) -> str:
    """Canonicalize a route for comparison (strip a single leading slash)."""
    return route[1:] if route.startswith("/") else route


def _api_path_of(api: str) -> str | None:
    """Extract the ``/path`` portion of a ``"METHOD /path"`` api string."""
    parts = api.split(None, 1)
    if len(parts) != 2:
        return None
    return parts[1].strip()


def _path_is_wired(api_path: str, api_ts_paths: set[str]) -> bool:
    """True if ``api_path`` is referenced by a runtime-wired ``/api/…`` literal.

    Templated path params differ between the OpenAPI form (``{vendor_id}``) and
    the TS template-literal form (``${...}``), so we compare on the static
    prefix up to the first ``{`` and accept any wired literal that shares it.
    """
    prefix = api_path.split("{", 1)[0].rstrip("/")
    if not prefix:
        return False
    for wired in api_ts_paths:
        wired_prefix = wired.split("{", 1)[0].rstrip("/")
        if wired_prefix == prefix or wired_prefix.startswith(prefix + "/"):
            return True
        # Exact endpoint with no params (e.g. /api/doctor) also matches when the
        # wired literal is exactly that path.
        if wired.rstrip("/") == prefix:
            return True
    return False


# ───────────────────────────── loaders ───────────────────────────────────


def _walk_typer_app() -> set[str] | None:
    """Walk the live Typer app to enumerate every leaf, or None on failure.

    Imports ``evidentia.cli.main.app`` and recurses ``registered_commands`` /
    ``registered_groups``. Returns ``{"gap analyze", "poam list", …}``.
    """
    try:
        import importlib

        import typer  # noqa: F401

        app = importlib.import_module("evidentia.cli.main").app
    except Exception:  # pragma: no cover - import-environment dependent
        return None

    def cmd_name(info: Any) -> str:
        if getattr(info, "name", None):
            return str(info.name)
        fn = getattr(info, "callback", None)
        return fn.__name__.replace("_", "-") if fn is not None else "?"

    def walk(t: Any, prefix: str = "") -> list[str]:
        leaves: list[str] = []
        for ci in t.registered_commands:
            leaves.append((prefix + " " + cmd_name(ci)).strip())
        for gi in t.registered_groups:
            gname = gi.name or "?"
            leaves.extend(walk(gi.typer_instance, (prefix + " " + gname).strip()))
        return leaves

    try:
        return set(walk(app))
    except Exception:  # pragma: no cover - defensive
        return None


def _walk_help_tree() -> set[str]:
    """Fallback leaf enumeration by shelling ``evidentia … --help`` recursively.

    Used only if the in-process Typer walk fails (e.g. the package isn't
    importable in the runner). Parses the Rich ``Commands`` panel of each
    ``--help`` page; recurses into groups (a group's help also has a Commands
    panel) until only leaves remain.
    """
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    cmd_re = re.compile(r"^[│|]\s+([A-Za-z][A-Za-z0-9-]*)\s{2,}\S")

    def children(path: list[str]) -> list[str]:
        proc = subprocess.run(
            ["uv", "run", "evidentia", *path, "--help"],
            capture_output=True, text=True, check=False,
            encoding="utf-8", errors="replace", env=env, cwd=str(REPO_ROOT),
        )
        out = proc.stdout or ""
        names: list[str] = []
        in_cmds = False
        for line in out.splitlines():
            if "Commands" in line and ("┌" in line or "─" in line):
                in_cmds = True
                continue
            if in_cmds and line.startswith("└"):
                break
            if in_cmds:
                m = cmd_re.match(line)
                if m:
                    names.append(m.group(1))
        return names

    leaves: set[str] = set()

    def recurse(path: list[str]) -> None:
        kids = children(path)
        if not kids:
            if path:
                leaves.add(" ".join(path))
            return
        for k in kids:
            recurse([*path, k])

    recurse([])
    return leaves


def load_cli_leaves() -> set[str]:
    """Enumerate every live CLI leaf (Typer walk preferred, --help fallback)."""
    leaves = _walk_typer_app()
    if leaves:
        return leaves
    return _walk_help_tree()


def load_openapi_ops(path: Path = OPENAPI_PATH) -> set[str]:
    """Parse openapi.json into ``{"METHOD /path", …}``."""
    spec = json.loads(path.read_text(encoding="utf-8"))
    ops: set[str] = set()
    for op_path, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method in methods:
            if method.lower() in _HTTP_METHODS:
                ops.add(f"{method.upper()} {op_path}")
    return ops


def load_app_routes(path: Path = APP_TSX_PATH) -> set[str]:
    """Parse ``<Route path="…">`` values from App.tsx (leading slash stripped)."""
    text = path.read_text(encoding="utf-8")
    routes = set(re.findall(r'<Route\s+[^>]*?path="([^"]+)"', text))
    return {_norm_route(r) for r in routes}


def load_api_ts_paths(src_dir: Path = UI_SRC_DIR) -> set[str]:
    """Collect runtime-wired ``/api/…`` literals from the frontend src tree.

    Scans every ``.ts``/``.tsx`` file EXCEPT the generated ``src/types`` tree.
    That exclusion is the whole point of the gui-existence guard: ``types/`` is
    the generated OpenAPI surface (it enumerates every path), so counting it
    would let a types-only route masquerade as wired. lib/api.ts plus the route
    pages/hooks are the genuine runtime client.
    """
    literal_re = re.compile(r"""['"`](/api/[A-Za-z0-9/_{}.-]*)""")
    paths: set[str] = set()
    for ext in ("*.ts", "*.tsx"):
        for f in src_dir.rglob(ext):
            rel = f.relative_to(src_dir).as_posix()
            if rel.startswith(_GENERATED_TYPES_PREFIX):
                continue
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            paths |= set(literal_re.findall(text))
    return paths


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    """Load + validate docs/cli-gui-parity.yaml."""
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:  # pragma: no cover - yaml is a workspace dep
        sys.exit("check_parity: PyYAML not available (run `uv sync --all-groups`)")

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        sys.exit(f"check_parity: cannot load manifest {path}: {exc}")

    if not isinstance(data, dict):
        sys.exit(f"check_parity: manifest {path} is not a mapping")
    if data.get("version") != 1:
        sys.exit(f"check_parity: manifest {path} must declare 'version: 1'")
    rows = data.get("commands")
    if not isinstance(rows, list) or not rows:
        sys.exit(f"check_parity: manifest {path} has no 'commands' list")

    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or "cli" not in row:
            sys.exit(f"check_parity: malformed command row: {row!r}")
        cli = row["cli"]
        if cli in seen:
            sys.exit(f"check_parity: duplicate manifest row for {cli!r}")
        seen.add(cli)
        status = row.get("status")
        if status not in VALID_STATUSES:
            sys.exit(
                f"check_parity: row {cli!r} has invalid status {status!r} "
                f"(expected one of {sorted(VALID_STATUSES)})"
            )
        if status == "exempt" and not str(row.get("reason") or "").strip():
            sys.exit(f"check_parity: exempt row {cli!r} must carry a 'reason'")

    extra = data.get("api_extra")
    if extra is not None:
        if not isinstance(extra, list):
            sys.exit("check_parity: manifest 'api_extra' must be a list")
        seen_extra: set[str] = set()
        for e in extra:
            if not isinstance(e, dict) or "api" not in e:
                sys.exit(f"check_parity: malformed api_extra entry: {e!r}")
            api = e["api"]
            if not isinstance(api, str) or api in seen_extra:
                sys.exit(f"check_parity: duplicate/invalid api_extra entry {api!r}")
            seen_extra.add(api)
            if not str(e.get("reason") or "").strip():
                sys.exit(
                    f"check_parity: api_extra entry {api!r} must carry a 'reason'"
                )
    return data


def manifest_baseline(manifest: dict[str, Any]) -> int:
    """Read ``baseline.cli_only`` (the ratchet floor) from the manifest."""
    baseline = manifest.get("baseline") or {}
    if not isinstance(baseline, dict) or "cli_only" not in baseline:
        sys.exit("check_parity: manifest missing 'baseline.cli_only'")
    try:
        return int(baseline["cli_only"])
    except (TypeError, ValueError):
        sys.exit("check_parity: 'baseline.cli_only' is not an integer")


def load_api_extra(manifest: dict[str, Any]) -> set[str]:
    """The ``api_extra`` allowlist — API ops intentionally beyond the CLI.

    Each entry is a ``{api, reason}`` mapping (validated in ``load_manifest``);
    this returns just the set of ``"METHOD /path"`` strings the inverse-
    completeness check needs.
    """
    extra = manifest.get("api_extra") or []
    return {str(e["api"]) for e in extra}


# ─────────────────────── distribution / rendering ────────────────────────


def status_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = {s: 0 for s in VALID_STATUSES}
    for row in rows:
        counts[row.get("status", "")] = counts.get(row.get("status", ""), 0) + 1
    return counts


def coverage_pct(counts: dict[str, int]) -> float:
    """full / (full + api-only + cli-only) — exempt rows are excluded."""
    coverable = counts["full"] + counts["api-only"] + counts["cli-only"]
    if coverable == 0:
        return 0.0
    return 100.0 * counts["full"] / coverable


def render_table(counts: dict[str, int], pct: float, baseline: int) -> str:
    total = sum(counts.values())
    lines = [
        "CLI<->GUI parity:",
        f"  full      {counts['full']:>4}",
        f"  api-only  {counts['api-only']:>4}",
        f"  cli-only  {counts['cli-only']:>4}  (baseline floor {baseline})",
        f"  exempt    {counts['exempt']:>4}",
        f"  total     {total:>4}",
        f"  GUI coverage = full / (full+api-only+cli-only) = {pct:.1f}%",
    ]
    return "\n".join(lines)


def render_coverage_md(rows: list[dict[str, Any]], baseline: int) -> str:
    """Render docs/parity-coverage.md (burndown table + per-row list)."""
    counts = status_counts(rows)
    pct = coverage_pct(counts)
    total = sum(counts.values())
    coverable = counts["full"] + counts["api-only"] + counts["cli-only"]

    out: list[str] = []
    out.append("# CLI<->GUI Parity Coverage")
    out.append("")
    out.append(
        "> Generated by `scripts/check_parity.py --emit-coverage-md` from "
        "`docs/cli-gui-parity.yaml`. Do not edit by hand."
    )
    out.append("")
    out.append(
        f"**GUI coverage: {pct:.1f}%** "
        f"({counts['full']} of {coverable} coverable CLI leaves are surfaced "
        f"as a dedicated GUI screen; `exempt` leaves are excluded)."
    )
    out.append("")
    out.append("## Burndown")
    out.append("")
    out.append("| status | count | meaning |")
    out.append("|---|---:|---|")
    out.append(f"| full | {counts['full']} | CLI verb + API op + wired GUI route |")
    out.append(
        f"| api-only | {counts['api-only']} | API op exists; no dedicated GUI route yet |"
    )
    out.append(
        f"| cli-only | {counts['cli-only']} | no API + no GUI "
        f"(ratchet floor: {baseline}) |"
    )
    out.append(
        f"| exempt | {counts['exempt']} | CLI-only by design (servers, local "
        f"cache, offline verify, MCP) |"
    )
    out.append(f"| **total** | **{total}** | every live CLI leaf |")
    out.append("")
    out.append("## Per-command status")
    out.append("")
    out.append("| CLI leaf | API | GUI route | status |")
    out.append("|---|---|---|---|")
    for row in rows:
        cli = str(row.get("cli", ""))
        api = row.get("api") or "—"
        gui = row.get("gui") or "—"
        status = str(row.get("status", ""))
        out.append(f"| `{cli}` | {api} | {gui} | {status} |")
    out.append("")
    return "\n".join(out)


def emit_coverage_md(rows: list[dict[str, Any]], baseline: int) -> None:
    COVERAGE_MD_PATH.write_text(render_coverage_md(rows, baseline), encoding="utf-8")
    print(f"check_parity: wrote {COVERAGE_MD_PATH.relative_to(REPO_ROOT).as_posix()}")


def update_baseline(manifest_text: str, new_cli_only: int) -> str:
    """Rewrite the ``baseline.cli_only`` value in the manifest text in place.

    Operates on the raw text (not a YAML round-trip) so the documented header
    comments + row layout are preserved verbatim.
    """
    pattern = re.compile(r"(?m)^(\s*cli_only:\s*)\d+\s*$")
    if not pattern.search(manifest_text):
        sys.exit("check_parity: could not locate 'cli_only:' line to update")
    return pattern.sub(rf"\g<1>{new_cli_only}", manifest_text, count=1)


# ─────────────────────────────── main ────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="emit a machine-readable JSON report"
    )
    parser.add_argument(
        "--emit-coverage-md", action="store_true",
        help="(re)generate docs/parity-coverage.md from the manifest and exit 0",
    )
    parser.add_argument(
        "--update-baseline", action="store_true",
        help="write the current cli-only count back to the manifest baseline "
             "(use only when debt legitimately dropped) and exit 0",
    )
    args = parser.parse_args(argv)

    manifest = load_manifest()
    rows: list[dict[str, Any]] = manifest["commands"]
    baseline = manifest_baseline(manifest)
    counts = status_counts(rows)

    # Side-effect modes run and exit before the gate.
    if args.update_baseline:
        new_text = update_baseline(MANIFEST_PATH.read_text(encoding="utf-8"),
                                   counts["cli-only"])
        MANIFEST_PATH.write_text(new_text, encoding="utf-8")
        print(
            f"check_parity: baseline.cli_only set to {counts['cli-only']} "
            f"(was {baseline})."
        )
        return 0

    if args.emit_coverage_md:
        emit_coverage_md(rows, baseline)
        return 0

    # Derive live inputs.
    cli_leaves = load_cli_leaves()
    openapi_ops = load_openapi_ops()
    app_routes = load_app_routes()
    api_ts_paths = load_api_ts_paths()
    manifest_clis = {str(r["cli"]) for r in rows}
    claimed_apis = {str(r["api"]) for r in rows if r.get("api")}
    api_extra = load_api_extra(manifest)

    completeness = check_completeness(cli_leaves, manifest_clis)
    api_existence = check_api_existence(rows, openapi_ops)
    gui_existence = check_gui_existence(rows, app_routes, api_ts_paths)
    ratchet = check_debt_ratchet(counts["cli-only"], baseline)
    inverse = check_inverse_completeness(openapi_ops, claimed_apis, api_extra)
    all_errors = (
        completeness + api_existence + gui_existence + ratchet + inverse
    )
    pct = coverage_pct(counts)

    if args.json:
        print(json.dumps({
            "ok": not all_errors,
            "counts": counts,
            "coverage_pct": round(pct, 1),
            "baseline_cli_only": baseline,
            "errors": {
                "completeness": completeness,
                "api_existence": api_existence,
                "gui_existence": gui_existence,
                "debt_ratchet": ratchet,
                "inverse_completeness": inverse,
            },
        }, indent=2))
        return 0 if not all_errors else 1

    print(render_table(counts, pct, baseline))
    print()
    for label, errs in (
        ("completeness", completeness),
        ("api-existence", api_existence),
        ("gui-existence", gui_existence),
        ("debt-ratchet", ratchet),
        ("inverse-completeness", inverse),
    ):
        if errs:
            print(f"{label}: FAIL ({len(errs)})")
            for e in errs:
                print(f"  - {e}")
        else:
            print(f"{label}: PASS")

    print()
    if all_errors:
        print(f"check_parity: FAIL ({len(all_errors)} issue(s)).")
        return 1
    print("check_parity: PASS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
