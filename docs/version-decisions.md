# Version-decisions log

Companion to [`scripts/version_tracked_files.yaml`](../scripts/version_tracked_files.yaml)
— the machine-readable classification that `scripts/bump_version.py` and
`scripts/check_version_consistency.py` read. **That manifest is the source of
truth;** this file is the *human* decision record: the process for classifying a
version literal, the rationale behind the non-obvious calls, and the
"looks-stale-but-is-correct" register that a naive staleness sweep must never
touch.

Every project-version literal in the repo is in exactly one of three classes:

- **tracked** — a live version that bumps every release (the `pyproject.toml`
  versions, inter-package pins, the README container tag, `CITATION.cff`, the
  marketplace `plugin.json`, …).
- **anchor** — a live "current release" claim that lives *inside* an otherwise
  **frozen** file, re-armed line-by-line so it can't silently drift (the
  `SECURITY.md` "Latest patch" row, the wiki install/verify examples,
  `docker/requirements.in`, the ROADMAP "Last updated" stamp, …).
- **frozen** — an intentionally historical literal that must **never** bump
  (CHANGELOG entries, dated `security-review-vX.md` references, "added in vX"
  source comments, per-version plan docs, third-party dependency pins, …).

## The classification process — run the 3× check before any version-literal change

`check_version_consistency.py`'s **never-skip** gate hard-fails on any
git-tracked file that contains a project-version literal yet is in none of the
three classes. When that fires (or when a new literal is introduced):

1. **Validate 3×.** (a) Read the literal in its actual line context; (b)
   cross-reference what it *means* — a current-release claim, a historical
   "added in vX" note, a dated doc filename, or a third-party pin?; (c) check
   the actual repo / runtime state, not the assumption.
2. **Classify** into `tracked`, `anchor`, or `frozen` per the definitions above.
3. **If the call is AMBIGUOUS, raise it to Allen with a pin/unpin
   recommendation — do not guess.** (This file exists because of one such case;
   see the register below.) Record his decision here and in the manifest.
4. **Record the rationale** in the manifest entry's `desc`. The
   `decisions_documented` check (in `check_version_consistency.py`) hard-fails
   if any `tracked` / `frozen` / `anchor` entry lacks a non-empty `desc`, so a
   classification can never be added without being documented — the automation
   then follows it and never re-litigates it.

## Decision log (notable calls)

| Date | Decision | Rationale |
|---|---|---|
| 2026-05-29 | Marketplace `plugin.json` → **tracked**; its README → durable, stays **frozen** | The plugin's own README states it "tracks the Evidentia release line," so its canonical version must auto-track; its README install examples were *unpinned* and its prose made version-agnostic so the README carries no live literal (it keeps a historical `v0.10.2` plan-doc link → must stay frozen). Reverses an earlier "freeze the whole plugin" call once the README evidence was read. |
| 2026-05-29 | `docker/requirements.in` `evidentia[gui]==` → **anchor** (force-refresh) | Was 14 patches behind (`0.9.1`). `release.yml` overwrites it at publish, so it never reaches the published image, but the committed preview should be *honest*. Anchored so it tracks each bump. |
| 2026-05-29 | `docs/ROADMAP.md` "Last updated: vX.Y.Z" → **anchor** | A live stamp; lock it to the current release so it can't drift. |
| 2026-05-29 | `SECURITY.md` supported-versions table → **reword + anchor** | The "Latest patch" row was the live instance of the drift this whole mechanism exists to kill (it sat at `0.10.6` while the repo was at `0.10.7`). Reworded so the row carries exactly one live literal (anchored) + a version-agnostic reason; the "Deprecated" row made version-agnostic. *Allen approved the reword (governance doc).* |
| 2026-05-29 | `docs/wiki/6-project/versioning.md` patch-range → **reword** | "`0.10.1` through `0.10.7`" was a two-literal range a force-set would mangle; dropped the explicit end-version so the prose carries no live literal (the historical `0.10.0` feature-surface origin stays). |
| 2026-05-29 | **"all" live-in-frozen literals → anchored** (15 anchors / 26 lines) | Allen's call: *guarantee* that no copy-paste wiki/demo example or supported-version claim can silently go stale. The exactly-one-literal anchor guard makes a sloppy marker hard-fail rather than corrupt a neighbour. |
| 2026-05-29 | **Air-gapped docker block → tarball reworded + anchored** (WS1-D closure) | The 3rd-pass audit found the `docker save`/`load` block stuck one release behind because its tarball filename + image tag put two live literals on one line (the guard correctly refused it). Reworded the tarball to a version-agnostic `evidentia.tar` so each line is single-literal, then anchored the `docker pull` + `save` container tags — closing the last live-drift surface. |

## False-positive-staleness register — LOOKS stale, is CORRECT, do NOT bump

These literals show an **old** version on purpose. A "fix the stale version"
pass MUST leave them alone. They are `frozen` (or below the 0.7 floor), and the
anchor mechanism's exactly-one-literal guard refuses to touch any line carrying
a second/historical literal — but they are listed here so a human reviewer
doesn't "helpfully" correct them:

- **`marketplace/grc-engineering-suite/plugins/evidentia/README.md`** — the
  [`docs/v0.10.2-marketplace.md`](releases/plans/v0.10.2-marketplace.md) plan-doc link + the
  "per the v0.10.2 scope decision" citation. *This is the case that motivated
  the entire register* (a `v0.10.2` that looks stale but is a correct historical
  reference).
- **`SECURITY.md`** legacy-`controlbridge*` / `v0.6.0` rename row — below the
  0.7 family floor; a fixed historical fact.
- **`docs/**`** "added in vX" / "removed in vX" annotations, dated
  `security-review-vX.md` references, and the per-version `vX.Y.Z-plan.md` /
  `-implementation-plan.md` documents — each records the release at which a fact
  was true.
- **`pyproject.toml`** third-party + historical-floor pins (`py-ocsf-models`,
  `worm-*`, the `evidentia-eval[...]>=` floor) — deliberately pinned to a past
  floor; protected by the F-V100-M1 `[tool.uv.sources]` workspace allowlist so
  the bumper only touches workspace members.
- **`.pre-commit-config.yaml`** third-party hook `rev:` tags that coincidentally
  fall in the `0.7`+ family — they are upstream hook-repo versions, not
  Evidentia's.
- **`README.md` "Recent Releases"** historical version mentions — regenerated
  from the CHANGELOG top-3 by `scripts/gen_readme_releases.py`, not anchored.

## Why a separate file (and not just the manifest)

The manifest answers *what* each literal is; this log answers *why*, captures
the **dated, human decisions** (especially the reversed and the
Allen-escalated ones), and gives the false-positive register a single visible
home so the recurrence class — "a correct historical reference that looks
stale" — is never re-introduced as a bug.
