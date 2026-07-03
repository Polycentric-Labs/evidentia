# Release-docs index — old → new path map

The `docs/` folder was reorganized in July 2026 (docs-hygiene closeout,
PR-B): the two closed per-release clutter families and the standalone
design docs moved out of the flat `docs/` root into dated sub-trees, so
the top level now holds only living-canonical docs. Nothing was deleted —
every file below was `git mv`-moved (history preserved).

- Per-release **security reviews** → `docs/releases/reviews/`
- Per-release **plans / shipped records / retrospectives / marketplace /
  walkthrough-validation** → `docs/releases/plans/`
- Standalone **design docs** → `docs/designs/`

**Stub policy (maintainer decision, frozen-cited only):** GitHub does not
redirect moved `blob/main/...` paths, so any file cited by an *immutable*
surface (a published GitHub Release body) keeps a 3-line "Moved" stub at
its **old** flat path so those links keep resolving. Files with no frozen
external citation moved clean (no stub); a bookmarked old blob URL to one
of those will 404 — they were never linked from an immutable surface. A
`†` in the tables below marks the files that retain a stub at the old path.

This index maps **every** moved file (88 total) to its new location.


## Security reviews → `docs/releases/reviews/`

| Old path | New path | Stub? |
|---|---|---|
| `docs/security-review-v0.10.0.md` | [`docs/releases/reviews/security-review-v0.10.0.md`](reviews/security-review-v0.10.0.md) | — |
| `docs/security-review-v0.10.1.md` | [`docs/releases/reviews/security-review-v0.10.1.md`](reviews/security-review-v0.10.1.md) | † yes |
| `docs/security-review-v0.10.12.md` | [`docs/releases/reviews/security-review-v0.10.12.md`](reviews/security-review-v0.10.12.md) | — |
| `docs/security-review-v0.10.2.md` | [`docs/releases/reviews/security-review-v0.10.2.md`](reviews/security-review-v0.10.2.md) | † yes |
| `docs/security-review-v0.10.3.md` | [`docs/releases/reviews/security-review-v0.10.3.md`](reviews/security-review-v0.10.3.md) | — |
| `docs/security-review-v0.10.4.md` | [`docs/releases/reviews/security-review-v0.10.4.md`](reviews/security-review-v0.10.4.md) | — |
| `docs/security-review-v0.10.5.md` | [`docs/releases/reviews/security-review-v0.10.5.md`](reviews/security-review-v0.10.5.md) | — |
| `docs/security-review-v0.10.6.md` | [`docs/releases/reviews/security-review-v0.10.6.md`](reviews/security-review-v0.10.6.md) | — |
| `docs/security-review-v0.10.7.md` | [`docs/releases/reviews/security-review-v0.10.7.md`](reviews/security-review-v0.10.7.md) | — |
| `docs/security-review-v0.7.10.md` | [`docs/releases/reviews/security-review-v0.7.10.md`](reviews/security-review-v0.7.10.md) | — |
| `docs/security-review-v0.7.11.md` | [`docs/releases/reviews/security-review-v0.7.11.md`](reviews/security-review-v0.7.11.md) | — |
| `docs/security-review-v0.7.12.md` | [`docs/releases/reviews/security-review-v0.7.12.md`](reviews/security-review-v0.7.12.md) | — |
| `docs/security-review-v0.7.13.md` | [`docs/releases/reviews/security-review-v0.7.13.md`](reviews/security-review-v0.7.13.md) | — |
| `docs/security-review-v0.7.14.md` | [`docs/releases/reviews/security-review-v0.7.14.md`](reviews/security-review-v0.7.14.md) | — |
| `docs/security-review-v0.7.15.md` | [`docs/releases/reviews/security-review-v0.7.15.md`](reviews/security-review-v0.7.15.md) | — |
| `docs/security-review-v0.7.16.md` | [`docs/releases/reviews/security-review-v0.7.16.md`](reviews/security-review-v0.7.16.md) | — |
| `docs/security-review-v0.7.7.md` | [`docs/releases/reviews/security-review-v0.7.7.md`](reviews/security-review-v0.7.7.md) | — |
| `docs/security-review-v0.7.8.md` | [`docs/releases/reviews/security-review-v0.7.8.md`](reviews/security-review-v0.7.8.md) | † yes |
| `docs/security-review-v0.7.9.md` | [`docs/releases/reviews/security-review-v0.7.9.md`](reviews/security-review-v0.7.9.md) | — |
| `docs/security-review-v0.8.0.md` | [`docs/releases/reviews/security-review-v0.8.0.md`](reviews/security-review-v0.8.0.md) | † yes |
| `docs/security-review-v0.8.1.md` | [`docs/releases/reviews/security-review-v0.8.1.md`](reviews/security-review-v0.8.1.md) | — |
| `docs/security-review-v0.8.2.md` | [`docs/releases/reviews/security-review-v0.8.2.md`](reviews/security-review-v0.8.2.md) | — |
| `docs/security-review-v0.8.3.md` | [`docs/releases/reviews/security-review-v0.8.3.md`](reviews/security-review-v0.8.3.md) | — |
| `docs/security-review-v0.8.4.md` | [`docs/releases/reviews/security-review-v0.8.4.md`](reviews/security-review-v0.8.4.md) | — |
| `docs/security-review-v0.8.5.md` | [`docs/releases/reviews/security-review-v0.8.5.md`](reviews/security-review-v0.8.5.md) | — |
| `docs/security-review-v0.8.6.md` | [`docs/releases/reviews/security-review-v0.8.6.md`](reviews/security-review-v0.8.6.md) | † yes |
| `docs/security-review-v0.8.7.md` | [`docs/releases/reviews/security-review-v0.8.7.md`](reviews/security-review-v0.8.7.md) | — |
| `docs/security-review-v0.9.0.md` | [`docs/releases/reviews/security-review-v0.9.0.md`](reviews/security-review-v0.9.0.md) | — |
| `docs/security-review-v0.9.1.md` | [`docs/releases/reviews/security-review-v0.9.1.md`](reviews/security-review-v0.9.1.md) | † yes |
| `docs/security-review-v0.9.2.md` | [`docs/releases/reviews/security-review-v0.9.2.md`](reviews/security-review-v0.9.2.md) | † yes |
| `docs/security-review-v0.9.3.md` | [`docs/releases/reviews/security-review-v0.9.3.md`](reviews/security-review-v0.9.3.md) | — |
| `docs/security-review-v0.9.4.md` | [`docs/releases/reviews/security-review-v0.9.4.md`](reviews/security-review-v0.9.4.md) | — |
| `docs/security-review-v0.9.5.md` | [`docs/releases/reviews/security-review-v0.9.5.md`](reviews/security-review-v0.9.5.md) | — |
| `docs/security-review-v0.9.6.md` | [`docs/releases/reviews/security-review-v0.9.6.md`](reviews/security-review-v0.9.6.md) | — |
| `docs/security-review-v0.9.7.md` | [`docs/releases/reviews/security-review-v0.9.7.md`](reviews/security-review-v0.9.7.md) | — |
| `docs/security-review-v0.9.8.md` | [`docs/releases/reviews/security-review-v0.9.8.md`](reviews/security-review-v0.9.8.md) | — |
| `docs/security-review-v0.9.9.md` | [`docs/releases/reviews/security-review-v0.9.9.md`](reviews/security-review-v0.9.9.md) | — |

## Plans / shipped / retrospectives → `docs/releases/plans/`

| Old path | New path | Stub? |
|---|---|---|
| `docs/v0.10.0-plan.md` | [`docs/releases/plans/v0.10.0-plan.md`](plans/v0.10.0-plan.md) | — |
| `docs/v0.10.1-plan.md` | [`docs/releases/plans/v0.10.1-plan.md`](plans/v0.10.1-plan.md) | † yes |
| `docs/v0.10.10-plan.md` | [`docs/releases/plans/v0.10.10-plan.md`](plans/v0.10.10-plan.md) | — |
| `docs/v0.10.11-plan.md` | [`docs/releases/plans/v0.10.11-plan.md`](plans/v0.10.11-plan.md) | — |
| `docs/v0.10.12-omb-m25-21-plan.md` | [`docs/releases/plans/v0.10.12-omb-m25-21-plan.md`](plans/v0.10.12-omb-m25-21-plan.md) | — |
| `docs/v0.10.2-marketplace.md` | [`docs/releases/plans/v0.10.2-marketplace.md`](plans/v0.10.2-marketplace.md) | † yes |
| `docs/v0.10.2-plan.md` | [`docs/releases/plans/v0.10.2-plan.md`](plans/v0.10.2-plan.md) | † yes |
| `docs/v0.10.3-plan.md` | [`docs/releases/plans/v0.10.3-plan.md`](plans/v0.10.3-plan.md) | † yes |
| `docs/v0.10.4-plan.md` | [`docs/releases/plans/v0.10.4-plan.md`](plans/v0.10.4-plan.md) | † yes |
| `docs/v0.10.5-plan.md` | [`docs/releases/plans/v0.10.5-plan.md`](plans/v0.10.5-plan.md) | † yes |
| `docs/v0.10.6-implementation-plan.md` | [`docs/releases/plans/v0.10.6-implementation-plan.md`](plans/v0.10.6-implementation-plan.md) | — |
| `docs/v0.10.6-plan.md` | [`docs/releases/plans/v0.10.6-plan.md`](plans/v0.10.6-plan.md) | † yes |
| `docs/v0.10.7-plan.md` | [`docs/releases/plans/v0.10.7-plan.md`](plans/v0.10.7-plan.md) | † yes |
| `docs/v0.10.8-plan.md` | [`docs/releases/plans/v0.10.8-plan.md`](plans/v0.10.8-plan.md) | † yes |
| `docs/v0.10.9-plan.md` | [`docs/releases/plans/v0.10.9-plan.md`](plans/v0.10.9-plan.md) | † yes |
| `docs/v0.7.1-plan.md` | [`docs/releases/plans/v0.7.1-plan.md`](plans/v0.7.1-plan.md) | † yes |
| `docs/v0.7.10-plan.md` | [`docs/releases/plans/v0.7.10-plan.md`](plans/v0.7.10-plan.md) | — |
| `docs/v0.7.11-plan.md` | [`docs/releases/plans/v0.7.11-plan.md`](plans/v0.7.11-plan.md) | — |
| `docs/v0.7.12-plan.md` | [`docs/releases/plans/v0.7.12-plan.md`](plans/v0.7.12-plan.md) | — |
| `docs/v0.7.13-shipped.md` | [`docs/releases/plans/v0.7.13-shipped.md`](plans/v0.7.13-shipped.md) | — |
| `docs/v0.7.14-plan.md` | [`docs/releases/plans/v0.7.14-plan.md`](plans/v0.7.14-plan.md) | — |
| `docs/v0.7.14-shipped.md` | [`docs/releases/plans/v0.7.14-shipped.md`](plans/v0.7.14-shipped.md) | — |
| `docs/v0.7.15-shipped.md` | [`docs/releases/plans/v0.7.15-shipped.md`](plans/v0.7.15-shipped.md) | † yes |
| `docs/v0.7.2-plan.md` | [`docs/releases/plans/v0.7.2-plan.md`](plans/v0.7.2-plan.md) | † yes |
| `docs/v0.7.3-plan.md` | [`docs/releases/plans/v0.7.3-plan.md`](plans/v0.7.3-plan.md) | † yes |
| `docs/v0.7.5-plan.md` | [`docs/releases/plans/v0.7.5-plan.md`](plans/v0.7.5-plan.md) | — |
| `docs/v0.7.6-plan.md` | [`docs/releases/plans/v0.7.6-plan.md`](plans/v0.7.6-plan.md) | † yes |
| `docs/v0.7.7-plan.md` | [`docs/releases/plans/v0.7.7-plan.md`](plans/v0.7.7-plan.md) | — |
| `docs/v0.7.8-plan.md` | [`docs/releases/plans/v0.7.8-plan.md`](plans/v0.7.8-plan.md) | † yes |
| `docs/v0.7.9-plan.md` | [`docs/releases/plans/v0.7.9-plan.md`](plans/v0.7.9-plan.md) | † yes |
| `docs/v0.7.x-retrospective.md` | [`docs/releases/plans/v0.7.x-retrospective.md`](plans/v0.7.x-retrospective.md) | † yes |
| `docs/v0.8.0-plan.md` | [`docs/releases/plans/v0.8.0-plan.md`](plans/v0.8.0-plan.md) | † yes |
| `docs/v0.8.2-plan.md` | [`docs/releases/plans/v0.8.2-plan.md`](plans/v0.8.2-plan.md) | — |
| `docs/v0.8.3-plan.md` | [`docs/releases/plans/v0.8.3-plan.md`](plans/v0.8.3-plan.md) | — |
| `docs/v0.8.4-plan.md` | [`docs/releases/plans/v0.8.4-plan.md`](plans/v0.8.4-plan.md) | — |
| `docs/v0.8.5-plan.md` | [`docs/releases/plans/v0.8.5-plan.md`](plans/v0.8.5-plan.md) | — |
| `docs/v0.8.6-plan.md` | [`docs/releases/plans/v0.8.6-plan.md`](plans/v0.8.6-plan.md) | † yes |
| `docs/v0.8.7-plan.md` | [`docs/releases/plans/v0.8.7-plan.md`](plans/v0.8.7-plan.md) | — |
| `docs/v0.9.0-plan.md` | [`docs/releases/plans/v0.9.0-plan.md`](plans/v0.9.0-plan.md) | — |
| `docs/v0.9.1-plan.md` | [`docs/releases/plans/v0.9.1-plan.md`](plans/v0.9.1-plan.md) | † yes |
| `docs/v0.9.3-plan.md` | [`docs/releases/plans/v0.9.3-plan.md`](plans/v0.9.3-plan.md) | † yes |
| `docs/v0.9.4-plan.md` | [`docs/releases/plans/v0.9.4-plan.md`](plans/v0.9.4-plan.md) | † yes |
| `docs/v0.9.5-plan.md` | [`docs/releases/plans/v0.9.5-plan.md`](plans/v0.9.5-plan.md) | † yes |
| `docs/v0.9.6-plan.md` | [`docs/releases/plans/v0.9.6-plan.md`](plans/v0.9.6-plan.md) | — |
| `docs/v0.9.7-plan.md` | [`docs/releases/plans/v0.9.7-plan.md`](plans/v0.9.7-plan.md) | — |
| `docs/v0.9.8-plan.md` | [`docs/releases/plans/v0.9.8-plan.md`](plans/v0.9.8-plan.md) | — |
| `docs/v0.9.9-plan.md` | [`docs/releases/plans/v0.9.9-plan.md`](plans/v0.9.9-plan.md) | — |
| `docs/walkthrough-validation-v0.9.5.md` | [`docs/releases/plans/walkthrough-validation-v0.9.5.md`](plans/walkthrough-validation-v0.9.5.md) | † yes |

## Design docs → `docs/designs/`

| Old path | New path | Stub? |
|---|---|---|
| `docs/demo-suite-design.md` | [`docs/designs/demo-suite-design.md`](../designs/demo-suite-design.md) | † yes |
| `docs/demo-suite-implementation-plan.md` | [`docs/designs/demo-suite-implementation-plan.md`](../designs/demo-suite-implementation-plan.md) | — |
| `docs/sarif-ingestion-collector-design.md` | [`docs/designs/sarif-ingestion-collector-design.md`](../designs/sarif-ingestion-collector-design.md) | † yes |

---

**Totals:** 37 reviews + 48 plans + 3 designs = 88 moved files; 34 frozen-cited stubs at old paths.
