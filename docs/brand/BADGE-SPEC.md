# Evidentia — Badge System Spec

Canonical badge palette, order, and tiering for the Evidentia README and every
Polycentric Labs public repo. **Facts are locked:** every label, value, and URL
below is taken verbatim from the current `README.md`. This spec changes only
**grouping** and **accent color** — never a claim, count, or link.

---

## Accent decision (please read)

The brand brief says to "standardize on the Evidentia **teal**," and to use
"the exact value of the `--primary` token in `index.css` — do not guess a hex."
Those two instructions point at different colors:

| | Value | Source |
|---|---|---|
| **`--primary` token (today)** | `hsl(214 70% 38%)` → **`#1D58A5`** | `index.css` `:root`; its own comment calls it *"federal-blue interactive primary"* |
| Dark `--primary` | `hsl(213 80% 62%)` → `#5196EC` | `index.css` `.dark` |
| "teal" (pre-refresh primary) | `hsl(186 100% 37%)` → `#00A6BD` | the 2026-05-30 UI brief's "starting point" |

**This spec follows the token: the brand accent is the federal blue `#1D58A5`
(`#5196EC` on dark).** The word "teal" appears to be stale terminology carried
over from the pre-refresh design. Per the brief I am flagging this rather than
editing anything — if you actually want teal, change `--primary` in `index.css`
first so the app, CLI, and badges stay in lockstep, then swap the hexes below.

---

## Color rules

- **Brand/identity badges** (solid color, no live data): use the accent —
  `#1D58A5` primary, `#0E1B25` chrome-navy for the "Documentation" pair,
  `#15478A` primary-strong for a secondary solid.
- **Semantic status badges** (pass/fail, coverage, license): keep their
  meaning-colors — green `#2EA043`/`brightgreen` for good, etc. Do **not**
  recolor these to the accent; the color *is* information.
- **Provider-owned badges** (codecov, OpenSSF Best Practices, OpenSSF
  Scorecard, PyPI version): keep the provider's own rendered color. Never
  hand-color a live badge.

---

## Tiers & order

Group top-to-bottom by purpose. Row 1 is the tall `for-the-badge` "call to
action" row; rows 2–4 are flat status badges.

### Tier 1 — Identity & get-started  ·  `style=for-the-badge`
| Badge | Value / color | Links to |
|---|---|---|
| Get Started | `#1D58A5` (was `#2563EB`) | `#quickstart-60-seconds` |
| Documentation | `#0E1B25` (was `#1E293B`) | wiki |
| PyPI | `#15478A` + `logo=pypi` (was `#3775A9`) | pypi.org/project/evidentia |

### Tier 2 — Version & CI / quality  (flat)
`pypi vX.Y.Z` (live) · `tests` (GitHub Actions, live) · `codecov` (live) ·
`CLI↔GUI parity 93%` (`brightgreen`)

### Tier 3 — Standards & security  (flat)
`python 3.12+` → recolor to `#1D58A5` · `license Apache-2.0` (`green`, keep) ·
`OpenSSF Best Practices` (provider, keep) · `OpenSSF Scorecard` (provider, keep)

### Tier 4 — Community  (flat)
`Contributor Covenant 2.1` → recolor to `#1D58A5` (was `#4baaaa`; keeping the
Covenant teal is also acceptable since it's a recognized standard)

---

## Recoloring reference (shields.io)

Only the **solid** identity/language badges change; swap the trailing hex.

```
Get Started    …/badge/Get%20Started-1D58A5?style=for-the-badge
Documentation  …/badge/Documentation-0E1B25?style=for-the-badge
PyPI           …/badge/PyPI-15478A?style=for-the-badge&logo=pypi&logoColor=white
python         …/badge/python-3.12+-1D58A5.svg
Covenant       …/badge/Contributor%20Covenant-2.1-1D58A5.svg
```

Live/semantic/provider badge URLs are unchanged from the current README.

---

## Custom branded pills (committed SVG, air-gap-safe)

For claims shields.io renders poorly. Shipped as **PNG** (IBM Plex Mono baked,
pixel-perfect, 3×) plus a matching SVG vector master. Use the PNG in the README;
use sparingly — one short row, never in place of a live badge.

| File | Use |
|---|---|
| `pill-oscal-native.svg` | OSCAL-native (accent, carries the mark) |
| `pill-air-gap-ready.svg` | Air-gap ready (navy outline, lock) |
| `pill-sigstore-signed.svg` | Sigstore-signed (success green, check) |
| `pill-slsa-provenance.svg` | SLSA · Provenance v1 (two-tone) |
