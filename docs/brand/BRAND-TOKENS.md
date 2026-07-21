# Evidentia — Brand Token Sheet

The portable brand definition for Evidentia and its Polycentric Labs siblings.
Every color is converted verbatim from `packages/evidentia-ui/src/index.css`
(the single color authority) — the app, CLI, and this brand kit stay in lockstep.

---

## Palette

### Accent — federal blue (`--primary`)
| Token | HSL | Hex | Notes |
|---|---|---|---|
| primary (light) | `214 70% 38%` | `#1D58A5` | **the brand accent** |
| primary-strong | `214 74% 31%` | `#15478A` | hover / secondary solid |
| primary (dark) | `213 80% 62%` | `#5196EC` | accent on dark surfaces |

> ⚠ The brief calls this "teal"; the token is a federal blue. See `BADGE-SPEC.md`.

### Neutrals — navy chrome & cream
| Token | HSL | Hex |
|---|---|---|
| chrome-bg (dark field) | `206 44% 10%` | `#0E1B25` |
| chrome-bg-2 | `207 46% 7.5%` | `#0A141C` |
| chrome-border | `206 28% 19%` | `#23323E` |
| foreground (ink) | `206 38% 13%` | `#15232E` |
| muted-foreground | `210 11% 44%` | `#64707D` |
| border | `214 22% 89%` | `#DDE2E9` |
| cream | `40 56% 85%` | `#EEE0C3` |
| cream-soft | `40 50% 90%` | `#F2EAD9` |
| background (off-white) | `40 28% 97.5%` | `#FAF9F7` |

### Severity — preserved verbatim (matches the CLI Rich tables — do not alter)
| Level | Light hex | Dark hex |
|---|---|---|
| critical | `#C51111` | `#E74040` |
| high | `#E6410F` | `#F16A41` |
| medium | `#E6950A` | `#F6AE31` |
| low | `#198DC8` | `#49B4E9` |
| informational | `#677589` | `#8F9CAE` |

Semantic: success `#21976B` · warning `#DC8F09` · destructive `#C51111`.

---

## Type pairing (self-hosted, air-gap-safe — no CDN font)

| Role | Family | Weights | File |
|---|---|---|---|
| Headline / wordmark | **IBM Plex Sans** | 700 | `IBMPlexSans-Bold.woff2` |
| Body / UI | IBM Plex Sans | 400 / 500 / 600 | `IBMPlexSans-*.woff2` |
| Details / mono | **IBM Plex Mono** | 500 / 600 | `IBMPlexMono-*.woff2` |

Already self-hosted in `packages/evidentia-ui/public/fonts/`. **The PNG assets
bake IBM Plex in — pixel-perfect and truly self-contained; use them in READMEs.**
The SVG masters are clean vector that reference IBM Plex via a `font-family`
stack (system fallback where the family isn't installed) — GitHub strips
`<style>` from SVGs, so fonts are intentionally *not* embedded there; the PNG is
the font-locked artifact. *(The PL marketing site uses Newsreader as a display serif;
it's an optional, self-hostable substitute for a more editorial register, but
IBM Plex is Evidentia's product + CLI face and the recommended default.)*

---

## Logo / wordmark

**Mark:** the hexagonal "layered-strata E" shield. Vector source
`packages/evidentia-ui/public/logo-transparent-background/evidentia-mark-*.svg`
(viewBox `168 × 176`). Ships in `evidentia-mark-{cream,navy,accent}.svg`.

- **Clear space:** keep padding ≥ the width of one internal strata bar (~⅕ of
  mark height) on all sides. In the banner the mark is flanked by a hairline at
  1.6× that distance.
- **Min size:** mark ≥ 24 px; full horizontal banner ≥ 320 px wide; favicon uses
  the square avatar, not the bare mark.
- **Fills:** cream `#ECE0C6` on dark, navy `#12212D` on light, accent `#1D58A5`
  only for standalone/icon use. Never recolor the mark to a severity color.
- **Don't:** add gradients, drop shadows, or the old rounded-square container;
  stretch; rotate; place cream mark on cream.

---

## Banner construction recipe (1280 × 232, ≈ 5.5 : 1)

Layout "Console" (the locked direction). Coordinates in the 1280×232 viewBox:

- **Field:** full-bleed `chrome-bg` (dark) or `background` (light).
- **Accent cap-rule:** 4 px bar along the top edge, `#5196EC` dark / `#1D58A5` light.
- **Mark:** height 134, at `x=74 y=52` (cream on dark, navy on light).
- **Divider:** 1.5 px hairline at `x=248`, `y 66→166`, `chrome-border` / `border`.
- **Wordmark:** "Evidentia", IBM Plex Sans 700, 80 px, letter-spacing −1,
  baseline `x=290 y=122`.
- **Descriptor:** IBM Plex Mono 500, 23 px, baseline `x=293 y=164`,
  `chrome-fg-muted` / `muted-foreground`. Locked text: `compliance-as-code · OSCAL-native`.
- **Never bake in** version numbers, counts, or dates — those live in badges.

Monochrome (1-color) variant: drop the accent cap-rule; render mark, wordmark,
and descriptor in a single ink (`evidentia-banner-mono-{navy,cream}.svg`).
