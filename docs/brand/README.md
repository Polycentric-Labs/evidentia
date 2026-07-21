# Evidentia Brand Kit

Committed, air-gap-safe brand assets for Evidentia and its Polycentric Labs
sibling repos. The **PNG** files are the pixel-perfect primary (IBM Plex baked
in, no network); the **SVG** files are clean vector masters (no external refs)
whose text uses an IBM Plex `font-family` stack — use the PNG in READMEs, since
GitHub renders SVG `<text>` in a fallback face. Accent = federal blue `#1D58A5` / `#5196EC`
(the `--primary` token; see `BADGE-SPEC.md` for the "teal" naming flag).

## Banners (≈ 5.5 : 1, 1280 × 232)
| File | Use |
|---|---|
| `evidentia-banner-light.svg` / `.png` | README banner, light theme |
| `evidentia-banner-dark.svg` / `.png` | README banner, dark theme (`<picture>` pair) |
| `evidentia-banner-mono-navy.svg` | 1-color fallback, cream ink on navy |
| `evidentia-banner-mono-cream.svg` | 1-color fallback, navy ink on cream |

## Social / OG (raster, 2400 × 1260)
| File | Use |
|---|---|
| `evidentia-og-dark.png` | GitHub social preview (Settings → Social preview) |
| `evidentia-og-light.png` | light-context link unfurls |

## Mark, avatars & lockups
| File | Use |
|---|---|
| `evidentia-mark-{cream,navy,accent}.svg` | bare hexagon-strata mark |
| `evidentia-avatar-square.svg` / `.png` | app icon / rounded-square (favicon-safe) |
| `evidentia-avatar-round-navy.svg` / `.png` | org avatar, navy |
| `evidentia-avatar-round-light.svg` / `.png` | org avatar, light + accent ring |
| `evidentia-lockup-{light,dark}.svg` | compact mark + wordmark for nav / bios |

## Seals & dividers
| File | Use |
|---|---|
| `evidentia-seal-light.svg` | compliance seal, navy ink (light surfaces) |
| `evidentia-seal-navy.svg` | compliance seal, cream ink (dark surfaces) |
| `evidentia-divider-{light,dark}.svg` | mark-centered section rule |
| `evidentia-divider-wave-{light,dark}.svg` | strata-wave section rule |

## Custom badge pills (static SVG)
`pill-oscal-native.svg` · `pill-air-gap-ready.svg` · `pill-sigstore-signed.svg`
· `pill-slsa-provenance.svg`

## Docs
- **`BRAND-TOKENS.md`** — palette, type, logo usage, banner recipe (the portable sheet)
- **`BADGE-SPEC.md`** — badge tiers, order, colors, recoloring reference
- **`PL-REPO-BRAND-TEMPLATE.md`** — how sibling repos inherit (swap wordmark + accent)
- **`README-PLACEMENT.md`** — how to place the banner + badge tiers (guidance, not the README)

*Fonts: IBM Plex Sans + IBM Plex Mono, self-hosted from
`packages/evidentia-ui/public/fonts/`. Regenerate rasters/recolors from the
recipe in `BRAND-TOKENS.md`.*
