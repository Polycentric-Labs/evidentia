# Polycentric Labs — Portable Repo Brand Template

How any PL public repo inherits this system. The **chassis is constant**; each
repo swaps **three things**: its wordmark, its accent, and its descriptor.

---

## The constant chassis (do not change per repo)

- **Field:** deep navy `#0E1B25` (dark) / warm off-white `#FAF9F7` (light).
- **Ink:** cream `#ECE0C6` on dark / navy `#15232E` on light.
- **Type:** IBM Plex Sans (wordmark 700 + body) · IBM Plex Mono (details),
  self-hosted woff2, embedded in shipped SVG (air-gap-safe).
- **Composition:** mark → hairline → wordmark + one-line mono descriptor, on a
  ~5.5 : 1 strip, with a 4 px accent cap-rule. Generous negative space, one
  confident accent, structural restraint. No gradients-as-hero, no animation.
- **Kicker (optional):** `— PRODUCT` in wide-tracked mono accent with a short
  leading rule, mirroring the PL site `.eyebrow`.
- **Badge tiers:** identity → version/CI → standards/security → community
  (see `BADGE-SPEC.md`).

## What each sibling swaps

1. **Wordmark + mark** — the product name and its glyph.
2. **Accent** — one brand color, pulled from that product's `--primary` token
   (Evidentia = `#1D58A5` / `#5196EC`). Recolor: accent cap-rule, kicker,
   identity badges, dashed seal ring, divider center, custom-pill fills.
3. **Descriptor** — one locked, factual line (Evidentia = `compliance-as-code · OSCAL-native`).

Everything else — field, ink, type, spacing, badge tiering, clear-space,
min-sizes, the seal/divider/avatar constructions — stays identical.

## Porting checklist

- [ ] Drop in the new mark SVG (transparent, single-color, `fill=currentColor`-ready).
- [ ] Set the accent hex (light + dark) from the product's `--primary` token.
- [ ] Rebuild banners (light/dark/mono) + PNG fallbacks from the recipe in `BRAND-TOKENS.md`.
- [ ] Recolor identity badges to the accent; keep semantic + provider badges as-is.
- [ ] Regenerate the seal, avatars, divider, and any custom pills with the new mark + accent.
- [ ] Keep the descriptor to one locked line; no versions/counts/dates in art.

Canonical home (decision pending per the brief): a `Polycentric-Labs/brand`
repo, or a `docs/brand/` seed copied into each repo. This folder is that seed.
