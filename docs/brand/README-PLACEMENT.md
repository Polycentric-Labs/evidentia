# README placement note (guidance — not the README markdown)

*The repo team assembles the actual `README.md`. This is guidance only; all
prose, claims, values, and URLs stay exactly as they are today. Flair is
image-borne, so the `readme_size_guard` (≤ 11,000 bytes) still holds — re-check
with `wc -c README.md` after assembly.*

**Placement, top of README, centered:**

1. **Banner** via `<picture>` so GitHub swaps light/dark automatically. Commit
   the assets to a shipping path (`docs/brand/` or `.github/assets/`), not `.local/`.
2. **One-line pitch** — the existing bold README line, unchanged.
3. **Tier 1** identity badges (`for-the-badge`), then **Tiers 2–4** status
   badges (flat), each tier its own centered row. See `BADGE-SPEC.md` for order.

Illustrative structure only (fill with your locked URLs/paths):

```html
<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/brand/evidentia-banner-dark.png">
  <img alt="Evidentia — compliance-as-code, OSCAL-native"
       src="docs/brand/evidentia-banner-light.png" width="820">
</picture>

<!-- existing one-line pitch, unchanged -->
<!-- Tier 1: Get Started · Documentation · PyPI  (for-the-badge) -->
<!-- Tier 2: pypi · tests · codecov · CLI↔GUI parity -->
<!-- Tier 3: python · license · OpenSSF Best Practices · OpenSSF Scorecard -->
<!-- Tier 4: Contributor Covenant -->

</div>
```

Notes: use the **`.png`** banners in the README — they bake in IBM Plex and
render identically everywhere (GitHub renders SVG `<text>` in a fallback face
and strips SVG `<style>`, so PNG is the font-locked choice). The `.svg` files
are clean, scalable vector masters for editing/print. The GitHub **social preview** image (repo Settings → Social preview)
must be raster — use `evidentia-og-dark.png` (2400×1260). Owned domains only in
any link (`demo.evidentiagrc.com`); never a vendor-preview URL.
