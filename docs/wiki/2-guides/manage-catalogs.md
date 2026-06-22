# Browse and manage framework catalogs

A *catalog* is the machine-readable copy of a compliance framework — its
controls, families, and cross-framework mappings — that every other Evidentia
verb resolves against. Most catalogs ship **bundled** with the package; you can
also **import** your own (a licensed ISO 27001 copy, an internal control set, an
OSCAL profile you have resolved) into a local user directory, where it *shadows*
the bundled copy of the same id. This guide walks the day-to-day catalog
operations with the `evidentia catalog` commands and their web-console
equivalents.

For the conceptual model — bundled-vs-user resolution, tiers, shadowing, the
crosswalk graph — see [Concepts → Catalog engine](../3-concepts/catalog-engine.md).
For the per-framework id / tier / license table, see
[Reference → Catalogs](../4-reference/catalogs.md). This guide is the *how-to*; it
does not duplicate either.

## Prerequisites

- A working Evidentia install (`evidentia catalog list` should print a table).
- For the web-console steps, the UI running: `evidentia serve` (needs the `[gui]`
  extra) — see [Serve the local web UI](serve-the-web-ui.md).
- To import a licensed framework, the catalog document itself — a JSON (or YAML)
  control catalog, or an OSCAL profile + source catalog pair.
- On Windows, if a `catalog` command crashes with a `UnicodeEncodeError` (some
  catalog names carry Unicode cp1252 can't print), set the encoding first:
  `$env:PYTHONIOENCODING = "utf-8"` in PowerShell, or `export
  PYTHONIOENCODING=utf-8` in bash.

## Step 1 — List what is registered

```bash
evidentia catalog list
```

The table shows every catalog Evidentia can resolve: its **Framework ID** (the
id every other verb takes), **Name**, **Tier** (A–D redistribution tier),
**Category**, control count, **Source** (`bundled` or `user`), and whether it
loaded. Narrow the list with the filters:

```bash
evidentia catalog list --tier=A
evidentia catalog list --category=control
evidentia catalog list --bundled-only
evidentia catalog list --user-only
```

`--tier` takes one of `A`, `B`, `C`, `D`; `--category` takes one of `control`,
`technique`, `vulnerability`, `obligation`. `--bundled-only` and `--user-only`
restrict the list to packaged catalogs or your own imports respectively.

## Step 2 — Inspect a framework's controls

```bash
evidentia catalog show nist-800-53-mod
```

`show` takes the framework id as a positional argument and lists its controls.
Drill into a single control with `--control` (`-c`):

```bash
evidentia catalog show nist-800-53-mod --control=AC-2
```

The control id is format-sensitive — use it exactly as it appears in the catalog
(`AC-2`, not `ac2`).

## Step 3 — See where a framework resolves from

When a user import and a bundled catalog share an id, the user copy wins
(*shadowing*). `where` tells you which one is active and where it lives on disk:

```bash
evidentia catalog where nist-800-53-mod
```

It reports the **Source** (`bundled` or `user`), the on-disk **Path**, the
**Tier**, the **Category**, and whether the entry is a placeholder. Use it to
confirm an import took effect (Source flips to `user`) or to find the file a
catalog is loading from. An unknown id is reported as not found.

## Step 4 — Check a framework's license terms

Redistributable control text is tiered; some frameworks require a license to
ship their full text. `license-info` surfaces that metadata:

```bash
evidentia catalog license-info iso-27001
```

It prints the tier, the redistribution license / terms, and the source URL so
you can confirm whether you may redistribute a catalog before you import or share
it. See [Reference → Catalogs](../4-reference/catalogs.md) for the full tier
policy.

## Step 5 — Resolve a cross-framework crosswalk

A crosswalk answers "this control in framework A — what does it map to in
framework B?". All three flags are required:

```bash
evidentia catalog crosswalk --source=nist-800-53 --target=soc2-tsc --control=AC-2
```

`--source` (`-s`), `--target` (`-t`), and `--control` (`-c`) name the source
framework, target framework, and the source control id. A control with no
mapping is a successful zero-result, not an error — Evidentia tells you no
mappings were found rather than failing.

## Step 6 — Import your own catalog

`import` registers a user catalog into your local catalog directory. Because a
user import **shadows** a bundled catalog with the same `framework_id`, importing
a licensed ISO 27001 copy makes it the active catalog for every subsequent
`catalog show`, `gap analyze`, etc. There are three modes.

**Direct JSON** — import a catalog file as-is (the `framework_id` is read from the
file):

```bash
evidentia catalog import ./my-iso27001.json
```

**OSCAL profile** — resolve an OSCAL profile against its source catalog and import
the result. This block uses backslash line-continuation, so it is shell-specific:

**Bash / Linux / macOS**

```bash
evidentia catalog import \
  --profile profile.json \
  --catalog source.json \
  --framework-id my-baseline \
  --tier C
```

**PowerShell (Windows)**

```powershell
evidentia catalog import `
  --profile profile.json `
  --catalog source.json `
  --framework-id my-baseline `
  --tier C
```

**Replace a bundled stub** — override the id and force past an existing import:

```bash
evidentia catalog import --framework-id=soc2-tsc ./my-tsc.json --force
```

Useful flags:

- `--framework-id` — override the `framework_id` in the file (it becomes
  authoritative for the on-disk filename and the manifest entry).
- `--name` — override the human-readable framework name.
- `--license-terms` — your statement about the content's source and licensing.
- `--tier` — redistribution tier of the imported content (`A`/`B`/`C`/`D`,
  default `C`).
- `--force` — overwrite an existing **user** import with the same id (bundled
  catalogs are never overwritten on disk; the import shadows them instead).
- `--catalog-dir` — override the user catalog directory (also honored via the
  `EVIDENTIA_CATALOG_DIR` environment variable).

After importing, confirm it is now the active copy:

```bash
evidentia catalog where soc2-tsc
```

The Source should read `user`.

## Step 7 — Remove a user import

```bash
evidentia catalog remove my-baseline
```

`remove` deletes a **user-imported** framework only — bundled catalogs are never
touched, and removing one of them (or an unknown id) reports that there is no
user import to remove. Removing a shadowing import re-exposes the bundled catalog
underneath. The command prompts for confirmation; skip it with `--yes` (`-y`):

```bash
evidentia catalog remove my-baseline --yes
```

`remove` also accepts `--catalog-dir` to target a non-default user catalog
directory.

## Managing catalogs in the web console

Everything above — except the read-only `list` / `show` browse, which lives on
the **Frameworks** browser (`/frameworks`) — also has a home in the browser.
Start the server with `evidentia serve` and open the **Catalog** screen (route
`/catalog`) from the sidebar. It is the **write / management** surface for the
catalog store, organized as five independent form cards, each backed by one
catalog API endpoint:

1. **Crosswalk lookup.** Enter a **Source framework**, a **Target framework**, and
   a **Control id**, then **Look up crosswalk**. The card renders the resolved
   mapping rows, or a "no mappings" empty state — the same result as
   `catalog crosswalk`. It calls `GET /api/catalog/crosswalk`.
2. **Where.** Enter a **Framework id** and click **Where** to see the Source
   (bundled vs user), on-disk Path, whether the catalog is Shadowed, and its
   Tier — the `catalog where` view. It calls `GET /api/catalog/where`.
3. **License info.** Enter a **Framework id** and click **License info** for the
   License, Tier, and URL — the `catalog license-info` view. It calls
   `GET /api/catalog/license-info/{id}`.
4. **Import.** Provide a **Framework id** (required) and the **Catalog content**
   pasted inline (required), pick a **Format** (JSON / YAML) and **Tier** (A–D),
   optionally set **Name** / **License terms** / **Force**, then **Import
   catalog**. The content is sent **inline** — the console never asks the server
   to read a file off disk — so this is the browser-safe equivalent of `catalog
   import`. It calls `POST /api/catalog/import` (requires the **write** role); a
   malformed or duplicate import returns a 400 the card surfaces inline.
5. **Remove.** Enter a **Framework id**, tick the confirmation checkbox (the
   destructive **Remove catalog** button stays disabled until you do), and
   confirm. It calls `DELETE /api/catalog/{id}` (requires the **admin** role); a
   missing user import returns 404 ("nothing to remove, or it is a bundled
   catalog that can't be removed").

A successful import or removal refreshes the **Frameworks** browser so the new
resolution shows up immediately.

> **RBAC note.** The CLI carries no role checks. The HTTP surface adds them on the
> two mutating verbs — `import` needs the `write` role and `remove` needs `admin`.
> Under the default permissive policy (no `EVIDENTIA_RBAC_POLICY_FILE` set) every
> caller is treated as admin, so an unconfigured local server behaves exactly like
> the CLI.

## What's next

- **How resolution, tiers, and shadowing work**:
  [Concepts → Catalog engine](../3-concepts/catalog-engine.md).
- **The per-framework id / tier / license table**:
  [Reference → Catalogs](../4-reference/catalogs.md).
- **Put a catalog to work**: [Run a gap analysis](run-gap-analysis.md) measures
  your posture against any registered framework.
- **Explain a control in plain English**:
  [Explaining a control](explain-controls.md).

## Got stuck?

- **"Unknown framework …"** — the id is not registered. Run
  `evidentia catalog list` to see the exact ids (the **Framework ID** column),
  and remember ids are kebab-case (`nist-800-53-mod`, not `NIST 800-53`).
- **An import did not take effect** — confirm it landed with
  `evidentia catalog where <id>`; the Source should read `user`. If a same-id
  user import already exists, re-run `catalog import` with `--force`.
- **"A user-imported … already exists; set force=true to overwrite"** (console
  400, or the CLI's overwrite refusal) — pass `--force` on the CLI, or tick the
  **Force** checkbox in the console.
- **`catalog remove` says there is nothing to remove** — only user imports can be
  removed; bundled catalogs are never touched. Check `catalog where <id>` reports
  Source `user` before removing.
- **A `catalog` command crashes with `UnicodeEncodeError` on Windows** — set
  `$env:PYTHONIOENCODING = "utf-8"` (PowerShell) before re-running.
