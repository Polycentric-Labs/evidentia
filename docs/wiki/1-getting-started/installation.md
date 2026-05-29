# Installation

Evidentia ships as a family of PyPI packages plus a cosign-signed container
image. The `evidentia` meta-package pulls in the CLI and every core subsystem;
optional extras add the web UI, the MCP server, cloud-WORM backends, and
signing/interop dependencies. This page covers each install path, the extras
matrix, the container image, the air-gapped pattern, and the most common
install failures.

## Prerequisites

- Python 3.12 or newer (`python --version` to check). Evidentia targets 3.12+
  and is tested against the current CPython releases.
- A virtual environment is strongly recommended (`python -m venv .venv` then
  activate it) so Evidentia's dependencies do not collide with system packages.

## Step 1 — Install from PyPI

The simplest path installs the meta-package, which gives you the `evidentia`
(and `cb` alias) command-line tool plus gap analysis, collectors, risk
statements, and OSCAL emit:

```bash
pip install evidentia
```

Verify the install:

```bash
evidentia version
# → Evidentia v0.10.6 / Python 3.12.x
```

If `evidentia` is not found on your PATH after install, your environment's
`Scripts/` (Windows) or `bin/` (POSIX) directory is not active — re-activate
your virtualenv, or invoke it as `python -m evidentia.cli.main`.

## Step 2 — (Optional) install extras

Extras are slim by default: the base install excludes the web UI, the MCP
server, the cloud SDKs, and the heavier crypto/interop dependencies so a plain
`pip install evidentia` stays small. Add only what you need.

| Extra | Install | What it adds |
| --- | --- | --- |
| `gui` | `pip install "evidentia[gui]"` | The FastAPI server + bundled React SPA. Then run `evidentia serve`. |
| `mcp` | `pip install "evidentia[mcp]"` | The Model Context Protocol server (`evidentia mcp serve`) for AI clients. |
| `worm-s3` | `pip install "evidentia[worm-s3]"` | AWS S3 Object Lock WORM backend (pulls `boto3`). |
| `worm-azure` | `pip install "evidentia[worm-azure]"` | Azure Immutable Blob WORM backend. |
| `worm-gcs` | `pip install "evidentia[worm-gcs]"` | GCS Bucket Lock WORM backend. |

Some capabilities live on the `evidentia-core` package and are installed by
extras on *that* distribution:

| Extra | Install | What it adds |
| --- | --- | --- |
| `sigstore` | `pip install "evidentia-core[sigstore]"` | Sigstore/Rekor keyless signing (`--sign-with-sigstore`). Not air-gap compatible. |
| `ocsf` | `pip install "evidentia-core[ocsf]"` | OCSF Compliance/Detection Finding interop (the `ocsf` / `ocsf-detection` formats + `evidentia collect ocsf`). |
| `xlsx` | `pip install "evidentia-core[xlsx]"` | Excel (`.xlsx`) output/ingest for the TPRM due-diligence questionnaire generator. |

You can combine extras: `pip install "evidentia[gui,mcp]" "evidentia-core[sigstore,ocsf]"`.

## Step 3 — (Alternative) install with uv

If you use [uv](https://docs.astral.sh/uv/), add Evidentia to a project:

```bash
uv add evidentia
```

Or install it as a standalone tool (isolated environment, on your PATH):

```bash
uv tool install evidentia
# with extras:
uv tool install "evidentia[gui]"
```

## Step 4 — (Alternative) run the container image

Every release publishes a cosign-signed multi-arch image to GitHub Container
Registry:

```bash
docker pull ghcr.io/polycentric-labs/evidentia:v0.10.6
docker run --rm ghcr.io/polycentric-labs/evidentia:v0.10.6 version
# → Evidentia v0.10.6 / Python 3.12.x
```

To run a gap analysis against a local inventory, mount your working directory:

```bash
docker run --rm -v "$PWD:/work" -w /work \
  ghcr.io/polycentric-labs/evidentia:v0.10.6 \
  gap analyze --inventory my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate --output gap-report.json
```

The image is keyless-signed via Fulcio + Rekor. Verify it before you trust it:

```bash
cosign verify ghcr.io/polycentric-labs/evidentia:v0.10.6 \
  --certificate-identity-regexp 'https://github\.com/Polycentric-Labs/evidentia/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# → "The cosign claims were validated"
```

Full artifact-verification recipes (wheel PEP 740 attestations, SBOM, SLSA
provenance) live in [Project → Verification](../6-project/verification.md).

## Air-gapped installation

For offline/disconnected environments, pre-stage the wheels in a local
wheelhouse on a connected host and transfer them across the air gap, then
install with `--no-index`. The full offline pattern — wheelhouse build, offline
catalog handling, and the GPG-only signing fallback when Fulcio/Rekor are
unreachable — is documented in [Guides → Air-gapped install](../2-guides/air-gapped-install.md).

## What's next

- [Quickstart](quickstart.md) — from a fresh install to your first OSCAL
  Assessment Results in five minutes.
- [First collection](first-collection.md) — wire your first evidence collector
  end-to-end.

## Troubleshooting

- **`evidentia: command not found`** — the install succeeded but the scripts
  directory is not on your PATH. Re-activate your virtualenv, or run
  `python -m evidentia.cli.main version`.
- **`ERROR: ... requires a different Python`** — Evidentia needs Python 3.12+.
  Check `python --version`; create a 3.12 virtualenv if your system Python is
  older.
- **`No module named 'sigstore'` when signing** — `--sign-with-sigstore` needs
  the `[sigstore]` extra: `pip install "evidentia-core[sigstore]"`. In
  air-gapped environments use `--sign-with-gpg` instead (Sigstore needs network
  access to Fulcio + Rekor).
- **`No module named 'py_ocsf_models'` on an OCSF format** — install the
  `[ocsf]` extra: `pip install "evidentia-core[ocsf]"`.
- **Resolver conflicts** — install into a clean virtualenv. Evidentia pins
  inter-package versions tightly (e.g. `evidentia-core>=0.10.6,<0.11.0`); mixing
  partial upgrades across the package family can produce unsatisfiable
  resolutions. Upgrade the whole family together: `pip install -U evidentia`.
- **Still stuck?** See the [FAQ](../6-project/faq.md) or open a
  [discussion](https://github.com/Polycentric-Labs/evidentia/discussions).
