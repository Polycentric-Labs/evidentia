# Dockerfile dependency pinning policy

> Status (v0.8.4): **G4 PATH 2 ACTIVATED — supply-chain hardening
> complete.** release.yml regenerates `docker/requirements.txt`
> against PyPI's just-published wheels between Wait-for-PyPI step
> + docker build step. Both pip-compile + the docker build's
> `pip install --require-hashes` run inside the same Linux runner
> against the same PyPI bytes → hashes match by construction.
> Cross-platform reproducibility no longer required. Closes the
> recurring Scorecard PinnedDependencies false-positive cycle
> (alerts #100 → #116 across v0.7.12 → v0.8.3.1) structurally +
> permanently. The historical v0.8.3 Path 1 attempt + v0.8.3.1
> revert narrative is preserved below for context.

## v0.8.4 G4 Path 2 activation (current)

The Dockerfile install line reads:

```dockerfile
COPY docker/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --user --require-hashes \
                -r /tmp/requirements.txt
```

The release-time regeneration pipeline:

1. **release.yml `publish-pypi` job** publishes 7 wheels to PyPI
   with PEP 740 attestations (unchanged from v0.7.0+).
2. **Wait-for-PyPI step** confirms all 7 packages propagated +
   appear in PyPI's simple index.
3. **NEW: Regenerate hash-pinned requirements.txt against PyPI**
   step (added in v0.8.4):
   - Overwrites `docker/requirements.in` to pin
     `evidentia[gui]==<release-version>` (the just-published
     version).
   - Runs `pip install -q pip-tools && pip-compile
     --generate-hashes --no-emit-find-links --output-file=
     docker/requirements.txt docker/requirements.in`.
   - Retry loop (3 attempts × 30s sleeps) catches CDN
     propagation lag between PyPI's index endpoint + the wheel
     files themselves.
4. **Build and push image** step copies the freshly-regenerated
   `docker/requirements.txt` into the container build context;
   `pip install --require-hashes` resolves evidentia[gui] from
   PyPI + verifies the hashes match.

### Why Path 2 works where Path 1 didn't

**Path 1 (v0.8.3 attempted + reverted)**: SOURCE_DATE_EPOCH-
driven `uv build` was supposed to make local pre-tag pip-compile
hash output match release.yml's CI-built wheels. Verified WITHIN
a platform (Windows-to-Windows: 7 wheels matched byte-for-byte).
But uv build is NOT byte-identical across host platforms
(Windows local vs Linux CI runner) even with same
SOURCE_DATE_EPOCH. The pre-tag locally-generated requirements.txt
had Windows-build hashes; CI uploaded Linux-build wheels with
different hashes; pip's `--require-hashes` install failed.

**Path 2 (v0.8.4 active)**: pip-compile runs INSIDE the GitHub
Actions Linux runner AFTER PyPI publish. It downloads the
just-published wheels from PyPI + computes SHA256 of the
downloaded bytes. The container's pip install then downloads
THE SAME wheels from PyPI + verifies the same hashes. Both
pip-compile + pip install run in the same Linux environment
against the same PyPI bytes — there's no cross-platform gap to
bridge.

The committed `docker/requirements.txt` ships as preview state
(operators can inspect it pre-tag for audit purposes). The
release-time regenerated file is what actually gets baked into
the container; the committed file is overwritten ephemerally
inside the workflow filesystem.

### Verification

```bash
# Post-tag: the release pipeline run shows the regen step + the
# subsequent successful container build
gh run list --branch main --workflow release --limit 1

# Pull the image + verify it ran the hash-pinned install
docker pull ghcr.io/polycentric-labs/evidentia:vX.Y.Z
docker run --rm ghcr.io/polycentric-labs/evidentia:vX.Y.Z version
# → "Evidentia vX.Y.Z"
```

### Scorecard impact

PinnedDependencies score moves from 9/10 → **10/10** at the
v0.8.4 ship-time Scorecard scan + STAYS at 10/10 across
subsequent releases. The recurring alert pattern
(#100/#101/#102/#103/#107/#108/#113/#114/#115/#116) does not
re-fire because the Dockerfile line no longer matches the
alert pattern's regex.

### Local regeneration (operator-facing)

The `bump_version.py --regenerate-requirements` script (v0.7.14
P1.5 + v0.8.2 + v0.8.3 evolution) still works for local
inspection / audit / experimentation. It uses uv build with
SOURCE_DATE_EPOCH for reproducible local wheels, then pip-compile
against `--find-links=./dist/` for the local-wheel hashes. The
output is intentionally NOT what release.yml uploads to PyPI
(different platform → different bytes → different hashes); use
the locally-regenerated file for understanding the dep tree
shape, not for CI hash matching.

For the actual release-time hash matching, release.yml does the
work itself (Path 2 above). Operators tagging a release just
need:

```bash
# Bump version (no --regenerate-requirements required for G4 Path 2)
./scripts/bump_version.py --to X.Y.Z
git add -p && git commit -m "chore(release): bump to X.Y.Z"
git tag vX.Y.Z && git push origin main vX.Y.Z
# release.yml does the rest, including requirements.txt regen
```

## v0.8.3.1 hot-fix narrative — Path 1 attempted + reverted (preserved for context)

> Why this section exists: the v0.8.3 release attempted G4 Path 1
> (SOURCE_DATE_EPOCH-driven reproducible builds). It failed at
> first-fire. v0.8.3.1 hot-fix reverted to exact-version pinning.
> v0.8.4 ships Path 2 instead. Section preserved so future
> readers can understand why the source-tree contains
> SOURCE_DATE_EPOCH machinery in release.yml + bump_version.py
> that's no longer the canonical hash-matching path (it remains
> as reproducibility-verification infrastructure, separately
> useful from `--require-hashes`).

The v0.8.3 release attempted G4 activation via SOURCE_DATE_EPOCH-
driven reproducible builds (Path 1) but the container build
first-fire FAILED at the `--require-hashes` install: uv build
is NOT byte-identical across host platforms (Windows local
regeneration vs Linux CI build runner) even with the same
SOURCE_DATE_EPOCH. PyPI publish at v0.8.3 succeeded; container
build failed; no `ghcr.io/polycentric-labs/evidentia:v0.8.3` image
was published. v0.8.3.1 hot-fix reverts the Dockerfile install
line to the v0.8.2 pattern (`evidentia[gui]==X.Y.Z` exact-
version pinning) for one cycle while v0.8.4 designs Path 2.

What did NOT work in v0.8.3:

- Cross-platform reproducibility of `uv build` — Windows local
  + Linux CI produce different wheel bytes even with same
  SOURCE_DATE_EPOCH. The pip-compile-driven hash generation
  was Windows-host-specific; CI's Linux build couldn't match.
- This is a uv / hatchling / Python wheel-format limitation,
  not specific to Evidentia. Other projects targeting full
  reproducibility either (a) build on a single canonical
  platform, or (b) accept post-publish regeneration of the
  hash file from PyPI's actual bytes (which is exactly what
  v0.8.4 G4 Path 2 does).

## Historical narrative (v0.7.13 → v0.8.3.1; preserved for context)

The `Dockerfile` at the repo root used to pin the `evidentia[gui]`
install to the exact current release version (e.g.,
`evidentia[gui]==0.7.12`), **not** a full hash-pinned requirements
file. This was a deliberate trade-off rather than an oversight.

**Regeneration**: `scripts/bump_version.py --regenerate-requirements
--to A.B.C` updates the pin in `requirements.in` + invokes
`pip-compile`. Run inside the pinned base-image
(`python:3.14-slim@sha256:...`) so platform-specific transitives
(uvloop, etc.) resolve correctly:

```bash
docker run --rm -v "$PWD/docker:/work" -w /work \
  python:3.14-slim@sha256:<base-digest> \
  sh -c "pip install -q pip-tools && pip-compile --generate-hashes \
    --output-file=requirements.txt requirements.in"
```

**Verification**: `docker build -t evidentia:test .` succeeds; the
pip install run inside the build emits the standard
`Successfully installed ...` lines for every package in the
hash-pinned set. A tampered transitive surfaces as
`THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE`
+ build failure.

**Scorecard impact**: PinnedDependencies score expected to move from
9/10 → 10/10 on the next scan. The recurring alert pattern
(#100/#101/#102/#103/#107/#108) does not re-fire because the
Dockerfile line no longer matches the alert pattern's regex.

## Historical narrative (v0.7.13 → v0.8.1; preserved for context)

The `Dockerfile` at the repo root used to pin the `evidentia[gui]`
install to the exact current release version (e.g.
`evidentia[gui]==0.7.12`), **not** a full hash-pinned requirements
file. This was a deliberate trade-off rather than an oversight.

## Why exact-version, not hash-pinning

OpenSSF Scorecard's
[`Pinned-Dependencies`](https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies)
check rates `pip install --require-hashes -r requirements.txt` (with
hashes for every transitive dep) as the "fully pinned" target. It
flags exact-version-only installs as partially pinned (score 9/10 in
practice on this repo).

For Evidentia today the trade-off lands on exact-version because:

1. **PEP 740 attestations cover the integrity story.** Every wheel
   pushed to PyPI from this repo carries a Sigstore-signed PEP 740
   publish attestation. The release-pipeline OIDC binding
   (`polycentric-labs/evidentia/release.yml@refs/tags/v*`) is verifiable via
   `pypi-attestations verify pypi`. A compromised mirror cannot serve
   a tampered `evidentia==0.7.12` wheel without the verification
   failing.
2. **Transitive-hash maintenance burden.** A hash-pinned
   `requirements.txt` covering the full transitive closure (~140
   packages at v0.7.12) needs regeneration on every dependency bump
   from any of the 6 inter-package wheels — multiple times per
   release cycle. Without tooling that regenerates atomically with
   `bump_version.py`, the file rots within days.
3. **Container image already carries an end-to-end signature.** The
   image is cosign-signed (keyless OIDC) at
   `ghcr.io/polycentric-labs/evidentia:vX.Y.Z` and carries a SLSA L3 build
   provenance attestation against its `sha256:` digest. Operators
   verifying the image digest are already confirming that the
   `pip install` produced the expected bytes inside this specific
   immutable image.

## Roadmap to full hash-pinning (v0.8.0+)

The v0.8.0 plan reserves G4 (reproducible-build verification — build
twice + `sha256sum dist/*` match). The complementary supply-chain
work that lands alongside is full hash-pinning of the Dockerfile
install:

1. Add a generated `docker/requirements.txt` to the repo, produced by
   `pip-compile --generate-hashes` against `evidentia[gui]==X.Y.Z`
   resolved against the pinned base-image's Python.
2. Wire `scripts/bump_version.py` to regenerate the file atomically
   on every release that touches inter-package pins or the Dockerfile.
3. Switch the Dockerfile `RUN pip install` to
   `pip install --require-hashes -r /tmp/requirements.txt`.
4. Verify Scorecard's `Pinned-Dependencies` score moves from 9/10 to
   10/10 + the Code Scanning alert auto-closes.

This change is non-trivial because of the multi-package workspace —
each release touches 6 wheels and their transitive trees. Folding it
into G4's reproducible-build work keeps the verification scope
coherent.

### v0.7.14 P1.5 preview state (2026-05-05)

Steps 1 + 2 above LANDED in v0.7.14:

- **`docker/requirements.txt`** is generated via
  `pip-compile --generate-hashes` against `evidentia[gui]==0.7.13`
  (and bumped on each release via `bump_version.py
  --regenerate-requirements`). 80 packages × 2-N SHA256 hashes per
  package (~2200 lines). Inspectable for operators planning their
  own hash-pinned image builds.
- **`scripts/bump_version.py`** has a new `--regenerate-requirements`
  flag that calls `pip-compile` after the version-bump
  substitutions. Default OFF so routine bumps don't re-resolve
  the transitive closure unless explicitly requested.

Steps 3 + 4 stay deferred to v0.8.0 G4. The v0.7.14 Dockerfile
`RUN pip install --no-cache-dir --user "evidentia[gui]==X.Y.Z"`
line is unchanged. Operators wanting to validate the hash-pin
locally can run:

```bash
docker run --rm -v "$PWD/docker/requirements.txt:/tmp/req.txt" \
  python:3.14-slim \
  pip install --require-hashes -r /tmp/req.txt --dry-run
```

If the dry-run succeeds, the official Dockerfile switch in v0.8.0
G4 will work.

**Why preview vs. ship**: switching the production Dockerfile install
to `--require-hashes` requires that the file format be validated
across all 6 cloud-WORM extras + the [gui] extra + future v0.8.0
extras. v0.7.14 ships the [gui]-only file as the canonical test
case; v0.8.0 G4 validates the full extras matrix + flips the
Dockerfile install line.

## What to do when the alert re-fires

Each release that bumps the Dockerfile line (`==0.7.12` →
`==0.7.13`) creates a new SARIF location fingerprint on the next
Scorecard scan. The dismissal of the prior alert ID does not carry
forward to the new ID; a fresh alert is created.

Per-release closeout (during `/pre-release-review` Step 7
post-tag verification):

1. Confirm only the recurring Dockerfile alert is open, not a new
   real finding. Run:
   ```
   gh api repos/polycentric-labs/evidentia/code-scanning/alerts \
     -q '[.[] | select(.state=="open")] | .[] | {number, file: .most_recent_instance.location.path, line: .most_recent_instance.location.start_line, rule: .rule.id}'
   ```
   Expected: one entry pointing at `Dockerfile` line 62 with rule
   `PinnedDependenciesID`.
2. Surface the dismissal command to Allen for explicit per-action
   approval (publishing-authority gated). Sample command:
   ```
   gh api -X PATCH repos/polycentric-labs/evidentia/code-scanning/alerts/<N> \
     -F state=dismissed \
     -F dismissed_reason="won't fix" \
     -F dismissed_comment="Recurring Scorecard PinnedDependencies false-positive on Dockerfile pip install. See docs/dockerfile-pinning.md. Full hash-pinning deferred to v0.8.0+."
   ```
3. After dismissal, verify CodeQL alert count returns to 0 open.

## References

- OpenSSF Scorecard checks:
  https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies
- PEP 740 attestation verification:
  https://peps.python.org/pep-0740/
- v0.8.0 reproducible-build target: see `docs/v0.8.0-plan.md` G4
