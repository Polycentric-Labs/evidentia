# Dockerfile dependency pinning policy

> Status (v0.8.2): **STRUCTURAL FOUNDATION LANDED; ACTIVATION
> DEFERRED to v0.8.3.** The hash-pinned `docker/requirements.txt`
> regeneration tooling is in place (`bump_version.py
> --regenerate-requirements`) + the file is regenerated at every
> version bump. The Dockerfile install line activation
> (`--require-hashes -r /tmp/requirements.txt`) is deferred per
> §25.6 R1 because release.yml's `uv build` is not byte-identical
> across build hosts (no SOURCE_DATE_EPOCH wired yet), so the
> SHA256 hashes computed pre-tag don't match what release.yml
> uploads to PyPI. v0.8.3 closes this via either build-time
> reproducibility OR a release-pipeline-integrated regeneration
> step. The historical narrative below is preserved for context.

## v0.8.2 G4 deferred-activation status

The Dockerfile install line currently reads:

```dockerfile
RUN pip install --no-cache-dir --user "evidentia[gui]==0.8.2"
```

The structural foundation IS in place:

- `docker/requirements.in` pins `evidentia[gui]==0.8.2`
- `docker/requirements.txt` is regenerated against the v0.8.2 dep
  tree (~140 transitive deps with SHA256 hashes per platform tag)
  via `pip-compile --generate-hashes`
- `scripts/bump_version.py --regenerate-requirements` wraps
  `pip-compile` invocation atomically with the version bump

When the v0.8.3 cycle adds release-pipeline support for hash-
pin alignment (see "v0.8.3 closure plan" below), flipping the
Dockerfile install line is a single-line change.

## v0.8.3 closure plan

Two equivalent paths under evaluation:

1. **SOURCE_DATE_EPOCH-driven reproducible builds**: set
   `SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)` in
   release.yml before `uv build` so the wheels' embedded
   timestamps are derived from the tag, not the build host's
   clock. Local builds at the same tagged commit produce
   byte-identical wheels → byte-identical SHA256 hashes →
   pre-tag-generated requirements.txt's hashes match PyPI's
   published wheels.
2. **Post-PyPI regeneration**: add a release.yml step in the
   `publish-container` job that runs after Wait-for-PyPI but
   before `docker build`. The step regenerates
   `docker/requirements.txt` against PyPI's just-published
   X.Y.Z wheels via `pip-compile`. The repo stays at the
   pre-tag requirements.txt; the container build uses the
   freshly-regenerated file ephemerally.

Path 1 is more invasive but cleaner long-term (the same
reproducible-builds work pays dividends across other supply-
chain assertions). Path 2 is a smaller release.yml change
that ships the activation immediately. v0.8.3 plan-mode
session decides which path to land.

## Historical narrative (v0.7.13 → v0.8.1; preserved for context)

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
   (`allenfbyrd/evidentia/release.yml@refs/tags/v*`) is verifiable via
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
   `ghcr.io/allenfbyrd/evidentia:vX.Y.Z` and carries a SLSA L3 build
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
   gh api repos/allenfbyrd/evidentia/code-scanning/alerts \
     -q '[.[] | select(.state=="open")] | .[] | {number, file: .most_recent_instance.location.path, line: .most_recent_instance.location.start_line, rule: .rule.id}'
   ```
   Expected: one entry pointing at `Dockerfile` line 62 with rule
   `PinnedDependenciesID`.
2. Surface the dismissal command to Allen for explicit per-action
   approval (publishing-authority gated). Sample command:
   ```
   gh api -X PATCH repos/allenfbyrd/evidentia/code-scanning/alerts/<N> \
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
