# This project was renamed: ControlBridge → Evidentia

**Rename effective:** April 2026 (v0.6.0 release).
**Old name:** ControlBridge
**New name:** Evidentia
**New repo:** `github.com/polycentric-labs/evidentia` (same URL tree; see "Redirect behaviour" below)

## Why we renamed

The name `ControlBridge` collided with **controlbridge.ai**, a live commercial
SOX 302/404 compliance platform for internal audit and finance teams. Both
products operate in the same category (GRC / compliance automation) and
target overlapping audiences (compliance officers, CFOs, audit committees).
Using an identical name in an overlapping market created:

- **Trademark exposure** — US trademark law protects marks based on first use
  in commerce. Common-law rights to "ControlBridge" in the GRC space belong
  to controlbridge.ai regardless of USPTO registration status.
- **SEO and buyer confusion** — Google for "ControlBridge" already routes to
  the commercial site. Users hearing about the project by name would land
  on the wrong product first.
- **Irreversible friction if we waited** — v0.5.0 shipped with an install
  base of ~0 external users. Renaming today costs ~2 days of mechanical
  refactoring; renaming later would cost downstream breakage, reputational
  ambiguity, and potentially a cease-and-desist letter.

## Migration for users

```bash
# uninstall the old packages
pip uninstall -y controlbridge controlbridge-core controlbridge-ai \
                 controlbridge-api controlbridge-collectors \
                 controlbridge-integrations

# install the new ones
pip install evidentia
# or, with the web UI extras:
pip install "evidentia[gui]"
```

Rewrite imports:

```python
# before
from controlbridge_core.models.gap import Gap
from controlbridge_integrations.jira import JiraClient

# after
from evidentia_core.models.gap import Gap
from evidentia_integrations.jira import JiraClient
```

Rewrite CLI invocations:

```bash
# before
controlbridge gap analyze --framework nist-800-53-rev5-moderate
# after
evidentia gap analyze --framework nist-800-53-rev5-moderate

# the `cb` short alias remains available under the new package.
cb gap analyze --framework nist-800-53-rev5-moderate
```

## Deprecation shims

If you can't migrate immediately, the six old PyPI package names remain
installable as v0.5.1 re-export shims that forward every import to the
new `evidentia-*` equivalents and emit a `DeprecationWarning`:

```bash
pip install controlbridge-core==0.5.1   # emits deprecation warning; works
```

The shims will be **yanked from PyPI in v0.7.0** (~October 2026). Plan to
migrate within 6 months.

## Redirect behaviour

The old GitHub repo URL `github.com/allenfbyrd/controlbridge` is
**permanently redirected** to the new repo (GitHub's built-in
repository-rename mechanism). Every existing bookmark, blog-post link,
resume citation, and `git clone https://github.com/allenfbyrd/controlbridge.git`
invocation continues to work. The redirect covers:

- Repo home, `/tree/main/*`, `/blob/*`, `/releases`, `/releases/tag/vN`
- Issue and PR URLs: `/issues/N`, `/pull/N`
- Raw content: `raw.githubusercontent.com/allenfbyrd/controlbridge/...`
- Git remotes: `git clone`, `git fetch`, `git push`

**The only way this redirect breaks** is if a new repository is ever created
at `github.com/allenfbyrd/controlbridge` (or `github.com/allenfbyrd/controlbridge-action`).
We won't. Both names are permanently retired.

## Historical note on PyPI packages

The v0.1.0 – v0.5.0 PyPI releases of `controlbridge`, `controlbridge-core`,
`controlbridge-ai`, `controlbridge-api`, `controlbridge-collectors`, and
`controlbridge-integrations` remain available for installation and will not
be retroactively modified. Project pages on PyPI are updated with a
"DEPRECATED — renamed to evidentia-*" notice.

## Git history

All prior commits, tags (`v0.1.0` through `v0.5.0`, `v0.4.0-alpha.1`), and
GitHub Releases are preserved under the new repo. Rename operations use
`git mv` so file history flows unbroken into the Evidentia namespace.

## Questions

File an issue at `github.com/polycentric-labs/evidentia/issues` with the label
`rename-question`.
