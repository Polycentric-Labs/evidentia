# Contributing to Evidentia

Thanks for considering a contribution. Evidentia is early-stage and
a small number of focused contributions will make a disproportionate
difference.

Please read [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) before participating.

## High-value contribution areas

Phase 1 is complete and the architecture is stable. The most valuable
places to contribute right now:

1. **Production OSCAL catalogs.** The bundled NIST 800-53 Moderate catalog
   has 16 hand-curated controls for demonstration purposes. Replacing it
   with the full ~323-control NIST OSCAL content repo (or adding the High
   and Rev 5 Full baselines, NIST CSF 2.0, ISO 27001:2022, CIS v8, CMMC 2.0,
   or PCI DSS 4.0) is a drop-in JSON addition to
   `packages/evidentia-core/src/evidentia_core/catalogs/data/`.

2. **Additional crosswalks.** The highest-leverage missing ones are:
   - ISO 27001:2022 ↔ NIST 800-53 Rev 5
   - PCI DSS 4.0 ↔ SOC 2 TSC
   - NIST CSF 2.0 ↔ NIST 800-53 Rev 5
   - CIS Controls v8 ↔ NIST 800-53 Rev 5

   Crosswalks live in
   `packages/evidentia-core/src/evidentia_core/catalogs/data/mappings/`
   as JSON files matching the `CrosswalkDefinition` Pydantic model.

3. **Phase 2 collectors.** AWS, GitHub, and Okta are the highest priority.
   The collector base class and contract are specified in the canonical
   architecture plan; see
   [`Evidentia-Architecture-and-Implementation-Plan.md`](Evidentia-Architecture-and-Implementation-Plan.md).

4. **Test coverage.** Particularly edge cases in CSV header matching,
   OSCAL parsing with unusual catalog structures, and status normalization
   for non-English spreadsheets.

## Development setup

```bash
git clone https://github.com/polycentric-labs/evidentia.git
cd evidentia
uv sync --all-packages
uv run pytest tests/ -q          # expected: full test suite passes (1259+ tests as of v0.7.8)
uv run ruff check .              # expected: All checks passed!
```

Python 3.12+ and [uv](https://docs.astral.sh/uv/) 0.4+ are required.

## Coding conventions

Evidentia follows established style guides, mechanically enforced in CI:

- **Python**: PEP 8 (style), PEP 257 (docstrings), PEP 484 / PEP 604 (type
  hints). Enforced by `ruff` (rule groups E/W/F/I/B/UP/RUF/SIM) + `mypy
  --strict` with the Pydantic plugin. Configuration: [`pyproject.toml`](pyproject.toml).
- **TypeScript** (`packages/evidentia-ui/`): ESLint with the
  `@typescript-eslint/recommended` ruleset + Prettier formatting.
  Configuration: `packages/evidentia-ui/eslint.config.js`.
- **Pre-commit hooks** ([`.pre-commit-config.yaml`](.pre-commit-config.yaml))
  catch most issues before commit-time. Install with `pre-commit install`.

Beyond the style guides:

- **Python 3.12 syntax.** Use `str | None` not `Optional[str]`,
  `list[str]` not `List[str]`, `from datetime import UTC` not
  `timezone.utc`.
- **`from __future__ import annotations`** at the top of every module.
- **Pydantic v2** with
  `ConfigDict(use_enum_values=True, extra="forbid", str_strip_whitespace=True)`.
  Prefer strict validation over permissive parsing.
- **Explicit UTF-8 encoding on every file read.** Windows default
  encoding is cp1252 and will corrupt em-dashes in compliance content.
  Always pass `encoding="utf-8"` to `open()`.
- **Ruff + mypy** are configured in `pyproject.toml`. Run `uv run ruff check .`
  before pushing.
- **Docstrings** on every public class and function. One-line summary,
  blank line, details.
- **No emoji or non-ASCII characters in CLI output** — the Rich console
  must render on Windows cp1252 terminals. Em-dashes and Unicode arrows
  belong in data, not in print statements.

## Pull request checklist

- [ ] Tests pass locally: `uv run pytest tests/ -q`
- [ ] Ruff passes locally: `uv run ruff check .`
- [ ] Any new public class or function has a docstring
- [ ] New features include at least one test
- [ ] New third-party dependencies are justified in the PR description
- [ ] The PR description explains the "why", not just the "what"

## Reporting security issues

**Security issues do not belong in public bug reports.** See
[`SECURITY.md`](SECURITY.md) for the private vulnerability
disclosure process — GitHub Private Vulnerability Reporting is
the preferred channel; email is documented as a backup.

## Reporting bugs and proposing features

Use the GitHub issue templates:

- **Bug report** — for something that doesn't work as documented
- **Feature request** — for new functionality or behavior changes

For questions, use GitHub Discussions rather than issues. For
**security issues, see the section above** — never use the bug
report template for vulnerabilities.

## License

By contributing to Evidentia, you agree that your contributions will be
licensed under the [Apache License 2.0](LICENSE).
