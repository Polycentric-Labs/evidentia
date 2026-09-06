"""`evidentia.yaml` project-config loader.

v0.4.0 moves this module from ``evidentia.config`` to
``evidentia_core.config`` so both the CLI meta-package
(``evidentia``) and the API backend (``evidentia-api``) can
consume it without inducing a circular dependency.

A transparent re-export shim remains at the old import path for backward
compatibility with external library consumers; internal callers have
been updated to the canonical location.

Honored schema (unchanged from v0.2.1):

- ``organization`` / ``system_name`` — override inventory metadata
  (matches ``gap analyze --organization`` / ``--system-name``)
- ``frameworks`` (list) — default framework set for ``gap analyze``
  when ``--frameworks`` is omitted
- ``llm.model`` / ``llm.temperature`` — default LLM settings for
  ``risk generate`` (flag > ``EVIDENTIA_LLM_*`` env vars > yaml > built-in)

Precedence for every honored value: **CLI flag > env var (where applicable)
> yaml > built-in default**.

Values support ``${ENV_VAR}`` interpolation so users can reference
``.env``-supplied secrets without committing plaintext.
"""

from __future__ import annotations

import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

logger = logging.getLogger(__name__)

CONFIG_FILENAME = "evidentia.yaml"
"""Filename looked up by ``find_config_file()``."""

_ENV_VAR_PATTERN = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")


class LLMConfig(BaseModel):
    """LLM defaults honored by ``evidentia risk generate``."""

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    model: str | None = Field(
        default=None,
        description=(
            "Default LLM model name (e.g. 'claude-sonnet-4-6'). Overridden by --model or $EVIDENTIA_LLM_MODEL."
        ),
    )
    temperature: float | None = Field(
        default=None,
        description="Default LLM temperature. Overridden by $EVIDENTIA_LLM_TEMPERATURE.",
        ge=0.0,
        le=2.0,
    )


class EvidentiaConfig(BaseModel):
    """Validated shape of ``evidentia.yaml``.

    Uses ``extra='allow'`` so legacy v0.2.0 keys (``storage``, ``logging``,
    ``version``) don't trigger validation errors. Only the keys below are
    consulted by CLI code.
    """

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    organization: str | None = Field(
        default=None,
        description=(
            "Organization name — seeds `gap analyze`'s inventory.organization when the inventory file lacks one."
        ),
    )
    system_name: str | None = Field(
        default=None,
        description="System / product name surfaced in reports alongside organization.",
    )
    frameworks: list[str] = Field(
        default_factory=list,
        description="Default framework IDs for `gap analyze` when --frameworks is omitted. CLI replaces, never unions.",
    )
    llm: LLMConfig = Field(
        default_factory=LLMConfig,
        description="LLM defaults for `risk generate`.",
    )

    # Path to the source YAML file (populated by load_config), for diagnostics.
    source_path: Path | None = Field(default=None, exclude=True, description="Source file path (internal).")

    @field_validator("frameworks", mode="before")
    @classmethod
    def _coerce_frameworks(cls, v: Any) -> list[str]:
        """Accept the v0.2.0 legacy shape ``frameworks: {default: [...]}``.

        Emits a deprecation warning so users know to flatten to top-level
        ``frameworks: [...]`` in v0.3.0+.
        """
        if isinstance(v, dict) and "default" in v:
            import warnings

            warnings.warn(
                "Legacy `frameworks.default` key in evidentia.yaml is "
                "deprecated; flatten to top-level `frameworks: [...]`. "
                "v0.5.0 will drop this alias.",
                DeprecationWarning,
                stacklevel=2,
            )
            return list(v.get("default", []))
        if v is None:
            return []
        return list(v)

    @model_validator(mode="after")
    def _warn_on_large_framework_set(self) -> EvidentiaConfig:
        """Emit a runtime warning if > 5 frameworks are configured.

        Large multi-framework analyses can be slow; users who accidentally
        configure 10 frameworks often complain about run time. Better to
        nudge at config-load than at analyze-time.
        """
        if len(self.frameworks) > 5:
            import warnings

            warnings.warn(
                f"evidentia.yaml lists {len(self.frameworks)} frameworks "
                "in `frameworks:` — large analyses can be slow. Consider "
                "narrowing the default set or using CLI `--frameworks` for "
                "ad-hoc scans.",
                UserWarning,
                stacklevel=2,
            )
        return self


def _expand_env_vars(value: Any) -> Any:
    """Recursively substitute ``${VAR}`` in strings within nested dicts/lists."""
    if isinstance(value, str):
        return _ENV_VAR_PATTERN.sub(lambda m: os.environ.get(m.group(1), m.group(0)), value)
    if isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env_vars(item) for item in value]
    return value


def find_config_file(start: Path | None = None, stop_at: Path | None = None) -> Path | None:
    """Walk upward from ``start`` (default: CWD) looking for ``evidentia.yaml``.

    Returns the first match found, or ``None`` if none exists between
    ``start`` and the filesystem root.

    ``stop_at`` bounds the upward walk: when set, no directory *above*
    ``stop_at`` is searched (``stop_at`` itself is still checked). This
    is primarily a test-isolation hook — pytest's tmp dirs live under
    ``$HOME``, so an unbounded walk can pick up a stray ``~/evidentia.yaml``
    from a developer's environment. Default ``None`` preserves the
    walk-to-filesystem-root behavior.
    """
    current = (start or Path.cwd()).resolve()
    boundary = stop_at.resolve() if stop_at is not None else None
    for candidate in [current, *current.parents]:
        cfg_path = candidate / CONFIG_FILENAME
        if cfg_path.is_file():
            return cfg_path
        if boundary is not None and candidate == boundary:
            break
    return None


@lru_cache(maxsize=4)
def _load_config_cached(path: Path) -> EvidentiaConfig:
    """Parse a specific config file path (cached for repeated loads)."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must contain a YAML mapping at the top level")
    raw = _expand_env_vars(raw)
    cfg = EvidentiaConfig.model_validate(raw)
    cfg.source_path = path
    return cfg


def load_config(path: Path | None = None) -> EvidentiaConfig:
    """Load and validate a ``evidentia.yaml`` file.

    If ``path`` is None, runs :func:`find_config_file` from CWD. If no
    config file is found, returns a default-constructed config (all
    optional fields None / empty).
    """
    resolved = path or find_config_file()
    if resolved is None:
        return EvidentiaConfig()
    return _load_config_cached(resolved)


def get_default(
    config: EvidentiaConfig,
    cli_value: Any,
    yaml_path: str,
    env_var: str | None = None,
    builtin_default: Any = None,
) -> Any:
    """Resolve a config value per the documented precedence.

    Precedence: ``cli_value`` (if truthy) > env var > yaml path > builtin
    default. Truthiness of ``cli_value`` is computed with ``bool()``, so
    empty strings and empty lists correctly fall through to the next
    layer.

    ``yaml_path`` is a dotted path like ``"llm.model"`` — traverses nested
    attributes on :class:`EvidentiaConfig`.
    """
    if cli_value:
        return cli_value
    if env_var is not None:
        env_val = os.environ.get(env_var)
        if env_val:
            return env_val
    # Walk dotted path on the config object
    cursor: Any = config
    for segment in yaml_path.split("."):
        cursor = getattr(cursor, segment, None)
        if cursor is None:
            break
    if cursor:
        return cursor
    return builtin_default
