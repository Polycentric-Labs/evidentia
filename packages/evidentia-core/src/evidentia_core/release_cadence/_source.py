"""Literal selected source facts under the pinned public GitHub profile."""

from __future__ import annotations

import re
from typing import cast

from ._json import canonical_bytes, detach
from ._limits import MAX_SAFE_INTEGER, PAGE_BYTES, SELECTED_BYTES, Budget, ReleaseFailure, text_value

SELECTED_FIELDS = (
    "id",
    "node_id",
    "url",
    "html_url",
    "tag_name",
    "target_commitish",
    "name",
    "draft",
    "prerelease",
    "immutable",
    "created_at",
    "published_at",
    "updated_at",
)
OPTIONAL_FIELDS = frozenset(("immutable", "updated_at"))
REQUIRED_FIELDS = frozenset(SELECTED_FIELDS) - OPTIONAL_FIELDS
_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+")


def canonical_repository(owner: object, repository: object) -> tuple[str, str]:
    native_owner = text_value(owner, 39, minimum=1)
    native_repository = text_value(repository, 100, minimum=1)
    if (
        _OWNER.fullmatch(native_owner) is None
        or _REPOSITORY.fullmatch(native_repository) is None
        or native_repository in (".", "..")
        or native_repository.lower().endswith(".git")
    ):
        raise ReleaseFailure()
    return native_owner.lower(), native_repository.lower()


def selected_facts(value: object, *, budget: Budget | None = None) -> dict[str, object]:
    # Native testing ingress permits acyclic aliases; this never lends caller data.
    native = detach(value, 6 * PAGE_BYTES, budget=budget, allow_aliases=True)
    if type(native) is not dict:
        raise ReleaseFailure("source_field")
    mapping = cast(dict[str, object], native)
    if not REQUIRED_FIELDS.issubset(mapping):
        raise ReleaseFailure("source_field")
    selected: dict[str, object] = {}
    for name in SELECTED_FIELDS:
        if name not in mapping:
            continue
        item = mapping[name]
        if name == "id":
            if type(item) is not int or not 1 <= cast(int, item) <= MAX_SAFE_INTEGER:
                raise ReleaseFailure("source_field")
        elif name in ("draft", "prerelease", "immutable"):
            if type(item) is not bool:
                raise ReleaseFailure("source_field")
        elif item is None and name in ("name", "published_at", "updated_at"):
            pass
        else:
            try:
                text_value(item, 128 if name in ("created_at", "published_at", "updated_at") else 16_384)
            except ReleaseFailure:
                raise ReleaseFailure("source_field") from None
        selected[name] = item
    try:
        canonical_bytes(selected, SELECTED_BYTES, budget=budget)
    except ReleaseFailure as error:
        if error.reason == "result_limit_exceeded":
            raise ReleaseFailure("selected_limit") from None
        raise
    return selected
