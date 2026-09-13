"""Finite OVAL core result profiles with exact native occurrence preservation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ._contracts import AssessmentProjection, SourceBinding, XmlElement
from ._limits import ScapFailure
from ._native import NativeView
from ._profiles import (
    OVAL_CHARACTERISTICS as S,
)
from ._profiles import (
    OVAL_COMMON as C,
)
from ._profiles import (
    OVAL_DEFINITIONS as D,
)
from ._profiles import (
    OVAL_OUTCOMES,
    SIGNATURE,
    ChildRule,
    ProfileContext,
    invalid_source,
    source_boolean,
    source_integer,
)
from ._profiles import (
    OVAL_RESULTS as R,
)

_RESULTS = "enum:" + "|".join(OVAL_OUTCOMES)
_CLASSES = "enum:compliance|inventory|miscellaneous|patch|vulnerability"
_OPERATORS = "enum:AND|ONE|OR|XOR"
_FLAGS = "enum:error|complete|incomplete|does not exist|not collected|not applicable"
_STATUSES = "enum:error|exists|does not exist|not collected"
_CHECKS = "enum:all|at least one|none exist|none satisfy|only one"
_EXISTENCE = "enum:all_exist|any_exist|at_least_one_exists|none_exist|only_one_exists"
_VERSIONS = {"oval-5.8-core-results": "5.8", "oval-5.11.2-core-results": "5.11.2", "oval-5.12.3-core-results": "5.12.3"}


def _rule(namespace: str, names: str | tuple[str, ...], minimum: int = 0, maximum: int = 32768) -> ChildRule:
    return ChildRule(namespace, (names,) if isinstance(names, str) else names, minimum, maximum)


class _AnyChild(ChildRule):
    def __init__(self) -> None:
        super().__init__("", ())

    def matches(self, node: XmlElement) -> bool:
        return True


def _atom(
    context: ProfileContext,
    index: int,
    required: dict[str, str] | None = None,
    optional: dict[str, str] | None = None,
    *,
    kind: str = "string",
    empty: bool = False,
) -> dict[str, str]:
    attributes = context.attributes(index, {} if required is None else required, optional)
    if empty:
        context.sequence(index, ())
    else:
        context.simple(index, kind)
    return attributes


def _identifier(value: str, kind: str) -> str:
    if re.fullmatch(r"oval:[A-Za-z0-9_.-]+:" + kind + r":[1-9][0-9]*", value) is None:
        raise invalid_source()
    return value


def _key(attributes: dict[str, str], name: str, kind: str) -> tuple[str, str, str]:
    return (_identifier(attributes[name], kind), attributes["version"], attributes.get("variable_instance", "1"))


def _unique(key: tuple[str, str, str], keys: set[tuple[str, str, str]]) -> None:
    if key in keys:
        raise invalid_source()
    keys.add(key)


def _message(context: ProfileContext, index: int) -> None:
    _atom(context, index, optional={"level": "enum:debug|error|fatal|info|warning"})


def _generator(context: ProfileContext, index: int, version: str, owner: int, scope: str) -> None:
    context.attributes(index, {})
    children = context.sequence(
        index,
        (
            _rule(C, "product_name", 0, 1),
            _rule(C, "product_version", 0, 1),
            _rule(C, "schema_version", 1, 1 if version == "5.8" else 32768),
            _rule(C, "timestamp", 1, 1),
            _AnyChild(),
        ),
    )
    core_versions = 0
    scalars: set[str] = set()
    for child in children:
        node = context.view.element(child)
        if node.name.namespace_uri != C:
            continue
        name = node.name.local_name
        if name == "schema_version":
            attributes = _atom(context, child, optional={} if version == "5.8" else {"platform": "uri"})
            if version == "5.8":
                declared = context.simple(child, "decimal")
                if declared != "5.8":
                    raise invalid_source()
            else:
                declared = context.simple(child)
                if re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?(?::[0-9]+\.[0-9]+(?:\.[0-9]+)?)?", declared) is None:
                    raise invalid_source()
                if ("platform" not in attributes and declared != version) or declared.partition(":")[0] != version:
                    raise invalid_source()
            if "platform" not in attributes:
                core_versions += 1
        elif name in ("product_name", "product_version", "timestamp"):
            if name in scalars:
                raise invalid_source()
            scalars.add(name)
            _atom(context, child)
            if name == "timestamp":
                context.time(child, None, owner, scope, "document_compilation")
    if core_versions != 1:
        raise invalid_source()


def _defaulted(context: ProfileContext, index: int, name: str, effective: bool | str) -> dict[str, object]:
    reference = context.view.attribute_ref(index, name)
    return {
        "present": reference is not None,
        "value_ref": None if reference is None else reference.model_dump(),
        "effective_value": effective,
    }


def _directive_rules(
    context: ProfileContext, index: int
) -> tuple[list[dict[str, object]], dict[str, tuple[bool, str]]]:
    names = tuple("definition_" + outcome.replace(" ", "_") for outcome in OVAL_OUTCOMES)
    children = context.sequence(index, tuple(_rule(R, name, 1, 1) for name in names))
    rows: list[dict[str, object]] = []
    values: dict[str, tuple[bool, str]] = {}
    for child, outcome in zip(children, OVAL_OUTCOMES, strict=True):
        attrs = _atom(context, child, {"reported": "boolean"}, {"content": "enum:full|thin"}, empty=True)
        reported, content = source_boolean(attrs["reported"]), attrs.get("content", "full")
        values[outcome] = (reported, content)
        rows.append(
            {
                "node_index": child,
                "outcome": outcome,
                "reported": _defaulted(context, child, "reported", reported),
                "content": _defaulted(context, child, "content", content),
            }
        )
    return rows, values


@dataclass(frozen=True, slots=True)
class _Directives:
    defaults: dict[str, tuple[bool, str]]
    classes: dict[str, dict[str, tuple[bool, str]]]
    any_full: bool


def _directives(context: ProfileContext, index: int, classes: list[int], embedded: int | None) -> _Directives:
    attrs = context.attributes(index, {}, {"include_source_definitions": "boolean"})
    include = source_boolean(attrs.get("include_source_definitions", "true"))
    if include != (embedded is not None):
        raise invalid_source()
    rows, defaults = _directive_rules(context, index)
    class_rows: list[dict[str, object]] = []
    class_values: dict[str, dict[str, tuple[bool, str]]] = {}
    details = {content for reported, content in defaults.values() if reported}
    for child in classes:
        name = context.attributes(child, {"class": _CLASSES})["class"]
        if name in class_values:
            raise invalid_source()
        directives, values = _directive_rules(context, child)
        class_values[name] = values
        details.update(content for reported, content in values.values() if reported)
        class_rows.append(
            {
                "node_index": child,
                "class_ref": context.reference(child, "class").model_dump(),
                "definition_class": name,
                "rules": directives,
            }
        )
    context.directives = {
        "node_index": index,
        "include_source_definitions": _defaulted(context, index, "include_source_definitions", include),
        "embedded_definitions_node_index": embedded,
        "default_rules": rows,
        "class_rules": class_rows,
    }
    context.export_detail = (
        "no_reported_rules" if not details else "mixed" if len(details) == 2 else next(iter(details))
    )
    return _Directives(defaults, class_values, "full" in details)


def _embedded(context: ProfileContext, index: int, version: str) -> None:
    context.attributes(index, {})
    children = context.sequence(index, (_rule(D, "generator", 1, 1), _AnyChild()))
    if len(context.view.children_named(index, D, "generator")) != 1:
        raise invalid_source()
    _generator(context, children[0], version, index, "embedded_definitions")
    if version != "5.8":
        return
    pending: list[int] = []
    for definitions in context.view.children_named(index, D, "definitions"):
        for definition in context.view.children_named(definitions, D, "definition"):
            pending.extend(context.view.children_named(definition, D, "criteria"))
    while pending:
        current = pending.pop()
        context.view.budget.check()
        if context.view.attribute_ref(current, "applicability_check") is not None:
            raise invalid_source()
        if context.view.element(current).name.local_name == "criteria":
            pending.extend(
                child
                for child in context.view.child_elements(current)
                if context.view.element(child).name.namespace_uri == D
                and context.view.element(child).name.local_name in ("criteria", "criterion", "extend_definition")
            )


@dataclass(slots=True)
class _SystemKeys:
    definitions: set[tuple[str, str, str]] = field(default_factory=set)
    tests: set[tuple[str, str, str]] = field(default_factory=set)
    objects: set[tuple[str, str, str]] = field(default_factory=set)
    definition_refs: set[tuple[str, str, str]] = field(default_factory=set)
    test_refs: set[tuple[str, str, str]] = field(default_factory=set)
    item_refs: set[str] = field(default_factory=set)
    items: set[str] = field(default_factory=set)

    def validate(self) -> None:
        if (
            not self.definition_refs <= self.definitions
            or self.tests != self.test_refs
            or not self.item_refs <= self.items
        ):
            raise invalid_source()


def _criteria(context: ProfileContext, index: int, unit: int, version: str, keys: _SystemKeys) -> None:
    pending = [index]
    while pending:
        current = pending.pop()
        name = context.view.element(current).name.local_name
        optional = {"negate": "boolean"}
        if version != "5.8":
            optional["applicability_check"] = "boolean"
        if name == "criteria":
            context.attributes(current, {"operator": _OPERATORS, "result": _RESULTS}, optional)
            children = context.sequence(current, (_rule(R, ("criteria", "criterion", "extend_definition"), 1),))
            pending.extend(reversed(children))
            level = "oval_criteria"
        else:
            is_test = name == "criterion"
            ref = "test_ref" if is_test else "definition_ref"
            optional["variable_instance"] = "nonnegative"
            attrs = _atom(
                context, current, {ref: "string", "version": "nonnegative", "result": _RESULTS}, optional, empty=True
            )
            key = _key(attrs, ref, "tst" if is_test else "def")
            (keys.test_refs if is_test else keys.definition_refs).add(key)
            level = "oval_criterion" if is_test else "oval_extend_definition"
        context.outcome(unit, current, level, context.reference(current, "result"))


def _definition(
    context: ProfileContext, index: int, unit: int, version: str, keys: _SystemKeys, directives: _Directives
) -> None:
    attrs = context.attributes(
        index,
        {"definition_id": "string", "version": "nonnegative", "result": _RESULTS},
        {"variable_instance": "nonnegative", "class": _CLASSES},
    )
    _unique(_key(attrs, "definition_id", "def"), keys.definitions)
    children = context.sequence(index, (_rule(R, "message"), _rule(R, "criteria", 0, 1)))
    context.outcome(unit, index, "oval_definition", context.reference(index, "result"))
    reported, detail = directives.classes.get(attrs.get("class", ""), directives.defaults)[attrs["result"]]
    criteria = context.view.children_named(index, R, "criteria")
    if not reported or bool(criteria) != (detail == "full"):
        raise invalid_source()
    for child in children:
        if context.view.element(child).name.local_name == "message":
            _message(context, child)
        else:
            _criteria(context, child, unit, version, keys)


def _variable(context: ProfileContext, index: int) -> None:
    attrs = _atom(context, index, {"variable_id": "string"})
    _identifier(attrs["variable_id"], "var")


def _test(context: ProfileContext, index: int, unit: int, keys: _SystemKeys) -> None:
    attrs = context.attributes(
        index,
        {"test_id": "string", "version": "nonnegative", "check": _CHECKS, "result": _RESULTS},
        {"variable_instance": "nonnegative", "check_existence": _EXISTENCE, "state_operator": _OPERATORS},
    )
    _unique(_key(attrs, "test_id", "tst"), keys.tests)
    children = context.sequence(index, (_rule(R, "message"), _rule(R, "tested_item"), _rule(R, "tested_variable")))
    context.outcome(unit, index, "oval_test", context.reference(index, "result"))
    for child in children:
        name = context.view.element(child).name.local_name
        if name == "message":
            _message(context, child)
        elif name == "tested_variable":
            _variable(context, child)
        else:
            item = context.attributes(child, {"item_id": "integer", "result": _RESULTS})
            keys.item_refs.add(item["item_id"])
            for message in context.sequence(child, (_rule(R, "message"),)):
                _message(context, message)
            context.outcome(unit, child, "oval_tested_item", context.reference(child, "result"))


def _interface(context: ProfileContext, index: int, unit: int, version: str) -> None:
    context.attributes(index, {})
    rules = [
        _rule(S, "interface_name", 1, 1),
        _rule(S, "ip_address", 0 if version == "5.12.3" else 1, 32768 if version == "5.12.3" else 1),
    ]
    if version == "5.12.3":
        rules.append(_rule(S, "ipv6_address"))
    rules.append(_rule(S, "mac_address", 0 if version == "5.12.3" else 1, 1))
    for child in context.sequence(index, rules):
        name = context.view.element(child).name.local_name
        if name == "ip_address" and version == "5.8":
            attrs = _atom(
                context,
                child,
                optional={"datatype": "enum:string|ipv4_address|ipv6_address", "status": _STATUSES, "mask": "boolean"},
            )
            if unit == context.selected:
                reference = context.view.attribute_ref(child, "status")
                context.core_status.append(
                    {
                        "node_index": child,
                        "present": reference is not None,
                        "value_ref": None if reference is None else reference.model_dump(),
                        "effective_status": attrs.get("status", "exists"),
                        "interpretation": "reviewed_5_8_core_ip_address_status",
                    }
                )
        else:
            _atom(context, child)


def _system_info(context: ProfileContext, index: int, unit: int, version: str) -> None:
    context.attributes(index, {})
    names = ("os_name", "os_version", "architecture", "primary_host_name", "interfaces")
    children = context.sequence(index, (*(_rule(S, name, 1, 1) for name in names), _AnyChild()))
    seen: set[str] = set()
    for child in children:
        node = context.view.element(child)
        name = node.name.local_name
        if node.name.namespace_uri != S or name not in names:
            continue
        if name in seen:
            raise invalid_source()
        seen.add(name)
        if name == "interfaces":
            context.attributes(child, {})
            for interface in context.sequence(child, (_rule(S, "interface"),)):
                _interface(context, interface, unit, version)
        else:
            _atom(context, child)


def _system_data(context: ProfileContext, index: int, unit: int, keys: _SystemKeys) -> None:
    context.attributes(index, {})
    for child in context.sequence(index, (_AnyChild(),)):
        value = context.view.attribute(child, "id", required=True)
        if value is None:
            raise invalid_source()
        key = source_integer(value)
        if key in keys.items:
            raise invalid_source()
        keys.items.add(key)
        if unit != context.selected:
            continue
        for nested in range(child, context.view.subtree_ends[child]):
            if nested % 128 == 0:
                context.view.budget.check()
            if type(context.view.document.nodes[nested]) is not XmlElement:
                continue
            reference = context.view.attribute_ref(nested, "status")
            if reference is not None:
                context.statuses.append(
                    {
                        "node_index": nested,
                        "scope": "direct_system_data_child" if nested == child else "nested_platform_position",
                        "value_ref": reference.model_dump(),
                        "interpretation": "unverified_platform_status",
                        "effective_status": None,
                    }
                )


def _collected_objects(context: ProfileContext, index: int, unit: int, keys: _SystemKeys) -> None:
    context.attributes(index, {})
    for child in context.sequence(index, (_rule(S, "object", 1),)):
        attrs = context.attributes(
            child,
            {"id": "string", "version": "nonnegative", "flag": _FLAGS},
            {"variable_instance": "nonnegative", "comment": "string"},
        )
        _unique(_key(attrs, "id", "obj"), keys.objects)
        if unit == context.selected:
            context.flags.append(
                {
                    "object_node_index": child,
                    "value_ref": context.reference(child, "flag").model_dump(),
                    "native_flag": attrs["flag"],
                }
            )
        for part in context.sequence(child, (_rule(S, "message"), _rule(S, "variable_value"), _rule(S, "reference"))):
            name = context.view.element(part).name.local_name
            if name == "message":
                _message(context, part)
            elif name == "variable_value":
                _variable(context, part)
            else:
                reference = _atom(context, part, {"item_ref": "integer"}, empty=True)
                keys.item_refs.add(reference["item_ref"])


def _characteristics(context: ProfileContext, index: int, unit: int, version: str, keys: _SystemKeys) -> None:
    context.attributes(index, {})
    children = context.sequence(
        index,
        (
            _rule(S, "generator", 1, 1),
            _rule(S, "system_info", 1, 1),
            _rule(S, "collected_objects", 0, 1),
            _rule(S, "system_data", 0, 1),
            _rule(SIGNATURE, "Signature", 0, 1),
        ),
    )
    for child in children:
        node = context.view.element(child)
        if node.name.namespace_uri != S:
            continue
        name = node.name.local_name
        if name == "generator":
            _generator(context, child, version, index, "system_characteristics")
        elif name == "system_info":
            _system_info(context, child, unit, version)
        elif name == "collected_objects":
            _collected_objects(context, child, unit, keys)
        else:
            _system_data(context, child, unit, keys)


def _system(context: ProfileContext, unit: int, version: str, directives: _Directives) -> None:
    context.attributes(unit, {})
    children = context.sequence(
        unit, (_rule(R, "definitions", 0, 1), _rule(R, "tests", 0, 1), _rule(S, "oval_system_characteristics", 1, 1))
    )
    if bool(context.view.children_named(unit, R, "tests")) != directives.any_full:
        raise invalid_source()
    keys = _SystemKeys()
    for child in children:
        node = context.view.element(child)
        if node.name.namespace_uri == S:
            _characteristics(context, child, unit, version, keys)
        elif node.name.local_name == "definitions":
            context.attributes(child, {})
            for definition in context.sequence(child, (_rule(R, "definition", 1),)):
                _definition(context, definition, unit, version, keys, directives)
        else:
            context.attributes(child, {})
            for test in context.sequence(child, (_rule(R, "test", 1),)):
                _test(context, test, unit, keys)
    keys.validate()


def project_oval(view: NativeView, source: SourceBinding, assessment_index: int) -> AssessmentProjection:
    """Validate every interpreted system before returning the selected projection."""
    version = _VERSIONS.get(source.profile)
    if version is None:
        raise ScapFailure("unsupported_profile")
    root = view.element(view.root_index)
    if root.name.namespace_uri != R or root.name.local_name != "oval_results":
        raise invalid_source()
    results = view.children_named(view.root_index, R, "results")
    if len(results) != 1:
        raise invalid_source()
    units = view.children_named(results[0], R, "system")
    context = ProfileContext(view, source, assessment_index, units)
    context.attributes(view.root_index, {})
    children = context.sequence(
        view.root_index,
        (
            _rule(R, "generator", 1, 1),
            _rule(R, "directives", 1, 1),
            _rule(R, "class_directives", 0, 5),
            _rule(D, "oval_definitions", 0, 1),
            _rule(R, "results", 1, 1),
            _rule(SIGNATURE, "Signature", 0, 1),
        ),
    )
    embedded = view.children_named(view.root_index, D, "oval_definitions")
    directives = _directives(
        context,
        children[1],
        view.children_named(view.root_index, R, "class_directives"),
        embedded[0] if embedded else None,
    )
    _generator(context, children[0], version, view.root_index, "document")
    if embedded:
        _embedded(context, embedded[0], version)
    context.attributes(results[0], {})
    context.sequence(results[0], (_rule(R, "system", 1),))
    for unit in units:
        _system(context, unit, version, directives)
    return context.finish()
