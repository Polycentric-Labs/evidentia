"""Source-bound XCCDF 1.2 result validation and assessment selection."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ._contracts import AssessmentProjection, SourceBinding, XmlElement
from ._limits import ScapFailure
from ._native import NativeView
from ._profiles import XCCDF, XCCDF_OUTCOMES, ChildRule, ProfileContext, invalid_source, source_type

_CPE_LANGUAGE = "http://cpe.mitre.org/language/2.0"
_OUTCOMES = "enum:" + "|".join(XCCDF_OUTCOMES)


@dataclass(frozen=True, slots=True)
class _References:
    rules: frozenset[str]
    values: frozenset[str]
    substitutions: frozenset[str]
    sets: frozenset[str]


class _XccdfContext(ProfileContext):
    def __init__(self, view: NativeView, source: SourceBinding, assessment_index: int, units: list[int]) -> None:
        super().__init__(view, source, assessment_index, units)
        self.check_ids: set[str] = set()
        self.xml_ids: set[str] = set()

    def unique(self, value: str | None, keys: set[str]) -> None:
        if value is not None:
            if value in keys:
                raise invalid_source()
            keys.add(value)


def _rule(names: str | tuple[str, ...], minimum: int = 0, maximum: int = 32768) -> ChildRule:
    return ChildRule(XCCDF, (names,) if isinstance(names, str) else names, minimum, maximum)


_RESULT_CHILDREN = (
    _rule("benchmark", 0, 1),
    _rule("tailoring-file", 0, 1),
    _rule("title"),
    _rule("remark"),
    _rule("organization"),
    _rule("identity", 0, 1),
    _rule("profile", 0, 1),
    _rule("target", 1),
    _rule("target-address"),
    _rule("target-facts", 0, 1),
    _rule("target-id-ref"),
    ChildRule(XCCDF, (), foreign=True),
    _rule("platform"),
    _rule(("set-value", "set-complex-value")),
    _rule("rule-result"),
    _rule("score", 1),
    _rule("metadata"),
    _rule("signature", 0, 1),
)
_RULE_CHILDREN = (
    _rule("result", 1, 1),
    _rule("override"),
    _rule("ident"),
    _rule("metadata"),
    _rule("message"),
    _rule("instance"),
    _rule("fix"),
    _rule(("check", "complex-check")),
)
_BENCHMARK_CHILDREN = (
    _rule("status", 1),
    _rule("dc-status"),
    _rule("title"),
    _rule("description"),
    _rule("notice"),
    _rule("front-matter"),
    _rule("rear-matter"),
    _rule("reference"),
    _rule("plain-text"),
    ChildRule(_CPE_LANGUAGE, ("platform-specification",), 0, 1),
    _rule("platform"),
    _rule("version", 1, 1),
    _rule("metadata"),
    _rule("model"),
    _rule("Profile"),
    _rule("Value"),
    _rule(("Group", "Rule")),
    _rule("TestResult", 1),
    _rule("signature", 0, 1),
)


def _atom(
    context: _XccdfContext,
    index: int,
    required: dict[str, str] | None = None,
    optional: dict[str, str] | None = None,
    *,
    kind: str = "string",
    empty: bool = False,
    xml: tuple[str, ...] = (),
    foreign: bool = False,
) -> dict[str, str]:
    attributes = context.attributes(index, {} if required is None else required, optional, xml=xml, foreign=foreign)
    if empty:
        context.sequence(index, ())
    else:
        context.simple(index, kind)
    return attributes


def _identifier(value: str, kind: str) -> str:
    value = source_type(value, "ncname")
    if re.fullmatch("xccdf_[^_]+_" + kind + "_.+", value) is None:
        raise invalid_source()
    return value


def _times(context: _XccdfContext, index: int, unit: int, roles: dict[str, str]) -> None:
    for attribute in context.view.element(index).attributes:
        if not attribute.name.namespace_uri and attribute.name.local_name in roles:
            context.time(
                index,
                attribute.name.local_name,
                index,
                "selected_assessment",
                roles[attribute.name.local_name],
                retain=unit == context.selected,
            )


def _check(context: _XccdfContext, index: int, references: _References | None) -> None:
    pending = [index]
    while pending:
        current = pending.pop()
        node = context.view.element(current)
        if node.name.local_name == "complex-check":
            context.attributes(current, {"operator": "enum:AND|OR"}, {"negate": "boolean"})
            children = context.sequence(current, (_rule(("check", "complex-check"), 1),))
            pending.extend(reversed(children))
            continue
        attributes = context.attributes(
            current,
            {"system": "uri"},
            {"negate": "boolean", "id": "ncname", "selector": "string", "multi-check": "boolean"},
            xml=("base",),
        )
        context.unique(attributes.get("id"), context.check_ids)
        children = context.sequence(
            current,
            (
                _rule("check-import"),
                _rule("check-export"),
                _rule("check-content-ref"),
                _rule("check-content", 0, 1),
            ),
        )
        if not children:
            raise invalid_source()
        for child in children:
            name = context.view.element(child).name.local_name
            if name == "check-import":
                context.attributes(child, {"import-name": "string"}, {"import-xpath": "string"})
                if len(context.view.child_elements(child)) > 1:
                    raise invalid_source()
            elif name == "check-export":
                attributes = _atom(context, child, {"value-id": "ncname", "export-name": "string"}, empty=True)
                if references is not None and attributes["value-id"] not in references.values:
                    raise invalid_source()
            elif name == "check-content-ref":
                _atom(context, child, {"href": "uri"}, {"name": "string"}, empty=True)
            else:
                context.attributes(child, {})
                if any(
                    context.view.element(n).name.namespace_uri in ("", XCCDF)
                    for n in context.view.child_elements(child)
                ):
                    raise invalid_source()
                # The check body is retained as opaque source, including any markup.
                context.interpreted.discard(child)


def _fix(context: _XccdfContext, index: int, references: _References | None) -> None:
    context.attributes(
        index,
        {},
        {
            "id": "ncname",
            "reboot": "boolean",
            "strategy": "enum:unknown|configure|combination|disable|enable|patch|policy|restrict|update",
            "disruption": "enum:unknown|low|medium|high",
            "complexity": "enum:unknown|low|medium|high",
            "system": "uri",
            "platform": "uri",
        },
    )
    for child in context.view.child_elements(index):
        node = context.view.element(child)
        if node.name.namespace_uri != XCCDF or node.name.local_name not in ("sub", "instance"):
            raise invalid_source()
        if node.name.local_name == "sub":
            attributes = _atom(context, child, {"idref": "ncname"}, {"use": "enum:value|title"}, empty=True)
            if references is not None and attributes["idref"] not in references.substitutions:
                raise invalid_source()
        else:
            _atom(context, child, optional={"context": "string"}, empty=True)
    # Fix instructions and substitutions remain source data, with no execution.
    context.interpreted.discard(index)


def _rule_result(context: _XccdfContext, index: int, unit: int, references: _References | None) -> None:
    attributes = context.attributes(
        index,
        {"idref": "ncname"},
        {
            "role": "enum:full|unscored|unchecked",
            "severity": "enum:unknown|info|low|medium|high",
            "time": "string",
            "version": "string",
            "weight": "weight",
        },
    )
    if "weight" in attributes and (
        len(attributes["weight"].replace(".", "").lstrip("0")) > 3 or len(attributes["weight"].partition(".")[2]) > 3
    ):
        raise invalid_source()
    if references is not None and attributes["idref"] not in references.rules:
        raise invalid_source()
    _times(context, index, unit, {"time": "rule_completion"})
    children = context.sequence(index, _RULE_CHILDREN)
    checks = [child for child in children if context.view.element(child).name.local_name in ("check", "complex-check")]
    if any(context.view.element(child).name.local_name == "complex-check" for child in checks) and len(checks) != 1:
        raise invalid_source()
    contexts: set[str] = set()
    parents: list[str] = []
    result = children[0]
    _atom(context, result, kind=_OUTCOMES)
    reported_result = context.view.simple_content(result)
    context.outcome(unit, index, "xccdf_rule_result", context.reference(result))
    for child in children[1:]:
        name = context.view.element(child).name.local_name
        if name == "override":
            context.attributes(child, {"time": "string", "authority": "string"})
            _times(context, child, unit, {"time": "override_time"})
            parts = context.sequence(
                child, (_rule("old-result", 1, 1), _rule("new-result", 1, 1), _rule("remark", 1, 1))
            )
            for part in parts[:2]:
                _atom(context, part, kind=_OUTCOMES)
            old, new = (context.view.simple_content(part) for part in parts[:2])
            if old != new and reported_result != new:
                raise invalid_source()
            _atom(context, parts[2], optional={"override": "boolean"}, xml=("lang",))
        elif name == "ident":
            _atom(context, child, {"system": "uri"}, foreign=True)
        elif name == "message":
            _atom(context, child, {"severity": "enum:error|warning|info"})
        elif name == "instance":
            attrs = _atom(context, child, optional={"context": "string", "parentContext": "string"})
            key = attrs.get("context", "undefined")
            if key in contexts:
                raise invalid_source()
            contexts.add(key)
            if "parentContext" in attrs:
                parents.append(attrs["parentContext"])
        elif name == "fix":
            _fix(context, child, references)
        elif name in ("check", "complex-check"):
            _check(context, child, references)
    if any(parent not in contexts for parent in parents):
        raise invalid_source()


def _test_result(
    context: _XccdfContext,
    index: int,
    *,
    standalone: bool,
    result_ids: set[str],
    references: _References | None,
) -> None:
    attributes = context.attributes(
        index,
        {"id": "ncname", "end-time": "string"},
        {
            "start-time": "string",
            "test-system": "string",
            "version": "string",
            "Id": "ncname",
        },
    )
    identifier = _identifier(attributes["id"], "testresult")
    if identifier in result_ids:
        raise invalid_source()
    result_ids.add(identifier)
    context.unique(attributes.get("Id"), context.xml_ids)
    _times(context, index, index, {"start-time": "assessment_start", "end-time": "assessment_completion"})
    # The one source choice permits target-id-ref and foreign children to interleave.
    children = context.view.child_elements(index)
    choice = [
        child
        for child in children
        if context.view.element(child).name.namespace_uri != XCCDF
        or context.view.element(child).name.local_name == "target-id-ref"
    ]
    if choice:
        first, last = children.index(choice[0]), children.index(choice[-1])
        if children[first : last + 1] != choice:
            raise invalid_source()
        # One explicit choice rule admits both arms without imposing an arm order.
        rules = list(_RESULT_CHILDREN)
        rules[10:12] = [_TargetChoiceRule()]
    else:
        rules = list(_RESULT_CHILDREN)
    context.sequence(index, rules)
    benchmarks = context.view.children_named(index, XCCDF, "benchmark")
    if standalone and not benchmarks:
        raise invalid_source()
    for child in children:
        node = context.view.element(child)
        if node.name.namespace_uri != XCCDF:
            continue
        name = node.name.local_name
        if name == "benchmark":
            _atom(context, child, {"href": "uri"}, {"id": "ncname"}, empty=True)
        elif name == "tailoring-file":
            _atom(context, child, {"href": "uri", "id": "ncname", "version": "string", "time": "string"}, empty=True)
            _times(context, child, index, {"time": "tailoring_version_time"})
        elif name in ("title", "remark"):
            _atom(context, child, optional={"override": "boolean"}, xml=("lang",))
        elif name in ("organization", "target", "target-address"):
            _atom(context, child)
        elif name == "identity":
            _atom(context, child, {"authenticated": "boolean", "privileged": "boolean"})
        elif name == "profile":
            _atom(context, child, {"idref": "ncname"}, empty=True)
        elif name == "target-facts":
            context.attributes(child, {})
            for fact in context.sequence(child, (_rule("fact"),)):
                _atom(context, fact, {"name": "uri"}, {"type": "enum:number|string|boolean"})
        elif name == "target-id-ref":
            _atom(context, child, {"system": "uri", "href": "string"}, {"name": "string"}, empty=True)
        elif name == "platform":
            _atom(context, child, {"idref": "string"}, empty=True)
        elif name == "set-value":
            attrs = _atom(context, child, {"idref": "ncname"})
            if references is not None and attrs["idref"] not in references.sets:
                raise invalid_source()
        elif name == "set-complex-value":
            attrs = context.attributes(child, {"idref": "ncname"})
            if references is not None and attrs["idref"] not in references.sets:
                raise invalid_source()
            for item in context.sequence(child, (_rule("item"),)):
                _atom(context, item)
        elif name == "rule-result":
            _rule_result(context, child, index, references)
        elif name == "score":
            _atom(context, child, optional={"system": "uri", "maximum": "decimal"}, kind="decimal")


class _TargetChoiceRule(ChildRule):
    def __init__(self) -> None:
        super().__init__(XCCDF, ("target-id-ref",))

    def matches(self, node: XmlElement) -> bool:
        return super().matches(node) or node.name.namespace_uri not in ("", XCCDF)


def _benchmark(context: _XccdfContext, index: int) -> _References:
    attributes = context.attributes(
        index,
        {"id": "ncname"},
        {"Id": "ncname", "resolved": "boolean", "style": "string", "style-href": "uri"},
        xml=("lang",),
    )
    _identifier(attributes["id"], "benchmark")
    context.unique(attributes.get("Id"), context.xml_ids)
    children = context.sequence(index, _BENCHMARK_CHILDREN)
    rule_ids: set[str] = set()
    value_ids: set[str] = set()
    text_ids: set[str] = set()
    value_clusters: set[str] = set()
    item_ids: set[str] = set()
    pending = list(reversed(children))
    while pending:
        child = pending.pop()
        node = context.view.element(child)
        if node.name.namespace_uri != XCCDF:
            continue
        name = node.name.local_name
        if name == "plain-text" and context.view.parents[child] != index:
            continue
        if name in ("Group", "Rule", "Value", "plain-text"):
            identifier = context.view.attribute(child, "id", required=True)
            if identifier is None:
                raise invalid_source()
            identifier = (
                source_type(identifier, "ncname") if name == "plain-text" else _identifier(identifier, name.lower())
            )
            if identifier in item_ids:
                raise invalid_source()
            item_ids.add(identifier)
            if name == "Rule":
                rule_ids.add(identifier)
            elif name == "Value":
                value_ids.add(identifier)
                cluster = context.view.attribute(child, "cluster-id")
                if cluster is not None:
                    value_clusters.add(source_type(cluster, "ncname"))
            elif name == "plain-text":
                text_ids.add(identifier)
            if name == "Group":
                pending.extend(reversed(context.view.child_elements(child)))
    version = context.view.children_named(index, XCCDF, "version")[0]
    _atom(context, version, optional={"time": "string", "update": "uri"})
    if context.view.attribute_ref(version, "time") is not None:
        context.time(version, "time", version, "document", "tailoring_version_time", retain=False)
    return _References(
        frozenset(rule_ids),
        frozenset(value_ids),
        frozenset(value_ids | text_ids),
        frozenset(value_ids | value_clusters),
    )


def project_xccdf(view: NativeView, source: SourceBinding, assessment_index: int) -> AssessmentProjection:
    """Validate the complete declared profile before projecting one occurrence."""
    if source.profile != "xccdf-1.2-results":
        raise ScapFailure("unsupported_profile")
    root = view.element(view.root_index)
    if root.name.namespace_uri != XCCDF or root.name.local_name not in ("Benchmark", "TestResult"):
        raise invalid_source()
    standalone = root.name.local_name == "TestResult"
    units = [view.root_index] if standalone else view.children_named(view.root_index, XCCDF, "TestResult")
    context = _XccdfContext(view, source, assessment_index, units)
    references = None if standalone else _benchmark(context, view.root_index)
    result_ids: set[str] = set()
    for unit in units:
        _test_result(context, unit, standalone=standalone, result_ids=result_ids, references=references)
    return context.finish()
