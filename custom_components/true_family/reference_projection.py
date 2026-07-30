"""Typed semantic entity-reference projection for migration documents."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from jinja2 import Environment, TemplateSyntaxError, nodes
from jinja2.visitor import NodeVisitor


PathPart = str | int
ReferencePath = tuple[PathPart, ...]

_ENTITY_TOKEN_PATTERN = re.compile(
    r"(?<![a-z0-9_])(?=(?P<entity>[a-z0-9_]+\.[a-z0-9_]+)"
    r"(?![a-z0-9_]))"
)
_JINJA_ENVIRONMENT = Environment(autoescape=False)
_REPLACEABLE_JINJA_HELPERS = frozenset(
    {"states", "state_attr", "is_state", "is_state_attr", "has_value"}
)
_NONREPLACEABLE_ENTITY_HELPERS = frozenset(
    {
        "area_devices",
        "area_entities",
        "area_id",
        "area_name",
        "closest",
        "config_entry_attr",
        "config_entry_id",
        "device_attr",
        "device_entities",
        "device_id",
        "device_name",
        "distance",
        "expand",
        "floor_areas",
        "floor_id",
        "floor_name",
        "integration_entities",
        "label_areas",
        "label_devices",
        "label_entities",
        "label_id",
        "label_name",
    }
)
_ENTITY_JINJA_HELPERS = (
    _REPLACEABLE_JINJA_HELPERS | _NONREPLACEABLE_ENTITY_HELPERS
)
_SAFE_JINJA_FILTERS = frozenset({"abs", "bool", "default", "float", "int", "round"})
_SOURCE_HELPER_PATTERN = re.compile(
    r"(?<![a-z0-9_.])"
    r"(?P<helper>states|state_attr|is_state|is_state_attr|has_value)"
    r"\s*\(\s*(?P<quote>['\"])(?P<entity>[a-z0-9_]+\.[a-z0-9_]+)"
    r"(?P=quote)(?=\s*(?:,|\)))"
)
_END_RAW_PATTERN = re.compile(r"\{%-?\s*endraw\s*-?%\}")
_COMMON_SCALAR_REFERENCE_FIELDS = frozenset(
    {
        "climate_entity",
        "entities",
        "entity",
        "entity_id",
        "heater",
        "source_entity",
        "target",
        "target_sensor",
        "temperature_sensor",
    }
)
_SCALAR_FIELDS_BY_PROVIDER = {
    "active_yaml": _COMMON_SCALAR_REFERENCE_FIELDS,
    "config_entry": _COMMON_SCALAR_REFERENCE_FIELDS,
    "external_writers": frozenset({"entities", "entity_id", "target"}),
    "lovelace": _COMMON_SCALAR_REFERENCE_FIELDS | {"camera_image"},
    "scheduler": frozenset({"entities", "entity_id", "target"}),
}
_TEMPLATE_PROVIDERS = frozenset({"active_yaml", "config_entry", "lovelace"})
_TEMPLATE_FIELDS = frozenset(
    {
        "availability_template",
        "condition",
        "entity_picture_template",
        "icon_template",
        "state",
        "state_template",
        "template",
        "value_template",
    }
)


@dataclass(frozen=True, slots=True)
class BlockedSemanticReference:
    """One old-entity occurrence that cannot be changed safely."""

    path: ReferencePath
    text: str
    mapping_key: bool = False


@dataclass(frozen=True, slots=True)
class SemanticReferenceScan:
    """Replaceable semantic paths and blocked textual occurrences."""

    replaceable_paths: tuple[ReferencePath, ...]
    blocked: tuple[BlockedSemanticReference, ...]


@dataclass(frozen=True, slots=True)
class _TemplateAnalysis:
    replaceable_count: int
    blocked: bool


class _TemplateInspector(NodeVisitor):
    """Accept only real literal calls to known Home Assistant helpers."""

    def __init__(self, old_entity_id: str) -> None:
        self.old_entity_id = old_entity_id
        self.domain, self.object_id = old_entity_id.split(".", 1)
        self.approved_constants: set[int] = set()
        self.approved_helper_names: set[int] = set()
        self.replaceable_count = 0
        self.blocked = False

    def visit_Call(self, node: nodes.Call) -> None:
        if isinstance(node.node, nodes.Name) and node.node.name in _ENTITY_JINJA_HELPERS:
            self.approved_helper_names.add(id(node.node))
            if node.node.name not in _REPLACEABLE_JINJA_HELPERS:
                self.blocked = True
            elif not node.args or not isinstance(node.args[0], nodes.Const):
                self.blocked = True
            elif not isinstance(node.args[0].value, str):
                self.blocked = True
            elif node.args[0].value == self.old_entity_id:
                self.approved_constants.add(id(node.args[0]))
                self.replaceable_count += 1
            elif _contains_complete_entity(
                node.args[0].value,
                self.old_entity_id,
            ):
                self.blocked = True
        else:
            self.blocked = True
        self.generic_visit(node)

    def visit_Name(self, node: nodes.Name) -> None:
        if (
            node.name in _ENTITY_JINJA_HELPERS
            and id(node) not in self.approved_helper_names
        ):
            self.blocked = True

    def visit_Const(self, node: nodes.Const) -> None:
        if (
            id(node) not in self.approved_constants
            and isinstance(node.value, str)
            and _contains_complete_entity(node.value, self.old_entity_id)
        ):
            self.blocked = True

    def visit_TemplateData(self, node: nodes.TemplateData) -> None:
        if _contains_complete_entity(node.data, self.old_entity_id):
            self.blocked = True

    def visit_Getattr(self, node: nodes.Getattr) -> None:
        chain = _access_chain(node)
        if chain is not None and _chain_matches_entity(chain[1], self.old_entity_id):
            self.blocked = True
        self.generic_visit(node)

    def visit_Getitem(self, node: nodes.Getitem) -> None:
        chain = _access_chain(node)
        if chain is None:
            self.blocked = True
        elif _chain_matches_entity(chain[1], self.old_entity_id):
            self.blocked = True
        self.generic_visit(node)

    def visit_Filter(self, node: nodes.Filter) -> None:
        if node.name not in _SAFE_JINJA_FILTERS:
            self.blocked = True
        self.generic_visit(node)

    def visit_Macro(self, node: nodes.Macro) -> None:
        if node.name in _ENTITY_JINJA_HELPERS or any(
            argument.name in _ENTITY_JINJA_HELPERS for argument in node.args
        ):
            self.blocked = True
        self.generic_visit(node)

    def visit_Assign(self, node: nodes.Assign) -> None:
        if _target_shadows_helper(node.target):
            self.blocked = True
        self.generic_visit(node)

    def visit_AssignBlock(self, node: nodes.AssignBlock) -> None:
        if _target_shadows_helper(node.target):
            self.blocked = True
        self.generic_visit(node)

    def visit_For(self, node: nodes.For) -> None:
        if _target_shadows_helper(node.target):
            self.blocked = True
        self.generic_visit(node)

    def visit_Import(self, node: nodes.Import) -> None:
        if node.target in _ENTITY_JINJA_HELPERS:
            self.blocked = True
        self.generic_visit(node)

    def visit_FromImport(self, node: nodes.FromImport) -> None:
        aliases = {
            item[1] if isinstance(item, tuple) else item
            for item in node.names
        }
        if aliases & _ENTITY_JINJA_HELPERS:
            self.blocked = True
        self.generic_visit(node)

    def visit_With(self, node: nodes.With) -> None:
        if any(_target_shadows_helper(target) for target in node.targets):
            self.blocked = True
        self.generic_visit(node)

    def visit_CallBlock(self, node: nodes.CallBlock) -> None:
        if any(_target_shadows_helper(argument) for argument in node.args):
            self.blocked = True
        self.generic_visit(node)


def scan_semantic_references(
    payload: Any,
    old_entity_id: str,
    *,
    provider: str | None = None,
) -> SemanticReferenceScan:
    """Find typed scalar/template references and reject ambiguous constructs."""

    if type(old_entity_id) is not str or not old_entity_id:
        raise ValueError("The old entity ID is required.")
    if provider is not None and (type(provider) is not str or not provider):
        raise ValueError("The provider name must be a non-empty string.")

    replaceable: list[ReferencePath] = []
    blocked: list[BlockedSemanticReference] = []

    def walk(value: Any, path: ReferencePath) -> None:
        if type(value) is dict:
            for key in sorted(value):
                if _contains_complete_entity(key, old_entity_id):
                    blocked.append(
                        BlockedSemanticReference(path + (key,), key, mapping_key=True)
                    )
                walk(value[key], path + (key,))
            return
        if type(value) is list:
            for index, item in enumerate(value):
                walk(item, path + (index,))
            return
        if not isinstance(value, str):
            return

        if value == old_entity_id:
            if _is_scalar_reference_path(path, provider):
                replaceable.append(path)
            else:
                blocked.append(BlockedSemanticReference(path, value))
            return

        if "{{" in value or "{%" in value:
            analysis = _analyze_template(value, old_entity_id)
            if _is_scalar_reference_path(path, provider):
                blocked.append(BlockedSemanticReference(path, value))
            elif (
                not _is_template_path(path)
                or (provider is not None and provider not in _TEMPLATE_PROVIDERS)
            ):
                if analysis.blocked or analysis.replaceable_count:
                    blocked.append(BlockedSemanticReference(path, value))
            elif analysis.blocked or analysis.replaceable_count > 1:
                blocked.append(BlockedSemanticReference(path, value))
            elif analysis.replaceable_count == 1:
                replaceable.append(path)
            return

        if _contains_complete_entity(value, old_entity_id):
            blocked.append(BlockedSemanticReference(path, value))

    walk(payload, ())
    return SemanticReferenceScan(tuple(replaceable), tuple(blocked))


def replace_semantic_references(
    payload: Any,
    old_entity_id: str,
    target_entity_id: str,
    *,
    provider: str | None = None,
) -> tuple[Any, int]:
    """Replace only paths approved by the semantic projection."""

    scan = scan_semantic_references(payload, old_entity_id, provider=provider)
    replaceable = set(scan.replaceable_paths)
    count = 0

    def replace_value(value: Any, path: ReferencePath) -> Any:
        nonlocal count
        if type(value) is dict:
            return {
                key: replace_value(item, path + (key,))
                for key, item in value.items()
            }
        if type(value) is list:
            return [
                replace_value(item, path + (index,))
                for index, item in enumerate(value)
            ]
        if path not in replaceable or not isinstance(value, str):
            return value
        if value == old_entity_id:
            count += 1
            return target_entity_id

        replaced, replacements = _replace_template_literal(
            value,
            old_entity_id,
            target_entity_id,
        )
        if replacements != 1:
            raise ValueError("The semantic reference path changed during replacement.")
        count += replacements
        return replaced

    return replace_value(payload, ()), count


def _is_scalar_reference_path(
    path: ReferencePath,
    provider: str | None,
) -> bool:
    field = next((part for part in reversed(path) if isinstance(part, str)), None)
    allowed = (
        _COMMON_SCALAR_REFERENCE_FIELDS
        if provider is None
        else _SCALAR_FIELDS_BY_PROVIDER.get(provider, frozenset())
    )
    return field in allowed


def _is_template_path(path: ReferencePath) -> bool:
    return bool(
        path and isinstance(path[-1], str) and path[-1] in _TEMPLATE_FIELDS
    )


def _contains_complete_entity(text: str, old_entity_id: str) -> bool:
    return any(
        match.group("entity") == old_entity_id
        for match in _ENTITY_TOKEN_PATTERN.finditer(text)
    )


def _analyze_template(text: str, old_entity_id: str) -> _TemplateAnalysis:
    try:
        parsed = _JINJA_ENVIRONMENT.parse(text)
    except TemplateSyntaxError:
        return _TemplateAnalysis(0, True)
    inspector = _TemplateInspector(old_entity_id)
    inspector.visit(parsed)
    if _node_mentions_old_parts(
        parsed,
        inspector.domain,
        inspector.object_id,
        excluded=inspector.approved_constants,
    ):
        inspector.blocked = True
    if inspector.replaceable_count and len(
        _source_literal_spans(text, old_entity_id)
    ) != inspector.replaceable_count:
        inspector.blocked = True
    return _TemplateAnalysis(inspector.replaceable_count, inspector.blocked)


def _node_mentions_old_parts(
    node: nodes.Node,
    domain: str,
    object_id: str,
    *,
    excluded: set[int] | None = None,
) -> bool:
    values: list[str] = []
    for child in _walk_nodes(node):
        if (
            not isinstance(child, nodes.Const)
            or not isinstance(child.value, str)
            or (excluded is not None and id(child) in excluded)
        ):
            continue
        if _contains_complete_entity(child.value, f"{domain}.{object_id}"):
            return True
        spans = [
            match.span("entity")
            for match in _ENTITY_TOKEN_PATTERN.finditer(child.value)
        ]
        values.append(_without_spans(child.value, spans))
    compact = re.sub(r"[^a-z0-9_.]", "", "".join(values).lower())
    return domain in compact and object_id in compact


def _walk_nodes(node: nodes.Node):
    yield node
    for child in node.iter_child_nodes():
        yield from _walk_nodes(child)


def _without_spans(text: str, spans: list[tuple[int, int]]) -> str:
    if not spans:
        return text
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    pieces: list[str] = []
    cursor = 0
    for start, end in merged:
        pieces.append(text[cursor:start])
        pieces.append(" ")
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _access_chain(node: nodes.Node) -> tuple[str, tuple[str, ...]] | None:
    segments: list[str] = []
    current = node
    while isinstance(current, (nodes.Getattr, nodes.Getitem)):
        if isinstance(current, nodes.Getattr):
            segments.append(current.attr)
        elif isinstance(current.arg, nodes.Const) and isinstance(
            current.arg.value,
            str,
        ):
            segments.append(current.arg.value)
        else:
            return None
        current = current.node
    root_name = current.name if isinstance(current, nodes.Name) else ""
    return root_name, tuple(reversed(segments))


def _target_shadows_helper(node: nodes.Node) -> bool:
    if isinstance(node, nodes.Name):
        return node.name in _ENTITY_JINJA_HELPERS
    if isinstance(node, (nodes.Tuple, nodes.List)):
        return any(_target_shadows_helper(item) for item in node.items)
    return False


def _chain_matches_entity(chain: tuple[str, ...], old_entity_id: str) -> bool:
    domain, object_id = old_entity_id.split(".", 1)
    return bool(
        old_entity_id in chain
        or any(
            chain[index] == domain and chain[index + 1] == object_id
            for index in range(len(chain) - 1)
        )
    )


def _replace_template_literal(
    text: str,
    old_entity_id: str,
    target_entity_id: str,
) -> tuple[str, int]:
    spans = _source_literal_spans(text, old_entity_id)
    if len(spans) != 1:
        return text, 0
    start, end = spans[0]
    return text[:start] + target_entity_id + text[end:], 1


def _source_literal_spans(
    text: str,
    old_entity_id: str,
) -> tuple[tuple[int, int], ...]:
    code_ranges = _jinja_code_ranges(text)
    return tuple(
        match.span("entity")
        for match in _SOURCE_HELPER_PATTERN.finditer(text)
        if match.group("entity") == old_entity_id
        and any(
            start <= match.start() and match.end() <= end
            for start, end in code_ranges
        )
    )


def _jinja_code_ranges(text: str) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []
    cursor = 0
    raw = False
    while cursor < len(text):
        if raw:
            match = _END_RAW_PATTERN.search(text, cursor)
            if match is None:
                break
            cursor = match.end()
            raw = False
            continue
        starts = [
            (index, delimiter)
            for delimiter in ("{{", "{%", "{#")
            if (index := text.find(delimiter, cursor)) >= 0
        ]
        if not starts:
            break
        start, delimiter = min(starts)
        if delimiter == "{#":
            end = text.find("#}", start + 2)
            if end < 0:
                break
            cursor = end + 2
            continue
        closing = "}}" if delimiter == "{{" else "%}"
        end = _find_jinja_closing(text, start + 2, closing)
        if end < 0:
            break
        content = text[start + 2 : end]
        if delimiter == "{%" and content.strip().strip("-").strip() == "raw":
            raw = True
        else:
            ranges.append((start + 2, end))
        cursor = end + 2
    return tuple(ranges)


def _find_jinja_closing(text: str, start: int, closing: str) -> int:
    quote: str | None = None
    escaped = False
    index = start
    while index < len(text) - 1:
        character = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
        elif text.startswith(closing, index):
            return index
        index += 1
    return -1
