# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Traversal of Yamale schemas and of data validated against them, and
lookups of what the schema says about a data path (``schema_at()``).

This is the only place relying on Yamale internals (``Schema._schema``,
``Schema._validate`` and the validators' constraint instances); the tests of
this module guard against changes of them in new Yamale versions.
"""

from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, TypeVar

from yamale.schema.datapath import DataPath
from yamale.validators import Any as AnyValidator
from yamale.validators import Include, Map, Subset, Validator
from yamale.validators import List as ListValidator

from .values import split_fields, valid_fields

KeyPath = tuple[str | int, ...]
# What a value of the data can be: a map, a list or a single value
Kind = Literal["map", "list", "scalar"]
# Whether a value satisfies the extensions configured on a validator
Accepts = Callable[[Validator, Any], bool]
_T = TypeVar("_T")


@dataclass(frozen=True)
class SchemaNode:
    """A validator of the schema with its location."""

    validator: Validator
    # Name of the include the validator is defined in, "" for the main schema
    include: str
    path: KeyPath

    @property
    def location(self) -> str:
        path = ".".join(str(p) for p in self.path)
        return f"{self.include}.{path}" if self.include else path


@dataclass(frozen=True)
class ListLevel:
    """An item of a list of the data that encloses a value."""

    # Path of the list in the data
    path: KeyPath
    index: int
    # Value of the item's single-field primary key, None if it has none
    key: Any
    validator: ListValidator


@dataclass(frozen=True)
class DataNode:
    """A data value with the schema validator it was validated with."""

    validator: Validator
    value: Any
    path: KeyPath
    # Items of lists enclosing the value, outermost first
    levels: tuple[ListLevel, ...] = ()


@dataclass(frozen=True)
class SchemaContext:
    """A validator of the schema at one place the data can reach it.

    A validator of an include used in several places has a context for each.
    """

    validator: Validator
    location: str
    # Schemas of the enclosing list items, outermost first, starting with the
    # root schema; each with the schema object its includes resolve against
    records: tuple[tuple[Any, Any], ...]
    # Lists enclosing the validator with their locations, outermost first
    lists: tuple[tuple[str, ListValidator], ...] = ()

    @property
    def depth(self) -> int:
        """Return the number of list items enclosing the validator."""
        return len(self.records) - 1


def known_keywords(validator: Validator) -> set[str]:
    """Return the Yamale keywords the validator still holds in its kwargs.

    Keywords Yamale consumes itself (e.g. ``required``) are already removed
    from ``kwargs``, so everything else in it is an unknown keyword.
    """
    return {k for c in validator._constraints_inst for k in c.keywords}


def single_key_field(validator: Validator) -> str | None:
    """Return the field of a single-field ``primary_key`` of a list, if any."""
    key = validator.kwargs.get("primary_key")
    if not valid_fields(key):
        return None
    fields = split_fields(key)
    return fields[0] if len(fields) == 1 else None


def walk_schema(schema: Any) -> Iterator[SchemaNode]:
    """Yield every validator of the schema and its includes."""
    yield from _schema_nodes(schema._schema, "", ())
    for name, include in schema.includes.items():
        yield from _schema_nodes(include._schema, name, ())


def _schema_nodes(node: Any, include: str, path: KeyPath) -> Iterator[SchemaNode]:
    if isinstance(node, dict):
        for key, child in node.items():
            yield from _schema_nodes(child, include, (*path, key))
    elif isinstance(node, list):
        for index, child in enumerate(node):
            yield from _schema_nodes(child, include, (*path, index))
    elif isinstance(node, Validator):
        yield SchemaNode(node, include, path)
        for child in getattr(node, "validators", []):
            yield from _schema_nodes(child, include, path)
        # e.g. the key validator of map(key=...)
        for value in node.kwargs.values():
            if isinstance(value, Validator):
                yield from _schema_nodes(value, include, path)


def walk_schema_contexts(schema: Any) -> Iterator[SchemaContext]:
    """Yield every validator reachable from the root with its context.

    Includes are followed from where they are used, so a validator of an
    include used in several places is yielded once per enclosing list item
    schema. Recursive includes are followed once.
    """
    root = ((schema._schema, schema),)
    yield from _contexts(schema, schema._schema, "", root, (), set())


def _contexts(
    schema: Any,
    node: Any,
    location: str,
    records: tuple[tuple[Any, Any], ...],
    lists: tuple[tuple[str, ListValidator], ...],
    seen: set[tuple[str, int]],
) -> Iterator[SchemaContext]:
    if isinstance(node, dict):
        for key, child in node.items():
            child_location = f"{location}.{key}" if location else str(key)
            yield from _contexts(schema, child, child_location, records, lists, seen)
        return
    if not isinstance(node, Validator):
        return
    yield SchemaContext(node, location, records, lists)
    if isinstance(node, Include):
        visit = (node.include_name, id(records[-1][0]))
        if visit in seen:
            return
        seen.add(visit)
        include = schema.includes[node.include_name]
        yield from _contexts(include, include._schema, location, records, lists, seen)
    elif isinstance(node, ListValidator):
        inner = (*lists, (location, node))
        for child in node.validators:
            yield from _contexts(
                schema, child, location, (*records, (child, schema)), inner, seen
            )
    elif isinstance(node, Map | AnyValidator | Subset):
        for child in node.validators:
            yield from _contexts(schema, child, location, records, lists, seen)


def resolves(schema: Any, node: Any, path: Sequence[str]) -> bool:
    """Return whether a dotted path of map keys exists below a schema node."""
    return _resolves(schema, node, list(path), set())


def _resolves(schema: Any, node: Any, path: list[str], seen: set[str]) -> bool:
    if not path:
        return True
    if isinstance(node, dict):
        return path[0] in node and _resolves(schema, node[path[0]], path[1:], seen)
    if isinstance(node, Include):
        if node.include_name in seen:
            return False
        include = schema.includes[node.include_name]
        return _resolves(include, include._schema, path, seen | {node.include_name})
    if isinstance(node, AnyValidator | Subset):
        return any(_resolves(schema, v, path, seen) for v in node.validators)
    return False


def walk_data(
    schema: Any, data: Any, strict: bool, accepts: Accepts | None = None
) -> Iterator[DataNode]:
    """Yield every value of the data with the validator it was validated with.

    Where a value could match several validators (``any()``, ``list()`` and
    ``map()`` with several validators, ``subset()``) the first matching one is
    used. Data that did not pass Yamale validation, like data merged from
    files that passed one by one, is still walked as far as possible: a value
    matching none of the validators is walked with the first one of the right
    type. Null values are skipped, as Yamale treats them as not set. The keys
    of a map with a key validator (``map(key=...)``) are yielded with it, at
    the path of their value. A map part of ``subset()`` is yielded as a map of
    just that key, the way Yamale validates it. Every value carries the items
    of the lists enclosing it.

    ``accepts`` narrows the validators matching a value to those whose
    extensions it satisfies, e.g. ``ip(type='network')`` of
    ``any(ip(type='address'), ip(type='network'))`` for ``10.0.0.0/24``. If
    none satisfies them, the first one matching it in Yamale is used.
    """
    yield from _data_nodes(schema, schema._schema, data, (), strict, (), accepts)


def _data_nodes(
    schema: Any,
    node: Any,
    data: Any,
    path: KeyPath,
    strict: bool,
    levels: tuple[ListLevel, ...],
    accepts: Accepts | None,
) -> Iterator[DataNode]:
    if isinstance(node, dict | list):
        keys = node.keys() if isinstance(node, dict) else range(len(node))
        for key in keys:
            try:
                value = data[key]
            except (KeyError, IndexError, TypeError):
                continue
            yield from _data_nodes(
                schema, node[key], value, (*path, key), strict, levels, accepts
            )
        return

    if data is None:
        return
    yield DataNode(node, data, path, levels)
    if isinstance(node, Include):
        include = schema.includes[node.include_name]
        strict = strict if node.strict is None else bool(node.strict)
        yield from _data_nodes(
            include, include._schema, data, path, strict, levels, accepts
        )
    elif isinstance(node, Map | ListValidator):
        if isinstance(data, Mapping):
            items: Iterator[tuple[str | int, Any]] = iter(data.items())
            is_list = False
        elif isinstance(data, Sequence) and not isinstance(data, str):
            items = enumerate(data)
            is_list = isinstance(node, ListValidator)
        else:
            return
        key_validator = node.kwargs.get("key")
        key_field = single_key_field(node) if is_list else None
        for key, value in items:
            item_levels = levels
            if is_list and isinstance(key, int):
                item_key = (
                    value.get(key_field)
                    if key_field is not None and isinstance(value, Mapping)
                    else None
                )
                item_levels = (*levels, ListLevel(path, key, item_key, node))
            if isinstance(key_validator, Validator):
                yield from _data_nodes(
                    schema,
                    key_validator,
                    key,
                    (*path, key),
                    strict,
                    item_levels,
                    accepts,
                )
            yield from _matching(
                schema,
                node.validators,
                value,
                (*path, key),
                strict,
                item_levels,
                accepts,
            )
    elif isinstance(node, AnyValidator):
        yield from _matching(
            schema, node.validators, data, path, strict, levels, accepts
        )
    elif isinstance(node, Subset):
        if isinstance(data, Mapping):
            parts = [{k: v} for k, v in data.items()]
        elif isinstance(data, Sequence) and not isinstance(data, str):
            parts = list(data)
        else:
            parts = [data]
        for part in parts:
            yield from _matching(
                schema, node.validators, part, path, strict, levels, accepts
            )


def _matching(
    schema: Any,
    validators: list[Validator],
    data: Any,
    path: KeyPath,
    strict: bool,
    levels: tuple[ListLevel, ...],
    accepts: Accepts | None,
) -> Iterator[DataNode]:
    if not validators:
        return
    match: Validator | None = None
    if len(validators) == 1:
        match = validators[0]
    else:
        first_valid = None
        for v in validators:
            if schema._validate(v, data, DataPath(), strict):
                continue
            if accepts is None or accepts(v, data):
                match = v
                break
            if first_valid is None:
                first_valid = v
        match = match or first_valid
        if match is None:
            # Not valid data: walk on with the first validator of the right type
            match = next((v for v in validators if v.is_valid(data)), validators[0])
    yield from _data_nodes(schema, match, data, path, strict, levels, accepts)


@dataclass(frozen=True)
class KeyInfo:
    """A key of the maps of the schema, with what its value can be.

    A key of several maps, as with ``any()``, has what each of them says
    combined, like the ``PathInfo`` of its value.
    """

    key: str
    required: bool
    # A short description of what the value can be, e.g. ``list of map (vrf)``
    summary: str
    kinds: tuple[Kind, ...]
    description: str | None
    # Whether the value can be a template variable, e.g. ``${vlan}``
    templatable: bool
    # The primary_key of a list the value can be, None if it has none
    primary_key: str | None


@dataclass(frozen=True)
class PathInfo:
    """What the schema says about the value at a data path.

    A value the schema allows in several forms, as with ``any()``, has all
    of them combined: the kinds, keys and values of every form, and it is
    required if one of them requires it. Where the schema allows any value
    (``map()`` values, ``list()`` items, ``any()``), the value can be of
    every kind and take any key.
    """

    path: KeyPath
    kinds: tuple[Kind, ...]
    # Whether the value must be set: the key is required in a map of the schema
    required: bool
    description: str | None
    # Whether the value can be a template variable, e.g. ``${vlan}``
    templatable: bool
    # A short description of what the value can be, e.g. ``integer (min 1)``
    summary: str
    # The keys of the maps of the schema the value can be, in schema order
    keys: tuple[KeyInfo, ...] = ()
    # Whether the value can be a map taking any key (``map()``, any value)
    any_key: bool = False
    # The primary_key of a list the value can be, None if it has none
    primary_key: str | None = None
    # What the items can be if the value can be a list, else None
    item_summary: str | None = None
    # The values a single value can take, if the schema lists them (enum, bool)
    values: tuple[Any, ...] = ()
    # Keywords restricting the value as (keyword, value), e.g. ("min", 1)
    constraints: tuple[tuple[str, Any], ...] = ()
    # The ref of a field referring to keys of a list, None if it refers to none
    ref: str | None = None


# The alternative of any() that lets a value be a template variable, e.g.
# ${vlan}: regex("^.*[\$\%]\{.*$"), recognised by this part of its pattern
_TEMPLATE_PATTERN = "[\\$\\%]\\{"

_TYPE_NAMES = {
    "str": "string",
    "int": "integer",
    "num": "number",
    "bool": "boolean",
    "ip": "IP address",
    "mac": "MAC address",
    "day": "date",
    "timestamp": "timestamp",
    "null": "null",
    "any": "any value",
}

# Keywords of validators that don't restrict the value itself: they document
# it, relate it to other values, or are described by fields of their own
_NOT_CONSTRAINTS = frozenset(
    {
        "description",
        "required",
        "primary_key",
        "unique",
        "ordered",
        "ref",
        "ref_name",
        "ref_in",
        "ref_implicit",
        "ref_scope",
        "key",
        "none",
    }
)

# What a value can be where the schema doesn't restrict it: any() without
# alternatives, which takes null too
_ANY_VALUE = AnyValidator(required=False)

# A place of the schema: the schema object its includes resolve against, and
# a static map (dict), a static list (list) or a validator
_Place = tuple[Any, Any]


def schema_at(schema: Any, path: Sequence[str | int]) -> PathInfo | None:
    """Describe what the schema says about the value at a data path.

    The path holds map keys and list positions, e.g.
    ``("nxos", "devices", 0, "name")``. All positions of a ``list()`` are the
    same to the schema; those of a static list (``- str()``) are not. A key
    that is a number in the schema can be given as text, e.g. ``"1"``, as it
    is written in YAML. Includes are followed, and the alternatives of
    ``any()`` and ``subset()``, and the validators of lists and maps with
    several, are all looked at; an include the schema doesn't define is
    left out. Returns None if the schema has no place for the path.
    """
    places: list[_Place] = [(schema, schema._schema)]
    for segment in path:
        places = [
            child
            for place in places
            for expanded in _expand(place, frozenset())
            for child in _children(expanded, segment)
        ]
        if not places:
            return None
    return _describe(places, tuple(path))


@dataclass(frozen=True)
class _Facts:
    """What places of the schema say about a value, for keys and paths."""

    expanded: list[_Place]
    validators: list[Validator]
    required: bool
    summary: str
    kinds: tuple[Kind, ...]
    description: str | None
    templatable: bool
    primary_key: str | None


def _facts(places: list[_Place], root: bool = False) -> _Facts:
    expanded = [e for place in places for e in _expand(place, frozenset())]
    validators = [node for _schema, node in places if isinstance(node, Validator)]
    lists = [node for _schema, node in expanded if isinstance(node, ListValidator)]
    return _Facts(
        expanded=expanded,
        validators=validators,
        # The keys of static maps and lists of the schema are required
        required=any(v.is_required for v in validators)
        or (not root and any(isinstance(n, dict | list) for _s, n in places)),
        summary=" or ".join(_unique(_summary(node) for _schema, node in places)),
        kinds=_kinds(expanded),
        description=_first(v.kwargs.get("description") for v in validators),
        templatable=any(_templatable(v) for v in validators),
        primary_key=_first(v.kwargs.get("primary_key") for v in lists),
    )


def _describe(places: list[_Place], path: KeyPath) -> PathInfo:
    facts = _facts(places, root=not path)
    expanded = facts.expanded
    return PathInfo(
        path=path,
        kinds=facts.kinds,
        required=facts.required,
        description=facts.description,
        templatable=facts.templatable,
        summary=facts.summary,
        keys=_keys(expanded),
        any_key=any(
            isinstance(node, Map) or _is_any_value(node) for _schema, node in expanded
        ),
        primary_key=facts.primary_key,
        item_summary=_item_summary(expanded),
        values=_values(expanded),
        constraints=_constraints(facts.validators, expanded),
        ref=_first(v.kwargs.get("ref") for v in _scalars(expanded)),
    )


def _is_any_value(node: Any) -> bool:
    return isinstance(node, AnyValidator) and not node.validators


def _expand(place: _Place, seen: frozenset[str]) -> list[_Place]:
    """The static maps and lists and the validators a place stands for:
    includes resolved, and the alternatives of any() and subset(). A subset()
    also stands for a list of its alternatives."""
    schema, node = place
    if isinstance(node, Include):
        include = schema.includes.get(node.include_name)
        if include is None or node.include_name in seen:
            return []
        return _expand((include, include._schema), seen | {node.include_name})
    if isinstance(node, AnyValidator | Subset) and node.validators:
        alternatives = [e for v in node.validators for e in _expand((schema, v), seen)]
        if isinstance(node, Subset):
            alternatives.append((schema, ListValidator(*node.validators)))
        return alternatives
    return [place]


def _children(place: _Place, segment: str | int) -> list[_Place]:
    schema, node = place
    if isinstance(node, dict):
        key = _dict_key(node, segment)
        return [] if key is _MISSING else [(schema, node[key])]
    if _is_any_value(node):
        return [(schema, _ANY_VALUE)]
    if isinstance(node, Map):
        # map() without value validators takes any value
        return [(schema, v) for v in node.validators or [_ANY_VALUE]]
    if not isinstance(segment, int) or isinstance(segment, bool):
        return []
    if isinstance(node, ListValidator):
        # list() without item validators takes any value
        return [(schema, v) for v in node.validators or [_ANY_VALUE]]
    if isinstance(node, list):
        # The items of a static list are validated by position
        return [(schema, node[segment])] if 0 <= segment < len(node) else []
    return []


# A key a static map doesn't have
_MISSING = object()


def _dict_key(node: dict[Any, Any], segment: str | int) -> Any:
    """The key of a static map a path segment names, e.g. ``1`` for ``"1"``."""
    if segment in node and not isinstance(segment, bool):
        return segment
    if isinstance(segment, str):
        return next(
            (k for k in node if not isinstance(k, str) and str(k) == segment),
            _MISSING,
        )
    return _MISSING


def _keys(expanded: list[_Place]) -> tuple[KeyInfo, ...]:
    """The keys of the static maps, in schema order, with what they hold."""
    children: dict[Any, list[_Place]] = {}
    for schema, node in expanded:
        if not isinstance(node, dict):
            continue
        for key, child in node.items():
            if isinstance(child, Validator | dict | list):
                children.setdefault(key, []).append((schema, child))
    keys = []
    for key, places in children.items():
        facts = _facts(places)
        keys.append(
            KeyInfo(
                key=str(key),
                required=facts.required,
                summary=facts.summary,
                kinds=facts.kinds,
                description=facts.description,
                templatable=facts.templatable,
                primary_key=facts.primary_key,
            )
        )
    return tuple(keys)


def _kinds(expanded: list[_Place]) -> tuple[Kind, ...]:
    kinds: list[Kind] = []
    for _schema, node in expanded:
        kinds += ["map", "list", "scalar"] if _is_any_value(node) else [_kind(node)]
    return tuple(_unique(kinds))


def _kind(node: Any) -> Kind:
    if isinstance(node, dict | Map):
        return "map"
    if isinstance(node, ListValidator | list):
        return "list"
    return "scalar"


def _item_summary(expanded: list[_Place]) -> str | None:
    """What the items of the lists can be, None if there are no lists."""
    items: list[str] = []
    is_list = False
    for _schema, node in expanded:
        if isinstance(node, ListValidator | list) or _is_any_value(node):
            is_list = True
            validators = node.validators if isinstance(node, Validator) else node
            items += [_summary(v) for v in validators] or ["any value"]
    return " or ".join(_unique(items)) if is_list else None


def _scalars(expanded: list[_Place]) -> list[Validator]:
    return [
        node
        for _schema, node in expanded
        if isinstance(node, Validator) and _kind(node) == "scalar"
    ]


def _values(expanded: list[_Place]) -> tuple[Any, ...]:
    """The values a scalar can take, if the schema lists them."""
    values: list[Any] = []
    for validator in _scalars(expanded):
        if validator.tag == "enum":
            values += list(getattr(validator, "enums", ()))
        elif validator.tag == "bool":
            values += [True, False]
    return tuple(_unique(values))


def _constraints(
    validators: list[Validator], expanded: list[_Place]
) -> tuple[tuple[str, Any], ...]:
    """The keywords restricting the value, e.g. ``min``: of the validators of
    the value, then of the alternatives of any() and subset() they hold."""
    alternatives = [n for _s, n in expanded if isinstance(n, Validator)]
    constraints: dict[str, Any] = {}
    for validator in [*validators, *alternatives]:
        for k, v in validator.kwargs.items():
            if k not in _NOT_CONSTRAINTS and not isinstance(v, Validator):
                constraints.setdefault(k, v)
    return tuple(constraints.items())


def _templatable(validator: Validator) -> bool:
    if isinstance(validator, AnyValidator):
        return any(_is_template_regex(v) for v in validator.validators)
    return False


def _is_template_regex(validator: Validator) -> bool:
    if validator.tag != "regex":
        return False
    return any(_TEMPLATE_PATTERN in pattern for pattern in _patterns(validator))


def _patterns(validator: Validator) -> list[str]:
    """The patterns of a regex() validator."""
    return [r.pattern for r in getattr(validator, "regexes", ())]


def _summary(node: Any) -> str:
    """A short description of what a node accepts, e.g. ``list of map``."""
    if isinstance(node, dict):
        return "map"
    if isinstance(node, list):
        items = " or ".join(_unique(_summary(v) for v in node))
        return f"list of {items}" if items else "list"
    if isinstance(node, Include):
        return f"map ({node.include_name})"
    if isinstance(node, ListValidator):
        items = " or ".join(_unique(_summary(v) for v in node.validators))
        return f"list of {items}" if items else "list"
    if isinstance(node, Map):
        values = " or ".join(_unique(_summary(v) for v in node.validators))
        return f"map of {values}" if values else "map"
    if isinstance(node, AnyValidator | Subset):
        parts = [_summary(v) for v in node.validators if not _is_template_regex(v)]
        return " or ".join(_unique(parts)) or "any value"
    if node.tag == "enum":
        return "one of " + ", ".join(str(e) for e in getattr(node, "enums", ()))
    if node.tag == "regex":
        return "string matching " + ", ".join(_patterns(node))
    tag = str(node.tag)
    name = _TYPE_NAMES.get(tag, tag)
    limits = [
        f"{k} {v}"
        for k, v in node.kwargs.items()
        if k in ("min", "max", "length", "exclude")
    ]
    return f"{name} ({', '.join(limits)})" if limits else name


def _unique(values: Iterable[_T]) -> list[_T]:
    result: list[_T] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _first(values: Iterable[Any]) -> Any:
    return next((v for v in values if v), None)
