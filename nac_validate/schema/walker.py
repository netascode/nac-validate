# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Traversal of Yamale schemas and of data validated against them.

This is the only place relying on Yamale internals (``Schema._schema``,
``Schema._validate`` and the validators' constraint instances); the tests of
this module guard against changes of them in new Yamale versions.
"""

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from yamale.schema.datapath import DataPath
from yamale.validators import Any as AnyValidator
from yamale.validators import Include, Map, Subset, Validator
from yamale.validators import List as ListValidator

from .values import split_fields, valid_fields

KeyPath = tuple[str | int, ...]


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


def walk_data(schema: Any, data: Any, strict: bool) -> Iterator[DataNode]:
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
    """
    yield from _data_nodes(schema, schema._schema, data, (), strict, ())


def _data_nodes(
    schema: Any,
    node: Any,
    data: Any,
    path: KeyPath,
    strict: bool,
    levels: tuple[ListLevel, ...],
) -> Iterator[DataNode]:
    if isinstance(node, dict | list):
        keys = node.keys() if isinstance(node, dict) else range(len(node))
        for key in keys:
            try:
                value = data[key]
            except (KeyError, IndexError, TypeError):
                continue
            yield from _data_nodes(
                schema, node[key], value, (*path, key), strict, levels
            )
        return

    if data is None:
        return
    yield DataNode(node, data, path, levels)
    if isinstance(node, Include):
        include = schema.includes[node.include_name]
        strict = strict if node.strict is None else bool(node.strict)
        yield from _data_nodes(include, include._schema, data, path, strict, levels)
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
                    schema, key_validator, key, (*path, key), strict, item_levels
                )
            yield from _matching(
                schema, node.validators, value, (*path, key), strict, item_levels
            )
    elif isinstance(node, AnyValidator):
        yield from _matching(schema, node.validators, data, path, strict, levels)
    elif isinstance(node, Subset):
        if isinstance(data, Mapping):
            parts = [{k: v} for k, v in data.items()]
        elif isinstance(data, Sequence) and not isinstance(data, str):
            parts = list(data)
        else:
            parts = [data]
        for part in parts:
            yield from _matching(schema, node.validators, part, path, strict, levels)


def _matching(
    schema: Any,
    validators: list[Validator],
    data: Any,
    path: KeyPath,
    strict: bool,
    levels: tuple[ListLevel, ...],
) -> Iterator[DataNode]:
    if not validators:
        return
    if len(validators) == 1:
        match = validators[0]
    else:
        match = next(
            (
                v
                for v in validators
                if not schema._validate(v, data, DataPath(), strict)
            ),
            None,
        )
        if match is None:
            # Not valid data: walk on with the first validator of the right type
            match = next((v for v in validators if v.is_valid(data)), validators[0])
    yield from _data_nodes(schema, match, data, path, strict, levels)
