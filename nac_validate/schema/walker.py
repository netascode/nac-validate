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
class DataNode:
    """A data value with the schema validator it was validated with."""

    validator: Validator
    value: Any
    path: KeyPath


def known_keywords(validator: Validator) -> set[str]:
    """Return the Yamale keywords the validator still holds in its kwargs.

    Keywords Yamale consumes itself (e.g. ``required``) are already removed
    from ``kwargs``, so everything else in it is an unknown keyword.
    """
    return {k for c in validator._constraints_inst for k in c.keywords}


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
    just that key, the way Yamale validates it.
    """
    yield from _data_nodes(schema, schema._schema, data, (), strict)


def _data_nodes(
    schema: Any, node: Any, data: Any, path: KeyPath, strict: bool
) -> Iterator[DataNode]:
    if isinstance(node, dict | list):
        keys = node.keys() if isinstance(node, dict) else range(len(node))
        for key in keys:
            try:
                value = data[key]
            except (KeyError, IndexError, TypeError):
                continue
            yield from _data_nodes(schema, node[key], value, (*path, key), strict)
        return

    if data is None:
        return
    yield DataNode(node, data, path)
    if isinstance(node, Include):
        include = schema.includes[node.include_name]
        strict = strict if node.strict is None else bool(node.strict)
        yield from _data_nodes(include, include._schema, data, path, strict)
    elif isinstance(node, Map | ListValidator):
        if isinstance(data, Mapping):
            items: Iterator[tuple[str | int, Any]] = iter(data.items())
        elif isinstance(data, Sequence) and not isinstance(data, str):
            items = enumerate(data)
        else:
            return
        key_validator = node.kwargs.get("key")
        for key, value in items:
            if isinstance(key_validator, Validator):
                yield from _data_nodes(schema, key_validator, key, (*path, key), strict)
            yield from _matching(schema, node.validators, value, (*path, key), strict)
    elif isinstance(node, AnyValidator):
        yield from _matching(schema, node.validators, data, path, strict)
    elif isinstance(node, Subset):
        if isinstance(data, Mapping):
            parts = [{k: v} for k, v in data.items()]
        elif isinstance(data, Sequence) and not isinstance(data, str):
            parts = list(data)
        else:
            parts = [data]
        for part in parts:
            yield from _matching(schema, node.validators, part, path, strict)


def _matching(
    schema: Any, validators: list[Validator], data: Any, path: KeyPath, strict: bool
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
    yield from _data_nodes(schema, match, data, path, strict)
