# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""``list(..., unique=...)``: values that must be unique within a list.

Unlike ``primary_key``, ``unique`` is a constraint, not the identity of an
item, so its fields may be optional:

- ``unique=True``: items that are single values (not maps or lists) must be
  unique, e.g. the strings of ``list(str(), unique=True)``
- ``unique='prefix,vrf'``: the combination of the fields must be unique among
  the items that are maps. A field that is not set (missing or null) is a
  value of its own, so ``{prefix: X}`` and ``{prefix: X, vrf: A}`` differ.
  Items setting none of the fields are not compared

Yamale only accepts constants as keyword values, so the fields are a
comma-separated string, as for ``primary_key``.
"""

from collections.abc import Iterator
from typing import Any, TypeVar

from yamale.validators import List, Validator

from .base import Extension, Scope
from .values import (
    TypedValue,
    format_key,
    is_single_value,
    kind,
    split_fields,
    typed,
    valid_fields,
)
from .walker import DataNode

K = TypeVar("K")


def _duplicates(indexes: dict[K, list[int]], scope: Scope) -> Iterator[tuple[K, str]]:
    """Yield every value with more than one item and where they are."""
    for value, indices in indexes.items():
        if len(indices) == 1:
            continue
        if scope == Scope.DOCUMENT:
            # Item numbers of the merged data are of no help to find them
            yield value, "across files"
        else:
            yield value, "in items " + ", ".join(str(i) for i in indices)


class Unique(Extension):
    keywords = ("unique",)
    validator_types = (List,)
    # Items with different values of a unique field don't merge, so duplicates
    # coming from different files remain after merging
    scopes = frozenset({Scope.FILE, Scope.DOCUMENT})

    def check_schema(self, validator: Validator) -> list[str]:
        value = validator.kwargs["unique"]
        if value is True:
            return []
        if not valid_fields(value):
            return [
                f"unique must be True or comma-separated field names, not {value!r}"
            ]
        primary_key = validator.kwargs.get("primary_key")
        if valid_fields(primary_key) and set(split_fields(primary_key)) == set(
            split_fields(value)
        ):
            return [
                f"unique names the fields of primary_key {primary_key!r}, which "
                "are unique already"
            ]
        return []

    def check(self, node: DataNode, scope: Scope) -> list[str]:
        # Merged data that is not valid may hold anything
        if not isinstance(node.value, list):
            return []
        unique = node.validator.kwargs["unique"]
        if unique is True:
            return self._check_values(node.value, scope)
        return self._check_fields(node.value, split_fields(unique), scope)

    @staticmethod
    def _check_values(items: list[Any], scope: Scope) -> list[str]:
        indexes: dict[TypedValue, list[int]] = {}
        for index, item in enumerate(items):
            # Maps and lists can't be compared, nulls are not set
            if item is None or not is_single_value(item):
                continue
            indexes.setdefault(typed(item), []).append(index)
        return [
            f"Duplicate value {value} {where}"
            for (_, value), where in _duplicates(indexes, scope)
        ]

    @staticmethod
    def _check_fields(items: list[Any], fields: list[str], scope: Scope) -> list[str]:
        errors: list[str] = []
        indexes: dict[tuple[TypedValue, ...], list[int]] = {}
        for index, item in enumerate(items):
            # Items that are not maps are validated by the item validators
            if not isinstance(item, dict):
                continue
            # Maps and lists can't be compared, whatever the item validators allow
            nested = [
                f
                for f in fields
                if item.get(f) is not None and not is_single_value(item[f])
            ]
            errors += [
                f"Unique field '{f}' in item {index} must be a single value, not "
                f"{kind(item[f])}"
                for f in nested
            ]
            if nested:
                continue
            key_value = tuple(typed(item.get(f)) for f in fields)
            # Items setting none of the fields are not compared
            if all(value is None for _, value in key_value):
                continue
            indexes.setdefault(key_value, []).append(index)
        errors += [
            f"Duplicate unique key {format_key(fields, key_value)} {where}"
            for key_value, where in _duplicates(indexes, scope)
        ]
        return errors
