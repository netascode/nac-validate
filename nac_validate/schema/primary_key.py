# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""``list(..., primary_key='name')``: a unique, non-empty key in every item.

A composite key names several fields (``primary_key='node_id,name'``), whose
combination must be unique. Yamale only accepts constants as keyword values,
so the fields are a comma-separated string.
"""

from typing import Any

from yamale.validators import List, Validator

from .base import Extension, Scope
from .walker import DataNode


def _fields(validator: Validator) -> list[str]:
    """Return the key fields of a valid ``primary_key`` keyword."""
    return [f.strip() for f in validator.kwargs["primary_key"].split(",")]


def _hashable(value: Any) -> bool:
    try:
        hash(value)
    except TypeError:
        return False
    return True


def _kind(value: Any) -> str:
    if isinstance(value, dict):
        return "a map"
    if isinstance(value, list):
        return "a list"
    return f"a {type(value).__name__}"


class PrimaryKey(Extension):
    keywords = ("primary_key",)
    validator_types = (List,)
    # Items with the same key only merge when all their shared fields match,
    # so conflicting items from two files remain duplicates after merging
    scopes = frozenset({Scope.FILE, Scope.DOCUMENT})

    def check_schema(self, validator: Validator) -> list[str]:
        key = validator.kwargs["primary_key"]
        if isinstance(key, str):
            fields = _fields(validator)
            if all(fields) and len(set(fields)) == len(fields):
                return []
        return [f"primary_key must be comma-separated field names, not {key!r}"]

    def check(self, node: DataNode, scope: Scope) -> list[str]:
        # Merged data that is not valid may hold anything
        if not isinstance(node.value, list):
            return []
        fields = _fields(node.validator)
        errors: list[str] = []
        indexes: dict[tuple[tuple[type, Any], ...], list[int]] = {}
        for index, item in enumerate(node.value):
            # Items that are not maps are validated by the item validators
            if not isinstance(item, dict):
                continue
            missing = [f for f in fields if item.get(f) is None]
            errors += [f"Primary key '{f}' missing in item {index}" for f in missing]
            # Maps and lists can't be compared, whatever the item validators allow
            nested = [f for f in fields if f not in missing and not _hashable(item[f])]
            errors += [
                f"Primary key '{f}' in item {index} must be a single value, not "
                f"{_kind(item[f])}"
                for f in nested
            ]
            if missing or nested:
                continue
            # Typed so that 1, "1" and True are different values
            key_value = tuple((type(item[f]), item[f]) for f in fields)
            indexes.setdefault(key_value, []).append(index)
        for key_value, items in indexes.items():
            if len(items) == 1:
                continue
            key = ", ".join(
                f"{f}={v}" for f, (_, v) in zip(fields, key_value, strict=True)
            )
            if scope == Scope.DOCUMENT:
                # Item numbers of the merged data are of no help to find them
                errors.append(
                    f"Duplicate primary key {key} across files"
                    " (with conflicting values that prevent merging)"
                )
            else:
                errors.append(
                    f"Duplicate primary key {key} in items "
                    + ", ".join(str(i) for i in items)
                )
        return errors
