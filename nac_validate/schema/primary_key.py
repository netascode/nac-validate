# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""``list(..., primary_key='name')``: a unique, non-empty key in every item."""

from typing import Any

from yamale.validators import List, Validator

from .base import Extension, Scope
from .walker import DataNode


class PrimaryKey(Extension):
    keywords = ("primary_key",)
    validator_types = (List,)
    # Items with the same key only merge when all their shared fields match,
    # so conflicting items from two files remain duplicates after merging
    scopes = frozenset({Scope.FILE, Scope.DOCUMENT})

    def check_schema(self, validator: Validator) -> list[str]:
        key = validator.kwargs["primary_key"]
        if not isinstance(key, str) or not key:
            return [f"primary_key must be a field name, not {key!r}"]
        return []

    def check(self, node: DataNode, scope: Scope) -> list[str]:
        # Merged data that is not valid may hold anything
        if not isinstance(node.value, list):
            return []
        key = node.validator.kwargs["primary_key"]
        errors = []
        indexes: dict[tuple[type, Any], list[int]] = {}
        for index, item in enumerate(node.value):
            # Items that are not maps are validated by the item validators
            if not isinstance(item, dict):
                continue
            key_value = item.get(key)
            if key_value is None:
                errors.append(f"Primary key '{key}' missing in item {index}")
                continue
            # Typed so that 1, "1" and True are different values
            try:
                indexes.setdefault((type(key_value), key_value), []).append(index)
            except TypeError:
                # Unhashable values (maps, lists) are validated by the item validators
                continue
        for (_, key_value), items in indexes.items():
            if len(items) == 1:
                continue
            if scope == Scope.DOCUMENT:
                # Item numbers of the merged data are of no help to find them
                errors.append(
                    f"Duplicate primary key {key}={key_value} across files"
                    " (with conflicting values that prevent merging)"
                )
            else:
                errors.append(
                    f"Duplicate primary key {key}={key_value} in items "
                    + ", ".join(str(i) for i in items)
                )
        return errors
