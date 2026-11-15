# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Helpers to compare the values of list items for key extensions."""

from typing import Any, TypeGuard

# A typed value, so that 1, "1" and True are different values
TypedValue = tuple[type, Any]


def split_fields(value: str) -> list[str]:
    """Return the field names of a comma-separated string."""
    return [f.strip() for f in value.split(",")]


def valid_fields(value: Any) -> TypeGuard[str]:
    """Return whether the value names fields: non-empty, none repeated."""
    if not isinstance(value, str):
        return False
    fields = split_fields(value)
    return all(fields) and len(set(fields)) == len(fields)


def is_single_value(value: Any) -> bool:
    """Return whether the value can be compared, i.e. is not a map or list."""
    try:
        hash(value)
    except TypeError:
        return False
    return True


def kind(value: Any) -> str:
    """Return the kind of a value for messages, e.g. ``a map``."""
    if isinstance(value, dict):
        return "a map"
    if isinstance(value, list):
        return "a list"
    return f"a {type(value).__name__}"


def typed(value: Any) -> TypedValue:
    """Return the value with its type, so that values of different types differ."""
    return (type(value), value)


def format_key(fields: list[str], values: tuple[TypedValue, ...]) -> str:
    """Format the set fields of a key, e.g. ``node=1, name=a``."""
    return ", ".join(
        f"{f}={v}" for f, (_, v) in zip(fields, values, strict=True) if v is not None
    )
