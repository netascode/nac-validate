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


def format_value(value: Any) -> str:
    """Format a single value for messages as it is written in YAML.

    Booleans and nulls are lowercase, and strings that would read as another
    type (e.g. ``'1'`` or ``'true'``) are quoted, so values of different types
    don't look the same.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str) and _reads_as_other_type(value):
        return repr(value)
    return str(value)


def _reads_as_other_type(value: str) -> bool:
    if value != value.strip() or value.lower() in _YAML_WORDS:
        return True
    try:
        float(value)
    except ValueError:
        return False
    return True


_YAML_WORDS = frozenset({"", "~", "null", "true", "false", "yes", "no", "on", "off"})


def format_key(fields: list[str], values: tuple[TypedValue, ...]) -> str:
    """Format the set fields of a key, e.g. ``node=1, name=a``."""
    return ", ".join(
        f"{f}={format_value(v)}"
        for f, (_, v) in zip(fields, values, strict=True)
        if v is not None
    )


def key_label(item: Any, key_fields: list[str]) -> str | None:
    """Return a list item's label by its key, e.g. ``[name=a]``.

    None if the item is not a map or does not set every key field to a
    single value.
    """
    if not isinstance(item, dict):
        return None
    values = [item.get(f) for f in key_fields]
    if not all(v is not None and is_single_value(v) for v in values):
        return None
    return f"[{format_key(key_fields, tuple(typed(v) for v in values))}]"


def item_label(item: Any, index: int, key_fields: list[str] | None) -> str:
    """Return a list item's label for messages, e.g. ``[name=a]``.

    Items are named by the list's primary key, as in the paths of messages;
    an item without a usable key is named by its index, e.g. ``[3]``.
    """
    label = key_label(item, key_fields) if key_fields is not None else None
    return label if label is not None else f"[{index}]"
