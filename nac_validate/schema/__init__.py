# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Schema extensions on top of Yamale.

Extensions are keyword arguments of the standard Yamale validators, which
vanilla Yamale accepts and ignores, so a schema using them still loads and
validates with plain Yamale (without enforcing the extensions). They are
checked in a separate pass over the data once it passed Yamale validation.

To add an extension, subclass ``Extension`` and add it to ``EXTENSIONS``.
"""

import logging
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

from yamale.validators import Validator

from ..exceptions import SchemaError
from .base import Extension, Scope
from .description import Description
from .ip_type import IpType
from .ordered import Ordered
from .primary_key import PrimaryKey
from .reference import (
    LevelChoice,
    Reference,
    ReferenceIndex,
    References,
    references,
)
from .unique import Unique
from .values import key_label, split_fields, valid_fields
from .walker import (
    DataNode,
    KeyInfo,
    KeyPath,
    Kind,
    ListLevel,
    PathInfo,
    SchemaContext,
    SchemaNode,
    known_keywords,
    resolves,
    schema_at,
    walk_data,
    walk_schema,
    walk_schema_contexts,
)

__all__ = [
    "EXTENSIONS",
    "DataNode",
    "Extension",
    "KeyInfo",
    "KeyPath",
    "Kind",
    "LevelChoice",
    "ListLevel",
    "PathInfo",
    "Reference",
    "ReferenceIndex",
    "SchemaContext",
    "SchemaNode",
    "Scope",
    "Violation",
    "check_data",
    "check_schema",
    "references",
    "resolves",
    "schema_at",
    "used_extensions",
    "walk_data",
    "walk_schema",
    "walk_schema_contexts",
    "yamale_violation",
]

logger = logging.getLogger(__name__)

EXTENSIONS: tuple[Extension, ...] = (
    PrimaryKey(),
    Unique(),
    References(),
    IpType(),
    Ordered(),
    Description(),
)


@dataclass(frozen=True)
class Violation:
    """A violation of an extension at a path of the data."""

    # Path segments, kept apart as map keys may contain dots
    path: KeyPath
    message: str
    # Labels of list items in the path by their schema primary key, e.g.
    # ``[name=a]``, as (position in the path, label)
    labels: tuple[tuple[int, str], ...] = ()

    def __str__(self) -> str:
        """Format the violation like a Yamale error (``path: message``)."""
        return f"{'.'.join(str(p) for p in self.path)}: {self.message}"


# A key the data doesn't have
_MISSING = object()


def yamale_violation(error: str, data: Any) -> Violation:
    """Turn a Yamale error (``a.b.0.c: message``) into a violation.

    Yamale joins the path with dots and puts a colon after it, so the path is
    found by following the data: a map key containing dots or colons is kept
    whole, and the position of a list item becomes an integer. The rest of a
    path not found in the data, e.g. a missing required key, is one key.
    """
    colons = [i for i, c in enumerate(error) if c == ":"]
    if not colons:
        return Violation((), error.strip())
    candidates = [
        (*_split_yamale_path(error[:colon].strip(), data), error[colon + 1 :].strip())
        for colon in colons
    ]
    # The first colon after a path that is in the data, else after one that
    # only misses its last key in a map (a required key), else the first one
    for wanted in ("found", "missing_key"):
        for path, state, message in candidates:
            if state == wanted:
                return Violation(path, message)
    path, _state, message = candidates[0]
    return Violation(path, message)


def _split_yamale_path(text: str, data: Any) -> tuple[KeyPath, str]:
    """The segments of a Yamale path, and whether it is in the data.

    The state is ``found`` for a path in the data, ``missing_key`` for one
    whose last key is not in the map it leads to, else ``unknown``.
    """
    if not text:
        return (), "found"
    tokens = text.split(".")
    path: list[str | int] = []
    value = data
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if isinstance(value, list) and token.isascii() and token.isdigit():
            index = int(token)
            path.append(index)
            if index >= len(value):
                return tuple(path), "unknown"
            value = value[index]
            i += 1
            continue
        if isinstance(value, dict):
            # The longest key first, as keys may contain dots
            for j in range(len(tokens), i, -1):
                key = _key(value, ".".join(tokens[i:j]))
                if key is not _MISSING:
                    path.append(key)
                    value = value[key]
                    i = j
                    break
            else:
                return (*path, ".".join(tokens[i:])), "missing_key"
            continue
        return (*path, ".".join(tokens[i:])), "unknown"
    return tuple(path), "found"


def _key(mapping: dict[Any, Any], text: str) -> Any:
    """The key of a map Yamale prints as ``text``, e.g. ``1`` for an int key."""
    if text in mapping:
        return text
    return next((k for k in mapping if str(k) == text), _MISSING)


def check_schema(schema: Any, extensions: Collection[Extension] = EXTENSIONS) -> None:
    """Check the keywords of all validators of a loaded schema.

    Unknown keywords are logged as warnings, as vanilla Yamale ignores them
    too and they might be meant for other tools.

    Raises:
        SchemaError: If an extension keyword is invalid or on an unsupported
            validator
    """
    problems = []
    for node in walk_schema(schema):
        validator = node.validator
        unknown = set(validator.kwargs) - known_keywords(validator)
        for ext in extensions:
            used = ext.configured(validator)
            if not used:
                continue
            unknown -= set(used)
            if not isinstance(validator, ext.validator_types):
                supported = ", ".join(f"{t.tag}()" for t in ext.validator_types)
                problems.append(
                    f"{node.location}: {', '.join(used)} is only supported on "
                    f"{supported}"
                )
                continue
            problems += [f"{node.location}: {p}" for p in ext.check_schema(validator)]
        for keyword in sorted(unknown):
            logger.warning(
                "Unknown schema keyword '%s' at '%s' is ignored", keyword, node.location
            )
    # Checks across the schema rely on the keywords being valid
    if not problems:
        for ext in extensions:
            problems += ext.check_whole_schema(schema)
    if problems:
        raise SchemaError("Invalid schema: " + "; ".join(problems))


def used_extensions(
    schema: Any, extensions: Collection[Extension] = EXTENSIONS
) -> list[Extension]:
    """Return the extensions configured anywhere in the schema."""
    validators = [node.validator for node in walk_schema(schema)]
    return [ext for ext in extensions if any(ext.applies(v) for v in validators)]


def check_data(
    schema: Any,
    data: Any,
    extensions: Collection[Extension],
    scope: Scope,
    strict: bool = True,
) -> list[Violation]:
    """Check data that passed Yamale validation against the extensions."""
    active = [ext for ext in extensions if scope in ext.scopes]
    if not active:
        return []
    # Extensions checking nodes one by one report in data order, extensions
    # relating values across the data after them
    per_node = [e for e in active if not e.relates_values]
    whole = [e for e in active if e.relates_values]
    nodes: list[DataNode] = []
    errors: list[tuple[KeyPath, str]] = []
    # Validators of the lists of the data, by path
    lists: dict[KeyPath, Validator] = {}

    def accepts(validator: Validator, value: Any) -> bool:
        return all(
            ext.accepts(validator, value)
            for ext in extensions
            if ext.applies(validator)
        )

    for node in walk_data(schema, data, strict, accepts):
        if node.levels:
            level = node.levels[-1]
            lists.setdefault(level.path, level.validator)
        if whole:
            nodes.append(node)
        for ext in per_node:
            if ext.applies(node.validator):
                errors += [(node.path, m) for m in ext.check(node, scope)]
    for ext in whole:
        errors += ext.check_nodes(schema, nodes, data, scope)
    return [Violation(p, m, _labels(p, data, lists)) for p, m in errors]


def _labels(
    path: KeyPath, data: Any, lists: dict[KeyPath, Validator]
) -> tuple[tuple[int, str], ...]:
    """Return the labels of the list items in a path by their primary key."""
    labels = []
    value = data
    for position, segment in enumerate(path):
        try:
            item = value[segment]
        except (KeyError, IndexError, TypeError):
            break
        validator = lists.get(path[:position])
        if isinstance(segment, int) and validator is not None:
            key = validator.kwargs.get("primary_key")
            label = key_label(item, split_fields(key)) if valid_fields(key) else None
            if label is not None:
                labels.append((position, label))
        value = item
    return tuple(labels)
