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
from typing import Any

from ..exceptions import SchemaError
from .base import Extension, Scope
from .primary_key import PrimaryKey
from .walker import known_keywords, walk_data, walk_schema

__all__ = [
    "EXTENSIONS",
    "Extension",
    "Scope",
    "check_data",
    "check_schema",
    "used_extensions",
]

logger = logging.getLogger(__name__)

EXTENSIONS: tuple[Extension, ...] = (PrimaryKey(),)


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
) -> list[str]:
    """Check data that passed Yamale validation against the extensions.

    Returns:
        Violations in Yamale's error format (``path: message``)
    """
    active = [ext for ext in extensions if scope in ext.scopes]
    if not active:
        return []
    errors: list[str] = []
    for node in walk_data(schema, data, strict):
        for ext in active:
            if ext.applies(node.validator):
                path = ".".join(str(p) for p in node.path)
                errors += [f"{path}: {m}" for m in ext.check(node, scope)]
    return errors
