# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Base class for schema extensions."""

from collections.abc import Sequence
from enum import Enum
from typing import Any, ClassVar

from yamale.validators import Validator

from .walker import DataNode, KeyPath, known_keywords


class Scope(Enum):
    """Data an extension is checked against."""

    # Every file on its own, so violations name the file
    FILE = "file"
    # The data merged from all files, for violations only visible after merging
    DOCUMENT = "document"


class Extension:
    """A schema extension, configured by keyword arguments of Yamale validators.

    Subclasses set ``keywords`` and implement ``check()``, or ``check_nodes()``
    to relate values across the data. An extension is only checked against
    data that passed the Yamale validation.

    Attributes:
        keywords: Keyword arguments configuring the extension
        validator_types: Validators the keywords are supported on
        scopes: Data the extension is checked against
        relates_values: Whether the extension overrides ``check_nodes()``
    """

    keywords: ClassVar[tuple[str, ...]]
    validator_types: ClassVar[tuple[type[Validator], ...]] = (Validator,)
    scopes: ClassVar[frozenset[Scope]] = frozenset({Scope.FILE})
    relates_values: ClassVar[bool] = False

    def configured(self, validator: Validator) -> list[str]:
        """Return the keywords of this extension the validator sets.

        A keyword Yamale itself supports on the validator is Yamale's.
        """
        used = [k for k in self.keywords if k in validator.kwargs]
        if used:
            known = known_keywords(validator)
            used = [k for k in used if k not in known]
        return used

    def applies(self, validator: Validator) -> bool:
        """Return whether the validator configures this extension."""
        return bool(self.configured(validator))

    def check_schema(self, validator: Validator) -> list[str]:
        """Return problems with the extension's keywords on the validator."""
        return []

    def check_whole_schema(self, schema: Any) -> list[str]:
        """Return problems that need the whole schema, e.g. names used across it.

        Problems name their location themselves.
        """
        return []

    def accepts(self, validator: Validator, value: Any) -> bool:
        """Return whether the value satisfies the extension on the validator.

        Used to choose among the validators of ``any()``, ``list()`` and
        ``subset()`` a value matches in Yamale, so only extensions checking
        single values need to override it.
        """
        return True

    def check(self, node: DataNode, scope: Scope) -> list[str]:
        """Return violations of the value validated by the node's validator."""
        raise NotImplementedError

    def check_nodes(
        self, schema: Any, nodes: Sequence[DataNode], data: Any, scope: Scope
    ) -> list[tuple[KeyPath, str]]:
        """Return violations of the walked data as ``(path, message)``.

        By default every node whose validator configures the extension is
        checked on its own with ``check()``. Extensions relating values across
        the data override this.
        """
        return [
            (node.path, message)
            for node in nodes
            if self.applies(node.validator)
            for message in self.check(node, scope)
        ]


class Annotation(Extension):
    """An extension only describing the schema, never checked against data.

    Subclasses set ``keywords`` and implement ``check_schema()``.
    """

    scopes: ClassVar[frozenset[Scope]] = frozenset[Scope]()

    def check(self, node: DataNode, scope: Scope) -> list[str]:
        return []
