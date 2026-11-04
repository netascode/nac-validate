# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Base class for schema extensions."""

from enum import Enum
from typing import ClassVar

from yamale.validators import Validator

from .walker import DataNode, known_keywords


class Scope(Enum):
    """Data an extension is checked against."""

    # Every file on its own, so violations name the file
    FILE = "file"
    # The data merged from all files, for violations only visible after merging
    DOCUMENT = "document"


class Extension:
    """A schema extension, configured by keyword arguments of Yamale validators.

    Subclasses set ``keywords`` and implement ``check()``. An extension is
    only checked against data that passed the Yamale validation.

    Attributes:
        keywords: Keyword arguments configuring the extension
        validator_types: Validators the keywords are supported on
        scopes: Data the extension is checked against
    """

    keywords: ClassVar[tuple[str, ...]]
    validator_types: ClassVar[tuple[type[Validator], ...]] = (Validator,)
    scopes: ClassVar[frozenset[Scope]] = frozenset({Scope.FILE})

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

    def check(self, node: DataNode, scope: Scope) -> list[str]:
        """Return violations of the value validated by the node's validator."""
        raise NotImplementedError
