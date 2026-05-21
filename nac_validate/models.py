# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Data models and base class for validation rules.

Defines RuleBase (the base class rules should subclass) and Violation
(a single detected issue).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar


class RuleBase:
    """Base class for validation rules.

    Subclasses must set ``id`` and ``description`` as class attributes
    and implement ``match()`` as a classmethod.

    Optional attributes have sensible defaults; override them on your
    rule class to enable rich output.
    """

    id: ClassVar[str]
    description: ClassVar[str]

    severity: ClassVar[str] = "HIGH"
    title: ClassVar[str] = ""
    explanation: ClassVar[str] = ""
    recommendation: ClassVar[str] = ""
    affected_items_label: ClassVar[str] = "Affected Items"
    references: ClassVar[list[str]] = []

    @classmethod
    def match(cls, data: dict[str, Any], *args: Any) -> Any:
        raise NotImplementedError


@dataclass
class Violation:
    """A single violation detected by a rule.

    Attributes:
        message: Human-readable description of what's wrong.
        path: Schema path where the violation occurred.
        details: Structured data for programmatic access.
    """

    message: str
    path: str = ""
    details: dict[str, Any] = field(default_factory=dict)


def _is_violation_list(result: list[Any]) -> bool:
    """Check if a list contains Violation objects (vs legacy strings)."""
    return len(result) > 0 and all(isinstance(item, Violation) for item in result)
