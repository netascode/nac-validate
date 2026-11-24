# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Data models and base class for validation rules.

Defines RuleBase (the base class rules should subclass) and Violation
(a single detected issue).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar

from .constants import DEFAULT_SEVERITY, SEVERITY_SORT_ORDER


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
    def match(cls, *args: Any, **kwargs: Any) -> Any:
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


def known_severity(severity: object) -> str | None:
    """Return the severity in upper case if it is a known level, else None."""
    if isinstance(severity, str):
        upper = severity.upper()
        if upper in SEVERITY_SORT_ORDER:
            return upper
    return None


def rule_severity(rule: Any) -> str:
    """Return the effective severity of a rule.

    The declared severity in upper case if it is ``HIGH``, ``MEDIUM`` or
    ``LOW``, else ``HIGH``: a rule with an unknown severity is never treated
    as less severe than intended.
    """
    return known_severity(getattr(rule, "severity", None)) or DEFAULT_SEVERITY


def is_blocking(severity: str, fail_on: str) -> bool:
    """Whether a violation of the given severity fails validation.

    Args:
        severity: Effective severity of the violated rule.
        fail_on: Lowest severity that fails validation.
    """
    return SEVERITY_SORT_ORDER[severity] <= SEVERITY_SORT_ORDER[fail_on]
