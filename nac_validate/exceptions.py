# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Custom exceptions for nac-validate."""

from dataclasses import dataclass


@dataclass
class SyntaxErrorResult:
    """Structured syntax validation error."""

    file: str
    line: int | None
    column: int | None
    message: str


@dataclass
class SemanticErrorResult:
    """Structured semantic validation error for a single rule.

    Attributes:
        rule_id: The rule identifier (e.g., "101", "312")
        description: Human-readable rule description
        errors: List of error strings in "path - message" format.
    """

    rule_id: str
    description: str
    errors: list[str]


class ValidationError(Exception):
    """Base class for validation errors."""

    pass


class SchemaNotFoundError(ValidationError):
    """Raised when schema file is not found."""

    pass


class RulesDirectoryNotFoundError(ValidationError):
    """Raised when rules directory is not found."""

    pass


class RuleLoadError(ValidationError):
    """Raised when a rule file fails to load."""

    def __init__(self, filename: str, message: str = ""):
        self.filename = filename
        super().__init__(
            f"Failed loading rule: {filename}" + (f" - {message}" if message else "")
        )


class SyntaxValidationError(ValidationError):
    """Raised when YAML syntax validation fails."""

    def __init__(
        self,
        errors: list[str],
        structured_results: list[SyntaxErrorResult] | None = None,
    ):
        self.errors = errors
        self.structured_results = structured_results or []
        super().__init__(f"Syntax validation failed with {len(errors)} error(s)")


class SemanticValidationError(ValidationError):
    """Raised when semantic validation fails."""

    def __init__(
        self,
        errors: list[str],
        structured_results: list[SemanticErrorResult] | None = None,
    ):
        self.errors = errors
        self.structured_results = structured_results or []
        super().__init__(f"Semantic validation failed with {len(errors)} error(s)")
