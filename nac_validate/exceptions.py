# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Daniel Schmidt <danischm@cisco.com>

"""Custom exceptions for nac-validate."""


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

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"Syntax validation failed with {len(errors)} error(s)")


class SemanticValidationError(ValidationError):
    """Raised when semantic validation fails."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"Semantic validation failed with {len(errors)} error(s)")
