# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Constants and shared definitions for nac-validate."""

from enum import IntEnum
from pathlib import Path

# Default paths
DEFAULT_SCHEMA = Path(".schema.yaml")
DEFAULT_RULES = Path(".rules/")

# Output formatting widths
HEADER_SEPARATOR_WIDTH = 80
SUMMARY_SEPARATOR_WIDTH = 60
MIN_SEPARATOR_LENGTH = 40

# File extensions
YAML_SUFFIXES = (".yaml", ".yml")

# Rule loading
RULE_MODULE_NAME = "nac_validate.rules"
VALID_RULE_MATCH_PARAM_COUNTS = (1, 2)

# Output formatting
MIN_HEADER_LENGTH = 10  # Minimum length for ALL CAPS header detection
UNKNOWN_SEVERITY_SORT_ORDER = 99  # Sort order for unknown severity levels

# Severity sort order
SEVERITY_SORT_ORDER: dict[str, int] = {
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 2,
}


class ExitCode(IntEnum):
    """Exit codes for CLI.

    Specific exit codes help automation distinguish between error types:
    - 0: Validation passed
    - 1: Semantic validation failed (business rule violations)
    - 2: Syntax validation failed (YAML syntax or schema errors)
    - 3: Configuration error (missing schema, invalid rules, etc.)
    """

    SUCCESS = 0
    SEMANTIC_ERROR = 1
    SYNTAX_ERROR = 2
    CONFIG_ERROR = 3


class Colors:
    """ANSI escape codes for terminal colorization."""

    # Standard colors
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"

    # Styles
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Reset
    RESET = "\033[0m"

    # Severity-to-color mapping
    _SEVERITY_COLORS: "dict[str, str]" = {
        "HIGH": RED,
        "MEDIUM": YELLOW,
        "LOW": CYAN,
    }

    @staticmethod
    def for_severity(severity: str) -> str:
        """Get the color code for a severity level.

        Args:
            severity: Severity level (HIGH, MEDIUM, LOW)

        Returns:
            ANSI color code, defaults to CYAN for unknown severities
        """
        return Colors._SEVERITY_COLORS.get(severity, Colors.CYAN)
