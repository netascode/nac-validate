# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""CLI option types and annotated type aliases for Typer.

This module defines the CLI-specific enums and type aliases used by the
main CLI command. Keeping them separate from the command logic makes
main.py a thin orchestration layer.
"""

from enum import Enum
from pathlib import Path
from typing import Annotated

import typer

import nac_validate


class VerbosityLevel(str, Enum):
    """Logging verbosity levels for CLI."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class OutputFormat(str, Enum):
    """Output format options for validation results."""

    TEXT = "text"
    JSON = "json"


def version_callback(value: bool) -> None:
    """Display version and exit."""
    if value:
        print(f"nac-validate, version {nac_validate.__version__}")
        raise typer.Exit()


# Type aliases for CLI options
Verbosity = Annotated[
    VerbosityLevel,
    typer.Option(
        "-v",
        "--verbosity",
        help="Verbosity level.",
        envvar="NAC_VALIDATE_VERBOSITY",
        is_eager=True,
    ),
]


Schema = Annotated[
    Path,
    typer.Option(
        "-s",
        "--schema",
        exists=False,
        dir_okay=False,
        file_okay=True,
        help="Path to schema file.",
        envvar="NAC_VALIDATE_SCHEMA",
    ),
]


Rules = Annotated[
    Path,
    typer.Option(
        "-r",
        "--rules",
        exists=False,
        dir_okay=True,
        file_okay=False,
        help="Path to directory with semantic validation rules.",
        envvar="NAC_VALIDATE_RULES",
    ),
]


Output = Annotated[
    Path | None,
    typer.Option(
        "-o",
        "--output",
        exists=False,
        dir_okay=False,
        file_okay=True,
        help="Write merged content from YAML files to a new YAML file.",
        envvar="NAC_VALIDATE_OUTPUT",
    ),
]


NonStrict = Annotated[
    bool,
    typer.Option(
        "--non-strict",
        help="Accept unexpected elements in YAML files.",
        envvar="NAC_VALIDATE_NON_STRICT",
    ),
]


Version = Annotated[
    bool,
    typer.Option(
        "--version",
        callback=version_callback,
        help="Display version number.",
        is_eager=True,
    ),
]


ListRules = Annotated[
    bool,
    typer.Option(
        "--list-rules",
        help="List all available validation rules and exit.",
    ),
]


Format = Annotated[
    OutputFormat,
    typer.Option(
        "-f",
        "--format",
        help="Output format for validation results.",
        envvar="NAC_VALIDATE_FORMAT",
    ),
]
