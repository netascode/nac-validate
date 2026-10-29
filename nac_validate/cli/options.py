# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""CLI option types and annotated type aliases for Typer.

This module defines the CLI-specific enums and type aliases used by the
main CLI command. Keeping them separate from the command logic makes
main.py a thin orchestration layer.
"""

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

import nac_validate


class VerbosityLevel(StrEnum):
    """Logging verbosity levels for CLI."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class OutputFormat(StrEnum):
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
    list[Path] | None,
    typer.Option(
        "-r",
        "--rules",
        exists=False,
        dir_okay=True,
        file_okay=False,
        help="Path(s) to directories with semantic validation rules (repeatable).",
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


ListArtifacts = Annotated[
    bool,
    typer.Option(
        "--list-artifacts",
        help="List the effective schema, artifact layers and validation rules and exit.",
    ),
]


# Kept for backward compatibility, behaves like --list-artifacts
ListRules = Annotated[
    bool,
    typer.Option(
        "--list-rules",
        hidden=True,
    ),
]


Bundle = Annotated[
    list[Path] | None,
    typer.Option(
        "--bundle",
        exists=False,
        help=(
            "Path to an artifact bundle (zip, tar.gz or directory), repeatable. "
            "Defaults to the .zip, .tar.gz or .tgz files (and bundle/ directory) in .nac/."
        ),
        envvar="NAC_VALIDATE_BUNDLE",
    ),
]


ModuleDir = Annotated[
    Path | None,
    typer.Option(
        "--module-dir",
        exists=False,
        dir_okay=True,
        file_okay=False,
        help=(
            "Path to a module directory containing nac/ artifacts. "
            "Defaults to the module discovered via terraform init."
        ),
        envvar="NAC_VALIDATE_MODULE_DIR",
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


NoColor = Annotated[
    bool,
    typer.Option(
        "--no-color",
        help="Disable colored output.",
        envvar="NO_COLOR",
    ),
]


Compact = Annotated[
    bool,
    typer.Option(
        "--compact",
        help="Use compact output format without rule context details.",
        envvar="NAC_VALIDATE_COMPACT",
    ),
]
