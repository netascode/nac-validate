# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Daniel Schmidt <danischm@cisco.com>

import logging
import sys
from enum import Enum

import typer
from typing_extensions import Annotated
from pathlib import Path
import errorhandler

import nac_validate.validator
from .defaults import DEFAULT_SCHEMA, DEFAULT_RULES

app = typer.Typer(add_completion=False)

logger = logging.getLogger(__name__)

error_handler = errorhandler.ErrorHandler()


def configure_logging(level: str) -> None:
    if level == "DEBUG":
        lev = logging.DEBUG
    elif level == "INFO":
        lev = logging.INFO
    elif level == "WARNING":
        lev = logging.WARNING
    elif level == "ERROR":
        lev = logging.ERROR
    else:
        lev = logging.CRITICAL
    logger = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(lev)
    error_handler.reset()


class VerbosityLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


def version_callback(value: bool) -> None:
    if value:
        print(f"nac-validate, version {nac_validate.__version__}")
        raise typer.Exit()


Paths = Annotated[
    list[Path],
    typer.Argument(
        help="List of paths pointing to YAML files or directories.",
        exists=True,
        dir_okay=True,
        file_okay=True,
    ),
]


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


@app.command()
def main(
    paths: Paths,
    verbosity: Verbosity = VerbosityLevel.WARNING,
    schema: Schema = DEFAULT_SCHEMA,
    rules: Rules = DEFAULT_RULES,
    output: Output = None,
    non_strict: NonStrict = False,
    version: Version = False,
) -> None:
    """A CLI tool to perform syntactic and semantic validation of YAML files."""
    configure_logging(verbosity)

    validator = nac_validate.validator.Validator(schema, rules)
    error = validator.validate_syntax(paths, not non_strict)
    if error:
        exit()
    validator.validate_semantics(paths)
    if output:
        validator.write_output(paths, output)

    if not error_handler.fired:
        print("Validation successful!")
    exit()


def exit() -> None:
    if error_handler.fired:
        raise typer.Exit(1)
    else:
        raise typer.Exit(0)
