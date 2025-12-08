# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

import logging
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer

import nac_validate
import nac_validate.validator

from ..exceptions import (
    RuleLoadError,
    RulesDirectoryNotFoundError,
    SchemaNotFoundError,
    SemanticValidationError,
    SyntaxValidationError,
)
from .defaults import DEFAULT_RULES, DEFAULT_SCHEMA

app = typer.Typer(add_completion=False)

logger = logging.getLogger(__name__)


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,  # Replaces manual handler clearing
    )


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


YamllintOn = Annotated[
    bool,
    typer.Option(
        "--yamllint-on",
        help="Enable yamllint validation.",
        envvar="NAC_VALIDATE_YAMLLINT_ON",
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
    yamllint_on: YamllintOn = False,
    version: Version = False,
) -> None:
    """A CLI tool to perform syntactic and semantic validation of YAML files."""
    configure_logging(verbosity)

    try:
        validator = nac_validate.validator.Validator(
            schema, rules, enable_yamllint=yamllint_on
        )
        validator.validate_syntax(paths, not non_strict)
        validator.validate_semantics(paths)
        if output:
            validator.write_output(paths, output)

    except (SchemaNotFoundError, RulesDirectoryNotFoundError, RuleLoadError) as e:
        logger.error(str(e))
        raise typer.Exit(1) from e

    except (SyntaxValidationError, SemanticValidationError) as e:
        # Errors are already logged by the validator
        raise typer.Exit(1) from e

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise typer.Exit(1) from e

    # Success - exit with code 0
    raise typer.Exit(0)
