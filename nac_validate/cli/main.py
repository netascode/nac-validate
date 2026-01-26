# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

import json
import logging
import sys
from dataclasses import asdict
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer

import nac_validate.validator

from ..constants import Colors
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


def print_rules_list(rules_path: Path) -> None:
    """Print all available validation rules and exit."""
    try:
        validator = nac_validate.validator.Validator(
            schema_path=Path(".schema.yaml"),  # Dummy, won't be used
            rules_path=rules_path,
        )
    except Exception:
        print(f"{Colors.YELLOW}Could not load rules from {rules_path}{Colors.RESET}")
        raise typer.Exit(1)

    if not validator.rules:
        print(f"{Colors.YELLOW}No rules found in {rules_path}{Colors.RESET}")
        raise typer.Exit(0)

    print(f"\n{Colors.CYAN}{Colors.BOLD}Available Validation Rules:{Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}\n")

    # Sort rules by ID
    sorted_rules = sorted(validator.rules.items(), key=lambda x: int(x[0]))

    for rule_id, rule in sorted_rules:
        severity = getattr(rule, "severity", "MEDIUM")
        if severity == "HIGH":
            severity_color = Colors.RED
        elif severity == "MEDIUM":
            severity_color = Colors.YELLOW
        else:
            severity_color = Colors.CYAN

        print(
            f"  {Colors.BOLD}[{rule_id}]{Colors.RESET} "
            f"{rule.description} "
            f"{severity_color}({severity}){Colors.RESET}"
        )

    print(f"\n{Colors.DIM}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.DIM}Total: {len(validator.rules)} rules{Colors.RESET}\n")
    raise typer.Exit(0)


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


class OutputFormat(str, Enum):
    TEXT = "text"
    JSON = "json"


def version_callback(value: bool) -> None:
    if value:
        print(f"nac-validate, version {nac_validate.__version__}")
        raise typer.Exit()


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


@app.command()
def main(
    paths: Annotated[
        list[Path] | None,
        typer.Argument(
            help="List of paths pointing to YAML files or directories.",
            exists=True,
            dir_okay=True,
            file_okay=True,
        ),
    ] = None,
    verbosity: Verbosity = VerbosityLevel.WARNING,
    schema: Schema = DEFAULT_SCHEMA,
    rules: Rules = DEFAULT_RULES,
    output: Output = None,
    non_strict: NonStrict = False,
    format: Format = OutputFormat.TEXT,
    version: Version = False,
    list_rules: ListRules = False,
) -> None:
    """A CLI tool to perform syntactic and semantic validation of YAML files."""
    # For JSON format at default verbosity, suppress logging to keep stdout clean
    if format == OutputFormat.JSON and verbosity == VerbosityLevel.WARNING:
        configure_logging("CRITICAL")
    else:
        configure_logging(verbosity)

    # Handle --list-rules
    if list_rules:
        print_rules_list(rules)
        # print_rules_list raises typer.Exit, but just in case:
        raise typer.Exit(0)

    # Require paths for validation
    if not paths:
        print(
            f"{Colors.RED}Error: Missing argument 'PATHS...'.{Colors.RESET}\n"
            f"Use --help for usage information, or --list-rules to see available rules."
        )
        raise typer.Exit(1)

    try:
        validator = nac_validate.validator.Validator(schema, rules)
        validator.validate_syntax(paths, not non_strict, format == OutputFormat.TEXT)
        validator.validate_semantics(paths, format == OutputFormat.TEXT)
        if output:
            validator.write_output(paths, output)

    except (SchemaNotFoundError, RulesDirectoryNotFoundError, RuleLoadError) as e:
        if format == OutputFormat.JSON:
            print(
                json.dumps(
                    {"error": str(e), "syntax_errors": [], "semantic_errors": []}
                )
            )
        else:
            logger.error(str(e))
        raise typer.Exit(1) from e

    except SyntaxValidationError as e:
        if format == OutputFormat.JSON:
            # Omit None values from syntax errors (line/column not always available)
            syntax_errors = [
                {k: v for k, v in asdict(r).items() if v is not None}
                for r in e.structured_results
            ]
            json_output = {
                "syntax_errors": syntax_errors,
                "semantic_errors": [],
            }
            print(json.dumps(json_output, indent=2))
        # For text format, errors are already logged by the validator
        raise typer.Exit(1) from e

    except SemanticValidationError as e:
        if format == OutputFormat.JSON:
            json_output = {
                "syntax_errors": [],
                "semantic_errors": [asdict(r) for r in e.structured_results],
            }
            print(json.dumps(json_output, indent=2))
        # For text format, errors are already logged by the validator
        raise typer.Exit(1) from e

    except Exception as e:
        if format == OutputFormat.JSON:
            print(
                json.dumps(
                    {
                        "error": f"Unexpected error: {e}",
                        "syntax_errors": [],
                        "semantic_errors": [],
                    }
                )
            )
        else:
            logger.error(f"Unexpected error: {e}")
        raise typer.Exit(1) from e

    # Success
    if format == OutputFormat.JSON:
        print(json.dumps({"syntax_errors": [], "semantic_errors": []}))
    raise typer.Exit(0)
