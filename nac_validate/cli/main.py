# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""CLI entry point for nac-validate.

This module is a thin orchestration layer that:
- Parses CLI arguments (via Typer)
- Calls validation services
- Formats and displays output
- Returns appropriate exit codes
"""

import json
import logging
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer

import nac_validate.validator

from ..constants import DEFAULT_RULES, DEFAULT_SCHEMA, YAML_SUFFIXES, Colors, ExitCode
from ..exceptions import (
    RuleLoadError,
    RulesDirectoryNotFoundError,
    SchemaNotFoundError,
    SemanticValidationError,
    SyntaxValidationError,
)
from ..output_formatter import format_rules_list, format_validation_summary
from .options import (
    Format,
    ListRules,
    NonStrict,
    Output,
    OutputFormat,
    Rules,
    Schema,
    Verbosity,
    VerbosityLevel,
    Version,
)

app = typer.Typer(add_completion=False)

logger = logging.getLogger(__name__)


def print_rules_list(rules_path: Path) -> None:
    """Load and print all available validation rules, then exit."""
    try:
        validator = nac_validate.validator.Validator.from_paths(
            schema_path=DEFAULT_SCHEMA,
            rules_path=rules_path,
        )
    except Exception as e:
        print(
            f"{Colors.YELLOW}Could not load rules from {rules_path}: {e}{Colors.RESET}"
        )
        raise typer.Exit(ExitCode.CONFIG_ERROR) from None

    if not validator.rules:
        print(f"{Colors.YELLOW}No rules found in {rules_path}{Colors.RESET}")
        raise typer.Exit(ExitCode.SUCCESS)

    print(format_rules_list(validator.rules))
    raise typer.Exit(ExitCode.SUCCESS)


def configure_logging(level: str) -> None:
    """Configure logging with the specified level."""
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )


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
        raise typer.Exit(ExitCode.SUCCESS)

    # Require paths for validation
    if not paths:
        print(
            f"{Colors.RED}Error: Missing argument 'PATHS...'.{Colors.RESET}\n"
            f"Use --help for usage information, or --list-rules to see available rules."
        )
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    validator = None
    file_count = 0

    try:
        validator = nac_validate.validator.Validator.from_paths(schema, rules)
        validator.validate_syntax(paths, not non_strict)

        # Count files validated
        for path in paths:
            if path.is_file():
                file_count += 1
            elif path.is_dir():
                file_count += sum(
                    1 for f in path.rglob("*") if f.suffix in YAML_SUFFIXES
                )

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
        raise typer.Exit(ExitCode.CONFIG_ERROR) from e

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
        else:
            # Print summary for text format
            print(
                format_validation_summary(
                    syntax_passed=False,
                    semantic_passed=True,  # Didn't get to semantic validation
                    file_count=file_count,
                )
            )
        raise typer.Exit(ExitCode.SYNTAX_ERROR) from e

    except SemanticValidationError as e:
        if format == OutputFormat.JSON:
            json_output = {
                "syntax_errors": [],
                "semantic_errors": [asdict(r) for r in e.structured_results],
            }
            print(json.dumps(json_output, indent=2))
        else:
            # Print summary for text format
            print(
                format_validation_summary(
                    syntax_passed=True,
                    semantic_passed=False,
                    file_count=file_count,
                    semantic_errors=e.structured_results,
                    rules=validator.rules if validator else None,
                )
            )
        raise typer.Exit(ExitCode.SEMANTIC_ERROR) from e

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
        raise typer.Exit(ExitCode.CONFIG_ERROR) from e

    # Success
    if format == OutputFormat.JSON:
        print(json.dumps({"syntax_errors": [], "semantic_errors": []}))
    else:
        print(
            format_validation_summary(
                syntax_passed=True,
                semantic_passed=True,
                file_count=file_count,
            )
        )
    raise typer.Exit(ExitCode.SUCCESS)
