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
from nac_artifacts import ArtifactError

import nac_validate.validator

from ..constants import DEFAULT_RULES, DEFAULT_SCHEMA, Colors, ExitCode
from ..exceptions import (
    RuleLoadError,
    RulesDirectoryNotFoundError,
    SchemaConflictError,
    SchemaNotFoundError,
    SemanticValidationError,
    SyntaxValidationError,
)
from ..output_formatter import (
    format_artifacts_list,
)
from .options import (
    Bundle,
    Compact,
    Format,
    ListArtifacts,
    ListRules,
    ModuleDir,
    NoColor,
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

# Problems with the schema, rules or artifacts, reported as configuration errors
CONFIG_ERRORS = (
    SchemaNotFoundError,
    SchemaConflictError,
    RulesDirectoryNotFoundError,
    RuleLoadError,
    ArtifactError,
)


def print_artifacts_list(
    schema: Path,
    rules_path: list[Path],
    bundles: list[Path] | None,
    module_dir: Path | None,
) -> None:
    """Load and print the effective schema, layers and rules, then exit."""
    try:
        validator = nac_validate.validator.Validator.from_project(
            Path.cwd(),
            schema=schema,
            rules=rules_path,
            bundles=bundles,
            module_dir=module_dir,
        )
    except CONFIG_ERRORS as e:
        print(f"{Colors.YELLOW}Could not load rules or artifacts: {e}{Colors.RESET}")
        raise typer.Exit(ExitCode.CONFIG_ERROR) from None

    print(format_artifacts_list(validator))
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
    rules: Rules = None,
    output: Output = None,
    non_strict: NonStrict = False,
    format: Format = OutputFormat.TEXT,
    no_color: NoColor = False,
    compact: Compact = False,
    version: Version = False,
    list_artifacts: ListArtifacts = False,
    list_rules: ListRules = False,
    bundle: Bundle = None,
    module_dir: ModuleDir = None,
) -> None:
    """A CLI tool to perform syntactic and semantic validation of YAML files."""
    if rules is None:
        rules = [DEFAULT_RULES]

    if no_color:
        Colors.disable()

    # For JSON format at default verbosity, suppress logging to keep stdout clean
    if format == OutputFormat.JSON and verbosity == VerbosityLevel.WARNING:
        configure_logging("CRITICAL")
    else:
        configure_logging(verbosity)

    # Handle --list-artifacts (and its hidden alias --list-rules)
    if list_artifacts or list_rules:
        print_artifacts_list(schema, rules, bundle, module_dir)
        # print_artifacts_list raises typer.Exit, but just in case:
        raise typer.Exit(ExitCode.SUCCESS)

    # Require paths for validation
    if not paths:
        print(
            f"{Colors.RED}Error: Missing argument 'PATHS...'.{Colors.RESET}\n"
            f"Use --help for usage information, or --list-artifacts to see the effective schema and rules."
        )
        raise typer.Exit(ExitCode.CONFIG_ERROR)

    validator = None
    rich_output = format == OutputFormat.TEXT

    try:
        validator = nac_validate.validator.Validator.from_project(
            Path.cwd(),
            schema=schema,
            rules=rules,
            bundles=bundle,
            module_dir=module_dir,
        )
        validator.validate_syntax(paths, not non_strict, rich_output)
        validator.validate_semantics(paths, rich_output, compact)
        if output:
            validator.write_output(paths, output)

    except CONFIG_ERRORS as e:
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
            syntax_errors = [
                {k: v for k, v in asdict(r).items() if v is not None}
                for r in e.structured_results
            ]
            json_output = {
                "syntax_errors": syntax_errors,
                "semantic_errors": [],
            }
            print(json.dumps(json_output, indent=2))
        raise typer.Exit(ExitCode.SYNTAX_ERROR) from e

    except SemanticValidationError as e:
        if format == OutputFormat.JSON:
            json_output = {
                "syntax_errors": [],
                "semantic_errors": [
                    {
                        k: v
                        for k, v in asdict(r).items()
                        if v is not None and v != "" and v != []
                    }
                    for r in e.structured_results
                ],
            }
            print(json.dumps(json_output, indent=2))
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
            logger.error("Unexpected error: %s", e)
        raise typer.Exit(ExitCode.CONFIG_ERROR) from e

    # Success
    if format == OutputFormat.JSON:
        print(json.dumps({"syntax_errors": [], "semantic_errors": []}))
    else:
        validator.print_success_summary()
    raise typer.Exit(ExitCode.SUCCESS)
