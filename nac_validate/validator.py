# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

import importlib
import importlib.util
import logging
import os
import sys
import warnings
from inspect import signature
from pathlib import Path
from typing import Any

import yamale
from nac_yaml.yaml import load_yaml_files, write_yaml_file
from ruamel import yaml
from yamale.yamale_error import YamaleError

from .cli.defaults import DEFAULT_RULES, DEFAULT_SCHEMA
from .exceptions import (
    RuleLoadError,
    RulesDirectoryNotFoundError,
    SchemaNotFoundError,
    SemanticErrorResult,
    SemanticValidationError,
    SyntaxErrorResult,
    SyntaxValidationError,
)
from .models import GroupedRuleResult, RuleResult
from .output_formatter import (
    format_checklist_summary,
    format_json_result,
    format_semantic_error,
)

logger = logging.getLogger(__name__)


class Validator:
    def __init__(self, schema_path: Path, rules_path: Path):
        self.data: dict[str, Any] | None = None
        self.schema = None
        if os.path.exists(schema_path):
            logger.info("Loading schema")
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    action="ignore",
                    category=SyntaxWarning,
                    message="invalid escape sequence",
                )
                self.schema = yamale.make_schema(schema_path, parser="ruamel")
        elif schema_path == DEFAULT_SCHEMA:
            logger.info("No schema file found")
        else:
            raise SchemaNotFoundError(f"Schema file not found: {schema_path}")
        self.errors: list[str] = []
        self.structured_syntax_errors: list[SyntaxErrorResult] = []
        self.rules = {}
        if os.path.exists(rules_path):
            logger.info("Loading rules")
            for filename in sorted(os.listdir(rules_path)):
                if Path(filename).suffix == ".py":
                    try:
                        file_path = Path(rules_path, filename)
                        spec = importlib.util.spec_from_file_location(
                            "nac_validate.rules", file_path
                        )
                        if spec is not None:
                            mod = importlib.util.module_from_spec(spec)
                            sys.modules["nac_validate.rules"] = mod
                            if spec.loader is not None:
                                spec.loader.exec_module(mod)
                                self.rules[mod.Rule.id] = mod.Rule
                    except Exception as e:
                        raise RuleLoadError(filename, str(e)) from e
        elif rules_path == DEFAULT_RULES:
            logger.info("No rules found")
        else:
            raise RulesDirectoryNotFoundError(
                f"Rules directory not found: {rules_path}"
            )

    def _validate_syntax_file(self, file_path: Path, strict: bool = True) -> None:
        """Run syntactic validation for a single file"""
        if os.path.isfile(file_path) and file_path.suffix in [".yaml", ".yml"]:
            logger.info("Validate file: %s", file_path)

            # YAML syntax validation
            data = None
            try:
                data = load_yaml_files([file_path])
            except yaml.error.MarkedYAMLError as e:
                line: int | None = None
                column: int | None = None
                if e.problem_mark is not None:
                    line = e.problem_mark.line + 1
                    column = e.problem_mark.column + 1
                line_str = line if line is not None else 0
                column_str = column if column is not None else 0
                msg = f"Syntax error '{file_path}': Line {line_str}, Column {column_str} - {e.problem}"
                logger.error(msg)
                self.errors.append(msg)
                self.structured_syntax_errors.append(
                    SyntaxErrorResult(
                        file=str(file_path),
                        line=line,
                        column=column,
                        message=e.problem or "Unknown YAML syntax error",
                    )
                )
                return

            # Schema syntax validation
            if self.schema is None or data is None:
                return
            try:
                yamale.validate(self.schema, [(data, file_path)], strict=strict)
            except YamaleError as e:
                for result in e.results:
                    for err in result.errors:
                        # Generate a meaningful path representation
                        named_path = self._get_named_path(
                            data, err.split(":")[0].strip()
                        )
                        transformed_err = err.replace(
                            err.split(":")[0].strip(), named_path
                        )
                        msg = f"Syntax error '{result.data}': {transformed_err}"
                        logger.error(msg)
                        self.errors.append(msg)
                        self.structured_syntax_errors.append(
                            SyntaxErrorResult(
                                file=str(result.data),
                                line=None,
                                column=None,
                                message=transformed_err,
                            )
                        )

    def _get_named_path(self, data: dict[str, Any], path: str) -> str:
        """Convert a numeric path to a named path for better error messages."""
        path_segments = path.split(".")
        named_path = []
        current: Any = data

        for segment in path_segments:
            try:
                if segment.isdigit() and isinstance(current, list):
                    current_item = current[int(segment)]
                    if isinstance(current_item, dict) and current_item:
                        # Use the first key-value pair as the identifier
                        primary_key = next(iter(current_item.items()))
                        named_path.append(f"[{primary_key[0]}={primary_key[1]}]")
                    current = current_item
                elif isinstance(current, dict) and segment in current:
                    named_path.append(segment)
                    current = current[segment]
                else:
                    named_path.append(segment)
            except (IndexError, KeyError, TypeError):
                # Append the segment as is if an error occurs
                named_path.append(segment)

        if named_path:
            return ".".join(named_path)
        else:
            return path

    def validate_syntax(
        self, input_paths: list[Path], strict: bool = True, rich_output: bool = True
    ) -> None:
        """Run syntactic validation"""
        # Clear any previous errors
        self.errors.clear()
        self.structured_syntax_errors.clear()

        for input_path in input_paths:
            if os.path.isfile(input_path):
                self._validate_syntax_file(input_path, strict)
            else:
                for dir, _subdir, files in os.walk(input_path):
                    for filename in files:
                        file_path = Path(dir, filename)
                        self._validate_syntax_file(file_path, strict)

        if self.errors:
            raise SyntaxValidationError(
                self.errors.copy(), self.structured_syntax_errors.copy()
            )

    def _get_violation_count(
        self, result: RuleResult | GroupedRuleResult | list[str]
    ) -> int:
        """Get the violation count from a rule result.

        Args:
            result: Structured result or string list

        Returns:
            Number of violations
        """
        if isinstance(result, RuleResult | GroupedRuleResult):
            return len(result)
        # String list - try to extract count from content
        if not result:
            return 0
        # For rich formatted content, try to find "Found N" pattern
        import re

        for item in result:
            match = re.search(r"Found (\d+)", str(item))
            if match:
                return int(match.group(1))
        # Fallback to list length
        return len(result)

    def _result_has_violations(
        self, result: RuleResult | GroupedRuleResult | list[str]
    ) -> bool:
        """Check if a rule result contains violations.

        Args:
            result: Structured result or string list

        Returns:
            True if there are violations
        """
        if isinstance(result, RuleResult | GroupedRuleResult):
            return bool(result)
        return len(result) > 0

    def validate_semantics(
        self, input_paths: list[Path], rich_output: bool = True
    ) -> None:
        """Run semantic validation"""
        if not self.rules:
            return

        logger.info("Loading yaml files from %s", input_paths)
        if self.data is None:
            self.data = load_yaml_files(input_paths)

        semantic_errors: list[str] = []
        structured_results: list[SemanticErrorResult] = []
        # Store raw results for JSON output
        raw_results: dict[str, RuleResult | GroupedRuleResult | list[str]] = {}

        for rule in self.rules.values():
            logger.info("Verifying rule id %s", rule.id)
            sig = signature(rule.match)
            if len(sig.parameters) == 1:
                result = rule.match(self.data)
            elif len(sig.parameters) == 2:
                result = rule.match(self.data, self.schema)

            if self._result_has_violations(result):
                raw_results[rule.id] = result

        if raw_results:
            failed_rules = []
            for rule_id, result in raw_results.items():
                rule = self.rules[rule_id]
                severity = getattr(rule, "severity", "HIGH")
                violation_count = self._get_violation_count(result)

                # Build structured result for JSON output
                json_result = format_json_result(
                    rule_id=rule_id,
                    description=rule.description,
                    severity=severity,
                    result=result,
                )
                structured_results.append(
                    SemanticErrorResult(
                        rule_id=rule_id,
                        description=rule.description,
                        # Store structured data instead of raw strings
                        errors=json_result.get(
                            "violations", json_result.get("errors", [])
                        ),
                    )
                )

                if rich_output:
                    # Rich text output with colors and formatting
                    formatted_msg = format_semantic_error(
                        rule_id=rule_id,
                        description=rule.description,
                        severity=severity,
                        result=result,
                    )
                    # Print directly to stderr for immediate visual feedback
                    print(formatted_msg, file=sys.stderr)
                    semantic_errors.append(f"Rule {rule_id}: {rule.description}")

                    # Collect info for checklist summary
                    failed_rules.append(
                        {
                            "rule_id": rule_id,
                            "description": rule.description,
                            "severity": severity,
                            "violation_count": violation_count,
                        }
                    )
                else:
                    # Simple output for JSON mode (logging suppressed)
                    header = f"Semantic error, rule {rule_id}: {rule.description}:"
                    logger.error(header)
                    semantic_errors.append(header)

            # Print checklist summary at the end (only for rich output)
            if rich_output:
                checklist = format_checklist_summary(failed_rules)
                if checklist:
                    print(checklist, file=sys.stderr)

            raise SemanticValidationError(semantic_errors, structured_results)

    def write_output(self, input_paths: list[Path], path: Path) -> None:
        if self.data is None:
            self.data = load_yaml_files(input_paths)
        write_yaml_file(self.data, path)
