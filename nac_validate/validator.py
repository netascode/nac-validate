# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

import importlib.util
import logging
import re
import sys
import warnings
from inspect import signature
from pathlib import Path
from typing import Any

import yamale
from nac_yaml.yaml import load_yaml_files, write_yaml_file
from ruamel import yaml
from yamale.yamale_error import YamaleError

from .constants import (
    DEFAULT_RULES,
    DEFAULT_SCHEMA,
    RULE_MODULE_NAME,
    VALID_RULE_MATCH_PARAM_COUNTS,
    YAML_SUFFIXES,
)
from .exceptions import (
    RuleLoadError,
    RulesDirectoryNotFoundError,
    SchemaNotFoundError,
    SemanticErrorResult,
    SemanticValidationError,
    SyntaxErrorResult,
    SyntaxValidationError,
)
from .models import _is_violation_list
from .output_formatter import (
    format_checklist_summary,
    format_json_result,
    format_semantic_error,
)

logger = logging.getLogger(__name__)


class Validator:
    @staticmethod
    def _load_schema(schema_path: Path) -> Any | None:
        """Load Yamale schema from file path.

        Args:
            schema_path: Path to schema.yaml file

        Returns:
            Loaded yamale.Schema or None if default path doesn't exist

        Raises:
            SchemaNotFoundError: If non-default schema path doesn't exist
        """
        if schema_path.exists():
            logger.info("Loading schema from %s", schema_path)
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    action="ignore",
                    category=SyntaxWarning,
                    message=r".*invalid escape sequence.*",
                )
                return yamale.make_schema(schema_path, parser="ruamel")
        elif schema_path == DEFAULT_SCHEMA:
            logger.info("No schema file found at default path")
            return None
        else:
            raise SchemaNotFoundError(f"Schema file not found: {schema_path}")

    @staticmethod
    def _load_rules_from_dir(rules_path: Path) -> dict[str, Any]:
        """Load validation rules from a single directory."""
        if not rules_path.exists():
            if rules_path == DEFAULT_RULES:
                logger.info("No rules found at default path")
                return {}
            else:
                raise RulesDirectoryNotFoundError(
                    f"Rules directory not found: {rules_path}"
                )

        logger.info("Loading rules from %s", rules_path)
        rules: dict[str, Any] = {}

        for filename in sorted(f.name for f in rules_path.iterdir()):
            if Path(filename).suffix == ".py":
                try:
                    file_path = rules_path / filename
                    spec = importlib.util.spec_from_file_location(
                        RULE_MODULE_NAME, file_path
                    )
                    if spec is not None:
                        mod = importlib.util.module_from_spec(spec)
                        sys.modules[RULE_MODULE_NAME] = mod
                        if spec.loader is not None:
                            spec.loader.exec_module(mod)

                            sig = signature(mod.Rule.match)
                            param_count = len(sig.parameters)
                            if param_count not in VALID_RULE_MATCH_PARAM_COUNTS:
                                raise RuleLoadError(
                                    filename,
                                    f"Rule.match() must accept 1 or 2 parameters, got {param_count}",
                                )
                            rules[mod.Rule.id] = mod.Rule
                except Exception as e:
                    raise RuleLoadError(filename, str(e)) from e

        return rules

    @classmethod
    def _load_rules(cls, rules_path: Path | list[Path]) -> dict[str, Any]:
        """Load validation rules from one or more directories."""
        if isinstance(rules_path, list):
            rules: dict[str, Any] = {}
            for p in rules_path:
                rules.update(cls._load_rules_from_dir(p))
            return rules
        return cls._load_rules_from_dir(rules_path)

    def __init__(self, schema: Any | None, rules: dict[str, Any] | None = None):
        """Initialize validator with pre-loaded schema and rules.

        Args:
            schema: Loaded yamale schema object, or None
            rules: Dictionary mapping rule ID to Rule class
        """
        self.schema = schema
        self.rules: dict[str, Any] = rules if isinstance(rules, dict) else {}
        self.data: dict[str, Any] | None = None
        self.errors: list[str] = []
        self.structured_syntax_errors: list[SyntaxErrorResult] = []

    @classmethod
    def from_paths(
        cls, schema_path: Path, rules_path: Path | list[Path]
    ) -> "Validator":
        """Create validator by loading schema and rules from file system paths.

        This is the primary way to create a Validator in production. It loads
        the schema and rules from disk, validates their structure, and returns
        a fully initialized Validator instance.

        Args:
            schema_path: Path to schema.yaml file
            rules_path: Path to directory containing rule .py files

        Returns:
            Initialized Validator instance

        Raises:
            SchemaNotFoundError: If non-default schema path doesn't exist
            RulesDirectoryNotFoundError: If non-default rules path doesn't exist
            RuleLoadError: If rule file has invalid structure
        """
        schema = cls._load_schema(schema_path)
        rules = cls._load_rules(rules_path)
        return cls(schema, rules)

    def load_data(self, data: dict[str, Any]) -> None:
        """Load a pre-parsed data model directly.

        When data is loaded this way, validate_syntax will validate the schema
        once against the full model instead of walking individual files.

        Args:
            data: Pre-parsed merged YAML data dictionary
        """
        self.data = data

    def _load_data_from_paths(self, input_paths: list[Path]) -> dict[str, Any]:
        """Load and merge YAML data from file system paths.

        Args:
            input_paths: List of paths to load data from

        Returns:
            Merged YAML data dictionary
        """
        logger.info("Loading yaml files from %s", input_paths)
        self.data = load_yaml_files(input_paths)
        return self.data

    def _validate_syntax_file(self, file_path: Path, strict: bool = True) -> None:
        """Run syntactic validation for a single file"""
        if file_path.is_file() and file_path.suffix in YAML_SUFFIXES:
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
        self, input_paths: list[Path] | None = None, strict: bool = True
    ) -> None:
        """Run syntactic validation"""
        self.errors.clear()
        self.structured_syntax_errors.clear()

        if self.data is not None:
            if self.schema is not None:
                source = str(input_paths[0]) if input_paths else "<pre-loaded>"
                try:
                    yamale.validate(
                        self.schema,
                        [(self.data, source)],
                        strict=strict,
                    )
                except YamaleError as e:
                    for result in e.results:
                        for err in result.errors:
                            named_path = self._get_named_path(
                                self.data, err.split(":")[0].strip()
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
        else:
            if not input_paths:
                return
            for input_path in input_paths:
                if input_path.is_file():
                    self._validate_syntax_file(input_path, strict)
                else:
                    for file_path in input_path.rglob("*"):
                        if file_path.is_file():
                            self._validate_syntax_file(file_path, strict)

        if self.errors:
            raise SyntaxValidationError(
                self.errors.copy(), self.structured_syntax_errors.copy()
            )

    def _get_violation_count(self, result: list[Any]) -> int:
        """Get the violation count from a rule result."""
        if not result:
            return 0
        if _is_violation_list(result):
            return len(result)
        # For rich formatted content, try to find "Found N" pattern
        for item in result:
            match = re.search(r"Found (\d+)", str(item))
            if match:
                return int(match.group(1))
        # Fallback to list length
        return len(result)

    def _result_has_violations(self, result: list[Any]) -> bool:
        """Check if a rule result contains violations."""
        return self._get_violation_count(result) > 0

    def validate_semantics(
        self, input_paths: list[Path], rich_output: bool = True
    ) -> None:
        """Run semantic validation"""
        if not self.rules:
            return

        if self.data is None:
            self._load_data_from_paths(input_paths)
        data = self.data

        semantic_errors: list[str] = []
        structured_results: list[SemanticErrorResult] = []
        # Store raw results for JSON output
        raw_results: dict[str, list[Any]] = {}

        for rule in self.rules.values():
            logger.info("Verifying rule id %s", rule.id)
            sig = signature(rule.match)
            if len(sig.parameters) == 1:
                result = rule.match(data)
            elif len(sig.parameters) == 2:
                result = rule.match(data, self.schema)

            if self._result_has_violations(result):
                raw_results[rule.id] = result

        if raw_results:
            failed_rules = []
            for rule_id, result in raw_results.items():
                rule = self.rules[rule_id]
                violation_count = self._get_violation_count(result)

                # Build structured result for JSON output
                json_result = format_json_result(
                    rule_id=rule_id,
                    description=rule.description,
                    severity=rule.severity,
                    result=result,
                )
                structured_results.append(
                    SemanticErrorResult(
                        rule_id=rule_id,
                        description=rule.description,
                        errors=json_result.get(
                            "violations", json_result.get("errors", [])
                        ),
                    )
                )

                if rich_output:
                    formatted_msg = format_semantic_error(
                        rule=rule,
                        result=result,
                    )
                    print(formatted_msg, file=sys.stderr)
                    semantic_errors.append(f"Rule {rule_id}: {rule.description}")

                    failed_rules.append(
                        {
                            "rule_id": rule_id,
                            "description": rule.description,
                            "severity": rule.severity,
                            "violation_count": violation_count,
                        }
                    )
                else:
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
        """Write loaded YAML data to output file."""
        if self.data is None:
            self._load_data_from_paths(input_paths)
        write_yaml_file(self.data, path)
