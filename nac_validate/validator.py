# Copyright: (c) 2022, Daniel Schmidt <danischm@cisco.com>

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
    SemanticValidationError,
    SyntaxValidationError,
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
        self.rules = {}
        if os.path.exists(rules_path):
            logger.info("Loading rules")
            for filename in os.listdir(rules_path):
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
                line = 0
                column = 0
                if e.problem_mark is not None:
                    line = e.problem_mark.line + 1
                    column = e.problem_mark.column + 1
                msg = f"Syntax error '{file_path}': Line {line}, Column {column} - {e.problem}"
                logger.error(msg)
                self.errors.append(msg)
                return

            # Schema syntax validation
            if self.schema is None or data is None:
                return
            try:
                yamale.validate(self.schema, [(data, file_path)], strict=strict)
            except YamaleError as e:
                for result in e.results:
                    for err in result.errors:
                        msg = f"Syntax error '{result.data}': {err}"
                        logger.error(msg)
                        self.errors.append(msg)

    def validate_syntax(self, input_paths: list[Path], strict: bool = True) -> None:
        """Run syntactic validation"""
        # Clear any previous errors
        self.errors.clear()

        for input_path in input_paths:
            if os.path.isfile(input_path):
                self._validate_syntax_file(input_path, strict)
            else:
                for dir, _subdir, files in os.walk(input_path):
                    for filename in files:
                        file_path = Path(dir, filename)
                        self._validate_syntax_file(file_path, strict)

        if self.errors:
            raise SyntaxValidationError(self.errors.copy())

    def validate_semantics(self, input_paths: list[Path]) -> None:
        """Run semantic validation"""
        if not self.rules:
            return

        logger.info("Loading yaml files from %s", input_paths)
        if self.data is None:
            self.data = load_yaml_files(input_paths)

        semantic_errors = []
        results = {}
        for rule in self.rules.values():
            logger.info("Verifying rule id %s", rule.id)
            sig = signature(rule.match)
            if len(sig.parameters) == 1:
                paths = rule.match(self.data)
            elif len(sig.parameters) == 2:
                paths = rule.match(self.data, self.schema)
            if len(paths) > 0:
                results[rule.id] = paths

        if len(results) > 0:
            for id, paths in results.items():
                msg = (
                    f"Semantic error, rule {id}: {self.rules[id].description} ({paths})"
                )
                logger.error(msg)
                semantic_errors.append(msg)

            raise SemanticValidationError(semantic_errors)

    def write_output(self, input_paths: list[Path], path: Path) -> None:
        if self.data is None:
            self.data = load_yaml_files(input_paths)
        write_yaml_file(self.data, path)
