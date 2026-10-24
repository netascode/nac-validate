# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

import hashlib
import importlib.machinery
import importlib.util
import logging
import re
import sys
import warnings
from collections.abc import Sequence
from dataclasses import dataclass
from inspect import signature
from pathlib import Path
from typing import Any

import yamale
from nac_artifacts import DisableEntry, DisableMatcher
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
    SchemaConflictError,
    SchemaNotFoundError,
    SemanticErrorResult,
    SemanticValidationError,
    SyntaxErrorResult,
    SyntaxValidationError,
)
from .layers import ValidationLayer, resolve_layers
from .models import _is_violation_list
from .output_formatter import (
    format_json_result,
    format_semantic_error,
    format_syntax_errors,
    format_validation_summary,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DisabledRule:
    """A rule that was loaded but disabled by an ``overrides.yaml`` entry.

    Attributes:
        rule_id: ID of the disabled rule.
        description: The rule's description.
        origin: Layer the rule came from.
        entry: The entry that disabled it, with the layer it came from.
    """

    rule_id: str
    description: str
    origin: str
    entry: DisableEntry


class _NoBytecodeLoader(importlib.machinery.SourceFileLoader):
    """Source loader that never writes ``__pycache__`` next to the file.

    Used for rules of modules and bundles, whose directories are not the user's
    to write to. Unlike ``sys.dont_write_bytecode`` it affects no other imports.
    """

    def set_data(self, path: str, data: Any, *, _mode: int = 0o666) -> None:
        """Skip writing the bytecode cache file."""


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
    def _load_rules_from_dir(
        rules_path: Path, origin: str = "local", key: str = ""
    ) -> dict[str, Any]:
        """Load validation rules from a single directory.

        Rules from packaged layers are registered under an origin-specific module
        name so same-named files in different layers do not overwrite each other,
        and are loaded without writing bytecode into module or bundle directories.
        """
        if not rules_path.exists():
            if rules_path == DEFAULT_RULES:
                logger.info("No rules found at default path")
                return {}
            else:
                raise RulesDirectoryNotFoundError(
                    f"Rules directory not found: {rules_path}"
                )

        logger.info("Loading %s rules from %s", origin, rules_path)
        rules: dict[str, Any] = {}
        prefix = (
            RULE_MODULE_NAME if origin == "local" else f"{RULE_MODULE_NAME}.{origin}"
        )
        if key:
            # Peer layers (several bundles) may contain files with the same name;
            # the hash keeps keys that only differ in punctuation apart
            safe_key = re.sub(r"\W", "_", key)
            digest = hashlib.sha256(key.encode()).hexdigest()[:8]
            prefix += f".{safe_key}_{digest}"
        Validator._load_rule_files(
            rules_path, prefix, rules, write_bytecode=origin == "local"
        )
        return rules

    @staticmethod
    def _load_rule_files(
        rules_path: Path,
        prefix: str,
        rules: dict[str, Any],
        *,
        write_bytecode: bool = True,
    ) -> None:
        for filename in sorted(f.name for f in rules_path.iterdir()):
            if Path(filename).suffix == ".py":
                try:
                    file_path = rules_path / filename
                    module_name = f"{prefix}.{Path(filename).stem}"
                    loader = (
                        None
                        if write_bytecode
                        else _NoBytecodeLoader(module_name, str(file_path))
                    )
                    spec = importlib.util.spec_from_file_location(
                        module_name, file_path, loader=loader
                    )
                    if spec is not None:
                        mod = importlib.util.module_from_spec(spec)
                        sys.modules[module_name] = mod
                        if spec.loader is not None:
                            spec.loader.exec_module(mod)

                            sig = signature(mod.Rule.match)
                            param_count = len(sig.parameters)
                            if param_count not in VALID_RULE_MATCH_PARAM_COUNTS:
                                raise RuleLoadError(
                                    filename,
                                    f"Rule.match() must accept 1 or 2 parameters, got {param_count}",
                                )
                            # IDs are matched as text (overrides, shadowing), so
                            # `id = 101` and `id = "101"` are the same rule
                            rule_id = str(mod.Rule.id)
                            if rule_id in rules:
                                existing = rules[rule_id]
                                raise RuleLoadError(
                                    filename,
                                    f"Duplicate rule ID '{rule_id}' - already defined in rule '{existing.description}'",
                                )
                            rules[rule_id] = mod.Rule
                except Exception as e:
                    raise RuleLoadError(filename, str(e)) from e

    @classmethod
    def _load_rules(
        cls, rules_path: Path | Sequence[Path], origin: str = "local", key: str = ""
    ) -> dict[str, Any]:
        """Load validation rules from one or more directories."""
        if isinstance(rules_path, Path):
            return cls._load_rules_from_dir(rules_path, origin, key)
        rules: dict[str, Any] = {}
        sources: dict[str, Path] = {}
        for p in rules_path:
            dir_rules = cls._load_rules_from_dir(p, origin, key)
            for rule_id in dir_rules:
                if rule_id in rules:
                    raise RuleLoadError(
                        str(p),
                        f"Duplicate rule ID '{rule_id}' - already defined in rule "
                        f"'{rules[rule_id].description}' from {sources[rule_id]}",
                    )
                sources[rule_id] = p
            rules.update(dir_rules)
        return rules

    def __init__(self, schema: Any | None, rules: Any | None = None):
        self.schema: Any | None = None
        self.rules: dict[str, Any] = {}
        if isinstance(schema, (str | Path)):
            inst = self.from_paths(
                Path(schema), Path(rules) if rules else DEFAULT_RULES
            )
            self.schema = inst.schema
            self.rules = inst.rules
        else:
            self.schema = schema
            if isinstance(rules, dict):
                self.rules = rules
        self.layers: list[ValidationLayer] = []
        self.schema_origin: ValidationLayer | None = None
        self.rule_origins: dict[str, str] = {}
        self.shadowed_rules: list[tuple[str, str, str]] = []
        self.disabled_rules: list[DisabledRule] = []
        self.unmatched_disables: list[DisableEntry] = []
        self.data: dict[str, Any] | None = None
        self.errors: list[str] = []
        self.structured_syntax_errors: list[SyntaxErrorResult] = []
        self.file_count: int = 0

    @classmethod
    def from_paths(
        cls, schema_path: Path, rules_path: Path | list[Path]
    ) -> "Validator":
        """Create validator by loading schema and rules from file system paths.

        Only the given local paths are used: schema and rules packaged with an
        installed module or a bundle, and ``overrides.yaml``, are not. Use
        :meth:`from_project` to validate the way the CLI does.

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

    @classmethod
    def from_project(
        cls,
        project_dir: Path,
        *,
        schema: Path = DEFAULT_SCHEMA,
        rules: Sequence[Path] = (DEFAULT_RULES,),
        bundles: Sequence[Path] | None = None,
        module_dir: Path | None = None,
    ) -> "Validator":
        """Create validator from all artifact layers of a project, like the CLI.

        Combines the local schema and rules with those packaged in bundles and
        an installed module, applying ``overrides.yaml``.

        Args:
            project_dir: Project directory (where ``.nac/`` and ``.terraform/`` live)
            schema: Local schema file
            rules: Local rules directories
            bundles: Bundles to use instead of those found in ``.nac/``
            module_dir: Module directory to use instead of the discovered one

        Returns:
            Initialized Validator instance

        Raises:
            SchemaNotFoundError: If a non-default local schema doesn't exist
            SchemaConflictError: If several bundles provide a schema
            RulesDirectoryNotFoundError: If a non-default local rules path doesn't exist
            RuleLoadError: If a rule file has invalid structure
            ArtifactError: If a bundle, the module or an overrides.yaml is invalid
        """
        layers = resolve_layers(
            project_dir,
            schema=schema,
            rules=rules,
            bundles=bundles,
            module_dir=module_dir,
        )
        return cls.from_layers(layers)

    @classmethod
    def from_layers(cls, layers: Sequence[ValidationLayer]) -> "Validator":
        """Create validator from artifact layers, highest priority first.

        The schema comes from the highest layer providing one (schemas are not
        merged). Rules are merged by ID, with higher layers shadowing lower ones.

        Args:
            layers: Resolved artifact layers, highest priority first

        Returns:
            Initialized Validator instance

        Raises:
            SchemaNotFoundError: If a non-default local schema doesn't exist
            RulesDirectoryNotFoundError: If a non-default local rules path doesn't exist
            RuleLoadError: If a rule file has invalid structure
        """
        schema_layers = [
            (layer, layer.schema) for layer in layers if layer.schema is not None
        ]
        schema = None
        if schema_layers:
            top, top_schema = schema_layers[0]
            peers = [(lay, s) for lay, s in schema_layers if lay.origin == top.origin]
            if len(peers) > 1:
                raise SchemaConflictError(
                    "Several bundles provide a schema ("
                    + ", ".join(f"{lay.tag}: {s}" for lay, s in peers)
                    + "); schemas cannot be merged, keep one"
                )
            schema = cls._load_schema(top_schema)
            # A local schema is often a stale copy; a bundle replacing the module's is by design
            if top.origin == "local":
                for lower, lower_schema in schema_layers[1:]:
                    logger.warning(
                        "Local schema (%s) shadows schema from %s layer (%s)",
                        top_schema,
                        lower.tag,
                        lower_schema,
                    )

        # Layers with the same origin (several bundles) are peers of one tier
        tiers: list[list[ValidationLayer]] = []
        for layer in layers:
            if tiers and tiers[-1][0].origin == layer.origin:
                tiers[-1].append(layer)
            else:
                tiers.append([layer])

        rules: dict[str, Any] = {}
        origins: dict[str, str] = {}
        shadowed: list[tuple[str, str, str]] = []
        disabled: list[DisabledRule] = []
        all_entries: dict[DisableEntry, None] = {}
        for tier in reversed(tiers):
            tier_rules: dict[str, Any] = {}
            tier_origins: dict[str, str] = {}
            for layer in tier:
                layer_rules = cls._load_rules(layer.rules_dirs, layer.origin, layer.tag)
                matcher = DisableMatcher(layer.disabled_rules)
                all_entries.update(dict.fromkeys(layer.disabled_rules))
                # Entries only remove rules of lower tiers; a peer's or a higher
                # layer's rule with the same ID is never touched
                for rule_id in list(layer_rules):
                    entry = matcher.match(rule_id)
                    if entry is not None:
                        rule = layer_rules.pop(rule_id)
                        disabled.append(
                            DisabledRule(rule_id, rule.description, layer.tag, entry)
                        )
                        logger.info(
                            "Rule %s from %s disabled by %s overrides",
                            rule_id,
                            layer.tag,
                            entry.source,
                        )
                for rule_id, rule in layer_rules.items():
                    if rule_id in tier_rules:
                        raise RuleLoadError(
                            layer.tag,
                            f"Duplicate rule ID '{rule_id}' - also provided by "
                            f"{tier_origins[rule_id]}",
                        )
                    tier_rules[rule_id] = rule
                    tier_origins[rule_id] = layer.tag
            for rule_id, tag in tier_origins.items():
                if rule_id in origins:
                    logger.info(
                        "Rule %s from %s shadows rule from %s",
                        rule_id,
                        tag,
                        origins[rule_id],
                    )
                    shadowed.append((rule_id, origins[rule_id], tag))
                origins[rule_id] = tag
            rules.update(tier_rules)

        validator = cls(schema, rules)
        validator.layers = list(layers)
        validator.schema_origin = schema_layers[0][0] if schema_layers else None
        validator.rule_origins = origins
        validator.shadowed_rules = shadowed
        validator.disabled_rules = disabled
        used = {d.entry for d in disabled}
        validator.unmatched_disables = [e for e in all_entries if e not in used]
        return validator

    def load_data(self, data: dict[str, Any]) -> None:
        """Load a pre-parsed data model directly.

        When data is loaded this way, validate_syntax will validate the schema
        once against the full model instead of walking individual files.

        Args:
            data: Pre-parsed merged YAML data dictionary
        """
        self.data = data

    def _load_data_from_paths(
        self, input_paths: Sequence[Path | str]
    ) -> dict[str, Any]:
        """Load and merge YAML data from file system paths.

        Args:
            input_paths: List of paths to load data from

        Returns:
            Merged YAML data dictionary
        """
        input_paths = [Path(p) for p in input_paths]
        logger.info("Loading yaml files from %s", input_paths)
        self.data = load_yaml_files(input_paths, typ="safe")
        return self.data

    def _validate_syntax_file(self, file_path: Path, strict: bool = True) -> None:
        """Run syntactic validation for a single file"""
        if file_path.is_file() and file_path.suffix in YAML_SUFFIXES:
            logger.info("Validate file: %s", file_path)

            # YAML syntax validation
            data = None
            try:
                data = load_yaml_files([file_path], typ="safe")
            except yaml.error.MarkedYAMLError as e:
                line: int | None = None
                column: int | None = None
                if e.problem_mark is not None:
                    line = e.problem_mark.line + 1
                    column = e.problem_mark.column + 1
                line_str = line if line is not None else 0
                column_str = column if column is not None else 0
                msg = f"Syntax error '{file_path}': Line {line_str}, Column {column_str} - {e.problem}"
                logger.debug(msg)
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
            if self.schema is None or data == {}:
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
                        logger.debug(msg)
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
                        preferred_keys = ("name", "id")
                        primary_key = next(
                            (
                                (k, current_item[k])
                                for k in preferred_keys
                                if k in current_item
                            ),
                            next(
                                (
                                    (k, v)
                                    for k, v in current_item.items()
                                    if isinstance(v, str | int | float)
                                ),
                                next(iter(current_item.items())),
                            ),
                        )
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
        self,
        input_paths: Sequence[Path | str] | None = None,
        strict: bool = True,
        rich_output: bool = True,
    ) -> None:
        """Run syntactic validation"""
        resolved_paths: list[Path] | None = (
            [Path(p) for p in input_paths] if input_paths is not None else None
        )
        self.errors.clear()
        self.structured_syntax_errors.clear()
        self.file_count = 0

        if self.data is not None:
            if self.schema is not None:
                source = (
                    str(resolved_paths[0])
                    if resolved_paths and len(resolved_paths) > 0
                    else "<pre-loaded>"
                )
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
            if not resolved_paths:
                return
            for input_path in resolved_paths:
                if input_path.is_file():
                    self._validate_syntax_file(input_path, strict)
                    if input_path.suffix in YAML_SUFFIXES:
                        self.file_count += 1
                else:
                    for file_path in input_path.rglob("*"):
                        if file_path.is_file():
                            self._validate_syntax_file(file_path, strict)
                            if file_path.suffix in YAML_SUFFIXES:
                                self.file_count += 1

        if self.errors:
            if rich_output:
                print(
                    format_syntax_errors(self.structured_syntax_errors),
                    file=sys.stderr,
                )
                print(
                    format_validation_summary(
                        syntax_passed=False,
                        semantic_passed=True,
                        file_count=self.file_count,
                        syntax_error_count=len(self.structured_syntax_errors),
                    ),
                    file=sys.stderr,
                )
            raise SyntaxValidationError(
                self.errors.copy(), self.structured_syntax_errors.copy()
            )

    def _get_violation_count(self, result: list[Any]) -> int:
        """Get the violation count from a rule result."""
        if not result:
            return 0
        if _is_violation_list(result):
            return len(result)
        return len(result)

    def _result_has_violations(self, result: list[Any]) -> bool:
        """Check if a rule result contains violations."""
        return self._get_violation_count(result) > 0

    def validate_semantics(
        self,
        input_paths: Sequence[Path | str],
        rich_output: bool = True,
        compact: bool = False,
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
            for rule_id, result in raw_results.items():
                rule = self.rules[rule_id]

                # Build structured result for JSON output
                json_result = format_json_result(
                    rule=rule,
                    result=result,
                )
                structured_results.append(
                    SemanticErrorResult(
                        rule_id=rule_id,
                        description=rule.description,
                        severity=json_result.get("severity", "HIGH"),
                        errors=json_result["errors"],
                        title=json_result.get("title", ""),
                        explanation=json_result.get("explanation", ""),
                        recommendation=json_result.get("recommendation", ""),
                        references=json_result.get("references"),
                    )
                )

                if rich_output:
                    formatted_msg = format_semantic_error(
                        rule=rule,
                        result=result,
                        compact=compact,
                    )
                    print(formatted_msg, file=sys.stderr)
                    semantic_errors.append(f"Rule {rule_id}: {rule.description}")
                else:
                    semantic_errors.append(f"Rule {rule_id}: {rule.description}")

            if rich_output:
                print(
                    format_validation_summary(
                        syntax_passed=True,
                        semantic_passed=False,
                        file_count=self.file_count,
                        semantic_errors=structured_results,
                        rules=self.rules,
                    ),
                    file=sys.stderr,
                )

            raise SemanticValidationError(semantic_errors, structured_results)

    def print_success_summary(self) -> None:
        """Print validation success summary to stderr."""
        print(
            format_validation_summary(
                syntax_passed=True,
                semantic_passed=True,
                file_count=self.file_count,
            ),
            file=sys.stderr,
        )

    def write_output(self, input_paths: Sequence[Path | str], path: Path) -> None:
        """Write loaded YAML data to output file."""
        if self.data is None:
            self._load_data_from_paths(input_paths)
        write_yaml_file(self.data, path)
