# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for nac_validate.validator module.

Tests verify the Validator class methods including data caching,
violation counting, and path name transformation utilities.
"""

import logging
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from nac_artifacts import DisableEntry
from nac_artifacts.testing import bundle_files as raw_bundle_files
from nac_artifacts.testing import overrides_yaml, write_files

from nac_validate.constants import DEFAULT_RULES, DEFAULT_SCHEMA
from nac_validate.exceptions import (
    RuleLoadError,
    RulesDirectoryNotFoundError,
    SchemaConflictError,
)
from nac_validate.layers import ValidationLayer
from nac_validate.models import RuleBase, Violation
from nac_validate.validator import Validator
from tests.unit.helpers import (
    artifact_files,
    bundle_files,
    install_module,
    make_zip,
    resolve,
    rule_source,
)


class TestValidatorLoadData:
    """Tests for load_data() and _load_data_from_paths()."""

    @pytest.fixture
    def validator(self) -> Validator:
        """Create Validator with mocked file system to avoid I/O."""
        with patch.object(Path, "exists", return_value=False):
            return Validator.from_paths(
                schema_path=DEFAULT_SCHEMA,
                rules_path=DEFAULT_RULES,
            )

    def test_load_data_sets_data(self, validator: Validator) -> None:
        """load_data() should set self.data directly."""
        data = {"key": "value"}
        validator.load_data(data)
        assert validator.data is data

    @patch("nac_validate.validator.load_yaml_files")
    def test_load_data_from_paths(
        self, mock_load: MagicMock, validator: Validator
    ) -> None:
        """_load_data_from_paths() should load from disk."""
        mock_load.return_value = {"key": "value"}
        paths = [Path("/data/file.yaml")]

        validator._load_data_from_paths(paths)

        mock_load.assert_called_once_with(paths, typ="safe")
        assert validator.data == {"key": "value"}


class TestValidatorGetViolationCount:
    """Tests for _get_violation_count() method."""

    @pytest.fixture
    def validator(self) -> Validator:
        """Create Validator with mocked file system."""
        with patch.object(Path, "exists", return_value=False):
            return Validator.from_paths(
                schema_path=DEFAULT_SCHEMA,
                rules_path=DEFAULT_RULES,
            )

    def test_violation_list_with_violations(self, validator: Validator) -> None:
        """Should count violations in list[Violation]."""
        result = [
            Violation(message="Error 1", path="path.a"),
            Violation(message="Error 2", path="path.b"),
        ]
        assert validator._get_violation_count(result) == 2

    def test_empty_violation_list(self, validator: Validator) -> None:
        """Should return 0 for empty list."""
        assert validator._get_violation_count([]) == 0

    def test_empty_string_list_returns_zero(self, validator: Validator) -> None:
        """Empty list returns 0."""
        assert validator._get_violation_count([]) == 0

    def test_string_list_uses_length(self, validator: Validator) -> None:
        """String list uses list length as violation count."""
        result = ["Found 5 violations", "other text"]
        assert validator._get_violation_count(result) == 2

    def test_string_list_fallback_to_length(self, validator: Validator) -> None:
        """String list without 'Found N' uses list length."""
        result = ["error 1", "error 2", "error 3"]
        assert validator._get_violation_count(result) == 3


class TestValidatorGetNamedPath:
    """Tests for _get_named_path() method."""

    @pytest.fixture
    def validator(self) -> Validator:
        """Create Validator with mocked file system."""
        with patch.object(Path, "exists", return_value=False):
            return Validator.from_paths(
                schema_path=DEFAULT_SCHEMA,
                rules_path=DEFAULT_RULES,
            )

    def test_numeric_index_replaced_with_key_value(self, validator: Validator) -> None:
        """Numeric path segments become [key=value] for list items."""
        data = {
            "tenants": [
                {"name": "Production", "id": 1},
                {"name": "Development", "id": 2},
            ]
        }
        result = validator._get_named_path(data, "tenants.0.name")
        assert result == "tenants.[name=Production].name"

    def test_second_list_item_named_correctly(self, validator: Validator) -> None:
        """Second list item uses its own first key-value pair."""
        data = {
            "tenants": [
                {"name": "Production"},
                {"name": "Development"},
            ]
        }
        result = validator._get_named_path(data, "tenants.1.name")
        assert result == "tenants.[name=Development].name"

    def test_dict_path_preserved(self, validator: Validator) -> None:
        """Non-numeric segments are preserved."""
        data = {"root": {"child": {"leaf": "value"}}}
        result = validator._get_named_path(data, "root.child.leaf")
        assert result == "root.child.leaf"

    def test_missing_key_preserved(self, validator: Validator) -> None:
        """Missing keys are preserved as-is."""
        data: dict[str, dict[str, str]] = {"config": {}}
        result = validator._get_named_path(data, "config.missing.key")
        assert result == "config.missing.key"

    def test_empty_path_returns_original(self, validator: Validator) -> None:
        """Empty path input returns empty path."""
        data = {"any": "data"}
        result = validator._get_named_path(data, "")
        assert result == ""


class TestRuleBase:
    """Tests for RuleBase subclassing."""

    def test_subclass_inherits_defaults(self) -> None:
        class MyRule(RuleBase):
            id = "999"
            description = "Test rule"

            @classmethod
            def match(cls, data: dict[str, Any]) -> list[str]:
                return []

        assert MyRule.severity == "HIGH"
        assert MyRule.title == ""
        assert MyRule.explanation == ""
        assert MyRule.recommendation == ""
        assert MyRule.affected_items_label == "Affected Items"
        assert MyRule.references == []

    def test_subclass_can_override_defaults(self) -> None:
        class MyRule(RuleBase):
            id = "999"
            description = "Test rule"
            severity = "LOW"
            title = "CUSTOM TITLE"

            @classmethod
            def match(cls, data: dict[str, Any]) -> list[str]:
                return []

        assert MyRule.severity == "LOW"
        assert MyRule.title == "CUSTOM TITLE"

    def test_match_raises_not_implemented(self) -> None:
        class MyRule(RuleBase):
            id = "999"
            description = "Test rule"

        import pytest

        with pytest.raises(NotImplementedError):
            MyRule.match({})


class TestContextInjection:
    """Tests for context injection in validate_semantics()."""

    def test_rule_result_gets_context_injected(self) -> None:
        class Rule(RuleBase):
            id = "900"
            description = "Test"
            title = "INJECTED"
            explanation = "Why"
            recommendation = "Fix"

            @classmethod
            def match(cls, data: dict[str, Any]) -> list[Any]:
                return [Violation(message="bad", path="x")]

        v = Validator(schema=None, rules={"900": Rule})
        with pytest.raises(Exception) as exc_info:
            v.validate_semantics([Path("/fake")], rich_output=False)
        assert exc_info.type.__name__ == "SemanticValidationError"


class TestDirectConstructor:
    """Tests for Validator.__init__ with pre-loaded objects."""

    def test_direct_objects_set_correctly(self) -> None:
        schema = MagicMock()
        rules = {"100": MagicMock()}
        v = Validator(schema, rules)
        assert v.schema is schema
        assert v.rules is rules


class TestCommentOnlyFiles:
    """Tests that comment-only/empty files don't cause validation errors."""

    @patch("nac_validate.validator.load_yaml_files", return_value={})
    def test_comment_only_file_no_syntax_error(self, mock_load: Any) -> None:
        """A comment-only file produces {} and should not fail schema validation."""
        schema = MagicMock()
        v = Validator(schema=schema, rules={})
        v.validate_syntax([Path("/tmp/comments.yaml")], strict=False, rich_output=False)
        assert v.errors == []

    @patch("nac_validate.validator.load_yaml_files", return_value={})
    def test_empty_file_no_syntax_error(self, mock_load: Any) -> None:
        """An empty file produces {} and should not fail schema validation."""
        schema = MagicMock()
        v = Validator(schema=schema, rules={})
        v.validate_syntax([Path("/tmp/empty.yaml")], strict=False, rich_output=False)
        assert v.errors == []


class TestFromPaths:
    """Tests that from_paths() keeps working alongside from_layers()."""

    def test_from_paths_loads_local_rules(self, project: Path) -> None:
        """Should load rules from the given directory without any layers."""
        (project / ".rules").mkdir()
        (project / ".rules/1.py").write_text(rule_source("1", "local"))

        validator = Validator.from_paths(DEFAULT_SCHEMA, DEFAULT_RULES)

        assert set(validator.rules) == {"1"}
        assert validator.layers == []


class TestFromLayersLocal:
    """Tests for from_layers() with only the local layer (existing behaviour)."""

    def test_explicit_missing_rules_dir_raises(self, project: Path) -> None:
        """Should raise when an explicitly given rules directory does not exist."""
        layers = resolve(project, rules=[Path("missing-rules")])

        with pytest.raises(RulesDirectoryNotFoundError):
            Validator.from_layers(layers)

    def test_default_rules_missing_is_silent(self, project: Path) -> None:
        """Should load no rules when the default .rules/ is absent."""
        assert Validator.from_layers(resolve(project)).rules == {}

    def test_no_schema_anywhere_keeps_skipping(self, project: Path) -> None:
        """Should keep skipping syntax validation when no layer has a schema."""
        validator = Validator.from_layers(resolve(project))

        assert validator.schema is None
        assert validator.schema_origin is None

    def test_multiple_rules_dirs_form_one_layer(self, project: Path) -> None:
        """Should merge several -r directories as a single local layer."""
        for name, rule_id in (("a", "1"), ("b", "2")):
            (project / name).mkdir()
            (project / name / f"{rule_id}.py").write_text(rule_source(rule_id, name))

        layers = resolve(project, rules=[project / "a", project / "b"])

        assert len(layers) == 1
        assert set(Validator.from_layers(layers).rules) == {"1", "2"}

    def test_duplicate_ids_across_rules_dirs_raise(self, project: Path) -> None:
        """Should raise instead of letting one -r directory replace another's rule."""
        for name in ("a", "b"):
            (project / name).mkdir()
            (project / name / "dup.py").write_text(rule_source("1", name))
        layers = resolve(project, rules=[project / "a", project / "b"])

        with pytest.raises(RuleLoadError, match="Duplicate rule ID '1'.*from .*a"):
            Validator.from_layers(layers)


class TestFromLayersPriority:
    """Tests for merging schema and rules across local, bundle and module layers."""

    @pytest.fixture
    def all_layers(self, project: Path, tmp_path: Path) -> list[ValidationLayer]:
        """Local rule 1 + schema, bundle rules 1+2, module rules 1+2+3."""
        (project / ".rules").mkdir()
        (project / ".rules/1.py").write_text(rule_source("1", "local one"))
        (project / ".schema.yaml").write_text("local: str()\n")
        archive = make_zip(
            tmp_path / "b.zip",
            bundle_files(extra={"nac/rules/1.py": rule_source("1", "bundle one")}),
        )
        install_module(
            project, rules={"1": "module one", "2": "module two", "3": "module three"}
        )
        return resolve(project, bundle=archive)

    def test_rules_merge_by_id_with_priority(
        self, all_layers: list[ValidationLayer]
    ) -> None:
        """Should keep the highest layer's rule for each ID."""
        validator = Validator.from_layers(all_layers)

        assert {rid: rule.description for rid, rule in validator.rules.items()} == {
            "1": "local one",
            "2": "bundle rule",
            "3": "module three",
        }
        assert validator.rule_origins == {
            "1": "local",
            "2": "bundle acme",
            "3": "module",
        }

    def test_shadowed_rules_are_recorded(
        self, all_layers: list[ValidationLayer]
    ) -> None:
        """Should record which layer's rule shadows which lower layer's rule."""
        validator = Validator.from_layers(all_layers)

        assert ("1", "bundle acme", "local") in validator.shadowed_rules
        assert ("1", "module", "bundle acme") in validator.shadowed_rules
        assert ("2", "module", "bundle acme") in validator.shadowed_rules

    def test_local_schema_wins_and_warns(
        self, all_layers: list[ValidationLayer], caplog: pytest.LogCaptureFixture
    ) -> None:
        """Should prefer the local schema and warn that it shadows a lower one."""
        caplog.set_level(logging.WARNING, logger="nac_validate")

        validator = Validator.from_layers(all_layers)

        assert validator.schema_origin is not None
        assert validator.schema_origin.origin == "local"
        assert "Local schema" in caplog.text

    def test_bundle_schema_replaces_module_schema_without_warning(
        self, project: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Should let a bundle schema replace the module's silently (by design)."""
        caplog.set_level(logging.WARNING, logger="nac_validate")
        install_module(project)
        archive = make_zip(tmp_path / "b.zip", bundle_files())

        validator = Validator.from_layers(resolve(project, bundle=archive))

        assert validator.schema_origin is not None
        assert validator.schema_origin.origin == "bundle"
        assert "shadows" not in caplog.text

    def test_module_schema_used_when_no_local_schema(self, project: Path) -> None:
        """Should fall back to the module schema when nothing higher has one."""
        install_module(project)

        validator = Validator.from_layers(resolve(project))

        assert validator.schema is not None
        assert validator.schema_origin is not None
        assert validator.schema_origin.origin == "module"

    def test_same_rule_filename_in_different_layers_does_not_collide(
        self, all_layers: list[ValidationLayer]
    ) -> None:
        """Should load same-named rule files from different layers independently."""
        validator = Validator.from_layers(all_layers)

        assert validator.rules["1"].description == "local one"
        assert validator.rules["3"].description == "module three"

    def test_int_and_str_ids_are_the_same_rule(self, project: Path) -> None:
        """Should let a local `id = "1"` shadow a module rule declaring `id = 1`."""
        module_dir = install_module(project, schema=False)
        (module_dir / "nac/rules").mkdir()
        (module_dir / "nac/rules/r.py").write_text(
            rule_source("1", "module").replace('"1"', "1")
        )
        (project / ".rules").mkdir()
        (project / ".rules/r.py").write_text(rule_source("1", "local"))

        validator = Validator.from_layers(resolve(project))

        assert {r: v.description for r, v in validator.rules.items()} == {"1": "local"}
        assert validator.shadowed_rules == [("1", "module", "local")]

    def test_duplicate_ids_within_a_layer_still_raise(self, project: Path) -> None:
        """Should not silently merge duplicate rule IDs inside one layer."""
        module_dir = install_module(project, schema=False)
        rules_dir = module_dir / "nac/rules"
        rules_dir.mkdir()
        (rules_dir / "a.py").write_text(rule_source("9", "a"))
        (rules_dir / "b.py").write_text(rule_source("9", "b"))

        with pytest.raises(RuleLoadError, match="Duplicate rule ID"):
            Validator.from_layers(resolve(project))


class TestPackagedRuleLoading:
    """Tests for how rules from packaged layers are imported."""

    def test_no_bytecode_written_into_module(self, project: Path) -> None:
        """Should not create __pycache__ inside installed modules."""
        install_module(project, rules={"1": "rule"})

        Validator.from_layers(resolve(project))

        assert not list((project / ".terraform").rglob("__pycache__"))

    def test_bytecode_flag_restored_after_failed_load(self, project: Path) -> None:
        """Should restore sys.dont_write_bytecode when a packaged rule fails."""
        module_dir = install_module(project, schema=False)
        (module_dir / "nac/rules").mkdir()
        (module_dir / "nac/rules/bad.py").write_text("class Rule:\n    pass\n")
        previous = sys.dont_write_bytecode
        sys.dont_write_bytecode = False
        try:
            with pytest.raises(RuleLoadError):
                Validator.from_layers(resolve(project))
            assert sys.dont_write_bytecode is False
        finally:
            sys.dont_write_bytecode = previous

    def test_local_rules_leave_bytecode_flag_alone(self, project: Path) -> None:
        """Should not change sys.dont_write_bytecode for local rules."""
        (project / ".rules").mkdir()
        (project / ".rules/1.py").write_text(rule_source("1", "local"))
        previous = sys.dont_write_bytecode
        sys.dont_write_bytecode = False
        try:
            Validator.from_layers(resolve(project))
            assert sys.dont_write_bytecode is False
        finally:
            sys.dont_write_bytecode = previous


class TestDisabledRules:
    """Tests for disabling rules of lower layers through overrides.yaml."""

    @staticmethod
    def disable(project: Path, *rules: str) -> None:
        write_files(project / ".nac", {"overrides.yaml": overrides_yaml(rules=rules)})

    def test_rule_is_removed_and_recorded(self, project: Path) -> None:
        """Should not validate with a disabled module rule, and say why."""
        install_module(project, rules={"1": "keep", "2": "drop"})
        self.disable(project, "2")

        validator = Validator.from_layers(resolve(project))

        assert set(validator.rules) == {"1"}
        (disabled,) = validator.disabled_rules
        assert (disabled.rule_id, disabled.description, disabled.origin) == (
            "2",
            "drop",
            "module",
        )
        assert disabled.entry == DisableEntry("2", "project")

    def test_rule_with_an_int_id_is_disabled(self, project: Path) -> None:
        """Should match an entry against a rule declaring `id = 101` as an int."""
        module_dir = install_module(project, schema=False)
        (module_dir / "nac/rules").mkdir()
        (module_dir / "nac/rules/r.py").write_text(
            rule_source("101", "int id").replace('"101"', "101")
        )
        self.disable(project, "101")

        validator = Validator.from_layers(resolve(project))

        assert validator.rules == {}
        assert [d.rule_id for d in validator.disabled_rules] == ["101"]
        assert validator.unmatched_disables == []

    def test_local_rule_with_the_same_id_survives(self, project: Path) -> None:
        """Should never disable local rules, so a copy can bring a rule back."""
        install_module(project, rules={"2": "module two"})
        (project / ".rules").mkdir()
        (project / ".rules/2.py").write_text(rule_source("2", "local two"))
        self.disable(project, "2")

        validator = Validator.from_layers(resolve(project))

        assert validator.rules["2"].description == "local two"
        assert validator.rule_origins["2"] == "local"
        assert [d.origin for d in validator.disabled_rules] == ["module"]

    def test_bundle_disables_module_rule(self, project: Path, tmp_path: Path) -> None:
        """Should let a bundle's overrides.yaml remove a module rule."""
        install_module(project, rules={"3": "module three", "4": "module four"})
        archive = make_zip(
            tmp_path / "b.zip",
            bundle_files(extra={"overrides.yaml": overrides_yaml(rules=["3"])}),
        )

        validator = Validator.from_layers(resolve(project, bundle=archive))

        assert "3" not in validator.rules
        assert "4" in validator.rules
        assert [d.entry.source for d in validator.disabled_rules] == ["bundle acme"]

    def test_bundle_rule_replacing_a_module_rule_is_not_disabled_by_the_bundle(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should only affect lower layers, never the disabling bundle's own rules."""
        install_module(project, rules={"2": "module two"})
        archive = make_zip(
            tmp_path / "b.zip",
            bundle_files(extra={"overrides.yaml": overrides_yaml(rules=["2"])}),
        )

        validator = Validator.from_layers(resolve(project, bundle=archive))

        # The bundle ships rule 2 itself (see bundle_files); only the module's goes
        assert validator.rules["2"].description == "bundle rule"
        assert [(d.rule_id, d.origin) for d in validator.disabled_rules] == [
            ("2", "module")
        ]

    def test_project_entry_disables_the_same_id_in_bundle_and_module(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should remove the rule from every packaged layer."""
        install_module(project, rules={"2": "module two"})
        archive = make_zip(tmp_path / "b.zip", bundle_files())
        self.disable(project, "2")

        validator = Validator.from_layers(resolve(project, bundle=archive))

        assert "2" not in validator.rules
        assert sorted(d.origin for d in validator.disabled_rules) == [
            "bundle acme",
            "module",
        ]

    def test_entry_matching_nothing_is_reported_not_an_error(
        self, project: Path
    ) -> None:
        """Should accept entries without a rule and list them as unmatched."""
        install_module(project, rules={"1": "one"})
        self.disable(project, "999")

        validator = Validator.from_layers(resolve(project))

        assert set(validator.rules) == {"1"}
        assert validator.disabled_rules == []
        assert [e.pattern for e in validator.unmatched_disables] == ["999"]

    def test_entry_matching_in_one_layer_is_not_unmatched(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should only call an entry unmatched if it matched in no layer at all."""
        install_module(project, rules={"1": "module one"})
        archive = make_zip(tmp_path / "b.zip", bundle_files())  # has rule 2, not 1
        self.disable(project, "1")

        validator = Validator.from_layers(resolve(project, bundle=archive))

        assert validator.unmatched_disables == []

    def test_no_overrides_changes_nothing(self, project: Path) -> None:
        """Should behave exactly as before without any overrides."""
        install_module(project, rules={"1": "one"})

        validator = Validator.from_layers(resolve(project))

        assert set(validator.rules) == {"1"}
        assert validator.disabled_rules == []
        assert validator.unmatched_disables == []

    def test_disabling_is_logged(
        self, project: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Should log each disabled rule at INFO level."""
        caplog.set_level(logging.INFO, logger="nac_validate")
        install_module(project, rules={"2": "two"})
        self.disable(project, "2")

        Validator.from_layers(resolve(project))

        assert "Rule 2 from module disabled by project overrides" in caplog.text


class TestMultipleBundles:
    """Several bundles are peers: they may split artifacts but must not overlap."""

    @staticmethod
    def bundle(tmp_path: Path, name: str, **kwargs: object) -> Path:
        files = raw_bundle_files(
            artifact_files(**kwargs),  # type: ignore[arg-type]
            name=name,
        )
        return make_zip(tmp_path / f"{name}.zip", files)

    def test_rules_split_across_bundles_are_all_used(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should combine rules from bundles that provide different rule IDs."""
        a = self.bundle(tmp_path, "a", schema=False, rules={"1": "from a"})
        b = self.bundle(tmp_path, "b", schema=False, rules={"2": "from b"})

        validator = Validator.from_layers(resolve(project, bundles=[a, b]))

        assert validator.rule_origins == {"1": "bundle a", "2": "bundle b"}

    def test_schema_and_rules_split_across_bundles(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should take the schema from one bundle and the rules from another."""
        rules = self.bundle(tmp_path, "rules", schema=False, rules={"1": "r"})
        schema = self.bundle(tmp_path, "schema")

        validator = Validator.from_layers(resolve(project, bundles=[rules, schema]))

        assert validator.schema is not None
        assert validator.schema_origin is not None
        assert validator.schema_origin.tag == "bundle schema"
        assert set(validator.rules) == {"1"}

    def test_same_rule_id_in_two_bundles_is_an_error(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should refuse overlapping rules, naming both bundles."""
        a = self.bundle(tmp_path, "a", schema=False, rules={"1": "from a"})
        b = self.bundle(tmp_path, "b", schema=False, rules={"1": "from b"})

        with pytest.raises(RuleLoadError, match="Duplicate rule ID '1'.*bundle a"):
            Validator.from_layers(resolve(project, bundles=[a, b]))

    def test_two_bundle_schemas_are_an_error(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should refuse two schemas, which cannot be merged."""
        a = self.bundle(tmp_path, "a", rules={})
        b = self.bundle(tmp_path, "b", rules={})

        with pytest.raises(SchemaConflictError, match="bundle a.*bundle b"):
            Validator.from_layers(resolve(project, bundles=[a, b]))

    def test_local_schema_wins_over_several_bundle_schemas(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should not complain about bundle schemas that a local schema replaces."""
        (project / ".schema.yaml").write_text("x: str()\n")
        a = self.bundle(tmp_path, "a", rules={})
        b = self.bundle(tmp_path, "b", rules={})

        validator = Validator.from_layers(resolve(project, bundles=[a, b]))

        assert validator.schema_origin is not None
        assert validator.schema_origin.tag == "local"

    def test_every_bundle_shadows_the_module(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should let both bundles replace module rules, each its own."""
        install_module(project, rules={"1": "module one", "2": "module two"})
        a = self.bundle(tmp_path, "a", schema=False, rules={"1": "from a"})
        b = self.bundle(tmp_path, "b", schema=False, rules={"2": "from b"})

        validator = Validator.from_layers(resolve(project, bundles=[a, b]))

        assert {r: v.description for r, v in validator.rules.items()} == {
            "1": "from a",
            "2": "from b",
        }
        assert sorted(validator.shadowed_rules) == [
            ("1", "module", "bundle a"),
            ("2", "module", "bundle b"),
        ]

    def test_a_bundles_disable_entry_does_not_remove_a_peers_rule(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should apply bundle overrides to the module only, never to a peer."""
        install_module(project, rules={"7": "module seven"})
        disabler = make_zip(
            tmp_path / "d.zip",
            raw_bundle_files(
                artifact_files(schema=False, rules={"1": "d one"}),
                name="d",
                extra={"overrides.yaml": overrides_yaml(rules=["7", "2"])},
            ),
        )
        peer = self.bundle(tmp_path, "peer", schema=False, rules={"2": "peer two"})

        validator = Validator.from_layers(resolve(project, bundles=[disabler, peer]))

        assert set(validator.rules) == {"1", "2"}  # module 7 gone, peer's 2 kept
        assert [(d.rule_id, d.origin) for d in validator.disabled_rules] == [
            ("7", "module")
        ]

    def test_bundles_may_share_rule_file_names(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should load same-named rule files from different bundles independently."""
        a = make_zip(
            tmp_path / "a.zip",
            raw_bundle_files({"rules/check.py": rule_source("1", "a")}, name="a"),
        )
        b = make_zip(
            tmp_path / "b.zip",
            raw_bundle_files({"rules/check.py": rule_source("2", "b")}, name="b"),
        )

        validator = Validator.from_layers(resolve(project, bundles=[a, b]))

        assert {r: v.description for r, v in validator.rules.items()} == {
            "1": "a",
            "2": "b",
        }

    def test_bundle_names_differing_in_punctuation_do_not_collide(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should register rules of `a-b` and `a_b` under distinct module names."""
        a = make_zip(
            tmp_path / "a.zip",
            raw_bundle_files({"rules/check.py": rule_source("1", "a")}, name="a-b"),
        )
        b = make_zip(
            tmp_path / "b.zip",
            raw_bundle_files({"rules/check.py": rule_source("2", "b")}, name="a_b"),
        )

        validator = Validator.from_layers(resolve(project, bundles=[a, b]))

        modules = {r: v.__module__ for r, v in validator.rules.items()}
        assert modules["1"] != modules["2"]
        assert sys.modules[modules["1"]].Rule is validator.rules["1"]
        assert sys.modules[modules["2"]].Rule is validator.rules["2"]


class TestFromProject:
    """Validator.from_project resolves all layers like the CLI."""

    def test_uses_module_rules_and_overrides(self, project: Path) -> None:
        """Should pick up module artifacts and apply project overrides."""
        install_module(project, rules={"1": "keep", "2": "drop"})
        write_files(project / ".nac", {"overrides.yaml": overrides_yaml(rules=["2"])})

        validator = Validator.from_project(project)

        assert validator.schema is not None
        assert set(validator.rules) == {"1"}
        assert [d.rule_id for d in validator.disabled_rules] == ["2"]

    def test_local_rules_win(self, project: Path) -> None:
        """Should let local rules shadow module rules with the same ID."""
        install_module(project, rules={"1": "module"})
        (project / "custom").mkdir()
        (project / "custom/r.py").write_text(rule_source("1", "local"))

        validator = Validator.from_project(project, rules=[Path("custom")])

        assert validator.rules["1"].description == "local"
        assert validator.rule_origins == {"1": "local"}
