# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for nac-validate CLI error handling."""

import json
import re
from pathlib import Path

import pytest
from nac_artifacts.testing import bundle_files as raw_bundle_files
from nac_artifacts.testing import overrides_yaml
from typer.testing import CliRunner

from nac_validate.cli.main import app
from nac_validate.constants import ExitCode, _ColorsMeta
from tests.unit.helpers import (
    artifact_files,
    bundle_files,
    install_module,
    make_zip,
    module_entry,
    rule_source,
    write_artifacts,
    write_modules_json,
)

runner = CliRunner()

# Rich styles help output when it detects CI (e.g. GITHUB_ACTIONS), splitting words
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


class TestListRules:
    """Test --list-rules functionality."""

    def test_list_rules_with_valid_rules(self, tmp_path: Path) -> None:
        """Should list all rules with IDs, descriptions, and severity."""
        rule_file = tmp_path / "test_rule.py"
        rule_file.write_text("""
class Rule:
    id = "999"
    description = "Test rule for validation"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        return []
""")

        result = runner.invoke(app, ["--list-rules", "-r", str(tmp_path)])

        assert result.exit_code == ExitCode.SUCCESS
        assert "999" in result.output
        assert "Test rule for validation" in result.output
        assert "HIGH" in result.output

    def test_list_rules_with_empty_directory(self, tmp_path: Path) -> None:
        """Should succeed with warning when no rules found."""
        result = runner.invoke(app, ["--list-rules", "-r", str(tmp_path)])

        assert result.exit_code == ExitCode.SUCCESS
        assert "No rules found" in result.output

    def test_list_rules_with_malformed_rule(self, tmp_path: Path) -> None:
        """Should error when rule file is missing required attributes."""
        rule_file = tmp_path / "bad_rule.py"
        rule_file.write_text("class Rule:\n    pass\n")  # Missing required attributes

        result = runner.invoke(app, ["--list-rules", "-r", str(tmp_path)])

        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "Could not load rules" in result.output


class TestMissingArguments:
    """Test missing required arguments."""

    def test_missing_paths_argument(self) -> None:
        """Should error with helpful message when no paths provided."""
        result = runner.invoke(app, [])

        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "Missing argument 'PATHS...'" in result.output
        assert "--help" in result.output or "help" in result.output


class TestConfigErrors:
    """Test configuration error handling in JSON mode."""

    def test_schema_not_found_json_format(self, tmp_path: Path) -> None:
        """Should output JSON error for missing schema in JSON mode."""
        data_file = tmp_path / "data.yaml"
        data_file.write_text("root: {}")

        result = runner.invoke(
            app, ["--format", "json", "-s", "/nonexistent/schema.yaml", str(data_file)]
        )

        assert result.exit_code == ExitCode.CONFIG_ERROR
        # Should be valid JSON
        output = json.loads(result.output)
        assert "error" in output
        assert (
            "schema" in output["error"].lower()
            or "not found" in output["error"].lower()
        )

    def test_rules_load_error_json_format(self, tmp_path: Path) -> None:
        """Should output JSON error for rule load failure in JSON mode."""
        data_file = tmp_path / "data.yaml"
        data_file.write_text("root: {}")

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        bad_rule = rules_dir / "bad.py"
        bad_rule.write_text("class Rule:\n    id = '1'\n")  # Missing match method

        result = runner.invoke(
            app, ["--format", "json", "-r", str(rules_dir), str(data_file)]
        )

        assert result.exit_code == ExitCode.CONFIG_ERROR
        output = json.loads(result.output)
        assert "error" in output


class TestUnexpectedErrors:
    """Test unexpected error handling."""

    def test_unexpected_error_json_format(self, tmp_path: Path) -> None:
        """Should output JSON error for unexpected exceptions in JSON mode.

        Uses a real rule that crashes during match() to trigger the error
        path without mocking.
        """
        data_file = tmp_path / "data.yaml"
        data_file.write_text("root: {}")

        # Create a rule that will crash during execution
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        crashing_rule = rules_dir / "crash.py"
        crashing_rule.write_text(
            """
class Rule:
    id = "999"
    description = "Crashes during match"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        raise RuntimeError("Unexpected crash during validation")
"""
        )

        result = runner.invoke(
            app, ["--format", "json", "-r", str(rules_dir), str(data_file)]
        )

        assert result.exit_code == ExitCode.CONFIG_ERROR
        output = json.loads(result.output)
        assert "error" in output
        assert "Unexpected" in output["error"]


class TestListArtifacts:
    """Test --list-artifacts functionality."""

    def test_shows_layers_schema_and_rules(self, project: Path) -> None:
        """Should list the module layer, effective schema and its rules."""
        install_module(project, version="1.2.3", rules={"1": "module rule"})

        result = runner.invoke(app, ["--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "module 'm' 1.2.3 at" in result.output
        assert "/m [module]" in result.output
        assert "schema.yaml [module]" in result.output
        assert "module rule" in result.output

    def test_list_rules_alias_is_hidden_but_works(self, project: Path) -> None:
        """Should accept --list-rules as an undocumented alias."""
        write_artifacts(project / "mod", rules={"1": "module rule"})

        help_output = ANSI_ESCAPE.sub("", runner.invoke(app, ["--help"]).output)
        result = runner.invoke(app, ["--list-rules", "--module-dir", "mod"])

        assert "--list-artifacts" in help_output
        assert "--list-rules" not in help_output
        assert result.exit_code == ExitCode.SUCCESS
        assert "module rule" in result.output

    def test_without_any_schema_or_rules(self, project: Path) -> None:
        """Should say syntax validation is skipped and no rules were found."""
        result = runner.invoke(app, ["--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "None (syntax validation skipped)" in result.output
        assert "No rules found" in result.output

    def test_marks_shadowed_rules(self, project: Path) -> None:
        """Should show a local rule and that it shadows the module's rule."""
        write_artifacts(project / "mod", rules={"5": "module five"})
        (project / ".rules").mkdir()
        (project / ".rules/5.py").write_text(rule_source("5", "local five"))

        result = runner.invoke(
            app, ["--no-color", "--list-artifacts", "--module-dir", "mod"]
        )

        assert result.exit_code == ExitCode.SUCCESS
        assert "local five" in result.output
        assert "[local] shadows [module]" in result.output
        assert "module five" not in result.output

    def test_local_layer_only_shows_existing_paths(self, project: Path) -> None:
        """Should leave out an empty local layer and missing default paths."""
        missing = runner.invoke(app, ["--no-color", "--list-artifacts"])
        (project / ".schema.yaml").write_text("a: str()\n")
        present = runner.invoke(app, ["--no-color", "--list-artifacts"])

        assert "[local]" not in missing.output
        assert "not found" not in missing.output
        assert "  schema .schema.yaml [local]" in present.output
        assert ".rules" not in present.output

    def test_labels_are_suffixes_with_one_style(
        self, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Should put every layer label after its item, always in magenta."""
        install_module(project, rules={"1": "module rule"})
        # Colors.disable() from earlier --no-color invocations is process-wide
        monkeypatch.setattr(_ColorsMeta, "_enabled", True)
        monkeypatch.delenv("NO_COLOR", raising=False)

        result = runner.invoke(app, ["--list-artifacts"])

        label = "\x1b[95m[module]\x1b[0m"
        assert result.output.count(label) == 3  # layer, schema, rule
        assert "\n  \x1b[95m[" not in result.output

    def test_invalid_module_dir(self, project: Path) -> None:
        """Should exit with a config error for a --module-dir that does not exist."""
        result = runner.invoke(app, ["--list-artifacts", "--module-dir", "nope"])

        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "Could not load rules" in result.output


class TestPackagedArtifacts:
    """Test validation using module and bundle artifacts."""

    def test_validation_uses_module_schema(self, project: Path) -> None:
        """Should apply the module schema when the project has none."""
        module_dir = install_module(project)
        (module_dir / "nac/schema.yaml").write_text("name: str()\n")
        data_dir = project / "data"
        data_dir.mkdir()
        (data_dir / "a.yaml").write_text("name: 5\n")

        invalid = runner.invoke(app, ["--no-color", "data"])
        (data_dir / "a.yaml").write_text("name: hello\n")
        valid = runner.invoke(app, ["--no-color", "data"])

        assert invalid.exit_code == ExitCode.SYNTAX_ERROR
        assert valid.exit_code == ExitCode.SUCCESS

    def test_json_output_unaffected_by_layers(self, project: Path) -> None:
        """Should keep JSON stdout clean when module artifacts are in use."""
        write_artifacts(project / "mod")
        (project / "data").mkdir()
        (project / "data/a.yaml").write_text("a: hello\n")

        result = runner.invoke(app, ["data", "--format", "json", "--module-dir", "mod"])

        assert result.exit_code == ExitCode.SUCCESS
        assert json.loads(result.output) == {"syntax_errors": [], "semantic_errors": []}

    def test_bundle_env_var(
        self, project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Should read the bundle location from NAC_VALIDATE_BUNDLE."""
        archive = make_zip(tmp_path / "b.zip", bundle_files())
        monkeypatch.setenv("NAC_VALIDATE_BUNDLE", str(archive))

        result = runner.invoke(app, ["--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "1.0.0 (" in result.output and "[bundle acme]" in result.output
        assert "bundle rule" in result.output

    def test_module_dir_env_var(
        self, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Should read the module directory from NAC_VALIDATE_MODULE_DIR."""
        write_artifacts(project / "mod", rules={"7": "from env module"})
        monkeypatch.setenv("NAC_VALIDATE_MODULE_DIR", "mod")

        result = runner.invoke(app, ["--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "from env module" in result.output

    def test_artifact_error_json_format(self, project: Path) -> None:
        """Should output JSON error for a missing bundle in JSON mode."""
        (project / "data").mkdir()
        (project / "data/a.yaml").write_text("a: 1\n")

        result = runner.invoke(
            app, ["data", "--format", "json", "--bundle", "missing.zip"]
        )

        assert result.exit_code == ExitCode.CONFIG_ERROR
        output = json.loads(result.output)
        assert "Bundle not found" in output["error"]
        assert output["syntax_errors"] == [] and output["semantic_errors"] == []

    def test_ambiguous_modules_is_config_error(self, project: Path) -> None:
        """Should exit with a config error when several modules ship artifacts."""
        for key in ("a", "b"):
            write_artifacts(project / f".terraform/modules/{key}")
        write_modules_json(
            project, [module_entry(k, f".terraform/modules/{k}") for k in ("a", "b")]
        )
        (project / "data").mkdir()
        (project / "data/a.yaml").write_text("a: 1\n")

        result = runner.invoke(app, ["data"])

        assert result.exit_code == ExitCode.CONFIG_ERROR


class TestListArtifactsDisabled:
    """--list-artifacts shows what overrides.yaml disabled."""

    @staticmethod
    def write_overrides(project: Path, text: str) -> None:
        (project / ".nac").mkdir(exist_ok=True)
        (project / ".nac" / "overrides.yaml").write_text(text)

    def test_shows_disabled_rules_with_origin_and_source(self, project: Path) -> None:
        """Should list each disabled rule, its layer and who disabled it."""
        install_module(project, rules={"1": "keep me", "2": "drop me"})
        self.write_overrides(project, overrides_yaml(rules=["2"]))

        result = runner.invoke(app, ["--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "Disabled Rules:" in result.output
        assert "[2] drop me [module] disabled by project overrides" in result.output
        listed = result.output.split("Disabled Rules:")[0]
        assert "keep me" in listed and "drop me" not in listed

    def test_shows_entries_matching_no_rule(self, project: Path) -> None:
        """Should report entries that matched nothing, without failing."""
        install_module(project, rules={"1": "one"})
        self.write_overrides(project, overrides_yaml(rules=["999"]))

        result = runner.invoke(app, ["--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "Overrides Matching No Rule:" in result.output
        assert "999 (project overrides)" in result.output

    def test_output_is_unchanged_without_overrides(self, project: Path) -> None:
        """Should not print the sections when nothing is disabled."""
        install_module(project, rules={"1": "one"})

        result = runner.invoke(app, ["--no-color", "--list-artifacts"])

        assert "Disabled Rules" not in result.output
        assert "Overrides Matching" not in result.output

    def test_disabled_rule_does_not_run_during_validation(self, project: Path) -> None:
        """Should skip a disabled rule that would otherwise fail validation."""
        module_dir = install_module(project, rules={})
        rules_dir = module_dir / "nac/rules"
        rules_dir.mkdir()
        (rules_dir / "1.py").write_text(
            "from nac_validate import RuleBase\n"
            "class Rule(RuleBase):\n"
            "    id = '1'\n    description = 'always fails'\n    severity = 'HIGH'\n"
            "    @classmethod\n    def match(cls, data):\n        return ['boom']\n"
        )
        (project / "data").mkdir()
        (project / "data/a.yaml").write_text("a: hello\n")

        failing = runner.invoke(app, ["--no-color", "data"])
        self.write_overrides(project, overrides_yaml(rules=["1"]))
        passing = runner.invoke(app, ["--no-color", "data"])

        assert failing.exit_code == ExitCode.SEMANTIC_ERROR
        assert passing.exit_code == ExitCode.SUCCESS

    def test_malformed_overrides_are_a_config_error(self, project: Path) -> None:
        """Should exit with a config error and name the file."""
        install_module(project)
        self.write_overrides(project, "disabel:\n  rules: ['1']\n")
        (project / "data").mkdir()
        (project / "data/a.yaml").write_text("a: 1\n")

        result = runner.invoke(app, ["data"])

        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "Unknown key" in result.output


class TestCliMultipleBundles:
    """--bundle is repeatable and bundles in .nac/ are all used."""

    @staticmethod
    def bundle(tmp_path: Path, name: str, **kwargs: object) -> Path:
        files = raw_bundle_files(
            artifact_files(**kwargs),  # type: ignore[arg-type]
            name=name,
        )
        return make_zip(tmp_path / f"{name}.zip", files)

    def test_bundle_option_is_repeatable(self, project: Path, tmp_path: Path) -> None:
        """Should list every bundle given with --bundle, with its name."""
        a = self.bundle(tmp_path, "base", schema=False, rules={"1": "base rule"})
        b = self.bundle(tmp_path, "extra", schema=False, rules={"2": "extra rule"})

        result = runner.invoke(
            app,
            ["--no-color", "--list-artifacts", "--bundle", str(a), "--bundle", str(b)],
        )

        assert result.exit_code == ExitCode.SUCCESS
        assert "[bundle base]" in result.output and "[bundle extra]" in result.output
        assert "base rule" in result.output and "extra rule" in result.output
        assert "[bundle base]" in result.output.split("Available Validation Rules:")[1]

    def test_shadowed_layers_are_listed_in_priority_order(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should name every lower layer a rule or the schema shadows, highest first."""
        install_module(project, rules={"7": "module seven"})
        a = self.bundle(tmp_path, "base", schema=False, rules={"7": "bundle seven"})
        (project / ".schema.yaml").write_text("a: str()\n")
        (project / ".rules").mkdir()
        (project / ".rules/7.py").write_text(rule_source("7", "local seven"))

        result = runner.invoke(
            app, ["--no-color", "--list-artifacts", "--bundle", str(a)]
        )

        assert result.exit_code == ExitCode.SUCCESS
        assert "local seven (HIGH) [local] shadows [bundle base], [module]" in (
            result.output
        )
        assert ".schema.yaml [local] shadows [module]" in result.output

    def test_all_bundles_in_nac_are_used(self, project: Path, tmp_path: Path) -> None:
        """Should use every archive dropped into .nac/."""
        (project / ".nac").mkdir()
        for name, rid in (("one", "1"), ("two", "2")):
            make_zip(
                project / ".nac" / f"{name}.zip",
                raw_bundle_files(
                    artifact_files(schema=False, rules={rid: f"rule {rid}"}), name=name
                ),
            )

        result = runner.invoke(app, ["--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "rule 1" in result.output and "rule 2" in result.output

    def test_overlapping_rules_are_a_config_error(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should exit with a config error naming the duplicate rule."""
        a = self.bundle(tmp_path, "a", schema=False, rules={"1": "x"})
        b = self.bundle(tmp_path, "b", schema=False, rules={"1": "y"})
        (project / "data").mkdir()
        (project / "data/a.yaml").write_text("a: 1\n")

        result = runner.invoke(app, ["data", "--bundle", str(a), "--bundle", str(b)])

        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "Duplicate rule ID '1'" in result.output

    def test_same_bundle_name_twice_is_a_config_error(self, project: Path) -> None:
        """Should refuse an old and a new version of one bundle left in .nac/."""
        (project / ".nac").mkdir()
        for version in ("1.0.0", "2.0.0"):
            make_zip(
                project / ".nac" / f"acme-{version}.zip",
                raw_bundle_files(
                    artifact_files(schema=False, rules={"1": "r"}),
                    name="acme",
                    version=version,
                ),
            )
        (project / "data").mkdir()
        (project / "data/a.yaml").write_text("a: 1\n")

        result = runner.invoke(app, ["data"])

        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "'acme' is present 2 times" in result.output

    def test_bundle_for_another_tool_is_ignored(self, project: Path) -> None:
        """Should not fail because .nac/ also holds a bundle with only test assets."""
        (project / ".nac").mkdir()
        make_zip(
            project / ".nac/tests.zip",
            raw_bundle_files({"tests/templates/a.robot": ""}, name="tests-only"),
        )
        (project / "data").mkdir()
        (project / "data/a.yaml").write_text("a: 1\n")

        result = runner.invoke(app, ["data"])

        assert result.exit_code == ExitCode.SUCCESS
