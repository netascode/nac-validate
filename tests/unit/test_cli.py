# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for nac-validate CLI error handling."""

import json
import re
from pathlib import Path
from typing import Any

import pytest
from nac_artifacts.testing import bundle_files as raw_bundle_files
from nac_artifacts.testing import install_module as raw_install_module
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
    write_files,
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
        """Should error when a rule file is not valid Python."""
        rule_file = tmp_path / "bad_rule.py"
        rule_file.write_text("class Rule(:\n    pass\n")

        result = runner.invoke(app, ["--list-rules", "-r", str(tmp_path)])

        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "Could not load rules" in result.output
        assert "bad_rule.py - Cannot parse" in result.output

    def test_list_rules_with_rule_missing_attributes(self, tmp_path: Path) -> None:
        """Should list a rule without a literal ID as unknown instead of failing."""
        rule_file = tmp_path / "bad_rule.py"
        rule_file.write_text("class Rule:\n    pass\n")  # Missing required attributes

        result = runner.invoke(app, ["--no-color", "--list-rules", "-r", str(tmp_path)])

        assert result.exit_code == ExitCode.SUCCESS
        assert "Rules With Unknown ID (not statically resolvable):" in result.output
        assert f"{rule_file} [local]" in result.output


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


class TestRuleIds:
    """Test rules declaring an integer or a non-numeric ID."""

    @staticmethod
    def write_failing_rule(project: Path, rule_id: str) -> None:
        """Write a local rule with the given `id` literal that always fails."""
        (project / ".rules").mkdir()
        (project / ".rules/r.py").write_text(
            "from nac_validate import RuleBase\n"
            "class Rule(RuleBase):\n"
            f"    id = {rule_id}\n    description = 'always fails'\n"
            "    severity = 'MEDIUM'\n"
            "    @classmethod\n    def match(cls, data):\n        return ['boom']\n"
        )
        (project / "data").mkdir()
        (project / "data/a.yaml").write_text("a: hello\n")

    def test_int_id_violation_is_reported(self, project: Path) -> None:
        """Should summarize a violation of a rule declaring `id = 412`."""
        self.write_failing_rule(project, "412")

        result = runner.invoke(app, ["--no-color", "data"])

        assert result.exit_code == ExitCode.SEMANTIC_ERROR
        assert "1 MEDIUM severity violation (rules: 412)" in result.output

    def test_int_id_is_text_in_json_output(self, project: Path) -> None:
        """Should report a rule declaring `id = 412` with the rule_id "412"."""
        self.write_failing_rule(project, "412")

        result = runner.invoke(app, ["data", "--format", "json"])

        assert result.exit_code == ExitCode.SEMANTIC_ERROR
        (error,) = json.loads(result.output)["semantic_errors"]
        assert error["rule_id"] == "412"

    def test_non_numeric_id_validates_with_a_warning(self, project: Path) -> None:
        """Should run a rule declaring `id = 'abc'` and warn about its ID."""
        self.write_failing_rule(project, "'abc'")

        result = runner.invoke(app, ["--no-color", "data"])

        assert result.exit_code == ExitCode.SEMANTIC_ERROR
        assert "1 MEDIUM severity violation (rules: abc)" in result.output
        assert (
            'WARNING - Rule ID should be a number such as 101 or "101", '
            "got 'abc' (r.py)" in result.output
        )

    @pytest.mark.parametrize("flag", ["--list-artifacts", "--list-rules"])
    def test_non_numeric_id_is_listed(self, project: Path, flag: str) -> None:
        """Should list a rule declaring `id = 'abc'` instead of failing on its ID."""
        self.write_failing_rule(project, "'abc'")

        result = runner.invoke(app, ["--no-color", flag])

        assert result.exit_code == ExitCode.SUCCESS
        assert "[abc] always fails (MEDIUM)" in result.output

    def test_unusable_id_is_a_config_error(self, project: Path) -> None:
        """Should name the rule file when its ID cannot work."""
        self.write_failing_rule(project, "None")

        result = runner.invoke(app, ["--no-color", "data"])

        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "r.py - Rule ID must be a number" in result.output


class TestListArtifactsRunsNoCode:
    """--list-artifacts reads rules statically instead of importing them."""

    @staticmethod
    def rule_with_side_effect(marker: Path, body: str) -> str:
        """Return a rule that creates ``marker`` when it is imported."""
        return (
            "import pathlib\n"
            f"pathlib.Path({str(marker)!r}).touch()\n"
            f"class Rule:\n{body}"
            "    @classmethod\n    def match(cls, data):\n        return []\n"
        )

    def test_module_and_bundle_rules_are_not_imported(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should list module and bundle rules without running their code."""
        module_marker = tmp_path / "module-ran"
        bundle_marker = tmp_path / "bundle-ran"
        raw_install_module(
            project,
            {
                "rules/r.py": self.rule_with_side_effect(
                    module_marker,
                    "    id = 1\n    description: str = 'module rule'\n",
                )
            },
        )
        write_files(
            project / "nac/bundles/acme",
            raw_bundle_files(
                {
                    "rules/r.py": self.rule_with_side_effect(
                        bundle_marker,
                        "    id = '2'\n    description = 'bundle rule'\n"
                        "    severity = 'LOW'\n",
                    )
                },
                name="acme",
            ),
        )

        result = runner.invoke(app, ["--artifacts", "--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert "[1] module rule (HIGH) [module]" in result.output
        assert "[2] bundle rule (LOW) [bundle acme]" in result.output
        assert not module_marker.exists()
        assert not bundle_marker.exists()

    def test_computed_values_are_unknown(self, project: Path) -> None:
        """Should list a computed ID separately and placeholders for other values."""
        (project / ".rules").mkdir()
        (project / ".rules/computed.py").write_text(
            "class Rule:\n    id = str(1)\n    description = 'computed id'\n"
        )
        (project / ".rules/desc.py").write_text(
            "class Rule:\n    id = '5'\n    description = 'a' + 'b'\n"
            "    severity = ''.join('LOW')\n"
        )

        result = runner.invoke(app, ["--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert (
            "[5] unknown (not statically resolvable) "
            "(unknown (not statically resolvable))" in result.output
        )
        assert "Rules With Unknown ID (not statically resolvable):" in result.output
        assert "computed.py [local]" in result.output
        assert "Total: 1 rules" in result.output

    def test_last_class_definition_wins(self, project: Path) -> None:
        """Should read the last top-level Rule class, as an import would."""
        (project / ".rules").mkdir()
        (project / ".rules/r.py").write_text(
            "class Rule:\n    id = '1'\n    description = 'earlier'\n"
            "class Rule:\n    id = '2'\n    description = 'second'\n"
        )

        result = runner.invoke(app, ["--no-color", "--list-artifacts"])

        assert "[2] second (HIGH)" in result.output
        assert "earlier" not in result.output

    def test_duplicate_ids_are_still_detected(self, project: Path) -> None:
        """Should report two literal IDs in one directory as a config error."""
        (project / ".rules").mkdir()
        (project / ".rules/a.py").write_text(rule_source("7", "a"))
        (project / ".rules/b.py").write_text(rule_source("7", "b"))

        result = runner.invoke(app, ["--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "Duplicate rule ID '7'" in result.output

    def test_unusable_id_is_a_config_error(self, project: Path) -> None:
        """Should reject a literal ID that cannot work, as loading does."""
        (project / ".rules").mkdir()
        (project / ".rules/r.py").write_text(
            "class Rule:\n    id = None\n    description = 'x'\n"
        )

        result = runner.invoke(app, ["--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "r.py - Rule ID must be a number" in result.output

    def test_unknown_id_is_not_disabled_by_overrides(self, project: Path) -> None:
        """Should keep a rule with an unknown ID out of overrides matching."""
        raw_install_module(project, {"rules/r.py": "class Rule:\n    id = str(1)\n"})
        write_files(project / "nac", {"overrides.yaml": overrides_yaml(rules=["*"])})

        result = runner.invoke(app, ["--artifacts", "--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert "r.py [module]" in result.output
        assert "Disabled Rules:" not in result.output


class TestListArtifacts:
    """Test --list-artifacts functionality."""

    def test_shows_layers_schema_and_rules(self, project: Path) -> None:
        """Should list the module layer, effective schema and its rules."""
        install_module(project, version="1.2.3", rules={"1": "module rule"})

        result = runner.invoke(app, ["--artifacts", "--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "module 'm' 1.2.3 at" in result.output
        assert re.search(r"[/\\]m \[module\]", result.output)
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

        result = runner.invoke(app, ["--artifacts", "--list-artifacts"])

        label = "\x1b[95m[module]\x1b[0m"
        assert result.output.count(label) == 3  # layer, schema, rule
        assert "\n  \x1b[95m[" not in result.output

    def test_invalid_module_dir(self, project: Path) -> None:
        """Should exit with a config error for a --module-dir that does not exist."""
        result = runner.invoke(app, ["--list-artifacts", "--module-dir", "nope"])

        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "Could not load rules" in result.output


class TestArtifactsOptIn:
    """Bundles and modules are only loaded with --artifacts (for now)."""

    @staticmethod
    def setup_project(project: Path) -> None:
        install_module(project, rules={"1": "module rule"})
        write_files(
            project / "nac/bundles/acme",
            raw_bundle_files(
                artifact_files(schema=False, rules={"2": "bundle rule"}), name="acme"
            ),
        )
        (project / "nac/overrides.yaml").write_text("- not valid\n")

    def test_off_by_default(self, project: Path) -> None:
        """Should ignore the module, bundles and overrides and hint at --artifacts."""
        self.setup_project(project)

        result = runner.invoke(app, ["--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "module rule" not in result.output
        assert "bundle rule" not in result.output
        assert "use --artifacts to include them" in result.output

    def test_validation_ignores_layers_by_default(self, project: Path) -> None:
        """Should validate with local paths only, as before."""
        self.setup_project(project)
        (project / "data").mkdir()
        (project / "data/a.yaml").write_text("a: 1\n")

        result = runner.invoke(app, ["--no-color", "data"])

        assert result.exit_code == ExitCode.SUCCESS

    def test_flag_enables_loading(self, project: Path) -> None:
        """Should load the module and bundles with --artifacts."""
        install_module(project, rules={"1": "module rule"})

        result = runner.invoke(app, ["--no-color", "--list-artifacts", "--artifacts"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "module rule" in result.output
        assert "use --artifacts" not in result.output

    @pytest.mark.parametrize("value", ["true", "1", "yes"])
    def test_env_var_enables_loading(
        self, project: Path, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        """Should read the opt-in from NAC_VALIDATE_ARTIFACTS."""
        install_module(project, rules={"1": "module rule"})
        monkeypatch.setenv("NAC_VALIDATE_ARTIFACTS", value)

        result = runner.invoke(app, ["--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "module rule" in result.output

    def test_no_artifacts_overrides_env_var(
        self, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Should let --no-artifacts win over NAC_VALIDATE_ARTIFACTS=true."""
        install_module(project, rules={"1": "module rule"})
        monkeypatch.setenv("NAC_VALIDATE_ARTIFACTS", "true")

        result = runner.invoke(
            app, ["--no-color", "--list-artifacts", "--no-artifacts"]
        )

        assert result.exit_code == ExitCode.SUCCESS
        assert "module rule" not in result.output

    def test_bundle_implies_artifacts(self, project: Path, tmp_path: Path) -> None:
        """Should load an explicit --bundle without --artifacts."""
        archive = make_zip(tmp_path / "b.zip", bundle_files())

        result = runner.invoke(
            app, ["--no-color", "--list-artifacts", "--bundle", str(archive)]
        )

        assert result.exit_code == ExitCode.SUCCESS
        assert "bundle rule" in result.output

    @pytest.mark.parametrize("args", [["--bundle", "b.zip"], ["--module-dir", "mod"]])
    def test_explicit_paths_conflict_with_no_artifacts(
        self, project: Path, args: list[str]
    ) -> None:
        """Should refuse --bundle or --module-dir together with --no-artifacts."""
        result = runner.invoke(
            app, ["--no-color", "--list-artifacts", "--no-artifacts", *args]
        )

        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "cannot be combined with --no-artifacts" in result.output


class TestPackagedArtifacts:
    """Test validation using module and bundle artifacts."""

    def test_validation_uses_module_schema(self, project: Path) -> None:
        """Should apply the module schema when the project has none."""
        module_dir = install_module(project)
        (module_dir / "nac/schema.yaml").write_text("name: str()\n")
        data_dir = project / "data"
        data_dir.mkdir()
        (data_dir / "a.yaml").write_text("name: 5\n")

        invalid = runner.invoke(app, ["--artifacts", "--no-color", "data"])
        (data_dir / "a.yaml").write_text("name: hello\n")
        valid = runner.invoke(app, ["--artifacts", "--no-color", "data"])

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

        result = runner.invoke(app, ["--artifacts", "data"])

        assert result.exit_code == ExitCode.CONFIG_ERROR


class TestListArtifactsDisabled:
    """--list-artifacts shows what overrides.yaml disabled."""

    @staticmethod
    def write_overrides(project: Path, text: str) -> None:
        (project / "nac").mkdir(exist_ok=True)
        (project / "nac" / "overrides.yaml").write_text(text)

    def test_shows_disabled_rules_with_origin_and_source(self, project: Path) -> None:
        """Should list each disabled rule, its layer and who disabled it."""
        install_module(project, rules={"1": "keep me", "2": "drop me"})
        self.write_overrides(project, overrides_yaml(rules=["2"]))

        result = runner.invoke(app, ["--artifacts", "--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "Disabled Rules:" in result.output
        assert "[2] drop me [module] disabled by project overrides" in result.output
        listed = result.output.split("Disabled Rules:")[0]
        assert "keep me" in listed and "drop me" not in listed

    def test_disabled_rules_sort_numeric_ids_first(self, project: Path) -> None:
        """Should list disabled numeric IDs numerically, then other IDs as text."""
        install_module(project, rules={"abc": "a", "10": "ten", "2": "two"})
        self.write_overrides(project, overrides_yaml(rules=["abc", "10", "2"]))

        result = runner.invoke(app, ["--artifacts", "--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS
        disabled = result.output.split("Disabled Rules:")[1]
        assert (
            0 <= disabled.find("[2]") < disabled.find("[10]") < disabled.find("[abc]")
        )

    def test_shows_entries_matching_no_rule(self, project: Path) -> None:
        """Should report entries that matched nothing, without failing."""
        install_module(project, rules={"1": "one"})
        self.write_overrides(project, overrides_yaml(rules=["999"]))

        result = runner.invoke(app, ["--artifacts", "--no-color", "--list-artifacts"])

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

        failing = runner.invoke(app, ["--artifacts", "--no-color", "data"])
        self.write_overrides(project, overrides_yaml(rules=["1"]))
        passing = runner.invoke(app, ["--artifacts", "--no-color", "data"])

        assert failing.exit_code == ExitCode.SEMANTIC_ERROR
        assert passing.exit_code == ExitCode.SUCCESS

    def test_malformed_overrides_are_a_config_error(self, project: Path) -> None:
        """Should exit with a config error and name the file."""
        install_module(project)
        self.write_overrides(project, "disabel:\n  rules: ['1']\n")
        (project / "data").mkdir()
        (project / "data/a.yaml").write_text("a: 1\n")

        result = runner.invoke(app, ["--artifacts", "data"])

        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "Unknown key" in result.output


class TestCliMultipleBundles:
    """--bundle is repeatable and bundles in nac/bundles/ are all used."""

    @staticmethod
    def bundle(tmp_path: Path, name: str, **kwargs: Any) -> Path:
        files = raw_bundle_files(
            artifact_files(**kwargs),
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
        """Should use every archive dropped into nac/bundles/."""
        (project / "nac/bundles").mkdir(parents=True)
        for name, rid in (("one", "1"), ("two", "2")):
            make_zip(
                project / "nac/bundles" / f"{name}.zip",
                raw_bundle_files(
                    artifact_files(schema=False, rules={rid: f"rule {rid}"}), name=name
                ),
            )

        result = runner.invoke(app, ["--artifacts", "--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "rule 1" in result.output and "rule 2" in result.output

    def test_bundle_directory_in_nac_bundles_is_used(self, project: Path) -> None:
        """Should use an extracted bundle directory with its artifacts at its root."""
        write_files(
            project / "nac/bundles/acme",
            raw_bundle_files(
                artifact_files(schema=False, rules={"3": "dir rule"}), name="acme"
            ),
        )

        result = runner.invoke(app, ["--artifacts", "--no-color", "--list-artifacts"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "dir rule" in result.output and "[bundle acme]" in result.output

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
        """Should refuse an old and a new version of one bundle left in nac/bundles/."""
        (project / "nac/bundles").mkdir(parents=True)
        for version in ("1.0.0", "2.0.0"):
            make_zip(
                project / "nac/bundles" / f"acme-{version}.zip",
                raw_bundle_files(
                    artifact_files(schema=False, rules={"1": "r"}),
                    name="acme",
                    version=version,
                ),
            )
        (project / "data").mkdir()
        (project / "data/a.yaml").write_text("a: 1\n")

        result = runner.invoke(app, ["--artifacts", "data"])

        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "'acme' is present 2 times" in result.output

    def test_bundle_for_another_tool_is_ignored(self, project: Path) -> None:
        """Should not fail because nac/bundles/ also holds a bundle with only test assets."""
        (project / "nac/bundles").mkdir(parents=True)
        make_zip(
            project / "nac/bundles/tests.zip",
            raw_bundle_files({"tests/templates/a.robot": ""}, name="tests-only"),
        )
        (project / "data").mkdir()
        (project / "data/a.yaml").write_text("a: 1\n")

        result = runner.invoke(app, ["--artifacts", "data"])

        assert result.exit_code == ExitCode.SUCCESS
