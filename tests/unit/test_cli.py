# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for nac-validate CLI error handling."""

import json
from pathlib import Path

from typer.testing import CliRunner

from nac_validate.cli.main import app
from nac_validate.constants import ExitCode

runner = CliRunner()


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
