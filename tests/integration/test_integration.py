# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

import filecmp
import json
import os
from pathlib import Path

import pytest
from ruamel import yaml
from typer.testing import CliRunner

import nac_validate.cli.main

pytestmark = pytest.mark.integration


def test_validate() -> None:
    runner = CliRunner()
    input_path = "tests/integration/fixtures/data/"
    schema_path = "tests/integration/fixtures/schema/schema.yaml"
    rules_path = "tests/integration/fixtures/rules/"
    result = runner.invoke(
        nac_validate.cli.main.app,
        [
            "-s",
            schema_path,
            "-r",
            rules_path,
            input_path,
        ],
    )
    assert result.exit_code == 0


def test_validate_non_strict() -> None:
    runner = CliRunner()
    input_path = "tests/integration/fixtures/data_non_strict/"
    schema_path = "tests/integration/fixtures/schema/schema.yaml"
    rules_path = "tests/integration/fixtures/rules/"
    result = runner.invoke(
        nac_validate.cli.main.app,
        [
            "-s",
            schema_path,
            "-r",
            rules_path,
            "--non-strict",
            input_path,
        ],
    )
    assert result.exit_code == 0


def test_validate_vault() -> None:
    runner = CliRunner()
    input_path = "tests/integration/fixtures/data_vault/"
    schema_path = "tests/integration/fixtures/schema/schema.yaml"
    os.environ["ANSIBLE_VAULT_ID"] = "dev"
    os.environ["ANSIBLE_VAULT_PASSWORD"] = "Password123"
    result = runner.invoke(
        nac_validate.cli.main.app,
        [
            "-s",
            schema_path,
            input_path,
        ],
    )
    assert result.exit_code == 0


def test_validate_env(tmpdir: Path) -> None:
    runner = CliRunner()
    input_path = "tests/integration/fixtures/data_env/"
    schema_path = "tests/integration/fixtures/schema/schema.yaml"
    output_path = os.path.join(tmpdir, "output.yaml")
    os.environ["ABC"] = "DEF"
    result = runner.invoke(
        nac_validate.cli.main.app,
        [
            "-s",
            schema_path,
            "-o",
            output_path,
            input_path,
        ],
    )
    assert result.exit_code == 0
    with open(output_path) as file:
        data_yaml = file.read()
    y = yaml.YAML()
    data = y.load(data_yaml)
    assert data["root"]["children"][0]["name"] == "DEF"


def test_validate_empty_data() -> None:
    runner = CliRunner()
    input_path = "tests/integration/fixtures/data_empty/"
    schema_path = "tests/integration/fixtures/schema/schema.yaml"
    result = runner.invoke(
        nac_validate.cli.main.app,
        [
            "-s",
            schema_path,
            input_path,
        ],
    )
    assert result.exit_code == 0


def test_validate_additional_data() -> None:
    runner = CliRunner()
    input_path = "tests/integration/fixtures/data/"
    input_path_2 = "tests/integration/fixtures/additional_data/"
    schema_path = "tests/integration/fixtures/additional_data_schema/schema.yaml"
    schema_path_fail = "tests/integration/fixtures/schema/schema.yaml"
    rules_path = "tests/integration/fixtures/rules/"
    result = runner.invoke(
        nac_validate.cli.main.app,
        [
            "-s",
            schema_path,
            "-r",
            rules_path,
            input_path,
            input_path_2,
        ],
    )
    assert result.exit_code == 0
    result = runner.invoke(
        nac_validate.cli.main.app,
        [
            "-s",
            schema_path_fail,
            "-r",
            rules_path,
            input_path,
            input_path_2,
        ],
    )
    assert result.exit_code == 1


def test_validate_syntax() -> None:
    runner = CliRunner()
    input_path = "tests/integration/fixtures/data_syntax_error/"
    schema_path = "tests/integration/fixtures/schema/schema.yaml"
    result = runner.invoke(
        nac_validate.cli.main.app,
        [
            "-s",
            schema_path,
            input_path,
        ],
    )
    assert result.exit_code == 1


def test_validate_semantics() -> None:
    runner = CliRunner()
    input_path = "tests/integration/fixtures/data_semantic_error/"
    rules_path = "tests/integration/fixtures/rules/"
    result = runner.invoke(
        nac_validate.cli.main.app,
        [
            "-r",
            rules_path,
            input_path,
        ],
    )
    assert result.exit_code == 1
    rules_path = "tests/integration/fixtures/rules_schema/"
    result = runner.invoke(
        nac_validate.cli.main.app,
        [
            "-r",
            rules_path,
            input_path,
        ],
    )
    assert result.exit_code == 1
    schema_path = "tests/integration/fixtures/schema/schema.yaml"
    result = runner.invoke(
        nac_validate.cli.main.app,
        [
            "-s",
            schema_path,
            "-r",
            rules_path,
            input_path,
        ],
    )
    assert result.exit_code == 0


def test_validate_output(tmpdir: Path) -> None:
    runner = CliRunner()
    input_path = "tests/integration/fixtures/data/"
    output_path = os.path.join(tmpdir, "output.yaml")
    result = runner.invoke(
        nac_validate.cli.main.app,
        [
            "-o",
            output_path,
            input_path,
        ],
    )
    assert result.exit_code == 0
    assert os.path.exists(output_path)


def test_merge(tmpdir: Path) -> None:
    runner = CliRunner()
    input_path_1 = "tests/integration/fixtures/data_merge/file1.yaml"
    input_path_2 = "tests/integration/fixtures/data_merge/file2.yaml"
    output_path = os.path.join(tmpdir, "output.yaml")
    result_path = "tests/integration/fixtures/data_merge/result.yaml"
    result = runner.invoke(
        nac_validate.cli.main.app,
        [
            "-o",
            output_path,
            input_path_1,
            input_path_2,
        ],
    )
    assert result.exit_code == 0
    assert filecmp.cmp(output_path, result_path, shallow=False)


def test_json_format_success() -> None:
    """Test JSON output format for successful validation."""
    runner = CliRunner()
    input_path = "tests/integration/fixtures/data/"
    schema_path = "tests/integration/fixtures/schema/schema.yaml"
    rules_path = "tests/integration/fixtures/rules/"
    result = runner.invoke(
        nac_validate.cli.main.app,
        ["-s", schema_path, "-r", rules_path, "--format", "json", input_path],
    )
    assert result.exit_code == 0
    output = json.loads(result.output)
    assert output == {"syntax_errors": [], "semantic_errors": []}


def test_json_format_semantic_errors() -> None:
    """Test JSON output format for semantic validation errors."""
    runner = CliRunner()
    input_path = "tests/integration/fixtures/data_semantic_error/"
    rules_path = "tests/integration/fixtures/rules/"
    result = runner.invoke(
        nac_validate.cli.main.app,
        ["-r", rules_path, "--format", "json", input_path],
    )
    assert result.exit_code == 1
    output = json.loads(result.output)
    assert "syntax_errors" in output
    assert "semantic_errors" in output
    assert output["syntax_errors"] == []
    assert len(output["semantic_errors"]) > 0
    # Verify structure of semantic error
    semantic_error = output["semantic_errors"][0]
    assert "rule_id" in semantic_error
    assert "description" in semantic_error
    assert "errors" in semantic_error
    assert isinstance(semantic_error["errors"], list)
    # Verify errors are strings in "path - message" format (not dicts)
    for error in semantic_error["errors"]:
        assert isinstance(error, str), f"Error should be string, got {type(error)}"
        assert " - " in error, f"Error should contain ' - ' separator: {error}"


def test_json_format_syntax_errors() -> None:
    """Test JSON output format for syntax validation errors."""
    runner = CliRunner()
    input_path = "tests/integration/fixtures/data_syntax_error/"
    schema_path = "tests/integration/fixtures/schema/schema.yaml"
    result = runner.invoke(
        nac_validate.cli.main.app,
        ["-s", schema_path, "--format", "json", input_path],
    )
    assert result.exit_code == 1
    output = json.loads(result.output)
    assert "syntax_errors" in output
    assert "semantic_errors" in output
    assert output["semantic_errors"] == []
    assert len(output["syntax_errors"]) > 0
    # Verify structure of syntax error
    syntax_error = output["syntax_errors"][0]
    assert "file" in syntax_error
    assert "message" in syntax_error


def test_json_format_no_logs_at_default_verbosity() -> None:
    """Test that JSON mode suppresses logs at default verbosity."""
    runner = CliRunner()
    input_path = "tests/integration/fixtures/data_semantic_error/"
    rules_path = "tests/integration/fixtures/rules/"
    result = runner.invoke(
        nac_validate.cli.main.app,
        ["-r", rules_path, "--format", "json", input_path],
    )
    assert result.exit_code == 1
    # Should be valid JSON without any log prefixes
    output = json.loads(result.output)
    assert "semantic_errors" in output
    # Verify no ERROR or INFO prefixes in output
    assert "ERROR - " not in result.output
    assert "INFO - " not in result.output
