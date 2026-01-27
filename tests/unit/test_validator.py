# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for nac_validate.validator module.

Tests verify the Validator class methods including data caching,
violation counting, and path name transformation utilities.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from nac_validate.constants import DEFAULT_RULES, DEFAULT_SCHEMA
from nac_validate.models import GroupedRuleResult, RuleResult, Violation
from nac_validate.validator import Validator


class TestValidatorGetData:
    """Tests for _get_data() caching behavior - P0 fix regression protection."""

    @pytest.fixture
    def validator(self) -> Validator:
        """Create Validator with mocked file system to avoid I/O."""
        with patch.object(Path, "exists", return_value=False):
            return Validator.from_paths(
                schema_path=DEFAULT_SCHEMA,
                rules_path=DEFAULT_RULES,
            )

    @patch("nac_validate.validator.load_yaml_files")
    def test_first_call_loads_data(
        self, mock_load: MagicMock, validator: Validator
    ) -> None:
        """First call to _get_data() should load from disk."""
        mock_load.return_value = {"key": "value"}
        paths = [Path("/data/file.yaml")]

        validator._get_data(paths)

        mock_load.assert_called_once_with(paths)

    @patch("nac_validate.validator.load_yaml_files")
    def test_same_paths_returns_cached_data(
        self, mock_load: MagicMock, validator: Validator
    ) -> None:
        """Repeated calls with same paths should return cached data."""
        mock_load.return_value = {"key": "value"}
        paths = [Path("/data/file.yaml")]

        first_result = validator._get_data(paths)
        second_result = validator._get_data(paths)  # Second call

        mock_load.assert_called_once()  # Only one load
        assert first_result is second_result  # Cache hit: same object

    @patch("nac_validate.validator.load_yaml_files")
    def test_different_paths_invalidates_cache(
        self, mock_load: MagicMock, validator: Validator
    ) -> None:
        """Different paths should trigger fresh load."""
        mock_load.side_effect = [{"first": "data"}, {"second": "data"}]

        result1 = validator._get_data([Path("/data/file1.yaml")])
        result2 = validator._get_data([Path("/data/file2.yaml")])

        assert mock_load.call_count == 2
        assert result1 is not result2  # Cache miss: different objects

    @patch("nac_validate.validator.load_yaml_files")
    def test_input_list_mutation_does_not_affect_cache(
        self, mock_load: MagicMock, validator: Validator
    ) -> None:
        """Mutating input list after call should not affect cache comparison."""
        mock_load.return_value = {"key": "value"}
        paths = [Path("/data/file.yaml")]

        validator._get_data(paths)
        paths.append(Path("/data/another.yaml"))  # Mutate the list
        validator._get_data([Path("/data/file.yaml")])  # Same original path

        mock_load.assert_called_once()  # Should still hit cache


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

    def test_rule_result_with_violations(self, validator: Validator) -> None:
        """Should count violations in RuleResult."""
        result = RuleResult(
            violations=[
                Violation(message="Error 1", path="path.a"),
                Violation(message="Error 2", path="path.b"),
            ]
        )
        assert validator._get_violation_count(result) == 2

    def test_rule_result_empty(self, validator: Validator) -> None:
        """Should return 0 for empty RuleResult."""
        result = RuleResult(violations=[])
        assert validator._get_violation_count(result) == 0

    def test_grouped_rule_result_sums_all_groups(self, validator: Validator) -> None:
        """Should count violations across all groups."""
        result = GroupedRuleResult(
            groups=[
                RuleResult(violations=[Violation(message="A", path="a")]),
                RuleResult(
                    violations=[
                        Violation(message="B", path="b"),
                        Violation(message="C", path="c"),
                    ]
                ),
            ]
        )
        assert validator._get_violation_count(result) == 3

    def test_empty_string_list_returns_zero(self, validator: Validator) -> None:
        """Empty list returns 0."""
        assert validator._get_violation_count([]) == 0

    def test_string_list_with_found_pattern(self, validator: Validator) -> None:
        """String list extracts count from 'Found N' pattern."""
        result = ["Found 5 violations", "other text"]
        assert validator._get_violation_count(result) == 5

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
