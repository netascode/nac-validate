# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for format_json_result function in output_formatter module.

Tests verify that format_json_result correctly transforms RuleResult,
GroupedRuleResult, and list[str] inputs into the expected JSON structure
with errors formatted as "path - message" strings.
"""

import pytest

from nac_validate.models import GroupedRuleResult, RuleContext, RuleResult, Violation
from nac_validate.output_formatter import format_json_result


class TestFormatJsonResultWithRuleResult:
    """Tests for format_json_result with RuleResult input."""

    def test_rule_result_with_violations_produces_path_message_format(self) -> None:
        """Violations are formatted as 'path - message' in errors array."""
        result = RuleResult(
            violations=[
                Violation(
                    message="Duplicate tenant name 'Production'",
                    path="apic.tenants[0].name",
                ),
                Violation(
                    message="Missing required field",
                    path="apic.tenants[1].vrfs[0]",
                ),
            ]
        )

        output = format_json_result(
            rule_id="101",
            description="Verify unique tenant names",
            severity="HIGH",
            result=result,
        )

        assert output == {
            "rule_id": "101",
            "description": "Verify unique tenant names",
            "errors": [
                "apic.tenants[0].name - Duplicate tenant name 'Production'",
                "apic.tenants[1].vrfs[0] - Missing required field",
            ],
        }

    def test_rule_result_with_empty_violations_produces_empty_errors(self) -> None:
        """RuleResult with no violations produces empty errors array."""
        result = RuleResult(violations=[])

        output = format_json_result(
            rule_id="102",
            description="Check VRF configuration",
            severity="MEDIUM",
            result=result,
        )

        assert output == {
            "rule_id": "102",
            "description": "Check VRF configuration",
            "errors": [],
        }

    def test_rule_result_context_is_ignored_in_json_output(self) -> None:
        """RuleContext is not included in JSON output (text-only feature)."""
        result = RuleResult(
            violations=[
                Violation(message="Test error", path="test.path"),
            ],
            context=RuleContext(
                title="TEST CONTEXT TITLE",
                explanation="This should not appear in JSON",
                recommendation="Fix it somehow",
            ),
        )

        output = format_json_result(
            rule_id="103",
            description="Test rule",
            severity="LOW",
            result=result,
        )

        # Context fields should not be in output
        assert "title" not in output
        assert "explanation" not in output
        assert "recommendation" not in output
        # Only standard fields present
        assert set(output.keys()) == {"rule_id", "description", "errors"}


class TestFormatJsonResultWithGroupedRuleResult:
    """Tests for format_json_result with GroupedRuleResult input."""

    def test_grouped_result_flattens_all_groups_into_single_errors_array(self) -> None:
        """All violations from all groups are flattened into one errors array."""
        result = GroupedRuleResult(
            groups=[
                RuleResult(
                    violations=[
                        Violation(message="Duplicate in group 1", path="path.a"),
                        Violation(message="Another in group 1", path="path.b"),
                    ]
                ),
                RuleResult(
                    violations=[
                        Violation(message="Error in group 2", path="path.c"),
                    ]
                ),
            ]
        )

        output = format_json_result(
            rule_id="201",
            description="Multiple validation categories",
            severity="HIGH",
            result=result,
        )

        assert output["errors"] == [
            "path.a - Duplicate in group 1",
            "path.b - Another in group 1",
            "path.c - Error in group 2",
        ]

    def test_grouped_result_with_empty_groups_produces_empty_errors(self) -> None:
        """GroupedRuleResult with all empty groups produces empty errors array."""
        result = GroupedRuleResult(
            groups=[
                RuleResult(violations=[]),
                RuleResult(violations=[]),
            ]
        )

        output = format_json_result(
            rule_id="202",
            description="No violations found",
            severity="LOW",
            result=result,
        )

        assert output["errors"] == []

    def test_grouped_result_with_no_groups_produces_empty_errors(self) -> None:
        """GroupedRuleResult with no groups produces empty errors array."""
        result = GroupedRuleResult(groups=[])

        output = format_json_result(
            rule_id="203",
            description="Empty grouped result",
            severity="MEDIUM",
            result=result,
        )

        assert output["errors"] == []


class TestFormatJsonResultWithStringList:
    """Tests for format_json_result with list[str] input."""

    def test_string_list_passes_through_directly(self) -> None:
        """Plain string list is passed through without transformation."""
        result = ["Error message one", "Error message two"]

        output = format_json_result(
            rule_id="301",
            description="String list format",
            severity="HIGH",
            result=result,
        )

        assert output == {
            "rule_id": "301",
            "description": "String list format",
            "errors": ["Error message one", "Error message two"],
        }

    def test_empty_string_list_produces_empty_errors(self) -> None:
        """Empty string list produces empty errors array."""
        result: list[str] = []

        output = format_json_result(
            rule_id="302",
            description="No errors",
            severity="LOW",
            result=result,
        )

        assert output["errors"] == []


class TestFormatJsonResultEdgeCases:
    """Edge cases for format_json_result."""

    def test_violation_with_empty_path_formats_correctly(self) -> None:
        """Violation with empty string path still produces 'path - message' format."""
        result = RuleResult(
            violations=[
                Violation(message="Global error", path=""),
            ]
        )

        output = format_json_result(
            rule_id="401",
            description="Global validation",
            severity="HIGH",
            result=result,
        )

        # Empty path results in " - message" format
        assert output["errors"] == [" - Global error"]

    def test_violation_message_with_special_characters(self) -> None:
        """Messages with special characters are preserved."""
        result = RuleResult(
            violations=[
                Violation(
                    message="Value 'test' contains \"quotes\" and $pecial chars: {a: 1}",
                    path="config[0].value",
                ),
            ]
        )

        output = format_json_result(
            rule_id="402",
            description="Special character handling",
            severity="MEDIUM",
            result=result,
        )

        assert output["errors"] == [
            "config[0].value - Value 'test' contains \"quotes\" and $pecial chars: {a: 1}"
        ]

    def test_violation_path_with_special_characters(self) -> None:
        """Paths with special characters (brackets, dots) are preserved."""
        result = RuleResult(
            violations=[
                Violation(
                    message="Invalid value",
                    path="apic.tenants[0].application_profiles[1].endpoint_groups[2]",
                ),
            ]
        )

        output = format_json_result(
            rule_id="403",
            description="Complex path handling",
            severity="LOW",
            result=result,
        )

        assert output["errors"] == [
            "apic.tenants[0].application_profiles[1].endpoint_groups[2] - Invalid value"
        ]

    def test_severity_parameter_does_not_affect_json_output(self) -> None:
        """Severity is not included in JSON output (affects text color only)."""
        result = RuleResult(
            violations=[Violation(message="Test", path="test")]
        )

        for severity in ["HIGH", "MEDIUM", "LOW"]:
            output = format_json_result(
                rule_id="404",
                description="Severity test",
                severity=severity,
                result=result,
            )

            # Severity should not appear in output
            assert "severity" not in output
            # Structure should be consistent regardless of severity
            assert set(output.keys()) == {"rule_id", "description", "errors"}

    def test_multiline_message_preserved(self) -> None:
        """Multiline messages are preserved as-is."""
        result = RuleResult(
            violations=[
                Violation(
                    message="Line 1\nLine 2\nLine 3",
                    path="config.item",
                ),
            ]
        )

        output = format_json_result(
            rule_id="405",
            description="Multiline test",
            severity="HIGH",
            result=result,
        )

        assert output["errors"] == ["config.item - Line 1\nLine 2\nLine 3"]

    def test_grouped_result_mixed_empty_and_populated_groups(self) -> None:
        """GroupedRuleResult with mix of empty and populated groups."""
        result = GroupedRuleResult(
            groups=[
                RuleResult(violations=[]),  # empty
                RuleResult(
                    violations=[Violation(message="Real error", path="path.x")]
                ),
                RuleResult(violations=[]),  # empty
                RuleResult(
                    violations=[Violation(message="Another error", path="path.y")]
                ),
            ]
        )

        output = format_json_result(
            rule_id="406",
            description="Mixed groups",
            severity="MEDIUM",
            result=result,
        )

        assert output["errors"] == [
            "path.x - Real error",
            "path.y - Another error",
        ]

    def test_violation_details_not_included_in_json_output(self) -> None:
        """Violation.details field is not included in simplified JSON format."""
        result = RuleResult(
            violations=[
                Violation(
                    message="Error with details",
                    path="config.item",
                    details={"key": "value", "count": 42},
                ),
            ]
        )

        output = format_json_result(
            rule_id="407",
            description="Details ignored",
            severity="HIGH",
            result=result,
        )

        # Details should not appear in the error string
        assert output["errors"] == ["config.item - Error with details"]
        # And not as a separate field
        assert "details" not in output
