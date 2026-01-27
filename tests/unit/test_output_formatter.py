# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for format_json_result function in output_formatter module.

Tests verify that format_json_result correctly transforms RuleResult,
GroupedRuleResult, and list[str] inputs into the expected JSON structure
with errors formatted as "path - message" strings.
"""

from nac_validate.models import GroupedRuleResult, RuleContext, RuleResult, Violation
from nac_validate.output_formatter import (
    format_checklist_summary,
    format_json_result,
    format_rules_list,
    format_validation_summary,
)


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
        result = RuleResult(violations=[Violation(message="Test", path="test")])

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
                RuleResult(violations=[Violation(message="Real error", path="path.x")]),
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


class TestFormatViolation:
    """Test format_violation() method."""

    def test_violation_with_path(self) -> None:
        """Should format violation with path."""
        from nac_validate.output_formatter import OutputFormatter

        formatter = OutputFormatter(severity="HIGH")
        violation = Violation(message="Error message", path="apic.tenants[0].name")
        lines = formatter.format_violation(violation)
        assert len(lines) == 2
        assert "Error message" in lines[0]
        assert "apic.tenants[0].name" in lines[1]
        assert "Path:" in lines[1]

    def test_violation_without_path(self) -> None:
        """Should format violation without path line."""
        from nac_validate.output_formatter import OutputFormatter

        formatter = OutputFormatter(severity="HIGH")
        violation = Violation(message="Error message", path="")
        lines = formatter.format_violation(violation)
        assert len(lines) == 1
        assert "Error message" in lines[0]


class TestFormatViolationsList:
    """Test format_violations_list() method."""

    def test_empty_list_returns_empty(self) -> None:
        """Should return empty list for no violations."""
        from nac_validate.output_formatter import OutputFormatter

        formatter = OutputFormatter(severity="HIGH")
        lines = formatter.format_violations_list([])
        assert lines == []

    def test_multiple_violations(self) -> None:
        """Should format multiple violations with header."""
        from nac_validate.output_formatter import OutputFormatter

        formatter = OutputFormatter(severity="HIGH")
        violations = [
            Violation(message="Error 1", path="path1"),
            Violation(message="Error 2", path="path2"),
        ]
        lines = formatter.format_violations_list(violations, "Issues Found")
        assert "Issues Found:" in lines[0]
        assert any("Error 1" in line for line in lines)
        assert any("Error 2" in line for line in lines)


class TestFormatContext:
    """Test format_context() method."""

    def test_context_with_references(self) -> None:
        """Should format context with references section."""
        from nac_validate.output_formatter import OutputFormatter

        formatter = OutputFormatter(severity="HIGH")
        context = RuleContext(
            title="Test Issue",
            affected_items_label="Items",
            explanation="Why this matters",
            recommendation="How to fix",
            references=["https://example.com/docs"],
        )
        lines = formatter.format_context(context)
        assert any("WHY THIS MATTERS" in line for line in lines)
        assert any("RECOMMENDED FIX" in line for line in lines)
        assert any("https://example.com/docs" in line for line in lines)

    def test_context_without_references(self) -> None:
        """Should format context without references section."""
        from nac_validate.output_formatter import OutputFormatter

        formatter = OutputFormatter(severity="HIGH")
        context = RuleContext(
            title="Test Issue",
            affected_items_label="Items",
            explanation="Why this matters",
            recommendation="How to fix",
            references=[],
        )
        lines = formatter.format_context(context)
        assert any("WHY THIS MATTERS" in line for line in lines)
        assert any("RECOMMENDED FIX" in line for line in lines)
        assert not any("References:" in line for line in lines)


class TestFormatRuleResult:
    """Test format_rule_result() method."""

    def test_empty_result_returns_empty(self) -> None:
        """Should return empty for result with no violations."""
        from nac_validate.output_formatter import OutputFormatter

        formatter = OutputFormatter(severity="HIGH")
        result = RuleResult(violations=[])
        lines = formatter.format_rule_result(result)
        assert lines == []

    def test_result_with_context(self) -> None:
        """Should format result with rich context."""
        from nac_validate.output_formatter import OutputFormatter

        formatter = OutputFormatter(severity="HIGH")
        context = RuleContext(
            title="Configuration Issue",
            affected_items_label="Affected Items",
            explanation="Why this matters",
            recommendation="How to fix",
        )
        result = RuleResult(
            violations=[Violation(message="Error", path="path")], context=context
        )
        lines = formatter.format_rule_result(result)
        assert any("Configuration Issue" in line for line in lines)
        assert any("Found 1 violation" in line for line in lines)

    def test_result_without_context(self) -> None:
        """Should format result with simple output."""
        from nac_validate.output_formatter import OutputFormatter

        formatter = OutputFormatter(severity="HIGH")
        result = RuleResult(violations=[Violation(message="Error", path="path")])
        lines = formatter.format_rule_result(result)
        assert any("Error" in line for line in lines)


class TestFormatValidationSummary:
    """Test format_validation_summary() function."""

    def test_all_passed_shows_green_checkmarks(self) -> None:
        """Should show green checkmarks when both validations pass."""
        result = format_validation_summary(
            syntax_passed=True,
            semantic_passed=True,
            file_count=5,
        )
        assert "PASSED" in result
        assert "Syntax validation" in result
        assert "Semantic validation" in result
        assert "(5 files)" in result

    def test_syntax_failed_shows_red_x(self) -> None:
        """Should show red X when syntax validation fails."""
        result = format_validation_summary(
            syntax_passed=False,
            semantic_passed=True,
        )
        assert "FAILED" in result
        assert "Syntax validation" in result

    def test_semantic_failed_with_severity_breakdown(self) -> None:
        """Should show severity breakdown when semantic validation fails."""
        from nac_validate.exceptions import SemanticErrorResult

        class MockRule:
            severity = "HIGH"

        errors = [
            SemanticErrorResult(
                rule_id="100", description="Test", errors=["err1", "err2"]
            ),
        ]
        rules = {"100": MockRule()}

        result = format_validation_summary(
            syntax_passed=True,
            semantic_passed=False,
            semantic_errors=errors,
            rules=rules,
        )
        assert "FAILED" in result
        assert "HIGH" in result
        assert "2" in result  # violation count


class TestFormatRulesList:
    """Test format_rules_list() function."""

    def test_empty_rules_shows_warning(self) -> None:
        """Should show warning when no rules found."""
        result = format_rules_list({})
        assert "No rules found" in result

    def test_rules_sorted_by_id(self) -> None:
        """Should list rules sorted by numeric ID."""

        class Rule100:
            description = "Rule 100"
            severity = "HIGH"

        class Rule50:
            description = "Rule 50"
            severity = "LOW"

        rules = {"100": Rule100, "50": Rule50}
        result = format_rules_list(rules)

        # Rule 50 should appear before Rule 100
        pos_50 = result.find("[50]")
        pos_100 = result.find("[100]")
        assert pos_50 < pos_100

    def test_rules_show_severity_with_color(self) -> None:
        """Should show severity in parentheses."""

        class Rule:
            description = "Test rule"
            severity = "MEDIUM"

        result = format_rules_list({"1": Rule})
        assert "(MEDIUM)" in result
        assert "Test rule" in result


class TestFormatChecklistSummary:
    """Test format_checklist_summary() function."""

    def test_empty_list_returns_empty_string(self) -> None:
        """Should return empty string for no failed rules."""
        result = format_checklist_summary([])
        assert result == ""

    def test_failed_rules_sorted_by_severity_then_id(self) -> None:
        """Should sort failed rules by severity (HIGH first) then by ID."""
        failed_rules = [
            {
                "rule_id": "200",
                "description": "Low rule",
                "severity": "LOW",
                "violation_count": 1,
            },
            {
                "rule_id": "100",
                "description": "High rule",
                "severity": "HIGH",
                "violation_count": 2,
            },
            {
                "rule_id": "150",
                "description": "Medium rule",
                "severity": "MEDIUM",
                "violation_count": 1,
            },
        ]
        result = format_checklist_summary(failed_rules)

        # HIGH (100) should come before MEDIUM (150) which should come before LOW (200)
        pos_100 = result.find("Rule 100")
        pos_150 = result.find("Rule 150")
        pos_200 = result.find("Rule 200")
        assert pos_100 < pos_150 < pos_200

    def test_shows_violation_count(self) -> None:
        """Should show violation count for each rule."""
        failed_rules = [
            {
                "rule_id": "100",
                "description": "Test",
                "severity": "HIGH",
                "violation_count": 5,
            },
        ]
        result = format_checklist_summary(failed_rules)
        assert "5 violations" in result

    def test_shows_checklist_header(self) -> None:
        """Should show REMEDIATION CHECKLIST header."""
        failed_rules = [
            {
                "rule_id": "100",
                "description": "Test",
                "severity": "HIGH",
                "violation_count": 1,
            },
        ]
        result = format_checklist_summary(failed_rules)
        assert "REMEDIATION CHECKLIST" in result
