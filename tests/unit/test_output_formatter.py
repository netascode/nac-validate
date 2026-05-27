# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for format_json_result function in output_formatter module.

Tests verify that format_json_result correctly transforms list[Violation]
and list[str] inputs into the expected JSON structure
with errors formatted as "path - message" strings.
"""

from nac_validate.models import RuleBase, Violation
from nac_validate.output_formatter import (
    format_json_result,
    format_rules_list,
    format_validation_summary,
)


class TestFormatJsonResultWithViolationList:
    """Tests for format_json_result with list[Violation] input."""

    def test_violation_list_produces_structured_dicts(self) -> None:
        """Violations are formatted as dicts with message, path, details."""

        class Rule(RuleBase):
            id = "101"
            description = "Verify unique tenant names"
            severity = "HIGH"

        result = [
            Violation(
                message="Duplicate tenant name 'Production'",
                path="apic.tenants[0].name",
            ),
            Violation(
                message="Missing required field",
                path="apic.tenants[1].vrfs[0]",
            ),
        ]

        output = format_json_result(
            rule=Rule,
            result=result,
        )

        assert output == {
            "rule_id": "101",
            "severity": "HIGH",
            "description": "Verify unique tenant names",
            "errors": [
                {
                    "message": "Duplicate tenant name 'Production'",
                    "path": "apic.tenants[0].name",
                    "details": {},
                },
                {
                    "message": "Missing required field",
                    "path": "apic.tenants[1].vrfs[0]",
                    "details": {},
                },
            ],
        }


class TestFormatJsonResultWithStringList:
    """Tests for format_json_result with list[str] input."""

    def test_string_list_normalized_to_dicts(self) -> None:
        """Plain string list is normalized to dicts with message key."""

        class Rule(RuleBase):
            id = "301"
            description = "String list format"
            severity = "HIGH"

        result = ["Error message one", "Error message two"]

        output = format_json_result(
            rule=Rule,
            result=result,
        )

        assert output == {
            "rule_id": "301",
            "severity": "HIGH",
            "description": "String list format",
            "errors": [
                {"message": "Error message one"},
                {"message": "Error message two"},
            ],
        }

    def test_empty_string_list_produces_empty_errors(self) -> None:
        """Empty string list produces empty errors array."""

        class Rule(RuleBase):
            id = "302"
            description = "No errors"
            severity = "LOW"

        result: list[str] = []

        output = format_json_result(
            rule=Rule,
            result=result,
        )

        assert output["errors"] == []


class TestFormatJsonResultEdgeCases:
    """Edge cases for format_json_result."""

    def test_violation_with_empty_path_formats_correctly(self) -> None:
        """Violation with empty string path is preserved in dict."""

        class Rule(RuleBase):
            id = "401"
            description = "Global validation"
            severity = "HIGH"

        result = [
            Violation(message="Global error", path=""),
        ]

        output = format_json_result(
            rule=Rule,
            result=result,
        )

        assert output["errors"] == [
            {"message": "Global error", "path": "", "details": {}}
        ]

    def test_violation_message_with_special_characters(self) -> None:
        """Messages with special characters are preserved."""

        class Rule(RuleBase):
            id = "402"
            description = "Special character handling"
            severity = "MEDIUM"

        result = [
            Violation(
                message="Value 'test' contains \"quotes\" and $pecial chars: {a: 1}",
                path="config[0].value",
            ),
        ]

        output = format_json_result(
            rule=Rule,
            result=result,
        )

        assert output["errors"] == [
            {
                "message": "Value 'test' contains \"quotes\" and $pecial chars: {a: 1}",
                "path": "config[0].value",
                "details": {},
            }
        ]

    def test_violation_path_with_special_characters(self) -> None:
        """Paths with special characters (brackets, dots) are preserved."""

        class Rule(RuleBase):
            id = "403"
            description = "Complex path handling"
            severity = "LOW"

        result = [
            Violation(
                message="Invalid value",
                path="apic.tenants[0].application_profiles[1].endpoint_groups[2]",
            ),
        ]

        output = format_json_result(
            rule=Rule,
            result=result,
        )

        assert output["errors"] == [
            {
                "message": "Invalid value",
                "path": "apic.tenants[0].application_profiles[1].endpoint_groups[2]",
                "details": {},
            }
        ]

    def test_severity_is_included_in_json_output(self) -> None:
        """Severity is included in JSON output."""

        for severity in ["HIGH", "MEDIUM", "LOW"]:

            class Rule(RuleBase):
                id = "404"
                description = "Severity test"

            Rule.severity = severity
            result = [Violation(message="Test", path="test")]

            output = format_json_result(
                rule=Rule,
                result=result,
            )

            assert output["severity"] == severity

    def test_multiline_message_preserved(self) -> None:
        """Multiline messages are preserved as-is."""

        class Rule(RuleBase):
            id = "405"
            description = "Multiline test"
            severity = "HIGH"

        result = [
            Violation(
                message="Line 1\nLine 2\nLine 3",
                path="config.item",
            ),
        ]

        output = format_json_result(
            rule=Rule,
            result=result,
        )

        assert output["errors"] == [
            {"message": "Line 1\nLine 2\nLine 3", "path": "config.item", "details": {}}
        ]

    def test_violation_details_included_in_json_output(self) -> None:
        """Violation.details field is included in JSON output."""

        class Rule(RuleBase):
            id = "407"
            description = "Details included"
            severity = "HIGH"

        result = [
            Violation(
                message="Error with details",
                path="config.item",
                details={"key": "value", "count": 42},
            ),
        ]

        output = format_json_result(
            rule=Rule,
            result=result,
        )

        assert output["errors"] == [
            {
                "message": "Error with details",
                "path": "config.item",
                "details": {"key": "value", "count": 42},
            }
        ]

    def test_rich_rule_fields_included(self) -> None:
        """Title, explanation, recommendation, references appear when set."""

        class Rule(RuleBase):
            id = "408"
            description = "Rich rule"
            severity = "MEDIUM"
            title = "Important Check"
            explanation = "This matters because..."
            recommendation = "Fix by doing X"
            references = ["https://example.com"]

        result = [Violation(message="err", path="p")]
        output = format_json_result(rule=Rule, result=result)

        assert output["title"] == "Important Check"
        assert output["explanation"] == "This matters because..."
        assert output["recommendation"] == "Fix by doing X"
        assert output["references"] == ["https://example.com"]

    def test_empty_rich_fields_omitted(self) -> None:
        """Empty title/explanation/recommendation/references are omitted."""

        class Rule(RuleBase):
            id = "409"
            description = "Minimal rule"
            severity = "LOW"

        result = [Violation(message="err", path="p")]
        output = format_json_result(rule=Rule, result=result)

        assert "title" not in output
        assert "explanation" not in output
        assert "recommendation" not in output
        assert "references" not in output


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

        class Rule(RuleBase):
            id = "100"
            description = "Test"
            title = "Test Issue"
            affected_items_label = "Items"
            explanation = "Why this matters"
            recommendation = "How to fix"
            references = ["https://example.com/docs"]

        formatter = OutputFormatter(severity="HIGH")
        lines = formatter.format_context(Rule)
        assert any("WHY THIS MATTERS" in line for line in lines)
        assert any("RECOMMENDED FIX" in line for line in lines)
        assert any("https://example.com/docs" in line for line in lines)

    def test_context_without_references(self) -> None:
        """Should format context without references section."""
        from nac_validate.output_formatter import OutputFormatter

        class Rule(RuleBase):
            id = "100"
            description = "Test"
            title = "Test Issue"
            affected_items_label = "Items"
            explanation = "Why this matters"
            recommendation = "How to fix"
            references = []

        formatter = OutputFormatter(severity="HIGH")
        lines = formatter.format_context(Rule)
        assert any("WHY THIS MATTERS" in line for line in lines)
        assert any("RECOMMENDED FIX" in line for line in lines)
        assert not any("References:" in line for line in lines)


class TestFormatRuleResult:
    """Test format_rule_result() method."""

    def test_empty_result_returns_empty(self) -> None:
        """Should return empty for empty violations list."""
        from nac_validate.output_formatter import OutputFormatter

        formatter = OutputFormatter(severity="HIGH")
        lines = formatter.format_rule_result([])
        assert lines == []

    def test_result_with_context(self) -> None:
        """Should format result with rich context."""
        from nac_validate.output_formatter import OutputFormatter

        class Rule(RuleBase):
            id = "100"
            description = "Test"
            title = "Configuration Issue"
            affected_items_label = "Affected Items"
            explanation = "Why this matters"
            recommendation = "How to fix"

        formatter = OutputFormatter(severity="HIGH")
        violations = [Violation(message="Error", path="path")]
        lines = formatter.format_rule_result(violations, Rule)
        assert any("Configuration Issue" in line for line in lines)
        assert any("Found 1 violation" in line for line in lines)

    def test_result_without_context(self) -> None:
        """Should format result with simple output."""
        from nac_validate.output_formatter import OutputFormatter

        formatter = OutputFormatter(severity="HIGH")
        violations = [Violation(message="Error", path="path")]
        lines = formatter.format_rule_result(violations)
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
                rule_id="100",
                description="Test",
                severity="HIGH",
                errors=[
                    {"message": "err1", "path": "", "details": {}},
                    {"message": "err2", "path": "", "details": {}},
                ],
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
