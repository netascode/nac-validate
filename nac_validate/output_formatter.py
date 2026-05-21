# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Output formatting for semantic validation results.

This module is responsible for ALL presentation decisions. It takes
structured data from rules and renders it for different output formats.
"""

from dataclasses import dataclass, field
from typing import Any

from .constants import (
    HEADER_SEPARATOR_WIDTH,
    SEVERITY_SORT_ORDER,
    SUMMARY_SEPARATOR_WIDTH,
    UNKNOWN_SEVERITY_SORT_ORDER,
    Colors,
)
from .models import RuleBase, Violation, _is_violation_list


class OutputFormatter:
    """Formats structured validation results for terminal output.

    This formatter renders violation lists as colored terminal
    output with rich context sections.
    """

    # Separator characters
    HEAVY_SEP = "="
    LIGHT_SEP = "-"
    LINE_SEP = "─"

    def __init__(self, severity: str = "HIGH"):
        """Initialize formatter with severity level.

        Args:
            severity: Rule severity (HIGH, MEDIUM, LOW) affects color scheme
        """
        self.severity = severity
        self._set_colors()

    def _set_colors(self) -> None:
        """Set colors based on severity level."""
        self.primary_color = Colors.for_severity(self.severity)

    def _separator(self, char: str, width: int = 80) -> str:
        """Create a colored separator line."""
        sep = char * width
        if char == self.HEAVY_SEP:
            return f"{self.primary_color}{sep}{Colors.RESET}"
        elif char == self.LIGHT_SEP:
            return f"{Colors.DIM}{sep}{Colors.RESET}"
        elif char == self.LINE_SEP:
            return f"{Colors.CYAN}{sep}{Colors.RESET}"
        return sep

    def _header(self, text: str) -> str:
        """Format a section header with bold yellow."""
        return f"{Colors.BOLD}{Colors.YELLOW}{text}{Colors.RESET}"

    def _rule_header(self, rule_id: str, description: str) -> str:
        """Format the rule identifier header."""
        return (
            f"\n{self.primary_color}{Colors.BOLD}[RULE {rule_id}]{Colors.RESET} "
            f"{Colors.DIM}{description}{Colors.RESET}"
        )

    def format_violation(self, violation: Violation) -> list[str]:
        """Format a single violation as indented lines.

        Args:
            violation: The Violation to format

        Returns:
            List of formatted lines
        """
        lines = []
        lines.append(f"  {Colors.YELLOW}•{Colors.RESET} {violation.message}")
        if violation.path:
            lines.append(f"    {Colors.DIM}Path:{Colors.RESET} {violation.path}")
        return lines

    def format_violations_list(
        self, violations: list[Violation], label: str = "Affected Items"
    ) -> list[str]:
        """Format a list of violations with a header.

        Args:
            violations: List of Violation objects
            label: Header label for the section

        Returns:
            List of formatted lines
        """
        if not violations:
            return []

        lines = [f"\n{self._header(f'{label}:')}"]
        for v in violations:
            lines.extend(self.format_violation(v))
        return lines

    def format_context(self, rule: type[RuleBase]) -> list[str]:
        """Format the rich context sections.

        Args:
            rule: Rule class with explanation, recommendation, references attributes

        Returns:
            List of formatted lines
        """
        lines = []

        # WHY THIS MATTERS section
        lines.append(f"\n{self._separator(self.LIGHT_SEP)}")
        lines.append(self._header("WHY THIS MATTERS:"))
        lines.append(self._separator(self.LIGHT_SEP))
        lines.append("")
        lines.append(rule.explanation)

        # RECOMMENDED FIX section
        lines.append(f"\n{self._separator(self.LINE_SEP)}")
        lines.append(self._header("RECOMMENDED FIX:"))
        lines.append(self._separator(self.LINE_SEP))
        lines.append("")
        lines.append(rule.recommendation)

        # References (if any)
        if rule.references:
            lines.append("")
            lines.append(f"{Colors.DIM}References:{Colors.RESET}")
            for ref in rule.references:
                lines.append(f"  {Colors.CYAN}{ref}{Colors.RESET}")

        return lines

    def format_rule_result(
        self, violations: list[Violation], rule: type[RuleBase] | None = None
    ) -> list[str]:
        """Format a list of Violation objects.

        Args:
            violations: List of Violation objects
            rule: Optional rule class for rich context output

        Returns:
            List of formatted lines
        """
        if not violations:
            return []

        lines = []

        if rule:
            lines.append(f"\n{self._separator(self.HEAVY_SEP)}")
            lines.append(self._header(rule.title))
            lines.append(self._separator(self.HEAVY_SEP))
            lines.append("")
            lines.append(f"Found {len(violations)} violation(s).")

            lines.extend(
                self.format_violations_list(violations, rule.affected_items_label)
            )

            lines.extend(self.format_context(rule))

            lines.append(f"\n{self._separator(self.HEAVY_SEP)}")
        else:
            lines.append(f"\n{self._separator(self.LINE_SEP)}")
            for v in violations:
                lines.extend(self.format_violation(v))
            lines.append(self._separator(self.LINE_SEP))

        return lines

    def format_output(
        self,
        rule: type[RuleBase],
        result: list[Any],
    ) -> str:
        """Format complete rule output.

        Args:
            rule: The rule class
            result: list[Violation] or list[str]

        Returns:
            Complete formatted output string
        """
        parts = [self._rule_header(rule.id, rule.description)]

        if _is_violation_list(result):
            has_rich_context = all((rule.title, rule.explanation, rule.recommendation))
            parts.extend(
                self.format_rule_result(result, rule if has_rich_context else None)
            )
        else:
            parts.extend(self._format_legacy_list_output(result))

        return "\n".join(parts)

    def _format_legacy_list_output(self, results: list[Any]) -> list[str]:
        """Format legacy string/dict-based results as bullet points."""
        if not results:
            return []

        lines = [f"\n{self._separator(self.LINE_SEP)}"]
        for item in results:
            lines.append(f"  {Colors.YELLOW}•{Colors.RESET} {item}")
        lines.append(self._separator(self.LINE_SEP))

        return lines


def format_semantic_error(
    rule: type[RuleBase],
    result: list[Any],
) -> str:
    """Convenience function for formatting semantic errors."""
    formatter = OutputFormatter(severity=rule.severity)
    return formatter.format_output(rule, result)


def format_json_result(
    rule_id: str,
    description: str,
    severity: str,
    result: list[Any],
) -> dict[str, Any]:
    """Format a rule result as a JSON-serializable dictionary."""
    base: dict[str, Any] = {
        "rule_id": rule_id,
        "description": description,
    }

    if _is_violation_list(result):
        base["errors"] = [f"{v.path} - {v.message}" for v in result]
    else:
        base["errors"] = result

    return base


@dataclass
class _SeverityBucket:
    count: int = 0
    rule_ids: list[str] = field(default_factory=list)


def _bucket_by_severity(
    semantic_errors: list[Any], rules: dict[str, Any]
) -> dict[str, _SeverityBucket]:
    """Group error counts and rule IDs by severity level."""
    buckets: dict[str, _SeverityBucket] = {
        "HIGH": _SeverityBucket(),
        "MEDIUM": _SeverityBucket(),
        "LOW": _SeverityBucket(),
    }
    for error in semantic_errors:
        rule = rules.get(error.rule_id)
        severity = getattr(rule, "severity", "HIGH") if rule else "HIGH"
        bucket = buckets.get(severity, buckets["LOW"])
        bucket.count += len(error.errors)
        bucket.rule_ids.append(error.rule_id)
    return buckets


def format_checklist_summary(failed_rules: list[dict[str, Any]]) -> str:
    """Format a checklist summary of all failed rules.

    Args:
        failed_rules: List of dicts with rule info

    Returns:
        Formatted checklist summary string
    """
    if not failed_rules:
        return ""

    lines = [
        f"\n{Colors.MAGENTA}{'━' * HEADER_SEPARATOR_WIDTH}{Colors.RESET}",
        f"{Colors.MAGENTA}{Colors.BOLD}  REMEDIATION CHECKLIST{Colors.RESET}",
        f"{Colors.MAGENTA}{'━' * HEADER_SEPARATOR_WIDTH}{Colors.RESET}\n",
    ]

    sorted_rules = sorted(
        failed_rules,
        key=lambda x: (
            SEVERITY_SORT_ORDER.get(x["severity"], UNKNOWN_SEVERITY_SORT_ORDER),
            int(x["rule_id"]),
        ),
    )

    for rule in sorted_rules:
        severity = rule["severity"]
        severity_color = Colors.for_severity(severity)

        count = rule.get("violation_count", 0)
        count_str = f"({count} violation{'s' if count != 1 else ''})" if count else ""

        lines.append(
            f"  {Colors.MAGENTA}[ ]{Colors.RESET} "
            f"{Colors.BOLD}Rule {rule['rule_id']}{Colors.RESET}: "
            f"{rule['description']} "
            f"{severity_color}{count_str}{Colors.RESET}"
        )

    lines.append(f"\n{Colors.MAGENTA}{'━' * HEADER_SEPARATOR_WIDTH}{Colors.RESET}")
    lines.append(
        f"{Colors.DIM}  {len(failed_rules)} rule{'s' if len(failed_rules) != 1 else ''} "
        f"failed validation. Address items above to resolve.{Colors.RESET}\n"
    )

    return "\n".join(lines)


def format_validation_summary(
    syntax_passed: bool,
    semantic_passed: bool,
    file_count: int = 0,
    semantic_errors: list[Any] | None = None,
    rules: dict[str, Any] | None = None,
) -> str:
    """Format a summary of validation results.

    Args:
        syntax_passed: Whether syntax validation passed
        semantic_passed: Whether semantic validation passed
        file_count: Number of files validated
        semantic_errors: List of SemanticErrorResult objects
        rules: Dict of loaded rules (for severity lookup)

    Returns:
        Formatted summary string
    """
    lines = []
    lines.append(f"\n{Colors.BOLD}{'─' * SUMMARY_SEPARATOR_WIDTH}{Colors.RESET}")
    lines.append(f"{Colors.BOLD}Validation Summary{Colors.RESET}")
    lines.append(f"{'─' * SUMMARY_SEPARATOR_WIDTH}")

    # Syntax validation status
    if syntax_passed:
        file_info = f" ({file_count} files)" if file_count > 0 else ""
        lines.append(
            f"  {Colors.GREEN}✓{Colors.RESET} Syntax validation: "
            f"{Colors.GREEN}PASSED{Colors.RESET}{file_info}"
        )
    else:
        lines.append(
            f"  {Colors.RED}✗{Colors.RESET} Syntax validation: "
            f"{Colors.RED}FAILED{Colors.RESET}"
        )

    # Semantic validation status
    if semantic_passed:
        lines.append(
            f"  {Colors.GREEN}✓{Colors.RESET} Semantic validation: "
            f"{Colors.GREEN}PASSED{Colors.RESET}"
        )
    else:
        lines.append(
            f"  {Colors.RED}✗{Colors.RESET} Semantic validation: "
            f"{Colors.RED}FAILED{Colors.RESET}"
        )

        # Count violations by severity
        if semantic_errors and rules:
            buckets = _bucket_by_severity(semantic_errors, rules)

            lines.append("")
            for severity, color in (
                ("HIGH", Colors.RED),
                ("MEDIUM", Colors.YELLOW),
                ("LOW", Colors.CYAN),
            ):
                bucket = buckets[severity]
                if bucket.count > 0:
                    rules_str = ", ".join(bucket.rule_ids)
                    lines.append(
                        f"    {color}•{Colors.RESET} {bucket.count} {severity} severity "
                        f"violation{'s' if bucket.count != 1 else ''} (rules: {rules_str})"
                    )

    lines.append(f"{'─' * SUMMARY_SEPARATOR_WIDTH}\n")
    return "\n".join(lines)


def format_rules_list(rules: dict[str, Any]) -> str:
    """Format a list of validation rules for display.

    Args:
        rules: Dict of rule_id -> Rule class mappings

    Returns:
        Formatted rules list string
    """
    if not rules:
        return f"{Colors.YELLOW}No rules found{Colors.RESET}"

    lines = []
    lines.append(
        f"\n{Colors.CYAN}{Colors.BOLD}Available Validation Rules:{Colors.RESET}"
    )
    lines.append(f"{Colors.DIM}{'─' * SUMMARY_SEPARATOR_WIDTH}{Colors.RESET}\n")

    # Sort rules by ID
    sorted_rules = sorted(rules.items(), key=lambda x: int(x[0]))

    for rule_id, rule in sorted_rules:
        severity = getattr(rule, "severity", "HIGH")
        severity_color = Colors.for_severity(severity)

        lines.append(
            f"  {Colors.BOLD}[{rule_id}]{Colors.RESET} "
            f"{rule.description} "
            f"{severity_color}({severity}){Colors.RESET}"
        )

    lines.append(f"\n{Colors.DIM}{'─' * SUMMARY_SEPARATOR_WIDTH}{Colors.RESET}")
    lines.append(f"{Colors.DIM}Total: {len(rules)} rules{Colors.RESET}\n")

    return "\n".join(lines)
