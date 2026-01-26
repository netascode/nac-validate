# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Output formatting for semantic validation results.

This module is responsible for ALL presentation decisions. It takes
structured data from rules and renders it for different output formats.

Design Principles:
- Rules provide structured data (Violation, RuleResult)
- This formatter owns colors, layout, separators, etc.
- Same data can be rendered as text (colored) or JSON (structured)
- Supports both structured RuleResult objects and simple string lists
"""

from typing import Any

from .constants import Colors
from .models import GroupedRuleResult, RuleContext, RuleResult, Violation


class OutputFormatter:
    """Formats structured validation results for terminal output.

    This formatter renders RuleResult and GroupedRuleResult objects
    as colored terminal output with rich context sections.
    """

    # Separator characters
    HEAVY_SEP = "="
    LIGHT_SEP = "-"
    LINE_SEP = "─"
    DOUBLE_SEP = "━"

    def __init__(self, severity: str = "HIGH"):
        """Initialize formatter with severity level.

        Args:
            severity: Rule severity (HIGH, MEDIUM, LOW) affects color scheme
        """
        self.severity = severity
        self._set_colors()

    def _set_colors(self) -> None:
        """Set colors based on severity level."""
        if self.severity == "HIGH":
            self.primary_color = Colors.RED
        elif self.severity == "MEDIUM":
            self.primary_color = Colors.YELLOW
        else:
            self.primary_color = Colors.CYAN

    def _separator(self, char: str, width: int = 80) -> str:
        """Create a colored separator line."""
        sep = char * width
        if char == self.HEAVY_SEP:
            return f"{self.primary_color}{sep}{Colors.RESET}"
        elif char == self.LIGHT_SEP:
            return f"{Colors.DIM}{sep}{Colors.RESET}"
        elif char == self.LINE_SEP:
            return f"{Colors.CYAN}{sep}{Colors.RESET}"
        elif char == self.DOUBLE_SEP:
            return f"{Colors.MAGENTA}{sep}{Colors.RESET}"
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

    def format_context(self, context: RuleContext) -> list[str]:
        """Format the rich context sections.

        Args:
            context: RuleContext with explanation and recommendation

        Returns:
            List of formatted lines
        """
        lines = []

        # WHY THIS MATTERS section
        lines.append(f"\n{self._separator(self.LIGHT_SEP)}")
        lines.append(self._header("WHY THIS MATTERS:"))
        lines.append(self._separator(self.LIGHT_SEP))
        lines.append("")
        lines.append(context.explanation)

        # RECOMMENDED FIX section
        lines.append(f"\n{self._separator(self.LINE_SEP)}")
        lines.append(self._header("RECOMMENDED FIX:"))
        lines.append(self._separator(self.LINE_SEP))
        lines.append("")
        lines.append(context.recommendation)

        # References (if any)
        if context.references:
            lines.append("")
            lines.append(f"{Colors.DIM}References:{Colors.RESET}")
            for ref in context.references:
                lines.append(f"  {Colors.CYAN}{ref}{Colors.RESET}")

        return lines

    def format_rule_result(self, result: RuleResult) -> list[str]:
        """Format a single RuleResult.

        Args:
            result: RuleResult containing violations and optional context

        Returns:
            List of formatted lines
        """
        if not result.violations:
            return []

        lines = []

        if result.context:
            # Rich format with context
            lines.append(f"\n{self._separator(self.HEAVY_SEP)}")
            lines.append(self._header(result.context.title))
            lines.append(self._separator(self.HEAVY_SEP))
            lines.append("")
            lines.append(
                f"Found {len(result.violations)} violation(s)."
            )

            # Violations list
            lines.extend(
                self.format_violations_list(
                    result.violations, result.context.affected_items_label
                )
            )

            # Context sections
            lines.extend(self.format_context(result.context))

            lines.append(f"\n{self._separator(self.HEAVY_SEP)}")
        else:
            # Simple format without context
            lines.append(f"\n{self._separator(self.LINE_SEP)}")
            for v in result.violations:
                lines.extend(self.format_violation(v))
            lines.append(self._separator(self.LINE_SEP))

        return lines

    def format_grouped_result(self, result: GroupedRuleResult) -> list[str]:
        """Format a GroupedRuleResult with multiple categories.

        Args:
            result: GroupedRuleResult containing multiple RuleResult groups

        Returns:
            List of formatted lines
        """
        lines = []
        for group in result.groups:
            lines.extend(self.format_rule_result(group))
        return lines

    def format_output(
        self,
        rule_id: str,
        description: str,
        result: RuleResult | GroupedRuleResult | list[str],
    ) -> str:
        """Format complete rule output.

        Handles both structured results and simple string lists.

        Args:
            rule_id: The rule ID
            description: The rule description
            result: RuleResult, GroupedRuleResult, or list[str]

        Returns:
            Complete formatted output string
        """
        parts = [self._rule_header(rule_id, description)]

        if isinstance(result, GroupedRuleResult):
            parts.extend(self.format_grouped_result(result))
        elif isinstance(result, RuleResult):
            parts.extend(self.format_rule_result(result))
        elif isinstance(result, list):
            # String list format
            parts.extend(self._format_string_list_output(result))

        return "\n".join(parts)

    def _format_string_list_output(self, results: list[str]) -> list[str]:
        """Format string-based results.

        Args:
            results: List of string results

        Returns:
            List of formatted lines
        """
        if not results:
            return []

        # Check if items look like rich pre-formatted content
        lines = []
        for item in results:
            if self._is_rich_content(item):
                lines.extend(self._colorize_rich_content(item))
            else:
                lines.append(f"  {Colors.YELLOW}•{Colors.RESET} {item}")

        if not any(self._is_rich_content(item) for item in results):
            # Wrap simple items in separators
            return [
                f"\n{self._separator(self.LINE_SEP)}",
                *lines,
                self._separator(self.LINE_SEP),
            ]

        return lines

    def _is_rich_content(self, item: str) -> bool:
        """Detect if an item is rich pre-formatted content."""
        return item.startswith("\n") and ("=" * 40 in item or "─" * 40 in item)

    def _colorize_rich_content(self, content: str) -> list[str]:
        """Apply colors to rich content based on patterns."""
        import re

        lines = []
        for line in content.split("\n"):
            stripped = line.strip()

            # Heavy separator (===)
            if re.match(r"^[=]{40,}$", stripped):
                lines.append(f"{self.primary_color}{line}{Colors.RESET}")
            # Light separator (---)
            elif re.match(r"^[-]{40,}$", stripped):
                lines.append(f"{Colors.DIM}{line}{Colors.RESET}")
            # Line separator (───)
            elif re.match(r"^[─]{40,}$", stripped):
                lines.append(f"{Colors.CYAN}{line}{Colors.RESET}")
            # ALL CAPS headers
            elif re.match(r"^[A-Z][A-Z0-9\s\-_/()]+[A-Z0-9)]$", stripped) and len(stripped) > 10:
                lines.append(f"{Colors.BOLD}{Colors.YELLOW}{line}{Colors.RESET}")
            # Section headers ending with colon
            elif re.match(r"^[A-Z].*:$", stripped):
                lines.append(f"{Colors.BOLD}{Colors.YELLOW}{line}{Colors.RESET}")
            else:
                lines.append(line)

        return lines


def format_semantic_error(
    rule_id: str,
    description: str,
    severity: str,
    result: RuleResult | GroupedRuleResult | list[str],
) -> str:
    """Convenience function for formatting semantic errors.

    Args:
        rule_id: The rule ID
        description: The rule description
        severity: Rule severity level
        result: Structured result or string list

    Returns:
        Formatted error output
    """
    formatter = OutputFormatter(severity=severity)
    return formatter.format_output(rule_id, description, result)


def format_json_result(
    rule_id: str,
    description: str,
    severity: str,
    result: RuleResult | GroupedRuleResult | list[str],
) -> dict[str, Any]:
    """Format a rule result as a JSON-serializable dictionary.

    Outputs a consistent format:
    {
        "rule_id": "311",
        "description": "Verify...",
        "errors": ["path - message", ...]
    }

    Args:
        rule_id: The rule ID
        description: The rule description
        severity: Rule severity level
        result: Structured result or string list

    Returns:
        Dictionary ready for JSON serialization
    """
    base = {
        "rule_id": rule_id,
        "description": description,
    }

    if isinstance(result, GroupedRuleResult):
        # Flatten all violations from all groups into simple strings
        errors = []
        for group in result.groups:
            for v in group.violations:
                errors.append(f"{v.path} - {v.message}")
        base["errors"] = errors

    elif isinstance(result, RuleResult):
        base["errors"] = [
            f"{v.path} - {v.message}" for v in result.violations
        ]

    elif isinstance(result, list):
        # String list format
        base["errors"] = result

    return base


def format_checklist_summary(failed_rules: list[dict]) -> str:
    """Format a checklist summary of all failed rules.

    Args:
        failed_rules: List of dicts with rule info

    Returns:
        Formatted checklist summary string
    """
    if not failed_rules:
        return ""

    lines = [
        f"\n{Colors.MAGENTA}{'━' * 80}{Colors.RESET}",
        f"{Colors.MAGENTA}{Colors.BOLD}  REMEDIATION CHECKLIST{Colors.RESET}",
        f"{Colors.MAGENTA}{'━' * 80}{Colors.RESET}\n",
    ]

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_rules = sorted(
        failed_rules,
        key=lambda x: (severity_order.get(x["severity"], 99), int(x["rule_id"])),
    )

    for rule in sorted_rules:
        severity = rule["severity"]
        if severity == "HIGH":
            severity_color = Colors.RED
        elif severity == "MEDIUM":
            severity_color = Colors.YELLOW
        else:
            severity_color = Colors.CYAN

        count = rule.get("violation_count", 0)
        count_str = f"({count} violation{'s' if count != 1 else ''})" if count else ""

        lines.append(
            f"  {Colors.MAGENTA}[ ]{Colors.RESET} "
            f"{Colors.BOLD}Rule {rule['rule_id']}{Colors.RESET}: "
            f"{rule['description']} "
            f"{severity_color}{count_str}{Colors.RESET}"
        )

    lines.append(f"\n{Colors.MAGENTA}{'━' * 80}{Colors.RESET}")
    lines.append(
        f"{Colors.DIM}  {len(failed_rules)} rule{'s' if len(failed_rules) != 1 else ''} "
        f"failed validation. Address items above to resolve.{Colors.RESET}\n"
    )

    return "\n".join(lines)
