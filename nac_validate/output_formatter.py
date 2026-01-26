# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Output formatting for semantic validation results.

This module provides rule-agnostic formatting. It colorizes output based on
patterns rather than specific header text, making it work with any rule
from any architecture (ACI, IOS-XE, NX-OS, etc.) without modification.
"""

import re
from typing import Any

from .constants import Colors


class OutputFormatter:
    """Formats semantic validation output with colorization.

    This formatter is completely rule-agnostic. It detects formatting patterns
    and applies appropriate colors without needing to know anything about
    specific rules or their headers.
    """

    # Separator patterns
    HEAVY_SEPARATOR = re.compile(r"^[=]{40,}$")
    LIGHT_SEPARATOR = re.compile(r"^[-]{40,}$")
    LINE_SEPARATOR = re.compile(r"^[─]{40,}$")

    # Header patterns (ALL CAPS with optional spaces/punctuation)
    ALL_CAPS_HEADER = re.compile(r"^[A-Z][A-Z0-9\s\-_/()]+[A-Z0-9)]$")

    # Section header pattern (ends with colon, may have parenthetical)
    SECTION_HEADER = re.compile(r"^[A-Z].*:$")

    # List item patterns
    BULLET_ITEM = re.compile(r"^\s*[•\-\*]\s+")

    # Violation/error indicators
    VIOLATION_KEYWORDS = [
        "violation",
        "error",
        "failed",
        "missing",
        "invalid",
        "duplicate",
    ]

    def __init__(self, severity: str = "HIGH"):
        """Initialize formatter with severity level.

        Args:
            severity: Rule severity (HIGH, MEDIUM, LOW) affects color scheme
        """
        self.severity = severity
        self._set_severity_colors()

    def _set_severity_colors(self) -> None:
        """Set colors based on severity level."""
        if self.severity == "HIGH":
            self.primary_color = Colors.RED
        elif self.severity == "MEDIUM":
            self.primary_color = Colors.YELLOW
        else:
            self.primary_color = Colors.CYAN

    def format_rule_header(self, rule_id: str, description: str) -> str:
        """Format the rule identifier header.

        Args:
            rule_id: The rule ID (e.g., "401")
            description: The rule description

        Returns:
            Formatted header string
        """
        return (
            f"\n{self.primary_color}{Colors.BOLD}[RULE {rule_id}]{Colors.RESET} "
            f"{Colors.DIM}{description}{Colors.RESET}"
        )

    def format_simple_list(self, items: list[str]) -> str:
        """Format a simple list of items (legacy format).

        Args:
            items: List of string items to format

        Returns:
            Formatted string with separators and bullets
        """
        lines = [f"{self.primary_color}{'─' * 80}{Colors.RESET}"]
        for item in items:
            lines.append(f"  {Colors.YELLOW}•{Colors.RESET} {item}")
        lines.append(f"{self.primary_color}{'─' * 80}{Colors.RESET}\n")
        return "\n".join(lines)

    def format_rich_content(self, content: str) -> str:
        """Format pre-formatted rich content from rules.

        This method applies colorization based on detected patterns,
        without needing to know anything about specific rules.

        Args:
            content: Pre-formatted content string from a rule

        Returns:
            Colorized content string
        """
        lines = content.split("\n")
        formatted_lines = []

        for line in lines:
            formatted_lines.append(self._format_line(line))

        return "\n".join(formatted_lines)

    def _format_line(self, line: str) -> str:
        """Apply formatting to a single line based on pattern detection.

        Args:
            line: A single line of text

        Returns:
            Formatted line with appropriate colors
        """
        stripped = line.strip()

        # Heavy separator (===)
        if self.HEAVY_SEPARATOR.match(stripped):
            return f"{self.primary_color}{line}{Colors.RESET}"

        # Light separator (---)
        if self.LIGHT_SEPARATOR.match(stripped):
            return f"{Colors.DIM}{line}{Colors.RESET}"

        # Line separator (───)
        if self.LINE_SEPARATOR.match(stripped):
            return f"{Colors.CYAN}{line}{Colors.RESET}"

        # ALL CAPS headers (e.g., "BRIDGE DOMAIN NAMING POLICY VIOLATION")
        if self.ALL_CAPS_HEADER.match(stripped) and len(stripped) > 10:
            return f"{Colors.BOLD}{Colors.YELLOW}{line}{Colors.RESET}"

        # Section headers ending with colon
        if self.SECTION_HEADER.match(stripped):
            return f"{Colors.BOLD}{Colors.YELLOW}{line}{Colors.RESET}"

        # Highlight violation keywords within lines
        for keyword in self.VIOLATION_KEYWORDS:
            if keyword in line.lower():
                # Highlight the keyword occurrence (case-insensitive replacement)
                pattern = re.compile(f"({re.escape(keyword)})", re.IGNORECASE)
                line = pattern.sub(
                    f"{Colors.RED}\\1{Colors.RESET}", line
                )
                break

        return line

    def _is_rich_content(self, item: str) -> bool:
        """Detect if a result item is rich pre-formatted content.

        Rich content typically starts with a newline and contains
        separator patterns (=== or ───).

        Args:
            item: A single result string

        Returns:
            True if the item appears to be rich formatted content
        """
        return (
            item.startswith("\n")
            and ("=" * 40 in item or "─" * 40 in item)
        )

    def format_output(
        self, rule_id: str, description: str, results: list[str]
    ) -> str:
        """Format complete rule output.

        Automatically detects whether results are simple list items or
        pre-formatted rich content and applies appropriate formatting.
        Handles mixed results where some items are rich and others are simple.

        Args:
            rule_id: The rule ID
            description: The rule description
            results: List of result strings from the rule

        Returns:
            Complete formatted output string
        """
        parts = [self.format_rule_header(rule_id, description)]

        if not results:
            return "\n".join(parts)

        # Separate rich content from simple items
        rich_items = []
        simple_items = []

        for item in results:
            if self._is_rich_content(item):
                rich_items.append(item)
            else:
                simple_items.append(item)

        # Format rich content items (apply pattern-based colorization)
        for item in rich_items:
            parts.append(self.format_rich_content(item))

        # Format simple items as a bullet list (if any)
        if simple_items:
            parts.append(self.format_simple_list(simple_items))

        return "\n".join(parts)


def format_semantic_error(
    rule_id: str,
    description: str,
    severity: str,
    results: list[str],
) -> str:
    """Convenience function for formatting semantic errors.

    Args:
        rule_id: The rule ID
        description: The rule description
        severity: Rule severity level
        results: List of result strings

    Returns:
        Formatted error output
    """
    formatter = OutputFormatter(severity=severity)
    return formatter.format_output(rule_id, description, results)


def format_checklist_summary(
    failed_rules: list[dict],
) -> str:
    """Format a checklist summary of all failed rules.

    This provides a quick action-item list at the end of validation output,
    allowing users to track remediation progress.

    Args:
        failed_rules: List of dicts with 'rule_id', 'description', 'severity',
                      and 'violation_count' keys

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

    # Sort by severity (HIGH first), then by rule ID
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

        # Format violation count
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
