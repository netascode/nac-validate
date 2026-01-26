# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Data models for structured rule results.

This module defines the core data structures that rules use to report
violations. By using structured data instead of formatted strings,
we achieve clean separation between detection (rules) and presentation
(formatter).

Design Principles:
- Rules return structured Violation objects with machine-readable data
- Formatter owns ALL presentation decisions (colors, layout, text vs JSON)
- Violations contain both human-readable messages and structured details
- Context is optional but enables rich explanatory output
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Violation:
    """A single violation detected by a rule.

    This is the core unit of validation output. Each violation represents
    one specific issue found in the configuration.

    Attributes:
        message: Human-readable description of what's wrong.
                 Should be concise but informative.
                 Example: "Duplicate tenant name 'Production'"
        path: Schema path where the violation occurred.
              Example: "apic.tenants[0].name"
        details: Structured data for programmatic access.
                 This is serialized directly to JSON output.
                 Example: {"value": "Production", "occurrences": 2}

    Example:
        Violation(
            message="VPC 'SERVER_VPC' cannot be resolved to nodes",
            path="apic.tenants[0].application_profiles[0].endpoint_groups[0].static_ports[0]",
            details={
                "channel": "SERVER_VPC",
                "issue": "not_found",
                "assigned_nodes": [],
                "expected_nodes": 2
            }
        )
    """

    message: str
    path: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class RuleContext:
    """Rich context explaining a category of violations.

    Provides the "why it matters" and "how to fix" information that
    makes validation output actionable. This is used by the text
    formatter to generate explanatory sections.

    Attributes:
        title: Bold header for this violation category.
               Should be ALL CAPS for visual distinction.
               Example: "DUPLICATE TENANT NAMES DETECTED"
        explanation: Detailed explanation of why this matters.
                     Can be multi-line. Should include ACI/technical context.
        recommendation: Actionable guidance on how to fix the issue.
                        Can include YAML examples.
        affected_items_label: Label for the violations list.
                              Default: "Affected Items"
        references: Optional list of documentation URLs.

    Example:
        RuleContext(
            title="VPC CHANNEL NODE RESOLUTION FAILURES",
            explanation="In Cisco ACI, vPCs span exactly 2 leaf switches...",
            recommendation="Add explicit node_id/node2_id to the channel...",
            references=["https://cisco.com/..."]
        )
    """

    title: str
    explanation: str
    recommendation: str
    affected_items_label: str = "Affected Items"
    references: list[str] = field(default_factory=list)


@dataclass
class RuleResult:
    """Complete structured result from a rule's match() method.

    This replaces the old list[str] return type. It contains both
    the violations (structured data) and optional context (for rich output).

    Attributes:
        violations: List of Violation objects detected by the rule.
        context: Optional RuleContext for rich text output.
                 If None, formatter uses a simple list format.

    The class supports boolean evaluation (truthy if violations exist)
    and len() for convenience.

    Example:
        result = RuleResult(
            violations=[
                Violation(message="Duplicate 'Tenant1'", path="apic.tenants[0]"),
                Violation(message="Duplicate 'Tenant2'", path="apic.tenants[1]"),
            ],
            context=RuleContext(
                title="DUPLICATE TENANT NAMES DETECTED",
                explanation="Tenant names must be unique...",
                recommendation="Rename duplicate tenants..."
            )
        )

        if result:  # True because violations exist
            print(f"Found {len(result)} violations")
    """

    violations: list[Violation] = field(default_factory=list)
    context: RuleContext | None = None

    def __bool__(self) -> bool:
        """RuleResult is truthy if there are violations."""
        return len(self.violations) > 0

    def __len__(self) -> int:
        """Return the number of violations."""
        return len(self.violations)


@dataclass
class GroupedRuleResult:
    """Result containing multiple violation groups with separate contexts.

    Some rules (like Rule 101 - unique keys) detect multiple categories
    of violations, each with its own explanation. This class supports
    that pattern while maintaining structured data.

    Attributes:
        groups: List of RuleResult objects, each representing a category.

    Example:
        GroupedRuleResult(groups=[
            RuleResult(
                violations=[Violation(message="Duplicate 'Tenant1'", ...)],
                context=RuleContext(title="DUPLICATE TENANT NAMES", ...)
            ),
            RuleResult(
                violations=[Violation(message="Duplicate 'VRF1'", ...)],
                context=RuleContext(title="DUPLICATE VRF NAMES", ...)
            ),
        ])
    """

    groups: list[RuleResult] = field(default_factory=list)

    def __bool__(self) -> bool:
        """GroupedRuleResult is truthy if any group has violations."""
        return any(group.violations for group in self.groups)

    def __len__(self) -> int:
        """Return total number of violations across all groups."""
        return sum(len(group) for group in self.groups)

    @property
    def all_violations(self) -> list[Violation]:
        """Flatten all violations from all groups."""
        return [v for group in self.groups for v in group.violations]
