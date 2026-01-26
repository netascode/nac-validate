# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

from importlib.metadata import version  # type: ignore

from .models import GroupedRuleResult, RuleContext, RuleResult, Violation

__version__ = version(__name__)

# Public API for rule authors
__all__ = [
    "Violation",
    "RuleContext",
    "RuleResult",
    "GroupedRuleResult",
    "__version__",
]
