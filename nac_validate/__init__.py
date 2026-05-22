# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

from importlib.metadata import version

from .models import RuleBase, Violation
from .validator import Validator

__version__ = version(__name__)

# Public API for rule authors
__all__ = [
    "Violation",
    "RuleBase",
    "Validator",
    "__version__",
]
