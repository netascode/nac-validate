# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

from importlib.metadata import version

from .models import RuleBase, RuleResult, Violation, is_blocking
from .validator import Validator

__version__ = version(__name__)

# Public API, for rule authors and tools using nac-validate as a library. The
# modules nac_validate.schema and nac_validate.ignores have a public API too
__all__ = [
    "RuleBase",
    "RuleResult",
    "Validator",
    "Violation",
    "__version__",
    "is_blocking",
]
