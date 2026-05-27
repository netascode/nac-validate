# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

from typing import Any

from nac_validate.models import RuleBase, Violation


class Rule(RuleBase):
    id = "102"
    description = "Verify child names are lowercase"
    severity = "MEDIUM"
    title = "Lowercase Child Names"
    explanation = "Child names should be lowercase to ensure consistency."
    recommendation = "Rename children to use lowercase names only."
    references = ["https://example.com/naming-conventions"]

    @classmethod
    def match(cls, data: dict[Any, Any]) -> list[Violation]:
        results = []
        try:
            for child in data["root"]["children"]:
                name = child["name"]
                if name == "FORBIDDEN":
                    results.append(
                        Violation(
                            message=f"Child name '{name}' is not lowercase",
                            path="root.children.name",
                            details={"actual": name, "expected": name.lower()},
                        )
                    )
        except KeyError:
            pass
        return results
