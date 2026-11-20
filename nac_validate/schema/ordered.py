# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""``list(..., ordered=True)``: the order of the items is significant.

A list without it, or with ``ordered=False``, has no significant order. Like
``description``, it only describes the schema and is not checked against the
data.
"""

from yamale.validators import List, Validator

from .base import Annotation


class Ordered(Annotation):
    keywords = ("ordered",)
    validator_types = (List,)

    def check_schema(self, validator: Validator) -> list[str]:
        value = validator.kwargs["ordered"]
        if not isinstance(value, bool):
            return [f"ordered must be True or False, not {value!r}"]
        return []
