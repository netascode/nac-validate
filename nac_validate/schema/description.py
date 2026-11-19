# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""``description=...``: documentation of a schema element.

The description is not checked against the data, it documents the element
for readers of the schema and for tools generating documentation from it.
It is supported on every validator, e.g.
``str(description='Name of the tenant')``.
"""

from yamale.validators import Validator

from .base import Annotation


class Description(Annotation):
    keywords = ("description",)

    def check_schema(self, validator: Validator) -> list[str]:
        value = validator.kwargs["description"]
        if not isinstance(value, str) or not value.strip():
            return [f"description must be a non-empty string, not {value!r}"]
        return []
