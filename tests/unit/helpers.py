# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Builders for nac-validate test fixtures (modules and bundles with rules)."""

from collections.abc import Sequence
from pathlib import Path

from nac_artifacts.testing import (
    bundle_files as _bundle_files,
)
from nac_artifacts.testing import (
    install_module as _install_module,
)
from nac_artifacts.testing import (
    make_tgz,
    make_zip,
    module_entry,
    write_files,
    write_modules_json,
)

from nac_validate.constants import DEFAULT_RULES, DEFAULT_SCHEMA
from nac_validate.layers import ValidationLayer, resolve_layers

__all__ = [
    "RULE_TEMPLATE",
    "artifact_files",
    "bundle_files",
    "install_module",
    "make_tgz",
    "make_zip",
    "module_entry",
    "resolve",
    "rule_source",
    "write_artifacts",
    "write_modules_json",
]

RULE_TEMPLATE = """
class Rule:
    id = "{id}"
    description = "{description}"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        return []
"""


def rule_source(rule_id: str, description: str) -> str:
    """Return the source of a minimal valid rule."""
    return RULE_TEMPLATE.format(id=rule_id, description=description)


def artifact_files(
    *, schema: bool = True, rules: dict[str, str] | None = None
) -> dict[str, str]:
    """Return a schema and rule files relative to ``nac/``.

    Args:
        schema: Whether to include a schema file
        rules: Mapping of rule ID to rule description
    """
    files: dict[str, str] = {"schema.yaml": "a: str()\n"} if schema else {}
    for rule_id, description in (rules or {}).items():
        files[f"rules/{rule_id}.py"] = rule_source(rule_id, description)
    return files


def write_artifacts(
    root: Path, *, schema: bool = True, rules: dict[str, str] | None = None
) -> Path:
    """Create ``root/nac/schema.yaml`` and ``root/nac/rules/<id>.py``."""
    write_files(root / "nac", artifact_files(schema=schema, rules=rules))
    (root / "nac").mkdir(exist_ok=True)
    return root


def install_module(
    project: Path,
    key: str = "m",
    *,
    version: str | None = None,
    schema: bool = True,
    rules: dict[str, str] | None = None,
) -> Path:
    """Install a module with a schema and rules below ``.terraform/modules``."""
    return _install_module(
        project,
        artifact_files(schema=schema, rules=rules),
        key=key,
        version=version,
    )


def bundle_files(
    version: str = "1.0.0", extra: dict[str, str] | None = None
) -> dict[str, str]:
    """Return a bundle with a schema, one rule (ID 2) and optional raw members."""
    return _bundle_files(
        artifact_files(rules={"2": "bundle rule"}), version=version, extra=extra
    )


def resolve(
    project: Path,
    *,
    schema: Path = DEFAULT_SCHEMA,
    rules: list[Path] | None = None,
    bundle: Path | None = None,
    bundles: Sequence[Path] | None = None,
    module_dir: Path | None = None,
) -> list[ValidationLayer]:
    """Resolve schema and rule layers with the CLI defaults for anything not given."""
    return resolve_layers(
        project,
        schema=schema,
        rules=rules or [DEFAULT_RULES],
        bundles=list(bundles)
        if bundles is not None and len(bundles) > 0
        else ([bundle] if bundle is not None else None),
        module_dir=module_dir,
    )
