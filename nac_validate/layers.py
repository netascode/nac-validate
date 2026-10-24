# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Schema and rule layers used by nac-validate.

Schema and rules come from up to three layers, highest priority first:

1. local:  explicit ``-s``/``-r`` options and the ``.schema.yaml`` / ``.rules/`` defaults
2. bundles: archives or directories dropped into the project (``.nac/``); several
   bundles are peers that may split artifacts but must not overlap
3. module: the ``nac/`` directory embedded in an installed Terraform module

The bundle and module layers are located by :mod:`nac_artifacts`; this
module adds the local layer and maps each layer to the schema and rules
nac-validate cares about.
"""

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from nac_artifacts import (
    AmbiguousModuleError,
    ArtifactLayer,
    DisableEntry,
    LayerDisables,
    ModuleDiscoveryError,
    layer_disables,
    resolve_artifact_layers,
)

from .constants import (
    ARTIFACTS_RULES_DIRNAME,
    ARTIFACTS_SCHEMA_FILENAME,
    DEFAULT_SCHEMA,
)
from .exceptions import SchemaNotFoundError

logger = logging.getLogger(__name__)

Origin = Literal["local", "bundle", "module"]


@dataclass(frozen=True)
class ValidationLayer:
    """One source of schema and rules.

    Attributes:
        origin: Which layer this is (local, bundle or module).
        schema: Schema file provided by this layer, if any.
        rules_dirs: Directories with rule files provided by this layer.
        version: Module version or bundle manifest version, if known.
        detail: Human-readable description of where the layer came from.
        disabled_rules: Entries (rule IDs) that disable rules of this layer, from
            ``.nac/overrides.yaml`` and from bundles above it.
        label: Name for messages, e.g. ``bundle acme-base`` (defaults to the origin).
    """

    origin: Origin
    schema: Path | None
    rules_dirs: tuple[Path, ...]
    version: str | None = None
    detail: str = ""
    disabled_rules: tuple[DisableEntry, ...] = ()
    label: str = ""

    @property
    def tag(self) -> str:
        """Label used in output and messages."""
        return self.label or self.origin

    @property
    def is_empty(self) -> bool:
        """Whether the layer provides neither a schema nor rules."""
        return self.schema is None and not any(d.exists() for d in self.rules_dirs)


def _local_layer(schema: Path, rules: Sequence[Path]) -> ValidationLayer:
    """Build the local layer from the explicit options and defaults.

    Missing default paths (``.schema.yaml``, ``.rules/``) are left out of the
    description; missing explicit ones are reported as errors.
    """
    if not schema.exists() and schema != DEFAULT_SCHEMA:
        raise SchemaNotFoundError(f"Schema file not found: {schema}")
    given = [f"schema {schema}"] if schema.exists() else []
    existing = [str(r) for r in rules if r.exists()]
    if existing:
        given.append(f"rules {', '.join(existing)}")
    return ValidationLayer(
        origin="local",
        schema=schema if schema.exists() else None,
        rules_dirs=tuple(rules),
        detail=", ".join(given),
    )


def _from_artifact_layer(
    layer: ArtifactLayer, disables: LayerDisables
) -> ValidationLayer:
    """Map a bundle or module layer to the schema and rules it provides."""
    schema = layer.nac_dir / ARTIFACTS_SCHEMA_FILENAME
    rules = layer.nac_dir / ARTIFACTS_RULES_DIRNAME
    return ValidationLayer(
        origin=layer.origin,
        schema=schema if schema.is_file() else None,
        rules_dirs=(rules,) if rules.is_dir() else (),
        version=layer.version,
        detail=layer.detail,
        disabled_rules=disables.rules,
        label=layer.label,
    )


def resolve_layers(
    project_dir: Path,
    *,
    schema: Path,
    rules: Sequence[Path],
    bundles: Sequence[Path] | None = None,
    module_dir: Path | None = None,
) -> list[ValidationLayer]:
    """Resolve all schema and rule layers, highest priority first."""
    local = _local_layer(schema, rules)
    logger.info("Artifact layer [%s]: %s", local.origin, local.detail)
    try:
        artifact_layers = resolve_artifact_layers(
            project_dir,
            provides=(ARTIFACTS_SCHEMA_FILENAME, ARTIFACTS_RULES_DIRNAME),
            bundles=bundles,
            module_dir=module_dir,
        )
    except AmbiguousModuleError as e:
        raise ModuleDiscoveryError(f"{e} Use --module-dir to select one.") from e
    disables = layer_disables(project_dir, artifact_layers)
    return [
        local,
        *(
            _from_artifact_layer(layer, d)
            for layer, d in zip(artifact_layers, disables, strict=True)
        ),
    ]
