# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Unit tests for nac_validate.layers module.

Tests verify the local layer and the mapping of bundle and module layers to
the schema and rules nac-validate reads from them.
"""

from pathlib import Path

import pytest
from nac_artifacts import BundleError, ModuleDiscoveryError, OverridesError
from nac_artifacts.testing import overrides_yaml, write_files

from nac_validate.exceptions import SchemaNotFoundError
from nac_validate.layers import ValidationLayer
from tests.unit.helpers import (
    bundle_files,
    install_module,
    make_zip,
    module_entry,
    resolve,
    write_artifacts,
    write_modules_json,
)


class TestLocalLayer:
    """Tests for the local layer (explicit options and default paths)."""

    def test_local_layer_always_first(self, project: Path) -> None:
        """Should return only the local layer when nothing else is found."""
        layers = resolve(project)

        assert [layer.origin for layer in layers] == ["local"]

    def test_explicit_missing_schema_raises(self, project: Path) -> None:
        """Should raise when an explicitly given schema does not exist."""
        with pytest.raises(SchemaNotFoundError):
            resolve(project, schema=Path("missing.yaml"))

    def test_default_schema_missing_is_silent(self, project: Path) -> None:
        """Should not raise or provide a schema when the default is absent."""
        assert resolve(project)[0].schema is None

    def test_existing_default_schema_is_used(self, project: Path) -> None:
        """Should pick up .schema.yaml from the working directory."""
        (project / ".schema.yaml").write_text("a: str()\n")

        assert resolve(project)[0].schema == Path(".schema.yaml")

    def test_rules_dirs_are_kept_as_given(self, project: Path) -> None:
        """Should keep every -r directory, existing or not, for the loader."""
        layers = resolve(project, rules=[Path("a"), Path("b")])

        assert layers[0].rules_dirs == (Path("a"), Path("b"))


class TestLocalLayerDescription:
    """Tests for how the local layer describes the paths it looked at."""

    def test_missing_default_paths_are_left_out(self, project: Path) -> None:
        """Should describe nothing, and be empty, without .schema.yaml and .rules."""
        local = resolve(project)[0]

        assert local.detail == ""
        assert local.is_empty

    def test_existing_paths_are_listed(self, project: Path) -> None:
        """Should list the existing default schema and rules paths."""
        (project / ".schema.yaml").write_text("a: str()\n")
        (project / ".rules").mkdir()

        local = resolve(project)[0]

        assert local.detail == "schema .schema.yaml, rules .rules"
        assert not local.is_empty

    def test_only_existing_rules_directories_are_listed(self, project: Path) -> None:
        """Should leave out rules directories that do not exist."""
        (project / "a").mkdir()

        detail = resolve(project, rules=[Path("a"), Path("b")])[0].detail

        assert detail == "rules a"


class TestPackagedLayers:
    """Tests for how bundle and module layers map to schema and rules."""

    def test_layer_order_is_local_bundle_module(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should order layers local, bundle, module (highest priority first)."""
        install_module(project)
        archive = make_zip(tmp_path / "b.zip", bundle_files())

        layers = resolve(project, bundle=archive)

        assert [layer.origin for layer in layers] == ["local", "bundle", "module"]

    def test_module_schema_and_rules_are_mapped(self, project: Path) -> None:
        """Should expose the module's schema file and rules directory."""
        module_dir = install_module(project, version="0.3.0", rules={"1": "rule"})

        module = resolve(project)[1]

        assert module.schema == module_dir.resolve() / "nac/schema.yaml"
        assert module.rules_dirs == (module_dir.resolve() / "nac/rules",)
        assert module.version == "0.3.0"

    def test_module_without_schema_has_no_schema(self, project: Path) -> None:
        """Should leave the schema empty when the module only ships rules."""
        install_module(project, schema=False, rules={"1": "rule"})

        module = resolve(project)[1]

        assert module.schema is None
        assert len(module.rules_dirs) == 1

    def test_module_without_rules_has_no_rules_dirs(self, project: Path) -> None:
        """Should leave the rules empty when the module only ships a schema."""
        install_module(project)

        assert resolve(project)[1].rules_dirs == ()

    def test_module_with_only_test_artifacts_is_not_used(self, project: Path) -> None:
        """Should ignore modules that ship nac/tests but neither schema nor rules."""
        module_dir = install_module(project, schema=False)
        (module_dir / "nac/tests/templates").mkdir(parents=True)

        assert [layer.origin for layer in resolve(project)] == ["local"]

    def test_bundle_without_schema_or_rules_raises(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should reject a bundle that only ships test artifacts."""
        files = {
            "manifest.yaml": "name: tests-only\n",
            "nac/tests/templates/a.robot": "*** Test Cases ***\n",
        }

        with pytest.raises(BundleError, match="contains no"):
            resolve(project, bundle=make_zip(tmp_path / "b.zip", files))

    def test_explicit_module_dir_is_mapped(self, project: Path, tmp_path: Path) -> None:
        """Should map an explicit --module-dir like a discovered module."""
        write_artifacts(tmp_path / "mod", rules={"3": "rule"})

        module = resolve(project, module_dir=tmp_path / "mod")[1]

        assert module.schema == tmp_path / "mod/nac/schema.yaml"
        assert module.rules_dirs == (tmp_path / "mod/nac/rules",)

    def test_ambiguous_modules_point_to_the_cli_option(self, project: Path) -> None:
        """Should tell CLI users to select a module with --module-dir."""
        for key in ("a", "b"):
            write_artifacts(project / f".terraform/modules/{key}")
        write_modules_json(
            project, [module_entry(k, f".terraform/modules/{k}") for k in ("a", "b")]
        )

        with pytest.raises(ModuleDiscoveryError, match="Use --module-dir"):
            resolve(project)


class TestDisabledRules:
    """Tests for which disable entries reach which layer."""

    @staticmethod
    def patterns(layer: ValidationLayer) -> list[tuple[str, str]]:
        return [(e.pattern, e.source) for e in layer.disabled_rules]

    def test_local_layer_has_no_disabled_rules(self, project: Path) -> None:
        """Should never disable anything in the local layer."""
        install_module(project)
        write_files(project / ".nac", {"overrides.yaml": overrides_yaml(rules=["1"])})

        assert resolve(project)[0].disabled_rules == ()

    def test_project_entries_reach_bundle_and_module(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should apply .nac/overrides.yaml to every packaged layer."""
        install_module(project)
        archive = make_zip(tmp_path / "b.zip", bundle_files())
        write_files(project / ".nac", {"overrides.yaml": overrides_yaml(rules=["102"])})

        _, bundle, module = resolve(project, bundle=archive)

        assert self.patterns(bundle) == [("102", "project")]
        assert self.patterns(module) == [("102", "project")]

    def test_bundle_entries_reach_only_the_module(
        self, project: Path, tmp_path: Path
    ) -> None:
        """Should apply a bundle's overrides.yaml to the module below it."""
        install_module(project)
        archive = make_zip(
            tmp_path / "b.zip",
            bundle_files(extra={"overrides.yaml": overrides_yaml(rules=["7"])}),
        )

        _, bundle, module = resolve(project, bundle=archive)

        assert bundle.disabled_rules == ()
        assert self.patterns(module) == [("7", "bundle acme")]

    def test_template_entries_are_not_nac_validate_business(
        self, project: Path
    ) -> None:
        """Should ignore template entries, which only nac-test uses."""
        install_module(project)
        write_files(
            project / ".nac", {"overrides.yaml": overrides_yaml(templates=["a.robot"])}
        )

        assert resolve(project)[1].disabled_rules == ()

    def test_malformed_project_overrides_raise(self, project: Path) -> None:
        """Should fail instead of ignoring a broken overrides file."""
        install_module(project)
        write_files(project / ".nac", {"overrides.yaml": "- x\n"})

        with pytest.raises(OverridesError, match="must be a mapping"):
            resolve(project)
