# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Unit tests for nac_validate.schema package (Yamale schema extensions)."""

import logging
from pathlib import Path
from typing import Any, ClassVar
from unittest.mock import patch

import pytest
import yamale

import nac_validate.validator
from nac_validate.constants import DEFAULT_RULES
from nac_validate.exceptions import SchemaError, SyntaxValidationError
from nac_validate.schema import (
    EXTENSIONS,
    Extension,
    Scope,
    check_data,
    check_schema,
    used_extensions,
)
from nac_validate.schema.walker import DataNode, walk_data, walk_schema
from nac_validate.validator import Validator

SCHEMA = """
tenants: list(include('tenant'), primary_key='name', required=False)
---
tenant:
  name: any(str(), int(), bool(), required=False)
  id: int(required=False)
  bds: list(include('bd'), primary_key='name', required=False)
bd:
  name: str()
"""


def errors(
    data: dict[str, Any], schema: str = SCHEMA, scope: Scope = Scope.FILE
) -> list[str]:
    """Check data that passes Yamale validation against the extensions."""
    loaded = yamale.make_schema(content=schema)
    yamale.validate(loaded, [(data, "data")])
    return check_data(loaded, data, EXTENSIONS, scope)


def walked(schema: str, data: dict[str, Any]) -> list[tuple[str, str]]:
    """Return the paths and validator tags the data walk visits."""
    loaded = yamale.make_schema(content=schema)
    yamale.validate(loaded, [(data, "data")])
    return [
        (".".join(str(p) for p in node.path), node.validator.tag)
        for node in walk_data(loaded, data, strict=True)
    ]


class TestPrimaryKey:
    """Tests for the primary_key keyword of list()."""

    def test_unique_keys_pass(self) -> None:
        assert errors({"tenants": [{"name": "a"}, {"name": "b"}]}) == []

    def test_duplicate_key_fails(self) -> None:
        data = {"tenants": [{"name": "a"}, {"name": "b"}, {"name": "a", "id": 1}]}
        assert errors(data) == ["tenants: Duplicate primary key name=a in items 0, 2"]

    def test_each_duplicated_value_reported_once(self) -> None:
        data = {"tenants": [{"name": "a"}, {"name": "b"}] * 3}
        assert errors(data) == [
            "tenants: Duplicate primary key name=a in items 0, 2, 4",
            "tenants: Duplicate primary key name=b in items 1, 3, 5",
        ]

    def test_duplicate_in_merged_data_names_no_items(self) -> None:
        data = {"tenants": [{"name": "a", "id": 1}, {"name": "a", "id": 2}]}
        assert errors(data, scope=Scope.DOCUMENT) == [
            "tenants: Duplicate primary key name=a across files"
            " (with conflicting values that prevent merging)"
        ]

    @pytest.mark.parametrize("item", [{"id": 1}, {"name": None}])
    def test_missing_key_fails(self, item: dict[str, Any]) -> None:
        data = {"tenants": [{"name": "a"}, item]}
        assert errors(data) == ["tenants: Primary key 'name' missing in item 1"]

    def test_null_list_is_not_set(self) -> None:
        assert errors({"tenants": None}) == []

    def test_values_of_different_types_are_distinct(self) -> None:
        data = {"tenants": [{"name": 1}, {"name": "1"}, {"name": True}]}
        assert errors(data) == []

    def test_outer_and_nested_duplicates_are_reported_together(self) -> None:
        bds = [{"name": "x"}, {"name": "x"}]
        data = {"tenants": [{"name": "a", "bds": bds}, {"name": "a"}]}
        assert errors(data) == [
            "tenants: Duplicate primary key name=a in items 0, 1",
            "tenants.0.bds: Duplicate primary key name=x in items 0, 1",
        ]

    def test_items_that_are_not_maps_are_left_to_item_validators(self) -> None:
        schema = "items: list(str(), primary_key='name')"
        assert errors({"items": ["a", "a"]}, schema) == []

    def test_list_without_primary_key_allows_duplicates(self) -> None:
        schema = "items: list(map())"
        assert errors({"items": [{"name": "a"}, {"name": "a"}]}, schema) == []


class TestVanillaYamale:
    """Schemas using extensions stay valid for vanilla Yamale."""

    def test_extension_keywords_are_ignored(self) -> None:
        loaded = yamale.make_schema(content=SCHEMA)
        data = {"tenants": [{"name": "a"}, {"name": "a"}]}
        yamale.validate(loaded, [(data, "data")])


class TestWalkData:
    """Tests for walk_data(), which mirrors Yamale's traversal."""

    def test_static_maps_includes_and_lists(self) -> None:
        schema = "root:\n  items: list(include('item'))\n---\nitem:\n  name: str()"
        assert walked(schema, {"root": {"items": [{"name": "a"}]}}) == [
            ("root.items", "list"),
            ("root.items.0", "include"),
            ("root.items.0.name", "str"),
        ]

    def test_missing_optional_keys_are_skipped(self) -> None:
        schema = "a: str(required=False)\nb: int()"
        assert walked(schema, {"b": 1}) == [("b", "int")]

    def test_null_values_are_skipped(self) -> None:
        schema = "a: list(int(), required=False)\nb: int()"
        assert walked(schema, {"a": None, "b": 1}) == [("b", "int")]

    def test_any_uses_the_matching_validator(self) -> None:
        schema = "a: any(int(), include('item'))\n---\nitem:\n  name: str()"
        assert walked(schema, {"a": {"name": "x"}}) == [
            ("a", "any"),
            ("a", "include"),
            ("a.name", "str"),
        ]

    def test_list_with_several_validators_matches_each_item(self) -> None:
        schema = "a: list(int(), map(str()))"
        assert walked(schema, {"a": [1, {"k": "v"}]}) == [
            ("a", "list"),
            ("a.0", "int"),
            ("a.1", "map"),
            ("a.1.k", "str"),
        ]

    def test_map_keys_are_walked_with_the_key_validator(self) -> None:
        schema = "a: map(int(), key=regex('^k'))"
        loaded = yamale.make_schema(content=schema)
        nodes = [
            (".".join(str(p) for p in n.path), n.validator.tag, n.value)
            for n in walk_data(loaded, {"a": {"k1": 1}}, strict=True)
        ]
        assert nodes == [
            ("a", "map", {"k1": 1}),
            ("a.k1", "regex", "k1"),
            ("a.k1", "int", 1),
        ]

    def test_subset_matches_each_part(self) -> None:
        schema = "a: subset(int(), str())"
        assert walked(schema, {"a": [1, "x"]}) == [
            ("a", "subset"),
            ("a", "int"),
            ("a", "str"),
        ]

    def test_subset_map_parts_are_maps_of_one_key(self) -> None:
        schema = "a: subset(map(int()), map(str()))"
        loaded = yamale.make_schema(content=schema)
        nodes = [
            (".".join(str(p) for p in n.path), n.validator.tag, n.value)
            for n in walk_data(loaded, {"a": {"x": 1, "y": "s"}}, strict=True)
        ]
        assert nodes == [
            ("a", "subset", {"x": 1, "y": "s"}),
            ("a", "map", {"x": 1}),
            ("a.x", "int", 1),
            ("a", "map", {"y": "s"}),
            ("a.y", "str", "s"),
        ]

    def test_invalid_data_is_walked_with_the_first_validator_of_its_type(
        self,
    ) -> None:
        schema = (
            "a: any(int(), include('x'), include('y'))\n---\n"
            "x:\n  kx: str(required=False)\n  l: list(int(), required=False)\n"
            "y:\n  ky: str()"
        )
        loaded = yamale.make_schema(content=schema)
        # Merged from two files, matches neither include in strict mode
        data = {"a": {"kx": "1", "ky": "2", "l": [1]}}
        tags = [
            getattr(node.validator, "include_name", node.validator.tag)
            for node in walk_data(loaded, data, strict=True)
        ]
        assert tags == ["any", "x", "str", "list", "int"]

    def test_include_strict_setting_decides_the_match(self) -> None:
        schema = (
            "a: any(include('strict'), include('loose', strict=False))\n---\n"
            "strict:\n  name: str()\nloose:\n  name: str()"
        )
        loaded = yamale.make_schema(content=schema)
        data = {"a": {"name": "x", "extra": 1}}
        tags = [
            getattr(node.validator, "include_name", node.validator.tag)
            for node in walk_data(loaded, data, strict=True)
        ]
        assert tags == ["any", "loose", "str"]


class TestWalkSchema:
    """Tests for walk_schema()."""

    def test_yields_nested_validators_with_their_location(self) -> None:
        schema = (
            "a: list(map(int(), key=str()), required=False)\n---\n"
            "item:\n  b:\n    c: any(str(), int())"
        )
        loaded = yamale.make_schema(content=schema)
        nodes = [(n.location, n.validator.tag) for n in walk_schema(loaded)]
        assert nodes == [
            ("a", "list"),
            ("a", "map"),
            ("a", "int"),
            ("a", "str"),
            ("item.b.c", "any"),
            ("item.b.c", "str"),
            ("item.b.c", "int"),
        ]


class TestCheckSchema:
    """Tests for check_schema()."""

    def test_yamale_keywords_are_known(self, caplog: pytest.LogCaptureFixture) -> None:
        schema = (
            "a: int(min=1, max=2, required=False, none=False)\n"
            "b: str(equals='x', ignore_case=True, multiline=True)\n"
            "c: map(key=str(), min=1)\n"
            "d: regex('^a', name='x')\n"
            "e: include('i', strict=False)\n"
            "f: ip(version=4)\n---\ni:\n  x: str()"
        )
        with caplog.at_level(logging.WARNING):
            check_schema(yamale.make_schema(content=schema))
        assert caplog.messages == []

    def test_unknown_keyword_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        schema = "---\ni:\n  a: list(map(), primary_keys='name')"
        with caplog.at_level(logging.WARNING):
            check_schema(yamale.make_schema(content=schema))
        assert caplog.messages == [
            "Unknown schema keyword 'primary_keys' at 'i.a' is ignored"
        ]

    def test_keyword_on_unsupported_validator_fails(self) -> None:
        with pytest.raises(SchemaError, match=r"a: primary_key is only .* list\(\)"):
            check_schema(yamale.make_schema(content="a: str(primary_key='name')"))

    @pytest.mark.parametrize("value", ["''", "1"])
    def test_invalid_primary_key_fails(self, value: str) -> None:
        schema = f"a: list(map(), primary_key={value})"
        with pytest.raises(SchemaError, match="primary_key must be a field name"):
            check_schema(yamale.make_schema(content=schema))

    def test_yamale_keyword_does_not_configure_an_extension(self) -> None:
        class Key(Extension):
            keywords: ClassVar[tuple[str, ...]] = ("key",)

            def check(self, node: DataNode, scope: Scope) -> list[str]:
                return ["checked"]

        loaded = yamale.make_schema(content="a: map(key=str())\nb: str(key='x')")
        assert check_data(loaded, {"a": {}, "b": "v"}, [Key()], Scope.FILE) == [
            "b: checked"
        ]

    def test_used_extensions(self) -> None:
        assert used_extensions(yamale.make_schema(content=SCHEMA)) == list(EXTENSIONS)
        assert used_extensions(yamale.make_schema(content="a: list(map())")) == []


class TestValidatorExtensions:
    """Tests for extensions checked by Validator.validate_syntax()."""

    @pytest.fixture
    def validator(self, project: Path) -> Validator:
        schema = project / "schema.yaml"
        schema.write_text(SCHEMA)
        return Validator.from_paths(schema, DEFAULT_RULES)

    @pytest.fixture
    def data(self, project: Path) -> Path:
        data = project / "data"
        data.mkdir()
        return data

    def test_invalid_extension_fails_loading_the_schema(self, project: Path) -> None:
        schema = project / "schema.yaml"
        schema.write_text("a: str(primary_key='name')")
        with pytest.raises(SchemaError):
            Validator.from_paths(schema, DEFAULT_RULES)

    def test_conflicting_items_across_files_fail(
        self, validator: Validator, data: Path
    ) -> None:
        (data / "a.yaml").write_text("tenants:\n  - name: a\n    id: 1\n")
        (data / "b.yaml").write_text("tenants:\n  - name: a\n    id: 2\n")
        with pytest.raises(SyntaxValidationError):
            validator.validate_syntax([data], rich_output=False)
        assert validator.errors == [
            f"Syntax error '{data}': tenants: Duplicate primary key name=a across"
            " files (with conflicting values that prevent merging)"
        ]

    def test_matching_items_across_files_merge(
        self, validator: Validator, data: Path
    ) -> None:
        (data / "a.yaml").write_text("tenants:\n  - name: a\n    id: 1\n")
        (data / "b.yaml").write_text("tenants:\n  - name: a\n    bds: []\n")
        validator.validate_syntax([data], rich_output=False)
        assert validator.errors == []

    def test_per_file_errors_skip_the_merged_check(
        self, validator: Validator, data: Path
    ) -> None:
        (data / "a.yaml").write_text("tenants:\n  - name: a\n  - name: a\n")
        (data / "b.yaml").write_text("tenants:\n  - name: b\n    id: 1\n")
        (data / "c.yaml").write_text("tenants:\n  - name: b\n    id: 2\n")
        with pytest.raises(SyntaxValidationError):
            validator.validate_syntax([data], rich_output=False)
        assert validator.errors == [
            f"Syntax error '{data / 'a.yaml'}': "
            "tenants: Duplicate primary key name=a in items 0, 1"
        ]

    def test_schema_errors_skip_extensions_of_the_file(
        self, validator: Validator, data: Path
    ) -> None:
        (data / "a.yaml").write_text("tenants:\n  - name: a\n  - name: a\n    id: x\n")
        with pytest.raises(SyntaxValidationError):
            validator.validate_syntax([data], rich_output=False)
        assert len(validator.errors) == 1
        assert "'x' is not a int" in validator.errors[0]

    def test_merged_data_is_not_validated_against_yamale_again(
        self, project: Path, data: Path
    ) -> None:
        schema = project / "schema.yaml"
        schema.write_text(
            SCHEMA.replace(
                "  id: int(required=False)\n",
                "  id: int(required=False)\n  ids: list(int(), max=1, required=False)\n",
            )
        )
        validator = Validator.from_paths(schema, DEFAULT_RULES)
        (data / "a.yaml").write_text("tenants:\n  - name: a\n    ids: [1]\n")
        (data / "b.yaml").write_text("tenants:\n  - name: a\n    ids: [2]\n")
        validator.validate_syntax([data], rich_output=False)
        assert validator.errors == []

    def test_preloaded_data_is_checked_as_merged_data(
        self, validator: Validator
    ) -> None:
        validator.load_data({"tenants": [{"name": "a", "id": 1}, {"name": "a"}]})
        with pytest.raises(SyntaxValidationError):
            validator.validate_syntax(rich_output=False)
        assert validator.errors == [
            "Syntax error '<pre-loaded>': tenants: Duplicate primary key name=a"
            " across files (with conflicting values that prevent merging)"
        ]

    def test_document_check_on_merged_data_that_is_not_valid(
        self, project: Path, data: Path
    ) -> None:
        schema = project / "schema.yaml"
        schema.write_text(
            "x: any(include('a'), include('b'))\n---\n"
            "a:\n  ka: str(required=False)\n"
            "  l: list(include('i'), primary_key='name', required=False)\n"
            "b:\n  kb: str()\n"
            "i:\n  name: str()\n  id: int(required=False)\n"
        )
        validator = Validator.from_paths(schema, DEFAULT_RULES)
        (data / "a.yaml").write_text("x:\n  ka: '1'\n  l: [{name: n, id: 1}]\n")
        (data / "b.yaml").write_text("x:\n  kb: '2'\n")
        (data / "c.yaml").write_text("x:\n  ka: '1'\n  l: [{name: n, id: 2}]\n")
        with pytest.raises(SyntaxValidationError):
            validator.validate_syntax([data], rich_output=False)
        assert len(validator.errors) == 1
        assert "x.l: Duplicate primary key name=n across files" in validator.errors[0]

    def test_reused_validator_reloads_changed_files(
        self, validator: Validator, data: Path
    ) -> None:
        (data / "a.yaml").write_text("tenants:\n  - name: a\n    id: 1\n")
        (data / "b.yaml").write_text("tenants:\n  - name: b\n")
        validator.validate_syntax([data], rich_output=False)
        (data / "b.yaml").write_text("tenants:\n  - name: a\n    id: 2\n")
        with pytest.raises(SyntaxValidationError):
            validator.validate_syntax([data], rich_output=False)

    def test_merged_data_is_reused_for_semantic_validation(
        self, validator: Validator, data: Path
    ) -> None:
        (data / "a.yaml").write_text("tenants:\n  - name: a\n")
        load = nac_validate.validator.load_yaml_files
        with patch.object(
            nac_validate.validator, "load_yaml_files", side_effect=load
        ) as mock_load:
            validator.validate_syntax([data], rich_output=False)
            validator.validate_semantics([data], rich_output=False)
        # Once for the file, once merged; the semantic validation reuses it
        assert mock_load.call_count == 2
