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
    Violation,
    check_data,
    check_schema,
    used_extensions,
)
from nac_validate.schema.ip_type import IpType
from nac_validate.schema.primary_key import PrimaryKey
from nac_validate.schema.reference import References
from nac_validate.schema.unique import Unique
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
    return [str(v) for v in check_data(loaded, data, EXTENSIONS, scope)]


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
        assert errors(data) == ["tenants: Duplicate primary key name=a in 2 items"]

    def test_each_duplicated_value_reported_once(self) -> None:
        data = {"tenants": [{"name": "a"}, {"name": "b"}] * 3}
        assert errors(data) == [
            "tenants: Duplicate primary key name=a in 3 items",
            "tenants: Duplicate primary key name=b in 3 items",
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
        assert errors(data) == ["tenants: Primary key 'name' missing in item [1]"]

    def test_null_list_is_not_set(self) -> None:
        assert errors({"tenants": None}) == []

    def test_values_of_different_types_are_distinct(self) -> None:
        data = {"tenants": [{"name": 1}, {"name": "1"}, {"name": True}]}
        assert errors(data) == []

    def test_outer_and_nested_duplicates_are_reported_together(self) -> None:
        bds = [{"name": "x"}, {"name": "x"}]
        data = {"tenants": [{"name": "a", "bds": bds}, {"name": "a"}]}
        assert errors(data) == [
            "tenants: Duplicate primary key name=a in 2 items",
            "tenants.0.bds: Duplicate primary key name=x in 2 items",
        ]

    @pytest.mark.parametrize(
        ("value", "kind"), [(["a"], "a list"), ({"k": "a"}, "a map")]
    )
    def test_key_value_must_be_a_single_value(self, value: Any, kind: str) -> None:
        schema = "items: list(map(), primary_key='name')"
        data = {"items": [{"name": value}, {"name": value}]}
        assert errors(data, schema) == [
            f"items: Primary key 'name' in item [{i}] must be a single value, not {kind}"
            for i in (0, 1)
        ]

    def test_items_that_are_not_maps_are_left_to_item_validators(self) -> None:
        schema = "items: list(str(), primary_key='name')"
        assert errors({"items": ["a", "a"]}, schema) == []

    def test_list_without_primary_key_allows_duplicates(self) -> None:
        schema = "items: list(map())"
        assert errors({"items": [{"name": "a"}, {"name": "a"}]}, schema) == []


class TestCompositePrimaryKey:
    """Tests for primary_key naming several comma-separated fields."""

    SCHEMA = "items: list(map(), primary_key='node, name')"

    def test_combination_must_be_unique(self) -> None:
        data = {
            "items": [
                {"node": 1, "name": "a"},
                {"node": 2, "name": "a"},
                {"node": 1, "name": "b"},
                {"node": 1, "name": "a", "x": 1},
            ]
        }
        assert errors(data, self.SCHEMA) == [
            "items: Duplicate primary key node=1, name=a in 2 items"
        ]

    def test_each_missing_field_is_reported(self) -> None:
        data = {"items": [{"node": 1, "name": "a"}, {"x": 1}, {"node": 1}]}
        assert errors(data, self.SCHEMA) == [
            "items: Primary key 'node' missing in item [1]",
            "items: Primary key 'name' missing in item [1]",
            "items: Primary key 'name' missing in item [2]",
        ]

    def test_items_missing_a_field_are_not_duplicates(self) -> None:
        data = {"items": [{"node": 1}, {"node": 1}]}
        assert errors(data, self.SCHEMA) == [
            "items: Primary key 'name' missing in item [0]",
            "items: Primary key 'name' missing in item [1]",
        ]

    def test_values_of_different_types_are_distinct(self) -> None:
        data = {"items": [{"node": 1, "name": "a"}, {"node": "1", "name": "a"}]}
        assert errors(data, self.SCHEMA) == []

    def test_duplicate_in_merged_data(self) -> None:
        data = {"items": [{"node": 1, "name": "a", "x": 1}] * 2}
        assert errors(data, self.SCHEMA, Scope.DOCUMENT) == [
            "items: Duplicate primary key node=1, name=a across files"
            " (with conflicting values that prevent merging)"
        ]


class TestUniqueValues:
    """Tests for unique=True on list() of single values."""

    SCHEMA = "items: list(any(str(), int(), bool(), map()), unique=True)"

    def test_unique_values_pass(self) -> None:
        assert errors({"items": ["a", "b"]}, self.SCHEMA) == []

    def test_duplicate_values_fail(self) -> None:
        data = {"items": ["a", "b", "a", "b", "a"]}
        assert errors(data, self.SCHEMA) == [
            "items: Duplicate value a in 3 items",
            "items: Duplicate value b in 2 items",
        ]

    def test_values_of_different_types_are_distinct(self) -> None:
        assert errors({"items": [1, "1", True]}, self.SCHEMA) == []

    @pytest.mark.parametrize(
        ("value", "shown"), [(True, "true"), ("true", "'true'"), ("1", "'1'")]
    )
    def test_values_are_shown_as_in_yaml(self, value: Any, shown: str) -> None:
        assert errors({"items": [value, value]}, self.SCHEMA) == [
            f"items: Duplicate value {shown} in 2 items"
        ]

    def test_maps_are_not_compared(self) -> None:
        assert errors({"items": [{"a": 1}, {"a": 1}]}, self.SCHEMA) == []

    def test_duplicate_in_merged_data_names_no_items(self) -> None:
        data = {"items": ["a", "a"]}
        assert errors(data, self.SCHEMA, Scope.DOCUMENT) == [
            "items: Duplicate value a across files"
        ]

    def test_list_without_unique_allows_duplicates(self) -> None:
        assert errors({"items": ["a", "a"]}, "items: list(str())") == []


class TestUniqueFields:
    """Tests for unique naming fields of the items of list()."""

    SCHEMA = "items: list(any(map(), str()), unique='prefix, vrf')"

    def test_combination_must_be_unique(self) -> None:
        data = {
            "items": [
                {"prefix": "p1", "vrf": "a"},
                {"prefix": "p1", "vrf": "b"},
                {"prefix": "p2", "vrf": "a"},
                {"prefix": "p1", "vrf": "a", "x": 1},
            ]
        }
        assert errors(data, self.SCHEMA) == [
            "items: Duplicate unique key prefix=p1, vrf=a in 2 items"
        ]

    def test_unset_field_is_a_value_of_its_own(self) -> None:
        data = {"items": [{"prefix": "p1"}, {"prefix": "p1", "vrf": "a"}]}
        assert errors(data, self.SCHEMA) == []

    @pytest.mark.parametrize("item", [{"prefix": "p1"}, {"prefix": "p1", "vrf": None}])
    def test_unset_fields_are_shown_as_not_set(self, item: dict[str, Any]) -> None:
        data = {"items": [{"prefix": "p1"}, item]}
        assert errors(data, self.SCHEMA) == [
            "items: Duplicate unique key prefix=p1 in 2 items"
        ]

    def test_items_setting_no_field_are_not_compared(self) -> None:
        data = {"items": [{"x": 1}, {"x": 1}, {"prefix": None}, "a", "a"]}
        assert errors(data, self.SCHEMA) == []

    def test_values_of_different_types_are_distinct(self) -> None:
        data = {"items": [{"prefix": 1}, {"prefix": "1"}]}
        assert errors(data, self.SCHEMA) == []

    @pytest.mark.parametrize(
        ("value", "kind"), [(["a"], "a list"), ({"k": "a"}, "a map")]
    )
    def test_field_value_must_be_a_single_value(self, value: Any, kind: str) -> None:
        data = {"items": [{"prefix": value}, {"prefix": value}]}
        assert errors(data, self.SCHEMA) == [
            f"items: Unique field 'prefix' in item [{i}] must be a single value, not "
            f"{kind}"
            for i in (0, 1)
        ]

    def test_unique_key_next_to_primary_key(self) -> None:
        schema = "items: list(map(), primary_key='name', unique='src,dst')"
        data = {
            "items": [
                {"name": "a", "src": 1, "dst": 2},
                {"name": "b", "src": 1, "dst": 2},
                {"name": "c", "src": 2, "dst": 1},
                {"name": "a"},
            ]
        }
        assert errors(data, schema) == [
            "items: Duplicate primary key name=a in 2 items",
            "items: Duplicate unique key src=1, dst=2 in items [name=a], [name=b]",
        ]

    def test_items_sharing_their_primary_key_are_counted(self) -> None:
        schema = "items: list(map(), primary_key='name', unique='ip')"
        data = {"items": [{"name": "a", "ip": "x"}, {"name": "a", "ip": "x", "z": 1}]}
        assert errors(data, schema) == [
            "items: Duplicate primary key name=a in 2 items",
            "items: Duplicate unique key ip=x in 2 items",
        ]

    def test_key_values_of_different_types_look_different(self) -> None:
        schema = "items: list(map(), primary_key='name', unique='ip')"
        data = {"items": [{"name": 1, "ip": True}, {"name": "1", "ip": True}]}
        assert errors(data, schema) == [
            "items: Duplicate unique key ip=true in items [name=1], [name='1']"
        ]

    def test_items_are_named_by_composite_primary_key(self) -> None:
        schema = "items: list(map(), primary_key='node, name', unique='ip')"
        data = {
            "items": [
                {"node": 1, "name": "a", "ip": "x"},
                {"node": 2, "name": "a", "ip": "x"},
            ]
        }
        assert errors(data, schema) == [
            "items: Duplicate unique key ip=x in items [node=1, name=a], "
            "[node=2, name=a]"
        ]

    def test_items_without_primary_key_value_are_named_by_index(self) -> None:
        schema = "items: list(map(), primary_key='name', unique='ip')"
        data = {"items": [{"name": "a", "ip": "x"}, {"ip": "x"}]}
        assert errors(data, schema) == [
            "items: Primary key 'name' missing in item [1]",
            "items: Duplicate unique key ip=x in items [name=a], [1]",
        ]

    def test_unique_field_errors_name_the_item_by_primary_key(self) -> None:
        schema = "items: list(map(), primary_key='name', unique='ip')"
        data = {"items": [{"name": "a", "ip": ["x"]}]}
        assert errors(data, schema) == [
            "items: Unique field 'ip' in item [name=a] must be a single value, "
            "not a list"
        ]

    def test_duplicate_in_merged_data_names_no_items(self) -> None:
        data = {"items": [{"prefix": "p1", "x": 1}, {"prefix": "p1", "x": 2}]}
        assert errors(data, self.SCHEMA, Scope.DOCUMENT) == [
            "items: Duplicate unique key prefix=p1 across files"
        ]


class TestVanillaYamale:
    """Schemas using extensions stay valid for vanilla Yamale."""

    def test_extension_keywords_are_ignored(self) -> None:
        loaded = yamale.make_schema(content=SCHEMA)
        data = {"tenants": [{"name": "a"}, {"name": "a"}]}
        yamale.validate(loaded, [(data, "data")])

    @pytest.mark.parametrize("value", ["True", "'a,b'"])
    def test_unique_keyword_is_ignored(self, value: str) -> None:
        loaded = yamale.make_schema(
            content=f"a: list(any(str(), map()), unique={value})"
        )
        yamale.validate(loaded, [({"a": ["x", "x", {"a": 1}, {"a": 1}]}, "data")])


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

    @pytest.mark.parametrize(
        "value", ["''", "1", "' '", "'a,,b'", "'a,'", "'a, a'", "True"]
    )
    def test_invalid_primary_key_fails(self, value: str) -> None:
        schema = f"a: list(map(), primary_key={value})"
        with pytest.raises(
            SchemaError, match="a: primary_key must be comma-separated field names"
        ):
            check_schema(yamale.make_schema(content=schema))

    @pytest.mark.parametrize("value", ["'name'", "'node,name'", "' node , name '"])
    def test_valid_primary_key_passes(self, value: str) -> None:
        check_schema(yamale.make_schema(content=f"a: list(map(), primary_key={value})"))

    def test_unique_on_unsupported_validator_fails(self) -> None:
        with pytest.raises(SchemaError, match=r"a: unique is only .* list\(\)"):
            check_schema(yamale.make_schema(content="a: map(unique=True)"))

    @pytest.mark.parametrize(
        "value", ["False", "1", "''", "' '", "'a,,b'", "'a,'", "'a, a'"]
    )
    def test_invalid_unique_fails(self, value: str) -> None:
        schema = f"a: list(map(), unique={value})"
        with pytest.raises(
            SchemaError, match="a: unique must be True or comma-separated field names"
        ):
            check_schema(yamale.make_schema(content=schema))

    def test_unique_naming_part_of_the_primary_key_passes(self) -> None:
        schema = "a: list(map(), primary_key='a,b', unique='a')"
        check_schema(yamale.make_schema(content=schema))

    def test_unique_naming_the_primary_key_fails(self) -> None:
        schema = "a: list(map(), primary_key='a,b', unique='b, a')"
        with pytest.raises(SchemaError, match="a: unique names the fields of primary"):
            check_schema(yamale.make_schema(content=schema))

    @pytest.mark.parametrize("value", ["True", "'a'", "'a,b'", "' a , b '"])
    def test_valid_unique_passes(self, value: str) -> None:
        check_schema(yamale.make_schema(content=f"a: list(map(), unique={value})"))

    def test_yamale_keyword_does_not_configure_an_extension(self) -> None:
        class Key(Extension):
            keywords: ClassVar[tuple[str, ...]] = ("key",)

            def check(self, node: DataNode, scope: Scope) -> list[str]:
                return ["checked"]

        loaded = yamale.make_schema(content="a: map(key=str())\nb: str(key='x')")
        assert check_data(loaded, {"a": {}, "b": "v"}, [Key()], Scope.FILE) == [
            Violation(("b",), "checked")
        ]

    def test_violations_are_reported_in_data_order(self) -> None:
        schema = "a: list(str(), unique=True)\nb: list(map(), primary_key='n')\nc: list(str(), unique=True)"
        loaded = yamale.make_schema(content=schema)
        data = {"a": ["x", "x"], "b": [{"n": 1}, {"n": 1}], "c": ["y", "y"]}
        assert [
            str(v).split(":")[0]
            for v in check_data(loaded, data, EXTENSIONS, Scope.FILE)
        ] == ["a", "b", "c"]

    def test_used_extensions(self) -> None:
        primary_key, unique, refs, ip_type = (
            next(e for e in EXTENSIONS if isinstance(e, t))
            for t in (PrimaryKey, Unique, References, IpType)
        )
        assert used_extensions(yamale.make_schema(content=SCHEMA)) == [primary_key]
        both = yamale.make_schema(content=f"{SCHEMA}\nu: list(str(), unique=True)")
        assert used_extensions(both) == [primary_key, unique]
        assert used_extensions(yamale.make_schema(content="a: list(map())")) == []
        referenced = yamale.make_schema(
            content="a: list(map(), primary_key='n', ref_name='x')\nb: str(ref='x')"
        )
        assert used_extensions(referenced) == [primary_key, refs]
        typed = yamale.make_schema(content="a: ip(type='address')")
        assert used_extensions(typed) == [ip_type]


class TestIpType:
    """Tests for the type keyword of ip()."""

    @pytest.mark.parametrize(
        ("types", "value"),
        [
            ("address", "10.0.0.1"),
            ("address", "2001:db8::1"),
            ("address", "fe80::1%eth0"),
            ("interface", "10.0.0.1/24"),
            ("interface", "10.0.0.254/24"),
            ("interface", "10.0.0.0/31"),
            ("interface", "10.0.0.1/31"),
            ("interface", "10.0.0.0/32"),
            ("interface", "2001:db8::1/64"),
            ("interface", "2001:db8::ffff:ffff:ffff:ffff/64"),
            ("interface", "2001:db8::/127"),
            ("interface", "2001:db8::/128"),
            ("network", "10.0.0.0/24"),
            ("network", "10.0.0.1/32"),
            ("network", "0.0.0.0/0"),
            ("network", "2001:db8::/32"),
            ("network", "fe80::%eth0/64"),
            ("address,network", "10.0.0.1"),
            ("address,network", "10.0.0.0/24"),
            ("address, interface", "10.0.0.1/24"),
            ("interface,network", "10.0.0.1/24"),
            ("interface,network", "10.0.0.0/24"),
            ("interface,network", "2001:db8::/64"),
        ],
    )
    def test_valid_value_passes(self, types: str, value: str) -> None:
        assert errors({"a": value}, f"a: ip(type='{types}')") == []

    @pytest.mark.parametrize(
        ("types", "value", "message"),
        [
            (
                "address",
                "10.0.0.1/24",
                "'10.0.0.1/24' is not an IP address, it has a prefix length",
            ),
            (
                "address",
                "10.0.0.1/255.255.255.0",
                "'10.0.0.1/255.255.255.0' is not an IP address, it has a prefix length",
            ),
            (
                "interface",
                "10.0.0.1",
                "'10.0.0.1' is not an IP host address with prefix length, it has "
                "no prefix length",
            ),
            (
                "interface",
                "10.0.0.1/255.255.255.0",
                "'10.0.0.1/255.255.255.0' is not an IP host address with prefix "
                "length, prefix length 255.255.255.0 must be a number, not a "
                "netmask",
            ),
            (
                "interface",
                "10.0.0.0/24",
                "'10.0.0.0/24' is not an IP host address with prefix length, it "
                "is the network address",
            ),
            (
                "interface",
                "10.0.0.255/24",
                "'10.0.0.255/24' is not an IP host address with prefix length, it "
                "is the broadcast address",
            ),
            (
                "interface",
                "2001:db8::/64",
                "'2001:db8::/64' is not an IP host address with prefix length, it "
                "is the subnet-router anycast address",
            ),
            (
                "interface,network",
                "10.0.0.255/24",
                "'10.0.0.255/24' is not an IP host address with prefix length or "
                "an IP network, it is the broadcast address",
            ),
            (
                "network",
                "10.0.0.1",
                "'10.0.0.1' is not an IP network, it has no prefix length",
            ),
            (
                "network",
                "10.0.0.1/24",
                "'10.0.0.1/24' is not an IP network, host bits are set (network "
                "is 10.0.0.0/24)",
            ),
            (
                "network",
                "2001:db8::1/32",
                "'2001:db8::1/32' is not an IP network, host bits are set "
                "(network is 2001:db8::/32)",
            ),
            (
                "address,network",
                "10.0.0.1/24",
                "'10.0.0.1/24' is not an IP address or an IP network, host bits "
                "are set (network is 10.0.0.0/24)",
            ),
        ],
    )
    def test_invalid_value_fails(self, types: str, value: str, message: str) -> None:
        assert errors({"a": value}, f"a: ip(type='{types}')") == [f"a: {message}"]

    def test_combined_with_version(self) -> None:
        schema = "a: ip(version=4, type='network')"
        assert errors({"a": "10.0.0.0/8"}, schema) == []
        with pytest.raises(yamale.YamaleError):
            yamale.validate(
                yamale.make_schema(content=schema), [({"a": "2001:db8::/32"}, "d")]
            )

    def test_list_items_are_checked(self) -> None:
        schema = "a: list(ip(type='network'))"
        assert errors({"a": ["10.0.0.0/8", "10.0.0.1/8"]}, schema) == [
            "a.1: '10.0.0.1/8' is not an IP network, host bits are set (network "
            "is 10.0.0.0/8)"
        ]

    @pytest.mark.parametrize(
        ("types", "message"),
        [
            ("address", None),
            ("interface", "'167772161' is not an IP host address with prefix length"),
            ("network", "'167772161' is not an IP network"),
        ],
    )
    def test_integer_is_an_address(self, types: str, message: str | None) -> None:
        schema = f"a: ip(type='{types}')"
        assert errors({"a": 167772161}, schema) == (
            [] if message is None else [f"a: {message}, it has no prefix length"]
        )

    def test_any_chooses_the_alternative_satisfying_the_type(self) -> None:
        schema = "a: any(ip(type='address'), ip(type='network'))"
        assert errors({"a": "10.0.0.0/24"}, schema) == []
        assert errors({"a": "10.0.0.1"}, schema) == []
        assert errors({"a": "10.0.0.1/24"}, schema) == [
            "a: '10.0.0.1/24' is not an IP address, it has a prefix length"
        ]

    def test_list_chooses_the_item_validator_satisfying_the_type(self) -> None:
        schema = "a: list(ip(type='address'), ip(type='network'))"
        assert errors({"a": ["10.0.0.1", "10.0.0.0/24"]}, schema) == []

    def test_merged_data_is_not_checked_again(self) -> None:
        assert errors({"a": "10.0.0.1"}, "a: ip(type='network')", Scope.DOCUMENT) == []

    @pytest.mark.parametrize(
        "value", ["''", "'host'", "'address,'", "'address,address'", "1", "True"]
    )
    def test_invalid_type_fails(self, value: str) -> None:
        with pytest.raises(
            SchemaError, match="a: type must be comma-separated IP forms of address"
        ):
            check_schema(yamale.make_schema(content=f"a: ip(type={value})"))

    def test_type_on_unsupported_validator_fails(self) -> None:
        with pytest.raises(SchemaError, match=r"a: type is only supported on ip\(\)"):
            check_schema(yamale.make_schema(content="a: str(type='address')"))


class TestOrdered:
    """Tests for the ordered keyword of list()."""

    SCHEMA = (
        "a: list(str(), ordered=True)\n"
        "b: list(include('i'), primary_key='x', ordered=False, required=False)\n"
        "---\ni:\n  x: int()"
    )

    def test_valid_values_pass(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            check_schema(yamale.make_schema(content=self.SCHEMA))
        assert caplog.messages == []

    @pytest.mark.parametrize("value", ["1", "'true'", "'yes'", "None"])
    def test_invalid_value_fails(self, value: str) -> None:
        with pytest.raises(SchemaError, match="a: ordered must be True or False"):
            check_schema(yamale.make_schema(content=f"a: list(str(), ordered={value})"))

    def test_on_unsupported_validator_fails(self) -> None:
        with pytest.raises(SchemaError, match=r"a: ordered is only .* list\(\)"):
            check_schema(yamale.make_schema(content="a: str(ordered=True)"))

    def test_not_checked_against_data(self) -> None:
        data = {"a": ["b", "a", "a"], "b": [{"x": 2}, {"x": 1}]}
        assert errors(data, self.SCHEMA) == []
        assert errors(data, self.SCHEMA, Scope.DOCUMENT) == []


class TestDescription:
    """Tests for the description keyword of all validators."""

    SCHEMA = (
        "a: str(description='A string')\n"
        "b: list(include('i'), description='A list', primary_key='x')\n"
        "c: include('i', description='An include', required=False)\n"
        "d: regex('^a', description='A regex')\n"
        "e: map(key=str(description='A key'), description='A map', required=False)\n"
        "---\ni:\n  x: int(description='A field')"
    )

    def test_supported_on_all_validators(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            check_schema(yamale.make_schema(content=self.SCHEMA))
        assert caplog.messages == []

    @pytest.mark.parametrize("value", ["''", "' '", "1", "True"])
    def test_invalid_description_fails(self, value: str) -> None:
        with pytest.raises(
            SchemaError, match="a: description must be a non-empty string"
        ):
            check_schema(yamale.make_schema(content=f"a: str(description={value})"))

    def test_not_checked_against_data(self) -> None:
        data = {"a": "x", "b": [{"x": 1}], "d": "ab"}
        assert errors(data, self.SCHEMA) == []
        assert errors(data, self.SCHEMA, Scope.DOCUMENT) == []

    def test_vanilla_yamale_ignores_description(self) -> None:
        loaded = yamale.make_schema(content=self.SCHEMA)
        yamale.validate(loaded, [({"a": "x", "b": [{"x": 1}], "d": "ab"}, "data")])
        with pytest.raises(yamale.YamaleError):
            yamale.validate(loaded, [({"a": 1, "b": [], "d": "ab"}, "data")])


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

    def test_invalid_extension_fails_creating_from_a_loaded_schema(self) -> None:
        schema = yamale.make_schema(content="a: list(map(), primary_key=1)")
        with pytest.raises(SchemaError):
            Validator(schema)

    def test_map_keys_with_dots_are_kept_in_error_paths(
        self, validator: Validator
    ) -> None:
        validator.schema = yamale.make_schema(
            content="m: map(list(include('i'), primary_key='name'))\n---\n"
            "i:\n  name: str()\n  l: list(map(), primary_key='name', required=False)"
        )
        validator.load_data({"m": {"x.y": [{"name": "a", "l": [{"name": "b"}] * 2}]}})
        with pytest.raises(SyntaxValidationError):
            validator.validate_syntax(rich_output=False)
        assert validator.errors == [
            "Syntax error '<pre-loaded>': m.x.y.[name=a].l: Duplicate primary key"
            " name=b across files (with conflicting values that prevent merging)"
        ]

    def test_error_paths_name_items_by_schema_primary_key(
        self, validator: Validator
    ) -> None:
        validator.schema = yamale.make_schema(
            content="l: list(include('i'), primary_key='id')\n---\n"
            "i:\n  id: int()\n  name: str()\n"
            "  s: list(str(), unique=True, required=False)"
        )
        validator.load_data({"l": [{"id": 1, "name": "a", "s": ["x", "x"]}]})
        with pytest.raises(SyntaxValidationError):
            validator.validate_syntax(rich_output=False)
        assert validator.errors == [
            "Syntax error '<pre-loaded>': l.[id=1].s: Duplicate value x across files"
        ]

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

    def test_unique_values_across_files_fail(self, project: Path, data: Path) -> None:
        schema = project / "schema.yaml"
        schema.write_text(
            "wlans: list(include('wlan'), primary_key='name', unique='id')\n---\n"
            "wlan:\n  name: str()\n  id: int(required=False)\n"
        )
        validator = Validator.from_paths(schema, DEFAULT_RULES)
        (data / "a.yaml").write_text("wlans:\n  - name: a\n    id: 1\n")
        # Item a merges, b uses the id of a from the other file
        (data / "b.yaml").write_text("wlans:\n  - name: a\n  - name: b\n    id: 1\n")
        with pytest.raises(SyntaxValidationError):
            validator.validate_syntax([data], rich_output=False)
        assert validator.errors == [
            f"Syntax error '{data}': wlans: Duplicate unique key id=1 across files"
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
            "tenants: Duplicate primary key name=a in 2 items"
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

    def test_merged_data_is_reused_once(
        self, validator: Validator, data: Path, project: Path
    ) -> None:
        (data / "a.yaml").write_text("tenants:\n  - name: a\n")
        (data / "b.yaml").write_text("tenants:\n  - name: b\n")
        load = nac_validate.validator.load_yaml_files
        with patch.object(
            nac_validate.validator, "load_yaml_files", side_effect=load
        ) as mock_load:
            validator.validate_syntax([data], rich_output=False)
            # Once per file, once merged
            assert mock_load.call_count == 3
            validator.write_output([data], project / "out.yaml")
            assert mock_load.call_count == 3
            # Handed over, so loading again reads the files
            validator.data = None
            validator.write_output([data], project / "out.yaml")
            assert mock_load.call_count == 4

    def test_single_file_is_not_merged(self, validator: Validator, data: Path) -> None:
        (data / "a.yaml").write_text("tenants:\n  - name: a\n")
        load = nac_validate.validator.load_yaml_files
        with patch.object(
            nac_validate.validator, "load_yaml_files", side_effect=load
        ) as mock_load:
            validator.validate_syntax([data], rich_output=False)
        assert mock_load.call_count == 1


class TestViolationLabels:
    """Tests for the labels of list items in violation paths."""

    def test_items_are_labelled_by_schema_primary_key(self) -> None:
        schema = yamale.make_schema(
            content="l: list(include('i'), primary_key='node, name')\n---\n"
            "i:\n  node: int()\n  name: str()\n"
            "  s: list(str(), unique=True, required=False)"
        )
        data = {
            "l": [{"node": 1, "name": "a"}, {"node": 1, "name": "b", "s": ["x"] * 2}]
        }
        yamale.validate(schema, [(data, "data")])
        assert check_data(schema, data, EXTENSIONS, Scope.FILE) == [
            Violation(
                ("l", 1, "s"),
                "Duplicate value x in 2 items",
                ((1, "[node=1, name=b]"),),
            )
        ]

    def test_lists_without_primary_key_are_not_labelled(self) -> None:
        schema = yamale.make_schema(
            content="l: list(include('i'))\n---\n"
            "i:\n  name: str()\n  s: list(str(), unique=True)"
        )
        data = {"l": [{"name": "a", "s": ["x", "x"]}]}
        yamale.validate(schema, [(data, "data")])
        (violation,) = check_data(schema, data, EXTENSIONS, Scope.FILE)
        assert violation.labels == ()
