# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Unit tests for the reference schema extension (ref_name, ref, ...)."""

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yamale

import nac_validate.validator
from nac_validate.constants import DEFAULT_RULES
from nac_validate.exceptions import SchemaError, SyntaxValidationError
from nac_validate.schema import (
    EXTENSIONS,
    Scope,
    check_data,
    check_schema,
    references,
)
from nac_validate.schema.walker import resolves, walk_data, walk_schema_contexts
from nac_validate.validator import Validator

DEVICES = """
devices: list(include('device'), primary_key='name', required=False)
---
device:
  name: str()
  vrfs: list(include('vrf'), primary_key='name', ref_name='vrf', ref_implicit='default,mgmt-*', required=False)
  interfaces: list(include('interface'), primary_key='name', required=False)
vrf:
  name: str()
interface:
  name: str()
  vrf: str(ref='vrf', required=False)
  vrfs: list(str(ref='vrf'), required=False)
"""

TENANTS = """
tenants: list(include('tenant'), primary_key='name', ref_name='tenant', ref_scope='any', required=False)
policies: include('policies', required=False)
---
tenant:
  name: str()
  vrfs: list(include('vrf'), primary_key='name', ref_name='tenant_vrf', required=False)
  aps: list(include('ap'), primary_key='name', ref_name='ap', required=False)
  bds: list(include('bd'), primary_key='name', required=False)
vrf:
  name: str()
  leaks: list(include('leak'), required=False)
leak:
  tenant: str(ref='tenant')
  vrf: str(ref='tenant_vrf', ref_in='tenant')
ap:
  name: str()
  epgs: list(include('epg'), primary_key='name', ref_name='epg', required=False)
epg:
  name: str()
  masters: list(include('master'), required=False)
master:
  ap: str(ref='ap', required=False)
  epg: str(ref='epg', ref_in='ap')
bd:
  name: str()
  vrf: str(ref='tenant_vrf')
policies:
  vrf: str(ref='tenant_vrf', required=False)
  span_sources: list(include('span_source'), required=False)
span_source:
  tenant: str(ref='tenant')
  vrf: str(ref='tenant_vrf', ref_in='tenant')
"""


def errors(data: dict[str, Any], schema: str = DEVICES) -> list[str]:
    """Check data that passes Yamale validation against the extensions."""
    loaded = yamale.make_schema(content=schema)
    check_schema(loaded)
    yamale.validate(loaded, [(data, "data")])
    return [str(v) for v in check_data(loaded, data, EXTENSIONS, Scope.DOCUMENT)]


def schema_problems(schema: str) -> str:
    with pytest.raises(SchemaError) as error:
        check_schema(yamale.make_schema(content=schema))
    return str(error.value)


def device(name: str, defined: list[str], **interface: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"name": name, "vrfs": [{"name": v} for v in defined]}
    if interface:
        result["interfaces"] = [{"name": "e1", **interface}]
    return result


class TestScope:
    """Targets are looked up in the items of the lists enclosing the reference."""

    def test_target_in_the_same_item_passes(self) -> None:
        assert errors({"devices": [device("a", ["P"], vrf="P")]}) == []

    def test_target_in_another_item_fails(self) -> None:
        data = {"devices": [device("a", ["P"]), device("b", [], vrf="P")]}
        assert errors(data) == [
            "devices.1.interfaces.0.vrf: vrf 'P' is not defined in devices[name=b]"
        ]

    def test_undefined_target_fails(self) -> None:
        assert errors({"devices": [device("a", ["P"], vrf="Q")]}) == [
            "devices.0.interfaces.0.vrf: vrf 'Q' is not defined in devices[name=a]"
        ]

    def test_reference_outside_the_enclosing_list_sees_all_items(self) -> None:
        schema = DEVICES.replace(
            "devices: list(",
            "default_vrf: str(ref='vrf', required=False)\ndevices: list(",
        )
        data = {"default_vrf": "P", "devices": [device("a", []), device("b", ["P"])]}
        assert errors(data, schema) == []
        assert errors({**data, "default_vrf": "Q"}, schema) == [
            "default_vrf: vrf 'Q' is not defined"
        ]

    def test_list_of_references(self) -> None:
        data = {"devices": [device("a", ["P"], vrfs=["P", "Q"])]}
        assert errors(data) == [
            "devices.0.interfaces.0.vrfs.1: vrf 'Q' is not defined in devices[name=a]"
        ]

    def test_nested_targets_are_only_visible_in_their_item(self) -> None:
        data = {
            "tenants": [
                {
                    "name": "t",
                    "aps": [
                        {"name": "a1", "epgs": [{"name": "e1"}]},
                        {
                            "name": "a2",
                            "epgs": [{"name": "e2", "masters": [{"epg": "e1"}]}],
                        },
                    ],
                }
            ]
        }
        assert errors(data, TENANTS) == [
            "tenants.0.aps.1.epgs.0.masters.0.epg: epg 'e1' is not defined in "
            "aps[name=a2]"
        ]

    def test_values_are_compared_as_text(self) -> None:
        schema = (
            "vlans: list(include('vlan'), primary_key='id', ref_name='vlan')\n"
            "svi: any(int(), str(), ref='vlan')\n---\nvlan:\n  id: int()"
        )
        assert errors({"vlans": [{"id": 10}], "svi": "10"}, schema) == []
        assert errors({"vlans": [{"id": 10}], "svi": 11}, schema) == [
            "svi: vlan '11' is not defined"
        ]


class TestImplicit:
    """Values that exist without being defined in the data."""

    @pytest.mark.parametrize("value", ["default", "mgmt-1", "mgmt-"])
    def test_implicit_values_pass(self, value: str) -> None:
        assert errors({"devices": [device("a", [], vrf=value)]}) == []

    def test_glob_must_match_the_whole_value(self) -> None:
        assert errors({"devices": [device("a", [], vrf="xmgmt-1")]}) == [
            "devices.0.interfaces.0.vrf: vrf 'xmgmt-1' is not defined in "
            "devices[name=a]"
        ]


class TestSeveralLists:
    """Lists sharing a ref_name form one target."""

    SCHEMA = """
hosts: list(include('obj'), primary_key='name', ref_name='network', required=False)
networks: list(include('obj'), primary_key='name', ref_name='network', ref_implicit='any', required=False)
groups: list(include('group'), required=False)
---
obj:
  name: str()
group:
  members: list(str(ref='network'))
"""

    def test_items_of_every_list_count(self) -> None:
        data = {
            "hosts": [{"name": "h"}],
            "networks": [{"name": "n"}],
            "groups": [{"members": ["h", "n", "any", "x"]}],
        }
        assert errors(data, self.SCHEMA) == [
            "groups.0.members.3: network 'x' is not defined"
        ]


class TestRefIn:
    """ref_in names the items of the lists enclosing the target."""

    def data(self, leak: dict[str, str]) -> dict[str, Any]:
        return {
            "tenants": [
                {"name": "a", "vrfs": [{"name": "va", "leaks": [leak]}]},
                {"name": "b", "vrfs": [{"name": "vb"}]},
            ]
        }

    def test_target_in_the_named_item_passes(self) -> None:
        assert errors(self.data({"tenant": "b", "vrf": "vb"}), TENANTS) == []

    def test_target_in_another_item_fails(self) -> None:
        assert errors(self.data({"tenant": "b", "vrf": "va"}), TENANTS) == [
            "tenants.0.vrfs.0.leaks.0.vrf: tenant_vrf 'va' is not defined in "
            "tenants[name=b]"
        ]

    def test_unknown_selector_is_only_reported_by_its_own_ref(self) -> None:
        assert errors(self.data({"tenant": "c", "vrf": "vb"}), TENANTS) == [
            "tenants.0.vrfs.0.leaks.0.tenant: tenant 'c' is not defined"
        ]

    def test_unset_selector_falls_back_to_nesting(self) -> None:
        data = {
            "tenants": [
                {
                    "name": "t",
                    "aps": [
                        {
                            "name": "a1",
                            "epgs": [
                                {"name": "e1"},
                                {"name": "e2", "masters": [{"epg": "e1"}]},
                            ],
                        },
                        {
                            "name": "a2",
                            "epgs": [
                                {"name": "e3", "masters": [{"ap": "a1", "epg": "e2"}]}
                            ],
                        },
                    ],
                }
            ]
        }
        assert errors(data, TENANTS) == []

    def test_selected_inner_item_with_several_outer_items(self) -> None:
        data = {
            "tenants": [
                {
                    "name": "t",
                    "aps": [
                        {"name": "a1", "epgs": [{"name": "e1"}]},
                        {
                            "name": "a2",
                            "epgs": [
                                {"name": "e2", "masters": [{"ap": "a1", "epg": "x"}]}
                            ],
                        },
                    ],
                },
                {"name": "u", "aps": [{"name": "b1", "epgs": [{"name": "y"}]}]},
            ]
        }
        assert errors(data, TENANTS) == [
            "tenants.0.aps.1.epgs.0.masters.0.epg: epg 'x' is not defined in "
            "aps[name=a1]"
        ]

    def test_location_does_not_depend_on_the_first_target_list(self) -> None:
        data = {
            "tenants": [
                {"name": "u", "aps": [{"name": "z", "epgs": [{"name": "y"}]}]},
                {
                    "name": "t",
                    "aps": [
                        {
                            "name": "a2",
                            "epgs": [{"name": "e", "masters": [{"epg": "x"}]}],
                        }
                    ],
                },
            ]
        }
        assert errors(data, TENANTS) == [
            "tenants.1.aps.0.epgs.0.masters.0.epg: epg 'x' is not defined in "
            "aps[name=a2]"
        ]

    def test_selector_outside_the_enclosing_list(self) -> None:
        data = {
            "tenants": [{"name": "a", "vrfs": [{"name": "va"}]}, {"name": "b"}],
            "policies": {
                "span_sources": [
                    {"tenant": "a", "vrf": "va"},
                    {"tenant": "b", "vrf": "va"},
                ]
            },
        }
        assert errors(data, TENANTS) == [
            "policies.span_sources.1.vrf: tenant_vrf 'va' is not defined in "
            "tenants[name=b]"
        ]


class TestRefScope:
    """ref_scope='any': the items of a list don't isolate references."""

    def test_target_in_another_item_passes(self) -> None:
        data = {
            "tenants": [
                {"name": "a", "bds": [{"name": "bd", "vrf": "shared"}]},
                {"name": "common", "vrfs": [{"name": "shared"}]},
            ]
        }
        assert errors(data, TENANTS) == []

    def test_undefined_target_fails(self) -> None:
        data = {"tenants": [{"name": "a", "bds": [{"name": "bd", "vrf": "x"}]}]}
        assert errors(data, TENANTS) == [
            "tenants.0.bds.0.vrf: tenant_vrf 'x' is not defined"
        ]


class TestReferencesHelper:
    """references() hands rules the references of the data."""

    DATA: dict[str, Any] = {
        "tenants": [
            {
                "name": "a",
                "bds": [{"name": "bd", "vrf": "vb"}],
                "vrfs": [{"name": "va", "leaks": [{"tenant": "b", "vrf": "vb"}]}],
            },
            {"name": "b", "vrfs": [{"name": "vb"}]},
        ],
        "policies": {"vrf": "va"},
    }

    def refs(self, within: str | None = None) -> list[Any]:
        loaded = yamale.make_schema(content=TENANTS)
        return references(loaded, self.DATA, within=within)

    def test_all_references(self) -> None:
        assert [(r.kind, r.value) for r in self.refs()] == [
            ("tenant", "b"),
            ("tenant_vrf", "vb"),
            ("tenant_vrf", "vb"),
            ("tenant_vrf", "va"),
        ]

    def test_references_within_a_list(self) -> None:
        refs = self.refs(within="tenants")
        assert len(refs) == 3
        bd_vrf = refs[2]
        assert bd_vrf.path == ("tenants", 0, "bds", 0, "vrf")
        assert bd_vrf.scope_key("tenants") == "a"
        assert bd_vrf.defined_in("tenants") == {"b"}
        assert not bd_vrf.selected("tenants")

    def test_selected_level(self) -> None:
        leak_vrf = self.refs(within="tenants")[1]
        assert leak_vrf.selectors == ("b",)
        assert leak_vrf.selected("tenants")

    def test_undeclared_kind_on_an_unchecked_schema(self) -> None:
        loaded = yamale.make_schema(content="a: str(ref='missing')")
        refs = references(loaded, {"a": "x"})
        assert [(r.kind, r.implicit, r.defined_in("x")) for r in refs] == [
            ("missing", False, set())
        ]

    def test_implicit(self) -> None:
        loaded = yamale.make_schema(content=DEVICES)
        data = {"devices": [device("a", [], vrf="default")]}
        assert [r.implicit for r in references(loaded, data)] == [True]


class TestCheckSchema:
    """Schema loading checks the reference keywords."""

    @pytest.mark.parametrize("keyword", ["ref_name='x'", "ref_scope='any'"])
    def test_list_keywords_on_other_validators_fail(self, keyword: str) -> None:
        name = keyword.split("=")[0]
        assert f"a: {name} is only supported on list()" in schema_problems(
            f"a: str({keyword})"
        )

    @pytest.mark.parametrize("keyword", ["ref_name='x'", "ref_scope='any'"])
    def test_list_keywords_need_a_single_field_primary_key(self, keyword: str) -> None:
        name = keyword.split("=")[0]
        expected = f"a: {name} needs a single-field primary_key"
        assert expected in schema_problems(f"a: list(map(), {keyword})")
        assert expected in schema_problems(
            f"a: list(map(), primary_key='x,y', {keyword})"
        )

    @pytest.mark.parametrize("value", ["''", "'a b'", "'a,b'", "1"])
    def test_invalid_names_fail(self, value: str) -> None:
        assert "ref_name must be a name" in schema_problems(
            f"a: list(map(), primary_key='n', ref_name={value})"
        )
        assert "ref must be a name" in schema_problems(f"a: str(ref={value})")

    def test_implicit_needs_ref_name(self) -> None:
        assert "a: ref_implicit needs ref_name" in schema_problems(
            "a: list(map(), primary_key='n', ref_implicit='x')"
        )

    @pytest.mark.parametrize("value", ["''", "'a,,b'", "1"])
    def test_invalid_implicit_values_fail(self, value: str) -> None:
        assert "ref_implicit must be comma-separated values" in schema_problems(
            f"a: list(map(), primary_key='n', ref_name='x', ref_implicit={value})"
        )

    def test_invalid_scope_fails(self) -> None:
        assert "ref_scope must be 'any', not 'all'" in schema_problems(
            "a: list(map(), primary_key='n', ref_scope='all')"
        )

    @pytest.mark.parametrize("validator", ["map()", "list()", "include('i')"])
    def test_ref_on_containers_fails(self, validator: str) -> None:
        tag = validator.split("(")[0]
        schema = f"a: {validator[:-1]}{', ' if validator != f'{tag}()' else ''}ref='x')\n---\ni:\n  b: str()"
        assert f"ref is not supported on {tag}()" in schema_problems(schema)

    def test_ref_in_needs_ref(self) -> None:
        assert "a: ref_in needs ref" in schema_problems("a: str(ref_in='b')")

    @pytest.mark.parametrize("value", ["''", "'a..b'", "'a,a'", "1"])
    def test_invalid_ref_in_fails(self, value: str) -> None:
        assert "ref_in must be comma-separated dotted field paths" in schema_problems(
            f"a: str(ref='x', ref_in={value})"
        )

    def test_unknown_ref_name_fails(self) -> None:
        assert "devices.interfaces.vrf: ref names no list with ref_name 'vfr'" in (
            schema_problems(
                DEVICES.replace("ref='vrf', required", "ref='vfr', required")
            )
        )

    def test_ref_in_path_must_exist(self) -> None:
        schema = TENANTS.replace("ref_in='ap'", "ref_in='application_profile'")
        assert "ref_in path 'application_profile' does not exist" in schema_problems(
            schema
        )

    def test_ref_in_can_not_name_more_items_than_enclose_the_target(self) -> None:
        schema = TENANTS.replace("ref_in='tenant'", "ref_in='tenant,vrf'", 1)
        assert "ref_in names 2 items, but lists with ref_name 'tenant_vrf'" in (
            schema_problems(schema)
        )

    def test_ref_in_needs_a_primary_key_on_the_selected_list(self) -> None:
        schema = (
            "tenants: list(include('tenant'))\nleaks: list(include('leak'))\n---\n"
            "tenant:\n  name: str()\n"
            "  vrfs: list(include('vrf'), primary_key='name', ref_name='v')\n"
            "vrf:\n  name: str()\nleak:\n  tenant: str()\n"
            "  vrf: str(ref='v', ref_in='tenant')"
        )
        assert (
            "leaks.vrf: ref_in selects items of tenants, which needs a single-field "
            "primary_key" in schema_problems(schema)
        )

    def test_ref_in_needs_lists_of_a_kind_nested_alike(self) -> None:
        schema = TENANTS.replace(
            "  bds: list(include('bd'), primary_key='name', required=False)",
            "  bds: list(include('bd'), primary_key='name', required=False)\n"
            "  more_epgs: list(include('vrf'), primary_key='name', ref_name='epg', "
            "required=False)",
        )
        assert (
            "ref_in needs the lists with ref_name 'epg' to be inside the same number "
            "of list items, not 1, 2" in schema_problems(schema)
        )

    def test_valid_schemas_pass(self) -> None:
        check_schema(yamale.make_schema(content=DEVICES))
        check_schema(yamale.make_schema(content=TENANTS))

    def test_vanilla_yamale_ignores_the_keywords(self) -> None:
        loaded = yamale.make_schema(content=DEVICES)
        yamale.validate(loaded, [({"devices": [device("a", [], vrf="Q")]}, "data")])


class TestWalker:
    """Walker support for references."""

    def test_values_carry_their_enclosing_list_items(self) -> None:
        loaded = yamale.make_schema(content=DEVICES)
        data = {"devices": [device("a", ["P"], vrf="P")]}
        node = next(n for n in walk_data(loaded, data, True) if n.path[-1] == "vrf")
        assert [(lv.path, lv.index, lv.key) for lv in node.levels] == [
            (("devices",), 0, "a"),
            (("devices", 0, "interfaces"), 0, "e1"),
        ]

    def test_contexts_follow_includes_from_where_they_are_used(self) -> None:
        loaded = yamale.make_schema(
            content="a: include('i')\nb: list(include('i'))\n---\ni:\n  x: str()"
        )
        contexts = [
            (c.location, c.depth)
            for c in walk_schema_contexts(loaded)
            if c.validator.tag == "str"
        ]
        assert contexts == [("a.x", 0), ("b.x", 1)]

    def test_recursive_includes_are_followed_once(self) -> None:
        loaded = yamale.make_schema(
            content="a: list(include('area'))\n---\narea:\n  name: str()\n"
            "  areas: list(include('area'), required=False)"
        )
        depths = [
            c.depth for c in walk_schema_contexts(loaded) if c.validator.tag == "str"
        ]
        assert depths == [1, 2]

    def test_resolves_follows_includes_and_any(self) -> None:
        loaded = yamale.make_schema(
            content="a: include('i')\n---\ni:\n  b: any(include('j'), int())\nj:\n  c: str()"
        )
        assert resolves(loaded, loaded._schema, ["a", "b", "c"])
        assert not resolves(loaded, loaded._schema, ["a", "b", "d"])


class TestValidator:
    """References are checked on the merged data, also for a single file."""

    @pytest.fixture
    def validator(self, project: Path) -> Validator:
        schema = project / "schema.yaml"
        schema.write_text(DEVICES)
        return Validator.from_paths(schema, DEFAULT_RULES)

    @pytest.fixture
    def data(self, project: Path) -> Path:
        data = project / "data"
        data.mkdir()
        return data

    def test_single_file_is_checked(self, validator: Validator, data: Path) -> None:
        (data / "a.yaml").write_text(
            "devices:\n  - name: a\n    interfaces:\n      - name: e1\n        vrf: Q\n"
        )
        with pytest.raises(SyntaxValidationError):
            validator.validate_syntax([data], rich_output=False)
        assert validator.errors == [
            f"Syntax error '{data}': devices.[name=a].interfaces.[name=e1].vrf: "
            "vrf 'Q' is not defined in devices[name=a]"
        ]

    def test_target_in_another_file_passes(
        self, validator: Validator, data: Path
    ) -> None:
        (data / "a.yaml").write_text(
            "devices:\n  - name: a\n    interfaces:\n      - name: e1\n        vrf: P\n"
        )
        (data / "b.yaml").write_text(
            "devices:\n  - name: a\n    vrfs:\n      - name: P\n"
        )
        validator.validate_syntax([data], rich_output=False)
        assert validator.errors == []

    def test_single_file_is_loaded_once(self, validator: Validator, data: Path) -> None:
        (data / "a.yaml").write_text("devices:\n  - name: a\n")
        load = nac_validate.validator.load_yaml_files
        with patch.object(
            nac_validate.validator, "load_yaml_files", side_effect=load
        ) as mock_load:
            validator.validate_syntax([data], rich_output=False)
        assert mock_load.call_count == 1

    def test_preloaded_data_is_checked(self, validator: Validator) -> None:
        validator.load_data({"devices": [device("a", [], vrf="Q")]})
        with pytest.raises(SyntaxValidationError):
            validator.validate_syntax(rich_output=False)
        assert len(validator.errors) == 1
