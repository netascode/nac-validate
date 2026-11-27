# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Unit tests for the library API used by tools such as editors."""

import logging
from pathlib import Path
from typing import Any

import pytest
import yamale

import nac_validate
from nac_validate import RuleResult, Validator, Violation
from nac_validate.exceptions import SyntaxValidationError
from nac_validate.ignores import (
    IgnoreMatcher,
    IgnoreProblem,
    Selector,
    parse_path,
    read_comments,
    scan_text,
)
from nac_validate.schema import yamale_violation

SCHEMA = """
devices: list(include('device'), primary_key='name', required=False)
groups: map(list(include('vrf'), primary_key='name'), required=False)
---
device:
  name: str()
  mtu: int(required=False)
  vrfs: list(include('vrf'), primary_key='name', ref_name='vrf', required=False)
  interfaces: list(include('interface'), primary_key='name', required=False)
vrf:
  name: str()
interface:
  name: str()
  vrf: str(ref='vrf', required=False)
"""


@pytest.fixture
def validator() -> Validator:
    return Validator(yamale.make_schema(content=SCHEMA))


def paths(violations: list[Any]) -> list[tuple[Any, ...]]:
    return [v.path for v in violations]


class TestYamaleViolation:
    """Tests for turning Yamale errors into violations with path segments."""

    def test_list_positions_become_integers(self) -> None:
        data = {"devices": [{"name": "a"}, {"name": "b", "mtu": "x"}]}
        violation = yamale_violation("devices.1.mtu: 'x' is not a int.", data)
        assert violation.path == ("devices", 1, "mtu")
        assert violation.message == "'x' is not a int."

    def test_map_keys_with_dots_are_kept_whole(self) -> None:
        data = {"groups": {"a.b": [{"name": 1}]}}
        violation = yamale_violation("groups.a.b.0.name: '1' is not a str.", data)
        assert violation.path == ("groups", "a.b", 0, "name")

    def test_missing_key_is_one_segment(self) -> None:
        data = {"devices": [{}]}
        violation = yamale_violation("devices.0.name: Required field missing", data)
        assert violation.path == ("devices", 0, "name")
        missing = yamale_violation("devices.0.x.y: Required field missing", data)
        assert missing.path == ("devices", 0, "x.y")

    def test_map_keys_that_are_not_strings(self) -> None:
        violation = yamale_violation("groups.1.0: bad", {"groups": {1: ["v"]}})
        assert violation.path == ("groups", 1, 0)

    def test_space_before_the_colon(self) -> None:
        violation = yamale_violation("devices : 'x' is not a list", {"devices": "x"})
        assert violation.path == ("devices",)
        assert violation.message == "'x' is not a list"

    def test_root_and_no_path(self) -> None:
        assert yamale_violation(" : 'x' is not a map", "x").path == ()
        assert yamale_violation("no path", {}) == yamale_violation("no path", {})
        assert yamale_violation("no path", {}).message == "no path"


class TestYamaleViolationColons:
    """Tests for Yamale errors at map keys containing colons."""

    def test_key_with_colons_is_kept_whole(self) -> None:
        violation = yamale_violation(
            "macs.00:11: '1' is not a str.", {"macs": {"00:11": 1}}
        )
        assert violation.path == ("macs", "00:11")
        assert violation.message == "'1' is not a str."

    def test_colons_in_the_message(self) -> None:
        data = {"devices": [{"mtu": "00:11"}]}
        violation = yamale_violation("devices.0.mtu: '00:11' is not a int.", data)
        assert violation.path == ("devices", 0, "mtu")
        assert violation.message == "'00:11' is not a int."

    def test_missing_key_at_the_root(self) -> None:
        violation = yamale_violation("name: Required field missing", {})
        assert violation.path == ("name",)

    def test_root_value_with_colons(self) -> None:
        violation = yamale_violation(" : 'a:b' is not a map", "a:b")
        assert violation.path == ()
        assert violation.message == "'a:b' is not a map"


class TestCheckFile:
    """Tests for Validator.check_file()."""

    def test_yamale_errors_have_path_segments(self, validator: Validator) -> None:
        data = {"devices": [{"name": "a", "mtu": "x"}]}
        (violation,) = validator.check_file(data)
        assert violation.path == ("devices", 0, "mtu")
        assert "is not a int" in violation.message

    def test_unknown_keys_only_in_strict_mode(self, validator: Validator) -> None:
        data = {"devices": [{"name": "a", "x": 1}]}
        assert paths(validator.check_file(data)) == [("devices", 0, "x")]
        assert validator.check_file(data, strict=False) == []

    def test_extensions_after_yamale_passes(self, validator: Validator) -> None:
        data = {"devices": [{"name": "a"}, {"name": "a"}]}
        (violation,) = validator.check_file(data)
        assert violation.path == ("devices",)
        assert "Duplicate primary key name=a" in violation.message

    def test_extensions_skipped_while_yamale_fails(self, validator: Validator) -> None:
        data = {"devices": [{"name": "a", "mtu": "x"}, {"name": "a"}]}
        assert paths(validator.check_file(data)) == [("devices", 0, "mtu")]

    def test_references_are_not_checked_per_file(self, validator: Validator) -> None:
        data = {"devices": [{"name": "a", "interfaces": [{"name": "e1", "vrf": "x"}]}]}
        assert validator.check_file(data) == []

    def test_nothing_to_check(self, validator: Validator) -> None:
        assert validator.check_file({}) == []
        assert validator.check_file(None) == []
        assert Validator(None).check_file({"devices": 1}) == []

    def test_matches_the_cli(self, validator: Validator, tmp_path: Path) -> None:
        file = tmp_path / "a.yaml"
        file.write_text("devices:\n  - name: a\n    mtu: x\n")
        with pytest.raises(SyntaxValidationError):
            validator.validate_syntax([file], rich_output=False)
        (violation,) = validator.check_file({"devices": [{"name": "a", "mtu": "x"}]})
        assert validator.errors == [
            f"Syntax error '{file}': devices.[name=a].mtu: {violation.message}"
        ]


class TestCheckMerged:
    """Tests for Validator.check_merged()."""

    DATA: dict[str, Any] = {
        "devices": [{"name": "a", "interfaces": [{"name": "e1", "vrf": "x"}]}]
    }

    def test_references_are_checked(self, validator: Validator) -> None:
        (violation,) = validator.check_merged(self.DATA, files=2)
        assert violation.path == ("devices", 0, "interfaces", 0, "vrf")
        assert violation.labels == ((1, "[name=a]"), (3, "[name=e1]"))

    def test_extensions_checked_per_file_only_with_several_files(
        self, validator: Validator
    ) -> None:
        data = {"devices": [{"name": "a"}, {"name": "a"}]}
        assert paths(validator.check_merged(data, files=2)) == [("devices",)]
        # A single file already had its primary keys checked
        assert validator.check_merged(data, files=1) == []

    def test_nothing_to_check(self, validator: Validator) -> None:
        assert validator.check_merged(self.DATA, files=0) == []
        assert validator.check_merged({}, files=2) == []
        assert Validator(None).check_merged(self.DATA, files=2) == []


class TestCheckModel:
    """Tests for Validator.check_model()."""

    def test_checks_yamale_and_every_extension(self, validator: Validator) -> None:
        assert paths(validator.check_model({"devices": [{"mtu": 1}]})) == [
            ("devices", 0, "name")
        ]
        assert paths(validator.check_model(TestCheckMerged.DATA)) == [
            ("devices", 0, "interfaces", 0, "vrf")
        ]

    def test_matches_preloaded_validation(self, validator: Validator) -> None:
        validator.load_data(TestCheckMerged.DATA)
        with pytest.raises(SyntaxValidationError):
            validator.validate_syntax(rich_output=False)
        (violation,) = validator.check_model(TestCheckMerged.DATA)
        assert validator.errors == [
            "Syntax error '<pre-loaded>': "
            f"devices.[name=a].interfaces.[name=e1].vrf: {violation.message}"
        ]


class TestValidateSyntaxFiles:
    """Tests for the files validate_syntax() reads."""

    def test_files_in_merge_order(self, validator: Validator, tmp_path: Path) -> None:
        for name in ("b.yaml", "a/c.yaml", "a.yaml", "x.txt"):
            file = tmp_path / name
            file.parent.mkdir(exist_ok=True)
            file.write_text("devices:\n  - name: a\n    mtu: x\n")
        with pytest.raises(SyntaxValidationError):
            validator.validate_syntax([tmp_path], rich_output=False)
        assert validator.file_count == 3
        assert [e.file for e in validator.structured_syntax_errors] == [
            str(tmp_path / "a.yaml"),
            str(tmp_path / "a" / "c.yaml"),
            str(tmp_path / "b.yaml"),
        ]


class Rule:
    id = "101"
    description = "Devices need an MTU"
    severity = "MEDIUM"

    @classmethod
    def match(cls, data: dict[str, Any]) -> list[Violation]:
        return [
            Violation(message="no mtu", path=f"devices[name={d['name']}]")
            for d in data.get("devices", [])
            if "mtu" not in d
        ]


class SchemaRule:
    id = "102"
    description = "Gets the schema"

    @classmethod
    def match(cls, data: dict[str, Any], schema: Any) -> list[str]:
        return ["schema"] if schema is not None else []


class FailingRule:
    id = "103"
    description = "Fails on incomplete data"

    @classmethod
    def match(cls, data: dict[str, Any]) -> list[str]:
        return [data["vrfs"][0]]


class TestRunRules:
    """Tests for Validator.run_rules()."""

    def test_results_of_every_rule(self) -> None:
        validator = Validator(
            yamale.make_schema(content=SCHEMA),
            {"101": Rule, "102": SchemaRule},
            severities={"102": "LOW"},
        )
        results = validator.run_rules(
            {"devices": [{"name": "a"}, {"name": "b", "mtu": 1}]}
        )
        assert results == [
            RuleResult("101", "MEDIUM", [Violation("no mtu", "devices[name=a]")]),
            RuleResult("102", "LOW", ["schema"]),
        ]

    def test_rules_without_violations(self) -> None:
        results = Validator(None, {"101": Rule}).run_rules({})
        assert results == [RuleResult("101", "MEDIUM", [])]

    def test_a_failing_rule_does_not_stop_the_others(self) -> None:
        validator = Validator(None, {"103": FailingRule, "101": Rule})
        failed, other = validator.run_rules({"devices": [{"name": "a"}]})
        assert failed.rule_id == "103"
        assert isinstance(failed.error, KeyError)
        assert failed.violations == []
        assert failed.severity == "HIGH"
        assert other == RuleResult(
            "101", "MEDIUM", [Violation("no mtu", "devices[name=a]")]
        )

    def test_rule_ids_are_the_keys_of_rules(self) -> None:
        class IntIdRule(Rule):
            id = 101  # type: ignore[assignment]

        validator = Validator(None, {"101": IntIdRule}, severities={"101": "LOW"})
        assert validator.run_rules({}) == [RuleResult("101", "LOW", [])]
        validator.load_data({"devices": [{"name": "a"}]})
        validator.validate_semantics([], rich_output=False, fail_on="MEDIUM")
        assert [r.rule_id for r in validator.semantic_results] == ["101"]

    def test_validate_semantics_raises_the_rule_error(self) -> None:
        validator = Validator(None, {"103": FailingRule})
        validator.load_data({"devices": []})
        with pytest.raises(KeyError):
            validator.validate_semantics([], rich_output=False)


class TestIgnoreComments:
    """Tests for reading ignore comments from text the caller provides."""

    TEXT = "devices:\n  - name: a  # nac-validate: ignore[101] lab\n"

    def test_read_comments_returns_problems(self) -> None:
        text = "a: 1  # nac-validate: skip[1]\nb: 2  # nac-validate: ignore[]\n"
        comments, problems = read_comments(Path("a.yaml"), text)
        assert comments == []
        assert problems == [
            IgnoreProblem(
                Path("a.yaml"),
                1,
                6,
                "unknown nac-validate comment 'skip[1]', expected "
                "'ignore[ID, ...]' or 'ignore-file[ID, ...]'",
            ),
            IgnoreProblem(
                Path("a.yaml"),
                2,
                6,
                "nac-validate ignore comment without rule IDs is ignored, "
                "name the rules, e.g. 'ignore[101]'",
            ),
        ]

    def test_scan_text_logs_problems(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            assert scan_text(Path("a.yaml"), "a: 1  # nac-validate: skip[1]\n") == []
        assert "a.yaml:1: unknown nac-validate comment 'skip[1]'" in caplog.text

    def test_matcher_uses_the_given_text(self, tmp_path: Path) -> None:
        file = tmp_path / "a.yaml"
        # On disk the comment is on another entry than in the given text
        file.write_text("other: 1\n" + self.TEXT)
        comments, _ = read_comments(file, self.TEXT)
        matcher = IgnoreMatcher(comments, {file: self.TEXT})
        kept, suppressed = matcher.suppress(
            "101", [Violation("no mtu", "devices[name=a]")]
        )
        assert kept == []
        assert [(s.file, s.line, s.reason) for s in suppressed] == [
            (str(file), 2, "lab")
        ]
        assert matcher.parsed_files == [file]

    def test_matcher_matches_relative_and_absolute_paths(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "a.yaml").write_text("other: 1\n" + self.TEXT)
        comments, _ = read_comments(Path("a.yaml"), self.TEXT)
        matcher = IgnoreMatcher(comments, {tmp_path / "a.yaml": self.TEXT})
        kept, _ = matcher.suppress("101", [Violation("no mtu", "devices[name=a]")])
        assert kept == []

    def test_selectors_match_loaded_values(self, tmp_path: Path) -> None:
        text = (
            "vlans:\n"
            "  - enabled: true  # nac-validate: ignore[101]\n"
            "  - id: 0x0A  # nac-validate: ignore[101]\n"
            "  - name: null  # nac-validate: ignore[101]\n"
        )
        file = tmp_path / "a.yaml"
        file.write_text(text)
        matcher = IgnoreMatcher(read_comments(file, text)[0])
        paths = ["vlans[enabled=True]", "vlans[id=10]", "vlans[name=None]"]
        kept, suppressed = matcher.suppress("101", [Violation("x", p) for p in paths])
        assert kept == []
        assert [s.line for s in suppressed] == [2, 3, 4]
        # As written still matches
        kept, _ = matcher.suppress("101", [Violation("x", "vlans[enabled=true]")])
        assert kept == []

    def test_matcher_reads_files_without_text(self, tmp_path: Path) -> None:
        file = tmp_path / "a.yaml"
        file.write_text(self.TEXT)
        matcher = IgnoreMatcher(read_comments(file, self.TEXT)[0])
        kept, _ = matcher.suppress("101", [Violation("no mtu", "devices[name=a]")])
        assert kept == []

    def test_parse_path(self) -> None:
        assert parse_path("devices[name=a].mtu") == [
            "devices",
            Selector((("name", "a"),)),
            "mtu",
        ]


def test_public_names() -> None:
    assert set(nac_validate.__all__) >= {"RuleResult", "Validator", "is_blocking"}
    assert nac_validate.is_blocking("MEDIUM", "LOW")
    assert not nac_validate.is_blocking("LOW", "MEDIUM")
