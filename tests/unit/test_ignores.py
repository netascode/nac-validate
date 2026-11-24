# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Unit tests for ignore comments in data files."""

import logging
import time
from pathlib import Path

import pytest

from nac_validate.ignores import (
    IgnoreMatcher,
    UnusedIgnore,
    _Select,
    data_files,
    parse_path,
    scan,
    scan_text,
)
from nac_validate.models import Violation

DATA = """\
iosxe:
  devices:
    - name: edge-1  # nac-validate: ignore[505, 506] legacy peer
      configuration:
        # nac-validate: ignore[205] migration
        interfaces:
          ethernets:
            - id: 1
              mode: access
    - name: edge-2
      configuration:
        interfaces:
          ethernets:
            - id: 1  # nac-validate: ignore[301]
"""


def write(tmp_path: Path, text: str, name: str = "data.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text)
    return path


def violation(path: str) -> Violation:
    return Violation(message=f"bad {path}", path=path)


def matcher_for(*files: Path) -> IgnoreMatcher:
    return IgnoreMatcher(scan(files))


class TestScan:
    """Tests for reading comments from the text."""

    def test_reads_trailing_and_own_line_comments(self, tmp_path: Path) -> None:
        file = write(tmp_path, DATA)

        comments = scan([file])

        assert [
            (c.line, c.kind, c.rule_ids, c.reason, c.own_line) for c in comments
        ] == [
            (3, "ignore", ("505", "506"), "legacy peer", False),
            (5, "ignore", ("205",), "migration", True),
            (14, "ignore", ("301",), "", False),
        ]

    def test_ignore_file(self) -> None:
        (comment,) = scan_text(
            Path("a.yaml"), "# nac-validate: ignore-file[413]\na: 1\n"
        )

        assert (comment.kind, comment.rule_ids) == ("ignore-file", ("413",))

    def test_spacing_and_duplicates(self) -> None:
        (comment,) = scan_text(Path("a.yaml"), "a: 1 #nac-validate:ignore[ 1 ,2,1] x\n")

        assert comment.rule_ids == ("1", "2")
        assert comment.reason == "x"

    @pytest.mark.parametrize(
        "line",
        [
            "a: 'text # nac-validate: ignore[1]'",
            'a: "text # nac-validate: ignore[1]"',
            "a: text#nac-validate: ignore[1]",
        ],
    )
    def test_text_that_is_not_a_comment(self, line: str) -> None:
        assert scan_text(Path("a.yaml"), line + "\n") == []

    @pytest.mark.parametrize("opener", ["|", ">-", "|2", "| # note"])
    def test_text_in_a_block_string_is_not_a_comment(self, opener: str) -> None:
        text = (
            "a:\n"
            "  - name: x\n"
            f"    notes: {opener}\n"
            "      # nac-validate: ignore[1] example\n"
            "      more text  # nac-validate: ignore[2]\n"
            "    other: 1  # nac-validate: ignore[3]\n"
        )

        assert [c.rule_ids for c in scan_text(Path("a.yaml"), text)] == [("3",)]

    def test_apostrophe_in_plain_text_does_not_open_a_string(self) -> None:
        text = "a: it's fine  # nac-validate: ignore[1]\n"

        assert len(scan_text(Path("a.yaml"), text)) == 1

    def test_comment_without_rule_ids_is_ignored_with_a_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        text = "a: 1  # nac-validate: ignore\nb: 1  # nac-validate: ignore[]\n"

        assert scan_text(Path("a.yaml"), text) == []
        assert caplog.text.count("without rule IDs") == 2

    def test_unknown_comment_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        assert scan_text(Path("a.yaml"), "a: 1  # nac-validate: skip[1]\n") == []
        assert "a.yaml:1: unknown nac-validate comment 'skip[1]'" in caplog.text

    def test_only_yaml_files_are_scanned(self, tmp_path: Path) -> None:
        write(tmp_path, "a: 1  # nac-validate: ignore[1]\n", "a.txt")
        (tmp_path / "sub").mkdir()
        nested = write(tmp_path / "sub", "a: 1  # nac-validate: ignore[1]\n", "b.yml")

        assert data_files([tmp_path]) == [nested]
        assert [c.file for c in scan([tmp_path])] == [nested]


class TestParsePath:
    """Tests for reading violation paths."""

    @pytest.mark.parametrize(
        "path",
        [
            "iosxe.devices[name=edge-1].configuration",
            "iosxe.devices.[name=edge-1].configuration",
        ],
    )
    def test_selector_styles(self, path: str) -> None:
        keys = [s for s in parse_path(path) or [] if isinstance(s, str)]

        assert keys == ["iosxe", "devices", "configuration"]
        assert len(parse_path(path) or []) == 4

    def test_several_fields_and_quoted_values(self) -> None:
        segments = parse_path("a[node=1, name='1']") or []

        select = segments[1]
        assert isinstance(select, _Select)
        assert select.pairs == (("node", "1"), ("name", "1"))

    def test_values_containing_commas(self) -> None:
        segments = parse_path("tenants[name=Prod, Lab].vrfs[name=x, node=1]") or []

        assert [s.pairs for s in segments if isinstance(s, _Select)] == [
            (("name", "Prod, Lab"),),
            (("name", "x"), ("node", "1")),
        ]

    def test_unreadable_path(self) -> None:
        assert parse_path("a[oops]") is None


class TestMatching:
    """Tests for suppressing violations by their path."""

    def test_trailing_comment_covers_the_list_item(self, tmp_path: Path) -> None:
        matcher = matcher_for(write(tmp_path, DATA))
        result = [
            violation("iosxe.devices[name=edge-1].configuration.hostname"),
            violation("iosxe.devices[name=edge-2].configuration.hostname"),
        ]

        kept, suppressed = matcher.suppress("505", result)

        assert [v.path for v in kept] == [
            "iosxe.devices[name=edge-2].configuration.hostname"
        ]
        (s,) = suppressed
        assert (s.rule_id, s.line, s.reason) == ("505", 3, "legacy peer")

    def test_own_line_comment_covers_the_next_entry(self, tmp_path: Path) -> None:
        matcher = matcher_for(write(tmp_path, DATA))
        inside = "iosxe.devices[name=edge-1].configuration.interfaces.ethernets[id=1]"
        beside = "iosxe.devices[name=edge-1].configuration.hostname"

        kept, suppressed = matcher.suppress(
            "205", [violation(inside), violation(beside)]
        )

        assert [s.path for s in suppressed] == [inside]
        assert [v.path for v in kept] == [beside]

    def test_nested_item_selected_by_all_parents(self, tmp_path: Path) -> None:
        matcher = matcher_for(write(tmp_path, DATA))
        edge_2 = "iosxe.devices[name=edge-2].configuration.interfaces.ethernets[id=1]"
        edge_1 = "iosxe.devices[name=edge-1].configuration.interfaces.ethernets[id=1]"

        kept, _ = matcher.suppress("301", [violation(edge_2), violation(edge_1)])

        assert [v.path for v in kept] == [edge_1]

    def test_path_with_position_or_another_rule_is_kept(self, tmp_path: Path) -> None:
        matcher = matcher_for(write(tmp_path, DATA))

        kept, _ = matcher.suppress("505", [violation("iosxe.devices[0].configuration")])
        other, _ = matcher.suppress(
            "999", [violation("iosxe.devices[name=edge-1].configuration")]
        )

        assert len(kept) == 1 and len(other) == 1

    def test_violation_above_the_comment_is_kept(self, tmp_path: Path) -> None:
        """Should not suppress a violation about the whole list."""
        matcher = matcher_for(write(tmp_path, DATA))

        kept, _ = matcher.suppress("505", [violation("iosxe.devices")])

        assert len(kept) == 1

    def test_string_results_are_unchanged(self, tmp_path: Path) -> None:
        matcher = matcher_for(write(tmp_path, DATA))

        assert matcher.suppress("505", ["edge-1 is bad"]) == (["edge-1 is bad"], [])

    def test_ignore_file_covers_objects_defined_in_the_file(
        self, tmp_path: Path
    ) -> None:
        file = write(
            tmp_path,
            "# nac-validate: ignore-file[413]\niosxe:\n  devices:\n    - name: a\n",
        )
        matcher = matcher_for(file)

        kept, suppressed = matcher.suppress(
            "413",
            [
                violation("iosxe.devices[name=a].configuration.ntp"),
                violation("iosxe.devices[name=b].configuration.ntp"),
            ],
        )

        assert [s.path for s in suppressed] == [
            "iosxe.devices[name=a].configuration.ntp"
        ]
        assert [v.path for v in kept] == ["iosxe.devices[name=b].configuration.ntp"]

    def test_comment_inside_a_block_string_is_not_a_comment(
        self, tmp_path: Path
    ) -> None:
        file = write(
            tmp_path,
            "a:\n  - name: x\n    text: |\n      # nac-validate: ignore[1]\n",
        )
        matcher = matcher_for(file)

        kept, _ = matcher.suppress("1", [violation("a[name=x].text")])

        assert len(kept) == 1
        assert matcher.unused() == []

    def test_comment_in_another_file_than_the_rest_of_the_object(
        self, tmp_path: Path
    ) -> None:
        """Should match by path, as the merged data combines files."""
        first = write(
            tmp_path, "a:\n  - name: x  # nac-validate: ignore[1]\n", "1.yaml"
        )
        write(tmp_path, "a:\n  - name: x\n    port: 2\n", "2.yaml")

        _, suppressed = matcher_for(first).suppress("1", [violation("a[name=x].port")])

        assert len(suppressed) == 1


class TestIgnoreFileLookup:
    """Tests for finding objects of a file quickly."""

    def test_many_items_and_violations_stay_fast(self, tmp_path: Path) -> None:
        """Should look list items up by their fields instead of scanning them."""
        items = "".join(f"  - name: dev-{i}\n    x: 1\n" for i in range(2000))
        file = write(tmp_path, "# nac-validate: ignore-file[1]\ndevices:\n" + items)
        result = [violation(f"devices[name=other-{i}].x") for i in range(2000)]
        result.append(violation("devices[name=dev-1999].x"))
        matcher = matcher_for(file)
        matcher._index(file)  # parse outside the timed part

        start = time.perf_counter()
        _, suppressed = matcher.suppress("1", result)
        elapsed = time.perf_counter() - start

        assert [s.path for s in suppressed] == ["devices[name=dev-1999].x"]
        assert elapsed < 0.5  # quadratic matching took over a second

    def test_item_selected_by_several_fields(self, tmp_path: Path) -> None:
        file = write(
            tmp_path,
            "# nac-validate: ignore-file[1]\n"
            "vrfs:\n  - {name: a, node: 1}\n  - {name: a, node: 2}\n",
        )

        kept, _ = matcher_for(file).suppress(
            "1", [violation("vrfs[name=a, node=2]"), violation("vrfs[name=a, node=3]")]
        )

        assert [v.path for v in kept] == ["vrfs[name=a, node=3]"]


class TestUnusedAndLaziness:
    """Tests for reporting unused comments and reading files only when needed."""

    def test_unused_rule_ids_are_reported(self, tmp_path: Path) -> None:
        file = write(tmp_path, DATA)
        matcher = matcher_for(file)

        matcher.suppress("505", [violation("iosxe.devices[name=edge-1].x")])

        assert matcher.unused() == [
            UnusedIgnore("506", str(file), 3),
            UnusedIgnore("205", str(file), 5),
            UnusedIgnore("301", str(file), 14),
        ]

    def test_every_matching_comment_counts_as_used(self, tmp_path: Path) -> None:
        file = write(
            tmp_path,
            "# nac-validate: ignore-file[1]\na:\n  - name: x  # nac-validate: ignore[1]\n",
        )
        matcher = matcher_for(file)

        _, (suppressed,) = matcher.suppress("1", [violation("a[name=x]")])

        assert suppressed.line == 1  # attributed to the first comment
        assert matcher.unused() == []

    def test_rule_without_paths_explains_the_unused_comment(
        self, tmp_path: Path
    ) -> None:
        file = write(tmp_path, "a:\n  - name: x  # nac-validate: ignore[1, 2]\n")
        matcher = matcher_for(file)

        matcher.suppress("1", ["x is bad"])
        matcher.suppress("2", [Violation(message="x is bad")])

        assert [u.note for u in matcher.unused()] == [
            "rule 1 reports violations without a path, which cannot be suppressed "
            "by comments",
            "rule 2 reports violations without a path, which cannot be suppressed "
            "by comments",
        ]

    def test_no_file_is_parsed_without_violations(self, tmp_path: Path) -> None:
        matcher = matcher_for(write(tmp_path, DATA))

        matcher.suppress("505", [])

        assert matcher.parsed_files == []
        assert len(matcher.unused()) == 4

    def test_only_files_with_comments_for_violated_rules_are_parsed(
        self, tmp_path: Path
    ) -> None:
        first = write(
            tmp_path, "a:\n  - name: x  # nac-validate: ignore[1]\n", "1.yaml"
        )
        second = write(
            tmp_path, "b:\n  - name: y  # nac-validate: ignore[2]\n", "2.yaml"
        )
        write(tmp_path, "c: 1\n", "3.yaml")
        matcher = matcher_for(first, second)

        matcher.suppress("1", [violation("a[name=x]")])

        assert matcher.parsed_files == [first]

    def test_unreadable_file_suppresses_nothing(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.WARNING)
        file = write(tmp_path, "a: [\n  # nac-validate: ignore[1]\n")

        kept, _ = matcher_for(file).suppress("1", [violation("a")])

        assert len(kept) == 1
        assert "Cannot read ignore comments" in caplog.text
