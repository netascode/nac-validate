# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Ignore comments in data files.

A comment in a data file exempts objects from rules:

.. code-block:: yaml

    iosxe:
      devices:
        - name: edge-1  # nac-validate: ignore[505, 506] legacy peer, CHG-1234
          configuration:
            # nac-validate: ignore[205] mixed modes during migration
            interfaces: ...
    # nac-validate: ignore-file[413]

* A comment after content applies to the entry starting on that line and
  everything below it (for ``- name: edge-1`` the whole list item).
* A comment on a line of its own applies to the next entry.
* ``ignore-file`` applies to the objects defined in the file.

A violation is suppressed if its path leads to the commented entry: list items
are matched by the ``[field=value]`` selectors of the path (e.g.
``devices[name=edge-1]``), not by their position, as positions change when
files are merged.

Reading is lazy, to keep the cost low on large data sets: every file is only
checked for the text ``nac-validate:``. A file is parsed again (its structure
only, with line numbers) only if one of its comments names a rule that
reported violations.
"""

import bisect
import logging
import os
import re
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from ruamel.yaml import YAML
from ruamel.yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from .constants import YAML_SUFFIXES
from .models import Violation, _is_violation_list

logger = logging.getLogger(__name__)

MARKER = "nac-validate:"
_MARKER_BYTES = MARKER.encode()
# A YAML comment starts at the beginning of a line or after whitespace
_COMMENT = re.compile(r"(?:^|(?<=\s))#\s*nac-validate:\s*(?P<body>.*)$")
# A line opening a block string: ``key: |``, ``- >-``, ``key: |2 # comment``
_BLOCK_START = re.compile(
    r"(?:^[ \t]*|:[ \t]+|-[ \t]+)[|>][0-9+-]*[ \t]*(?:#.*)?$", re.MULTILINE
)
_DIRECTIVE = re.compile(
    r"(?P<kind>ignore-file|ignore)\b\s*(?:\[(?P<ids>[^\]]*)\])?\s*(?P<reason>.*)$"
)

IgnoreKind = Literal["ignore", "ignore-file"]


@dataclass(frozen=True)
class IgnoreComment:
    """One ``# nac-validate: ignore[...]`` comment.

    Attributes:
        file: The data file.
        line: Line number (1-based).
        column: Column of the ``#`` (0-based).
        kind: ``ignore`` (the commented entry) or ``ignore-file``.
        rule_ids: The rules to ignore.
        reason: Text after the rule IDs, may be empty.
        own_line: Whether nothing but the comment is on the line.
    """

    file: Path
    line: int
    column: int
    kind: IgnoreKind
    rule_ids: tuple[str, ...]
    reason: str
    own_line: bool

    @property
    def location(self) -> str:
        """``file:line`` for messages."""
        return f"{self.file}:{self.line}"


@dataclass(frozen=True)
class SuppressedViolation:
    """A violation suppressed by an ignore comment.

    Attributes:
        rule_id: The violated rule.
        message: The violation's message.
        path: The violation's path.
        file: File of the comment.
        line: Line of the comment (1-based).
        reason: The comment's reason, may be empty.
    """

    rule_id: str
    message: str
    path: str
    file: str
    line: int
    reason: str


@dataclass(frozen=True)
class UnusedIgnore:
    """A rule ID of an ignore comment that suppressed nothing.

    Attributes:
        rule_id: The rule ID.
        file: File of the comment.
        line: Line of the comment (1-based).
        note: Why it could not suppress anything, if known.
    """

    rule_id: str
    file: str
    line: int
    note: str = ""


def data_files(paths: Iterable[Path | str]) -> list[Path]:
    """YAML files of the given files and directories, like the data loading."""
    files: list[Path] = []
    for path in map(Path, paths):
        if path.is_file():
            if path.suffix in YAML_SUFFIXES:
                files.append(path)
        else:
            for directory, _dirs, names in os.walk(path):
                files += [
                    Path(directory, n)
                    for n in sorted(names)
                    if n.endswith(YAML_SUFFIXES)
                ]
    return files


def _comment_start(line: str) -> re.Match[str] | None:
    """Find a ``# nac-validate:`` comment that is not inside a quoted string."""
    for match in _COMMENT.finditer(line):
        if not _in_quotes(line, match.start()):
            return match
    return None


def _in_quotes(line: str, end: int) -> bool:
    """Whether ``end`` is inside a single- or double-quoted string on the line."""
    quote = ""
    i = 0
    while i < end:
        ch = line[i]
        if quote == '"':
            if ch == "\\":
                i += 1
            elif ch == '"':
                quote = ""
        elif quote == "'":
            if ch == "'":
                # '' is an escaped quote inside a single-quoted string
                if i + 1 < end and line[i + 1] == "'":
                    i += 1
                else:
                    quote = ""
        elif ch in "'\"" and (i == 0 or line[i - 1] in " \t[{,:-"):
            # A quote only starts a string at the start of a value (it's).
            quote = ch
        i += 1
    return bool(quote)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _block_string_lines(lines: Sequence[str]) -> set[int]:
    """Indexes of the lines that are content of a block string (``key: |``).

    Content of a block string is indented more than the line opening it and
    ends at the first non-empty line that is not.
    """
    inside: set[int] = set()
    opener: int | None = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if opener is not None:
            if not stripped or _indent(line) > opener:
                inside.add(index)
                continue
            opener = None
        if not stripped.startswith("#") and _BLOCK_START.search(line):
            opener = _indent(line)
    return inside


def scan_text(file: Path, text: str) -> list[IgnoreComment]:
    """Read the ignore comments of a file's text, warning about malformed ones."""
    comments: list[IgnoreComment] = []
    lines = text.splitlines()
    # Only files with block strings need the pass over every line
    has_blocks = ("|" in text or ">" in text) and (
        _BLOCK_START.search(text) is not None
    )
    in_blocks = _block_string_lines(lines) if has_blocks else set()
    for index, line in enumerate(lines):
        number = index + 1
        if MARKER not in line or index in in_blocks:
            continue
        match = _comment_start(line)
        if match is None:
            continue
        body = match.group("body").strip()
        directive = _DIRECTIVE.match(body)
        if directive is None:
            logger.warning(
                "%s:%d: unknown nac-validate comment %r, expected "
                "'ignore[ID, ...]' or 'ignore-file[ID, ...]'",
                file,
                number,
                body,
            )
            continue
        ids = [i.strip() for i in (directive.group("ids") or "").split(",")]
        ids = [i for i in ids if i]
        if not ids:
            logger.warning(
                "%s:%d: nac-validate %s comment without rule IDs is ignored, "
                "name the rules, e.g. '%s[101]'",
                file,
                number,
                directive.group("kind"),
                directive.group("kind"),
            )
            continue
        kind: IgnoreKind = (
            "ignore-file" if directive.group("kind") == "ignore-file" else "ignore"
        )
        comments.append(
            IgnoreComment(
                file=file,
                line=number,
                column=match.start(),
                kind=kind,
                rule_ids=tuple(dict.fromkeys(ids)),
                reason=directive.group("reason").strip(),
                own_line=not line[: match.start()].strip(),
            )
        )
    return comments


# Reading many small files is dominated by opening them, which threads overlap
_SCAN_THREADS = 4
_SCAN_THREADS_FROM = 64


def _marked_text(file: Path) -> str | None:
    """The file's text if it contains ``nac-validate:``, else None."""
    try:
        raw = file.read_bytes()
    except OSError:
        return None
    if _MARKER_BYTES not in raw:
        return None
    return raw.decode("utf-8", errors="replace")


def scan(paths: Iterable[Path | str]) -> list[IgnoreComment]:
    """Read the ignore comments of all data files.

    Only files containing ``nac-validate:`` are decoded and read line by line.
    """
    files = data_files(paths)
    if len(files) >= _SCAN_THREADS_FROM:
        with ThreadPoolExecutor(_SCAN_THREADS) as executor:
            texts = list(executor.map(_marked_text, files, chunksize=64))
    else:
        texts = [_marked_text(f) for f in files]
    comments: list[IgnoreComment] = []
    for file, text in zip(files, texts, strict=True):
        if text is not None:
            comments += scan_text(file, text)
    return comments


# Path segments: a map key (str), the selectors of a list item, or a position


@dataclass(frozen=True)
class _Select:
    """``[name=a, node=1]``: a list item with these field values."""

    pairs: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class _Index:
    """``[3]``: a list item by position (cannot be matched to a comment)."""

    index: int


@dataclass(frozen=True)
class _Item:
    """A list item of a data file, with its scalar fields as written."""

    fields: dict[str, str] = field(hash=False)

    def satisfies(self, select: _Select) -> bool:
        return all(self.fields.get(k) == v for k, v in select.pairs)


PathSegment = str | _Select | _Index
_TOKEN = re.compile(r"\.?(?:\[(?P<select>[^\]]*)\]|(?P<key>[^.\[\]]+))")
_FIELD_SEPARATOR = re.compile(r",\s*(?=[^=,\s]+\s*=)")


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def parse_path(path: str) -> list[PathSegment] | None:
    """Split a violation path into keys and list item selectors.

    Accepts ``a.b[name=x].c``, ``a.b.[name=x]`` and ``[node=1, name=a]``.
    Returns None for a path that cannot be read this way.
    """
    segments: list[PathSegment] = []
    pos = 0
    while pos < len(path):
        match = _TOKEN.match(path, pos)
        if match is None or match.end() == pos:
            return None
        pos = match.end()
        key = match.group("key")
        if key is not None:
            segments.append(key.strip())
            continue
        content = match.group("select").strip()
        if re.fullmatch(r"-?\d+", content):
            segments.append(_Index(int(content)))
            continue
        pairs: list[tuple[str, str]] = []
        # Fields are joined by commas, but a value may contain one too
        for part in _FIELD_SEPARATOR.split(content):
            name, sep, value = part.partition("=")
            if not sep or not name.strip():
                return None
            pairs.append((name.strip(), _unquote(value.strip())))
        segments.append(_Select(tuple(pairs)))
    return segments


def _item(node: Node) -> _Item:
    if not isinstance(node, MappingNode):
        return _Item({})
    return _Item(
        {
            k.value: v.value
            for k, v in node.value
            if isinstance(k, ScalarNode) and isinstance(v, ScalarNode)
        }
    )


Target = tuple[str | _Item, ...]


class _FileIndex:
    """Entries of one data file by the line they start on, from its node tree."""

    def __init__(self, root: Node | None) -> None:
        self.root = root
        # Line (0-based) -> path of the outermost entry starting on it
        self._starts: dict[int, Target] = {}
        # Scalars spanning several lines, and the others by line
        self._multiline: list[tuple[int, int, int, int]] = []
        self._scalars: dict[int, list[tuple[int, int]]] = {}
        # Fields of each list item, and the items of a list by field value
        self._items: dict[int, _Item] = {}
        self._lookup: dict[int, dict[tuple[str, str], list[Node]]] = {}
        if root is not None:
            self._walk(root, (), set())
        self._lines = sorted(self._starts)

    def _record(self, line: int, path: Target) -> None:
        existing = self._starts.get(line)
        if existing is None or len(path) < len(existing):
            self._starts[line] = path

    def _walk(self, node: Node, path: Target, active: set[int]) -> None:
        if id(node) in active:  # a recursive alias
            return
        if isinstance(node, ScalarNode):
            start, end = node.start_mark, node.end_mark
            if start.line == end.line:
                self._scalars.setdefault(start.line, []).append(
                    (start.column, end.column)
                )
            else:
                self._multiline.append((start.line, start.column, end.line, end.column))
            return
        active.add(id(node))
        if isinstance(node, MappingNode):
            for key, value in node.value:
                if not isinstance(key, ScalarNode):
                    continue
                child = (*path, key.value)
                self._record(key.start_mark.line, child)
                self._walk(key, child, active)
                self._walk(value, child, active)
        elif isinstance(node, SequenceNode):
            for value in node.value:
                item = self._items[id(value)] = _item(value)
                child = (*path, item)
                self._record(value.start_mark.line, child)
                self._walk(value, child, active)
        active.discard(id(node))

    def in_scalar(self, line: int, column: int) -> bool:
        """Whether a position is inside a string, so not a comment."""
        if any(s <= column < e for s, e in self._scalars.get(line, ())):
            return True
        return any(
            (sl, sc) <= (line, column) < (el, ec) for sl, sc, el, ec in self._multiline
        )

    def target(self, comment: IgnoreComment) -> Target | None:
        """The path of the entry a comment applies to, if any."""
        line = comment.line - 1
        if self.in_scalar(line, comment.column):
            return None
        if not comment.own_line:
            return self._starts.get(line)
        index = bisect.bisect_right(self._lines, line)
        return self._starts[self._lines[index]] if index < len(self._lines) else None

    def contains(self, segments: Sequence[PathSegment]) -> bool:
        """Whether the object a violation path leads to is defined in the file.

        The path is followed down to its last list item selector (or to its end
        if it selects none); keys after it may be missing, e.g. for a violation
        about an attribute that is not set.
        """
        last = max(
            (i for i, s in enumerate(segments) if isinstance(s, _Select)), default=-1
        )
        needed = segments[: last + 1] if last >= 0 else segments
        node = self.root
        for segment in needed:
            if isinstance(segment, str) and isinstance(node, MappingNode):
                node = next(
                    (
                        v
                        for k, v in node.value
                        if isinstance(k, ScalarNode) and k.value == segment
                    ),
                    None,
                )
            elif isinstance(segment, _Select) and isinstance(node, SequenceNode):
                node = self._find(node, segment)
            else:
                return False
            if node is None:
                return False
        return bool(needed)

    def _find(self, sequence: SequenceNode, select: _Select) -> Node | None:
        """The first item of a list with the selected field values."""
        lookup = self._lookup.get(id(sequence))
        if lookup is None:
            lookup = self._lookup[id(sequence)] = {}
            for value in sequence.value:
                for pair in self._items[id(value)].fields.items():
                    lookup.setdefault(pair, []).append(value)
        candidates = lookup.get(select.pairs[0], ()) if select.pairs else ()
        return next(
            (v for v in candidates if self._items[id(v)].satisfies(select)), None
        )


def _leads_to(target: Target, segments: Sequence[PathSegment]) -> bool:
    """Whether a violation path starts with the path of a commented entry."""
    if len(segments) < len(target):
        return False
    for expected, segment in zip(target, segments, strict=False):
        if isinstance(expected, str):
            if segment != expected:
                return False
        elif not (isinstance(segment, _Select) and expected.satisfies(segment)):
            return False
    return True


class IgnoreMatcher:
    """Suppress violations by ignore comments and track which comments were used.

    Files are parsed (structure only) on first use, so only files with comments
    for rules that reported violations are read again.
    """

    def __init__(self, comments: Sequence[IgnoreComment]) -> None:
        self._comments = list(comments)
        self._by_rule: dict[str, list[IgnoreComment]] = {}
        for comment in self._comments:
            for rule_id in comment.rule_ids:
                self._by_rule.setdefault(rule_id, []).append(comment)
        self._yaml = YAML(typ="safe")
        self._indexes: dict[Path, _FileIndex] = {}
        self._targets: dict[IgnoreComment, Target | None] = {}
        self._used: set[tuple[IgnoreComment, str]] = set()
        self._not_comments: set[IgnoreComment] = set()
        # Rules with violations that cannot be matched: no path or no readable one
        self._pathless: set[str] = set()

    @property
    def parsed_files(self) -> list[Path]:
        """Files parsed to resolve comments so far."""
        return list(self._indexes)

    def _index(self, file: Path) -> _FileIndex:
        index = self._indexes.get(file)
        if index is None:
            try:
                root = self._yaml.compose(file.read_text(encoding="utf-8"))
            except Exception as e:  # a bad file must not fail validation
                logger.warning("Cannot read ignore comments of %s: %s", file, e)
                root = None
            index = self._indexes[file] = _FileIndex(root)
        return index

    def _target(self, comment: IgnoreComment) -> Target | None:
        if comment not in self._targets:
            target = self._index(comment.file).target(comment)
            self._targets[comment] = target
            if target is None and self._index(comment.file).in_scalar(
                comment.line - 1, comment.column
            ):
                self._not_comments.add(comment)
        return self._targets[comment]

    def _matches(self, comment: IgnoreComment, segments: Sequence[PathSegment]) -> bool:
        if comment.kind == "ignore-file":
            return self._index(comment.file).contains(segments)
        target = self._target(comment)
        return target is not None and _leads_to(target, segments)

    def suppress(
        self, rule_id: str, result: list[Any]
    ) -> tuple[list[Any], list[SuppressedViolation]]:
        """Split a rule's result into kept and suppressed violations.

        Only violations with a path can be suppressed; results of plain strings
        are returned unchanged.
        """
        comments = self._by_rule.get(rule_id, [])
        if not comments or not result:
            return result, []
        if not _is_violation_list(result):
            self._pathless.add(rule_id)
            return result, []
        kept: list[Violation] = []
        suppressed: list[SuppressedViolation] = []
        for violation in result:
            segments = parse_path(violation.path) if violation.path else None
            if segments is None or len(segments) == 0:
                self._pathless.add(rule_id)
                kept.append(violation)
                continue
            # Every matching comment counts as used; the first is reported
            hits = [c for c in comments if self._matches(c, segments)]
            if not hits:
                kept.append(violation)
                continue
            self._used.update((c, rule_id) for c in hits)
            hit = hits[0]
            suppressed.append(
                SuppressedViolation(
                    rule_id=rule_id,
                    message=violation.message,
                    path=violation.path,
                    file=str(hit.file),
                    line=hit.line,
                    reason=hit.reason,
                )
            )
        return kept, suppressed

    def unused(self) -> list[UnusedIgnore]:
        """Rule IDs of comments that suppressed nothing, in file order."""
        return [
            UnusedIgnore(rule_id, str(c.file), c.line, self._note(rule_id))
            for c in sorted(self._comments, key=lambda c: (str(c.file), c.line))
            if c not in self._not_comments
            for rule_id in c.rule_ids
            if (c, rule_id) not in self._used
        ]

    def _note(self, rule_id: str) -> str:
        if rule_id in self._pathless:
            return (
                f"rule {rule_id} reports violations without a path, which "
                "cannot be suppressed by comments"
            )
        return ""
