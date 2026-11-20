# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""References from a value to an item of a list elsewhere in the data.

A list declares what its items can be referenced as, a field what it refers
to::

    vrfs: list(include('vrf'), primary_key='name', ref_name='vrf',
               ref_implicit='default,management')
    vrf: str(ref='vrf')

- ``ref_name`` (on a ``list()`` with a single-field ``primary_key``): its
  items' keys can be referenced by that name. Several lists may share a name,
  forming one target
- ``ref_implicit`` (on the same list): comma-separated values that exist
  without being defined in the data, ``*`` and ``?`` being globs
- ``ref`` (on a scalar validator, also the item validator of a list): the
  value must be the key of a visible item registered under the name, or an
  implicit value
- ``ref_in`` (next to ``ref``): comma-separated dotted paths, read from the
  nearest list item enclosing the reference, whose values name the items of
  the lists enclosing the target; the last path names the item of the
  innermost list, e.g. ``ref_in='tenant,application_profile'``
- ``ref_scope='any'`` (on a ``list()`` with a single-field ``primary_key``):
  its items don't isolate references

Scope follows the data's nesting: for every list enclosing both the reference
and a target list, both must sit in the same item of it, unless a ``ref_in``
selector names the item or the list has ``ref_scope='any'``. Values are
compared as text, so an integer key matches its string form.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatchcase
from functools import cached_property
from typing import Any

from yamale.validators import Include, Map, Subset, Validator
from yamale.validators import List as ListValidator

from .base import Extension, Scope
from .values import is_single_value, split_fields, valid_fields
from .walker import (
    DataNode,
    KeyPath,
    ListLevel,
    SchemaContext,
    resolves,
    single_key_field,
    walk_data,
    walk_schema,
    walk_schema_contexts,
)

LIST_KEYWORDS = ("ref_name", "ref_implicit", "ref_scope")
VALUE_KEYWORDS = ("ref", "ref_in")
SCOPE_VALUES = ("any",)
_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_PATH = re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$")


class Mode(Enum):
    """How the item of a list enclosing a target is chosen for a reference."""

    # Named by a ref_in selector
    SELECTED = "selected"
    # Any item, the list has ref_scope='any'
    ANY = "any"
    # The reference's own item of the same list
    OWN = "own"
    # Any item, the reference is not inside the list
    FREE = "free"


@dataclass(frozen=True)
class LevelChoice:
    """The choice of the item of one list enclosing a target."""

    mode: Mode
    # The selector's value (SELECTED)
    selector: Any = None
    # The reference's own item (OWN)
    own: ListLevel | None = None


def _container(path: KeyPath) -> str:
    """Return a list's path without item indexes, e.g. ``apic.tenants``."""
    return ".".join(p for p in path if isinstance(p, str))


def _label(location: str, validator: ListValidator, key: Any, index: int) -> str:
    """Return a list item's label for messages, e.g. ``devices[name=LEAF1]``."""
    name = location.rsplit(".", 1)[-1]
    field_name = single_key_field(validator)
    if field_name is None or key is None:
        return f"{name}[{index}]"
    return f"{name}[{field_name}={key}]"


def _lookup(data: Any, path: Sequence[str]) -> Any:
    for segment in path:
        if not isinstance(data, dict):
            return None
        data = data.get(segment)
    return data


def _get(data: Any, path: KeyPath) -> Any:
    for segment in path:
        try:
            data = data[segment]
        except (KeyError, IndexError, TypeError):
            return None
    return data


def _keyword(validator: Validator, keyword: str) -> Any:
    """Return a reference keyword of the validator, None if not set."""
    if keyword in validator.kwargs and keyword in References.keywords:
        return validator.kwargs[keyword]
    return None


def _scope_any(validator: ListValidator) -> bool:
    return bool(validator.kwargs.get("ref_scope") == "any")


@dataclass
class Reference:
    """A value referring to an item of a list registered under ``kind``.

    Also handed to rules by ``references()`` to check visibility the schema
    can't express, e.g. a fallback to a shared item.
    """

    kind: str
    value: Any
    path: KeyPath
    # Items of the lists enclosing the reference, outermost first
    levels: tuple[ListLevel, ...]
    # Values of the ref_in selectors, the innermost container's last
    selectors: tuple[Any, ...]
    index: "ReferenceIndex" = field(repr=False)

    @property
    def implicit(self) -> bool:
        """Return whether the value is an implicit value of its kind."""
        patterns = self.index.implicit.get(self.kind, [])
        return any(fnmatchcase(str(self.value), p) for p in patterns)

    def scope_key(self, container: str) -> Any:
        """Return the key of the item of a container list the reference is in."""
        return next(
            (lv.key for lv in self.levels if _container(lv.path) == container), None
        )

    def defined_in(self, container: str) -> set[str]:
        """Return the keys of a container list's items the value is defined in."""
        return {
            str(lv.key)
            for levels in self.index.targets.get((self.kind, str(self.value)), [])
            for lv in levels
            if _container(lv.path) == container and lv.key is not None
        }

    def selected(self, container: str) -> bool:
        """Return whether a ``ref_in`` selector names the container's item."""
        return any(
            location == container and choice.mode == Mode.SELECTED
            for location, _, choice in self.index.choices_in_schema(self)
        )


class ReferenceIndex:
    """The targets and references of data that passed Yamale validation."""

    def __init__(self, schema: Any, data: Any, nodes: Sequence[DataNode]) -> None:
        self.schema = schema
        self.implicit: dict[str, list[str]] = {}
        for schema_node in walk_schema(schema):
            validator = schema_node.validator
            name = _keyword(validator, "ref_name")
            if isinstance(name, str):
                implicit = _keyword(validator, "ref_implicit")
                values = split_fields(implicit) if isinstance(implicit, str) else []
                self.implicit.setdefault(name, []).extend(values)
        # Enclosing levels of every target, by kind and key
        self.targets: dict[tuple[str, str], list[tuple[ListLevel, ...]]] = {}
        # Every list registered under a kind, with its enclosing levels
        self.target_lists: dict[str, list[tuple[KeyPath, tuple[ListLevel, ...]]]] = {}
        # Keys of the items of all lists at a path without indexes, e.g. the
        # names of the application profiles of all tenants at tenants.aps
        self.keys_by_container: dict[str, set[str]] = {}
        self.references: list[Reference] = []
        for node in nodes:
            validator = node.validator
            if isinstance(validator, ListValidator) and isinstance(node.value, list):
                self._add_list(node)
            kind = _keyword(validator, "ref")
            if isinstance(kind, str):
                self._add_reference(node, kind, data)

    @cached_property
    def target_contexts(self) -> dict[str, list[SchemaContext]]:
        """Return where lists registered under each kind are in the schema."""
        contexts: dict[str, list[SchemaContext]] = {}
        for ctx in walk_schema_contexts(self.schema):
            name = _keyword(ctx.validator, "ref_name")
            if isinstance(ctx.validator, ListValidator) and isinstance(name, str):
                contexts.setdefault(name, []).append(ctx)
        return contexts

    def _add_list(self, node: DataNode) -> None:
        key_field = single_key_field(node.validator)
        if key_field is None:
            return
        keys = {
            str(item[key_field])
            for item in node.value
            if isinstance(item, dict)
            and item.get(key_field) is not None
            and is_single_value(item[key_field])
        }
        self.keys_by_container.setdefault(_container(node.path), set()).update(keys)
        kind = _keyword(node.validator, "ref_name")
        if not isinstance(kind, str):
            return
        self.target_lists.setdefault(kind, []).append((node.path, node.levels))
        for key in keys:
            self.targets.setdefault((kind, key), []).append(node.levels)

    def _add_reference(self, node: DataNode, kind: str, data: Any) -> None:
        levels = node.levels
        # A value that is itself a list item sits in its own list's item
        if levels and node.path == (*levels[-1].path, levels[-1].index):
            levels = levels[:-1]
        record = _get(data, (*levels[-1].path, levels[-1].index)) if levels else data
        ref_in = _keyword(node.validator, "ref_in")
        paths = split_fields(ref_in) if isinstance(ref_in, str) else []
        selectors = tuple(_lookup(record, p.split(".")) for p in paths)
        self.references.append(
            Reference(kind, node.value, node.path, levels, selectors, self)
        )

    @staticmethod
    def _choose(
        depth: int,
        validators: Sequence[ListValidator],
        containers: Sequence[str],
        ref: Reference,
    ) -> list[LevelChoice]:
        """Return how the item of each list enclosing a target is chosen.

        The selectors name the items of the innermost lists, the last one the
        innermost list's item.
        """
        selectors = ref.selectors[-depth:] if depth else ()
        start = depth - len(selectors)
        choices = []
        for i in range(depth):
            selector = selectors[i - start] if i >= start else None
            if selector is not None:
                choices.append(LevelChoice(Mode.SELECTED, selector=selector))
            elif _scope_any(validators[i]):
                choices.append(LevelChoice(Mode.ANY))
            else:
                own = next(
                    (lv for lv in ref.levels if _container(lv.path) == containers[i]),
                    None,
                )
                choices.append(
                    LevelChoice(Mode.OWN, own=own) if own else LevelChoice(Mode.FREE)
                )
        return choices

    def choices(
        self, target_levels: tuple[ListLevel, ...], ref: Reference
    ) -> list[tuple[ListLevel, LevelChoice]]:
        """Return the choice of each level enclosing a target of the data."""
        choices = self._choose(
            len(target_levels),
            [lv.validator for lv in target_levels],
            [_container(lv.path) for lv in target_levels],
            ref,
        )
        return list(zip(target_levels, choices, strict=True))

    def choices_in_schema(
        self, ref: Reference
    ) -> list[tuple[str, ListValidator, LevelChoice]]:
        """Return the choice of each list enclosing the kind's lists in the schema.

        Of several places of the kind's lists, the one sharing the most lists
        with the reference is used.
        """
        own = {_container(lv.path) for lv in ref.levels}
        contexts = self.target_contexts.get(ref.kind, [])
        if not contexts:
            return []
        ctx = max(contexts, key=lambda c: sum(loc in own for loc, _ in c.lists))
        locations = [loc for loc, _ in ctx.lists]
        validators = [v for _, v in ctx.lists]
        choices = self._choose(len(ctx.lists), validators, locations, ref)
        return list(zip(locations, validators, choices, strict=True))

    @staticmethod
    def _passes(level: ListLevel, choice: LevelChoice) -> bool:
        if choice.mode == Mode.SELECTED:
            return str(level.key) == str(choice.selector)
        if choice.mode == Mode.OWN:
            own = choice.own
            return own is not None and (own.path, own.index) == (
                level.path,
                level.index,
            )
        return True

    def visible(self, target_levels: tuple[ListLevel, ...], ref: Reference) -> bool:
        """Return whether a target enclosed by the levels is visible from ref."""
        return all(self._passes(lv, c) for lv, c in self.choices(target_levels, ref))

    def unknown_selector(self, ref: Reference) -> bool:
        """Return whether a selector names an item no list it selects from has.

        Such a selector is reported by its own ``ref``, if it has one.
        """
        return any(
            choice.mode == Mode.SELECTED
            and str(choice.selector) not in self.keys_by_container.get(location, set())
            for location, _, choice in self.choices_in_schema(ref)
        )

    def violation(self, ref: Reference) -> str | None:
        """Return why the reference names no visible item, None if it does."""
        if not is_single_value(ref.value) or ref.implicit:
            return None
        candidates = self.targets.get((ref.kind, str(ref.value)), [])
        if any(self.visible(levels, ref) for levels in candidates):
            return None
        # An unknown selector value is reported by the selector's own ref
        if self.unknown_selector(ref):
            return None
        message = f"{ref.kind} '{ref.value}' is not defined"
        where = self._where(ref)
        return f"{message} in {where}" if where else message

    def _where(self, ref: Reference) -> str:
        """Return the items the target was looked up in, for messages."""
        labels = []
        for location, validator, choice in self.choices_in_schema(ref):
            if choice.mode == Mode.SELECTED:
                labels.append(_label(location, validator, choice.selector, 0))
            elif choice.own is not None:
                own = choice.own
                labels.append(_label(location, validator, own.key, own.index))
        return ".".join(labels)


def references(
    schema: Any, data: Any, within: str | None = None, strict: bool = True
) -> list[Reference]:
    """Return the references of data that passed Yamale validation.

    For rules that check what the schema can't express, e.g. visibility of a
    shared item. With ``within`` (a container list's path without indexes,
    e.g. ``apic.tenants``), only references inside an item of it.
    """
    index = ReferenceIndex(schema, data, list(walk_data(schema, data, strict)))
    refs = index.references
    if within is not None:
        refs = [
            r for r in refs if any(_container(lv.path) == within for lv in r.levels)
        ]
    return refs


class References(Extension):
    keywords = (*LIST_KEYWORDS, *VALUE_KEYWORDS)
    relates_values = True
    # Targets may be defined in other files than the references
    scopes = frozenset({Scope.DOCUMENT})

    def check_schema(self, validator: Validator) -> list[str]:
        used = self.configured(validator)
        kwargs = validator.kwargs
        problems = []
        is_list = isinstance(validator, ListValidator)
        for keyword in (k for k in LIST_KEYWORDS if k in used):
            if not is_list:
                problems.append(f"{keyword} is only supported on list()")
            elif single_key_field(validator) is None:
                problems.append(f"{keyword} needs a single-field primary_key")
        if "ref_name" in used and not _valid_name(kwargs["ref_name"]):
            problems.append(f"ref_name must be a name, not {kwargs['ref_name']!r}")
        if "ref_implicit" in used:
            if "ref_name" not in used:
                problems.append("ref_implicit needs ref_name")
            elif not valid_fields(kwargs["ref_implicit"]):
                problems.append(
                    "ref_implicit must be comma-separated values, not "
                    f"{kwargs['ref_implicit']!r}"
                )
        if "ref_scope" in used and kwargs["ref_scope"] not in SCOPE_VALUES:
            problems.append(
                f"ref_scope must be {', '.join(repr(v) for v in SCOPE_VALUES)}, "
                f"not {kwargs['ref_scope']!r}"
            )
        if "ref" in used:
            if isinstance(validator, Map | ListValidator | Include | Subset):
                problems.append(f"ref is not supported on {validator.tag}()")
            elif not _valid_name(kwargs["ref"]):
                problems.append(f"ref must be a name, not {kwargs['ref']!r}")
        if "ref_in" in used:
            if "ref" not in used:
                problems.append("ref_in needs ref")
            elif not _valid_paths(kwargs["ref_in"]):
                problems.append(
                    "ref_in must be comma-separated dotted field paths, not "
                    f"{kwargs['ref_in']!r}"
                )
        return problems

    def check_whole_schema(self, schema: Any) -> list[str]:
        if not any(self.applies(n.validator) for n in walk_schema(schema)):
            return []
        contexts = list(walk_schema_contexts(schema))
        targets: dict[str, list[SchemaContext]] = {}
        for ctx in contexts:
            name = _keyword(ctx.validator, "ref_name")
            if isinstance(ctx.validator, ListValidator) and isinstance(name, str):
                targets.setdefault(name, []).append(ctx)
        problems: dict[str, None] = {}
        for ctx in contexts:
            kind = _keyword(ctx.validator, "ref")
            if not isinstance(kind, str):
                continue
            if kind not in targets:
                problems[
                    f"{ctx.location}: ref names no list with ref_name {kind!r}"
                ] = None
                continue
            ref_in = _keyword(ctx.validator, "ref_in")
            if isinstance(ref_in, str):
                problems.update(
                    dict.fromkeys(
                        _ref_in_problems(ctx, split_fields(ref_in), kind, targets[kind])
                    )
                )
        return list(problems)

    def check_nodes(
        self, schema: Any, nodes: Sequence[DataNode], data: Any, scope: Scope
    ) -> list[tuple[KeyPath, str]]:
        if not any(isinstance(_keyword(n.validator, "ref"), str) for n in nodes):
            return []
        index = ReferenceIndex(schema, data, nodes)
        return [
            (ref.path, message)
            for ref in index.references
            if (message := index.violation(ref)) is not None
        ]


def _ref_in_problems(
    ctx: SchemaContext, paths: list[str], kind: str, targets: list[SchemaContext]
) -> list[str]:
    """Return problems with the ref_in selectors of a reference."""
    problems = []
    # A value that is itself a list item reads from the enclosing item
    records = ctx.records
    if len(records) > 1 and records[-1][0] is ctx.validator:
        records = records[:-1]
    record, record_schema = records[-1]
    for path in paths:
        if not resolves(record_schema, record, path.split(".")):
            problems.append(
                f"{ctx.location}: ref_in path {path!r} does not exist in the "
                "enclosing list item"
            )
    depths = sorted({target.depth for target in targets})
    if len(depths) > 1:
        problems.append(
            f"{ctx.location}: ref_in needs the lists with ref_name {kind!r} to be "
            f"inside the same number of list items, not {', '.join(map(str, depths))}"
        )
    elif len(paths) > depths[0]:
        problems.append(
            f"{ctx.location}: ref_in names {len(paths)} items, but lists with "
            f"ref_name {kind!r} are inside {depths[0]} list item(s)"
        )
    else:
        for target in targets:
            for location, validator in target.lists[len(target.lists) - len(paths) :]:
                if single_key_field(validator) is None:
                    problems.append(
                        f"{ctx.location}: ref_in selects items of {location}, "
                        "which needs a single-field primary_key"
                    )
    return problems


def _valid_name(value: Any) -> bool:
    return isinstance(value, str) and bool(_NAME.match(value))


def _valid_paths(value: Any) -> bool:
    return valid_fields(value) and all(_PATH.match(p) for p in split_fields(value))
