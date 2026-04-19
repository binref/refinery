"""
Minimal unified AST base for script parsers. Provides abstract node types shared
across language-specific parsers.
"""
from __future__ import annotations

import copy
import dataclasses
import enum
import io
import typing

from dataclasses import dataclass, field
from typing import Callable, Generator, TypeVar

from refinery.lib.annotations import get_type_hints as _get_type_hints


class Kind(enum.IntEnum):
    ChildNode = 1
    ChildList = 2
    TupleList = 3


_SKIP_FIELDS = frozenset(('offset', 'parent', 'leading_comments'))

_child_fields_cache: dict[type, list[tuple[str, Kind]]] = {}


def _has_node_type(hint) -> bool:
    if isinstance(hint, type):
        return issubclass(hint, Node)
    return any(_has_node_type(a) for a in typing.get_args(hint))


def _classify_fields(node_type: type[Node]) -> list[tuple[str, Kind]]:
    try:
        return _child_fields_cache[node_type]
    except KeyError:
        pass
    result: list[tuple[str, Kind]] = []
    try:
        hints = _get_type_hints(node_type)
    except Exception:
        _child_fields_cache[node_type] = result
        return result
    for f in dataclasses.fields(node_type):
        if f.name in _SKIP_FIELDS:
            continue
        hint = hints.get(f.name)
        if hint is None:
            continue
        origin = typing.get_origin(hint)
        if origin is list:
            args = typing.get_args(hint)
            if not args:
                continue
            inner = args[0]
            inner_origin = typing.get_origin(inner)
            if inner_origin is tuple:
                inner_args = typing.get_args(inner)
                if any(_has_node_type(a) for a in inner_args):
                    result.append((f.name, Kind.TupleList))
            elif _has_node_type(inner):
                result.append((f.name, Kind.ChildList))
        elif _has_node_type(hint):
            result.append((f.name, Kind.ChildNode))
    _child_fields_cache[node_type] = result
    return result


def _children(node: Node):
    def _candidates():
        for name, kind in _classify_fields(type(node)):
            field = getattr(node, name)
            if kind == Kind.ChildNode:
                yield field
            elif kind == Kind.ChildList:
                yield from field
            elif kind == Kind.TupleList:
                for item in field:
                    yield from item
    for item in _candidates():
        if isinstance(item, Node):
            yield item


@dataclass(repr=False)
class Node:
    """
    Base class for all AST nodes.
    """
    offset: int = -1
    parent: Node | None = field(default=None, compare=False)
    leading_comments: list[str] = field(default_factory=list, compare=False)

    def __post_init__(self):
        for c in _children(self):
            self._adopt(c)

    def children(self) -> Generator[Node, None, None]:
        yield from _children(self)

    def walk(self) -> Generator[Node, None, None]:
        stack: list[Node] = [self]
        while stack:
            node = stack.pop()
            yield node
            for child in node.children():
                stack.append(child)

    def _adopt(self, *nodes: Node | None):
        for node in nodes:
            if node is not None:
                node.parent = self

    def __repr__(self):
        name = type(self).__name__
        return F'{name}@{self.offset}'


class Expression(Node):
    """
    Abstract base for all expression nodes.
    """
    pass


class Statement(Node):
    """
    Abstract base for all statement nodes.
    """
    pass


@dataclass(repr=False)
class Block(Node):
    """
    Ordered sequence of statements.
    """
    body: list[Statement] = field(default_factory=list)


@dataclass(repr=False)
class Script(Node):
    """
    Top-level node representing an entire script.
    """
    body: list[Statement] = field(default_factory=list)


class Visitor:
    """
    Dispatch-based tree walker. Subclasses define visit_ClassName methods;
    unhandled nodes fall through to generic_visit.
    """

    def __init__(self):
        self._dispatch: dict[type[Node], Callable[[Node], Node | None]] = {}

    def visit(self, node: Node) -> Node | None:
        t = type(node)
        try:
            handler = self._dispatch[t]
        except KeyError:
            handler = getattr(self, F'visit_{t.__name__}', self.generic_visit)
            self._dispatch[t] = handler
        return handler(node)

    def generic_visit(self, node: Node) -> Node | None:
        for child in node.children():
            self.visit(child)


class Transformer(Visitor):
    """
    In-place tree rewriter. Each visit method may return a replacement node
    or None to keep the original. Tracks whether any transformation was applied
    via the `changed` flag.
    """

    def __init__(self):
        super().__init__()
        self.changed = False

    def mark_changed(self):
        self.changed = True

    def generic_visit(self, node: Node):
        for field_name, kind in _classify_fields(type(node)):
            if kind == Kind.ChildNode:
                value = getattr(node, field_name)
                if isinstance(value, Node):
                    replacement = self.visit(value)
                    if replacement is not None:
                        replacement.parent = node
                        setattr(node, field_name, replacement)
                        self.mark_changed()
            elif kind == Kind.ChildList:
                items = getattr(node, field_name)
                new_list = []
                changed = False
                for item in items:
                    if isinstance(item, Node):
                        replacement = self.visit(item)
                        if replacement is not None:
                            replacement.parent = node
                            new_list.append(replacement)
                            changed = True
                        else:
                            new_list.append(item)
                    else:
                        new_list.append(item)
                if changed:
                    setattr(node, field_name, new_list)
                    self.mark_changed()
            elif kind == Kind.TupleList:
                items = getattr(node, field_name)
                new_list = []
                changed = False
                for item in items:
                    new_tuple = []
                    tuple_changed = False
                    for elem in item:
                        if isinstance(elem, Node):
                            replacement = self.visit(elem)
                            if replacement is not None:
                                replacement.parent = node
                                new_tuple.append(replacement)
                                tuple_changed = True
                            else:
                                new_tuple.append(elem)
                        else:
                            new_tuple.append(elem)
                    new_list.append(tuple(new_tuple) if tuple_changed else item)
                    changed = changed or tuple_changed
                if changed:
                    setattr(node, field_name, new_list)
                    self.mark_changed()
        return None


def _replace_in_parent(old: Node, new: Node):
    """
    Replace `old` with `new` in `old`'s parent node. Sets `new.parent` and handles direct fields,
    list items, and tuple-in-list items.
    """
    parent = old.parent
    if parent is None:
        return
    new.parent = parent
    for attr_name in vars(parent):
        if attr_name in _SKIP_FIELDS:
            continue
        value = getattr(parent, attr_name)
        if value is old:
            setattr(parent, attr_name, new)
            return
        if isinstance(value, list):
            for i, item in enumerate(value):
                if item is old:
                    value[i] = new
                    return
                if isinstance(item, tuple):
                    lst = list(item)
                    for j, elem in enumerate(lst):
                        if elem is old:
                            lst[j] = new
                            value[i] = tuple(lst)
                            return


def _remove_from_parent(node: Node) -> bool:
    """
    Remove `node` from its parent's child list. Returns True if the node was found and removed.
    Uses identity comparison to avoid removing structurally equal but distinct nodes.
    """
    parent = node.parent
    if parent is None:
        return False
    for attr_name in vars(parent):
        if attr_name in _SKIP_FIELDS:
            continue
        value = getattr(parent, attr_name)
        if isinstance(value, list):
            for i, item in enumerate(value):
                if item is node:
                    del value[i]
                    return True
    return False


_N = TypeVar('_N', bound='Node')


def _clone_node(node: _N) -> _N:
    """
    Deep-clone a node tree downward without following parent pointers.
    """
    clone = copy.copy(node)
    clone.parent = None
    for field_name, kind in _classify_fields(type(node)):
        if kind == Kind.ChildNode:
            value = getattr(node, field_name)
            if isinstance(value, Node):
                child = _clone_node(value)
                child.parent = clone
                setattr(clone, field_name, child)
        elif kind == Kind.ChildList:
            items = getattr(node, field_name)
            cloned = []
            for item in items:
                if isinstance(item, Node):
                    child = _clone_node(item)
                    child.parent = clone
                    cloned.append(child)
                else:
                    cloned.append(item)
            setattr(clone, field_name, cloned)
        elif kind == Kind.TupleList:
            items = getattr(node, field_name)
            cloned = []
            for tup in items:
                new_tup = []
                for elem in tup:
                    if isinstance(elem, Node):
                        child = _clone_node(elem)
                        child.parent = clone
                        new_tup.append(child)
                    else:
                        new_tup.append(elem)
                cloned.append(tuple(new_tup))
            setattr(clone, field_name, cloned)
    return clone


class Synthesizer(Visitor):
    """
    Base class for AST-to-source synthesizers. Provides indentation-aware output buffering shared
    by all language-specific synthesizers.
    """

    def __init__(self, indent: str = '  '):
        super().__init__()
        self._indent = indent
        self._depth = 0
        self._parts = io.StringIO()

    def convert(self, node: Node) -> str:
        self._parts.seek(0)
        self._parts.truncate(0)
        self._depth = 0
        self.visit(node)
        return self._parts.getvalue()

    def _write(self, text: str):
        self._parts.write(text)

    def _newline(self):
        self._parts.write('\n')
        self._parts.write(self._indent * self._depth)

    def generic_visit(self, node: Node):
        raise LookupError(F'no synthesizer visit method for {type(node).__name__}')
