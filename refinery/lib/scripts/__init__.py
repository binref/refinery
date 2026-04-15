"""
Minimal unified AST base for script parsers. Provides abstract node types shared
across language-specific parsers.
"""
from __future__ import annotations

import dataclasses
import enum
import typing

from dataclasses import dataclass, field
from typing import Callable, Generator

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


def _classify_fields(node_type: type) -> list[tuple[str, Kind]]:
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


@dataclass(repr=False)
class Node:
    """
    Base class for all AST nodes.
    """
    offset: int = -1
    parent: Node | None = field(default=None, compare=False)
    leading_comments: list[str] = field(default_factory=list, compare=False)

    def children(self) -> Generator[Node, None, None]:
        yield from ()

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
        try:
            return self.synthesize()
        except Exception:
            name = type(self).__name__
            return F'{name}@{self.offset}'

    def synthesize(self) -> str:
        from refinery.lib.scripts.ps1.synth import Ps1Synthesizer
        return Ps1Synthesizer().convert(self)


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

    def __post_init__(self):
        self._adopt(*self.body)

    def children(self) -> Generator[Node, None, None]:
        yield from self.body


@dataclass(repr=False)
class Script(Node):
    """
    Top-level node representing an entire script.
    """
    body: list[Statement] = field(default_factory=list)

    def __post_init__(self):
        self._adopt(*self.body)

    def children(self) -> Generator[Node, None, None]:
        yield from self.body


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
