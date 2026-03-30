"""
Minimal unified AST base for script parsers. Provides abstract node types shared
across language-specific parsers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Generator


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
        stack = [self]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(list(node.children())))

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

    def visit(self, node: Node):
        name = F'visit_{type(node).__name__}'
        handler = getattr(self, name, self.generic_visit)
        return handler(node)

    def generic_visit(self, node: Node):
        for child in node.children():
            self.visit(child)


class Transformer(Visitor):
    """
    In-place tree rewriter. Each visit method may return a replacement node
    or None to keep the original.
    """

    def generic_visit(self, node: Node):
        for attr_name in list(vars(node)):
            if attr_name in ('parent', 'offset'):
                continue
            value = getattr(node, attr_name)
            if isinstance(value, Node):
                replacement = self.visit(value)
                if replacement is not None:
                    replacement.parent = node
                    setattr(node, attr_name, replacement)
            elif isinstance(value, list):
                new_list = []
                for item in value:
                    if isinstance(item, Node):
                        replacement = self.visit(item)
                        result = item if replacement is None else replacement
                        result.parent = node
                        new_list.append(result)
                    elif isinstance(item, tuple):
                        new_tuple = []
                        for elem in item:
                            if isinstance(elem, Node):
                                replacement = self.visit(elem)
                                result = elem if replacement is None else replacement
                                result.parent = node
                                new_tuple.append(result)
                            else:
                                new_tuple.append(elem)
                        new_list.append(tuple(new_tuple))
                    else:
                        new_list.append(item)
                setattr(node, attr_name, new_list)
        return None
