"""
This module contains an implementation of Ukkonen's suffix tree algorithm.
"""
from __future__ import annotations

import weakref

from abc import ABCMeta
from collections import deque
from io import BytesIO

from refinery.lib.types import Iterable, Self, buf


class NodeMeta(ABCMeta):
    def __new__(mcls, name, bases, namespace: dict):
        namespace.setdefault('__slots__', tuple(namespace.get('__annotations__', ())))
        return ABCMeta.__new__(mcls, name, bases, namespace)


class Node(metaclass=NodeMeta):
    """
    A node of a `refinery.lib.suffixtree.SuffixTree`. While the tree is built, `link` is the suffix
    link of the node. Once it is built, a node refers to its parent only weakly, so that the tree
    forms no reference cycle: The tree has to be kept while the paths of its nodes are read.
    """
    children: dict[int, Self]
    end: int
    link: Node | None
    start: int
    data: memoryview
    _parent: weakref.ReferenceType[Node] | None

    __slots__ = ('children', 'end', 'link', 'start', 'data', '_parent', '__weakref__')

    def __init__(self, data: memoryview):
        self.data = data
        self.link = None
        self.children = {}
        self._parent = None

    @property
    def parent(self) -> Node | None:
        if (ref := self._parent) is None:
            return None
        if (parent := ref()) is None:
            raise RuntimeError('The suffix tree of this node was freed; keep the tree while reading paths of its nodes.')
        return parent

    @property
    def label(self) -> buf:
        return self.data[self.start:self.end + 1]

    @property
    def rootpath(self) -> Iterable[Node]:
        if (parent := self.parent) is None:
            return
        yield from parent.rootpath
        yield self

    def visualize(self, depth=0, **kwargs):
        r = repr(self)
        print(r.rjust(len(r) + depth * 2), **kwargs)
        for child in self.children.values():
            child.visualize(depth + 1, **kwargs)

    @property
    def depth(self) -> int:
        if (parent := self.parent) is None:
            return 0
        return 1 + parent.depth

    @property
    def suffix(self) -> bytes:
        with BytesIO() as stream:
            for node in self.rootpath:
                stream.write(node.label)
            return stream.getvalue()

    def fixlinks(self):
        """
        Replaces the suffix links of this node and all nodes below it by weak references to their
        parents.
        """
        self.link = None
        queue = deque([self])
        while queue:
            node = queue.pop()
            for child in node.children.values():
                queue.appendleft(child)
                child.link = None
                child._parent = weakref.ref(node)

    def __repr__(self) -> str:
        label = bytes(self.label).decode('utf8', errors='backslashreplace')
        label = label and F': {label}'
        return F'<{self.__class__.__name__}{label}>'

    def __iter__(self) -> Iterable[Node]:
        yield from self.children.values()


class Link(Node):

    def __init__(self, data: memoryview, root: Root, start=None, end=None):
        Node.__init__(self, data)
        self.start = start
        self.link = root
        self.end = end


class Leaf(Node):
    """
    A leaf ends where the tree's cursor is: at the last byte of the data once the tree is built.
    """
    cursor: list[int]

    def __init__(self, data: memoryview, root: Root, cursor: list[int], start=None):
        Node.__init__(self, data)
        self.start = start
        self.link = root
        self.cursor = cursor

    @property
    def end(self):
        return self.cursor[0]


class Root(Node):
    def __init__(self, data: memoryview):
        Node.__init__(self, data)
        self.start = self.end = -1


class SuffixTree:
    root: Root
    data: memoryview

    def __init__(self, data: buf):
        self.data = memoryview(data)
        self.root = Root(self.data)

        self.half = None
        self.node = self.root
        self.end = None
        self.suffix_left = 0
        self.length_left = 0
        self.leaves: list[Leaf] = []
        self._cursor = [0]

        for cursor in range(len(self.data)):
            self._cursor[0] = cursor
            self.extend(cursor)

        del self.suffix_left
        del self.length_left
        del self.end
        del self.node
        del self.half

        self.root.fixlinks()

    def __iter__(self) -> Iterable[Node]:
        yield from self.root.children.values()

    def traversable(self, node):
        length = node.end - node.start + 1
        if self.length_left < length:
            return False
        self.node = node
        self.end += length
        self.length_left -= length
        return True

    def sprout(self, cursor: int) -> Leaf:
        leaf = Leaf(self.data, self.root, self._cursor, cursor)
        self.leaves.append(leaf)
        return leaf

    def extend(self, cursor: int):
        self.suffix_left += 1
        self.half = None

        while self.suffix_left > 0:

            if not self.length_left:
                self.end = cursor

            bridge = self.node.children.get(self.data[self.end])

            if bridge:
                if self.traversable(bridge):
                    continue
                if self.data[bridge.start + self.length_left] == self.data[cursor]:
                    if self.half is not None and self.node != self.root:
                        self.half.link = self.node
                        self.half = None
                    self.length_left += 1
                    break
                split = Link(self.data, self.root, bridge.start, bridge.start + self.length_left - 1)
                self.node.children[self.data[self.end]] = split
                split.children[self.data[cursor]] = self.sprout(cursor)
                bridge.start += self.length_left
                split.children[self.data[bridge.start]] = bridge
                if self.half:
                    self.half.link = split
                self.half = split
            else:
                self.node.children[self.data[self.end]] = self.sprout(cursor)
                if self.half:
                    self.half.link = self.node
                    self.half = None

            self.suffix_left -= 1

            if self.node is not self.root:
                self.node = self.node.link
            elif self.length_left:
                self.length_left -= 1
                self.end = cursor - self.suffix_left + 1
