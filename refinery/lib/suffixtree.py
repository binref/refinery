"""
This module contains an implementation of Ukkonen's suffix tree algorithm.
"""
from __future__ import annotations

from abc import ABCMeta
from collections.abc import Iterator

from refinery.lib.types import Self, buf


class NodeMeta(ABCMeta):
    def __new__(mcls, name, bases, namespace: dict):
        namespace.setdefault('__slots__', tuple(namespace.get('__annotations__', ())))
        return ABCMeta.__new__(mcls, name, bases, namespace)


class Source:
    """
    The data of a `refinery.lib.suffixtree.SuffixTree` and the position of the last byte that was
    added to the tree, which is where every leaf ends. The nodes of a tree share it; it refers to
    no node, so that the tree forms no reference cycle.
    """
    __slots__ = 'data', 'end'

    def __init__(self, data: memoryview):
        self.data = data
        self.end = -1


class Node(metaclass=NodeMeta):
    """
    A node of a `refinery.lib.suffixtree.SuffixTree`. The edge to the node spells the data from
    `start` to `end`. While the tree is built, `link` is the suffix link of the node.
    """
    children: dict[int, Self]
    end: int
    link: Node | None
    start: int
    source: Source

    def __init__(self, source: Source):
        self.source = source
        self.link = None
        self.children = {}

    @property
    def label(self) -> buf:
        return self.source.data[self.start:self.end + 1]

    def visualize(self, depth=0, **kwargs):
        r = repr(self)
        print(r.rjust(len(r) + depth * 2), **kwargs)
        for child in self.children.values():
            child.visualize(depth + 1, **kwargs)

    def unlink(self):
        """
        Drops the suffix links of this node and of all nodes below it. They are needed only while
        the tree is built, and they would keep the tree in reference cycles.
        """
        pending = [self]
        while pending:
            node = pending.pop()
            node.link = None
            pending.extend(node.children.values())

    def __repr__(self) -> str:
        label = bytes(self.label).decode('utf8', errors='backslashreplace')
        label = label and F': {label}'
        return F'<{self.__class__.__name__}{label}>'

    def __iter__(self) -> Iterator[Node]:
        yield from self.children.values()


class Link(Node):

    def __init__(self, source: Source, root: Root, start: int, end: int):
        Node.__init__(self, source)
        self.start = start
        self.link = root
        self.end = end


class Leaf(Node):

    def __init__(self, source: Source, root: Root, start: int):
        Node.__init__(self, source)
        self.start = start
        self.link = root

    @property
    def end(self):
        return self.source.end


class Root(Node):
    def __init__(self, source: Source):
        Node.__init__(self, source)
        self.start = self.end = -1


class SuffixTree:
    root: Root
    data: memoryview

    def __init__(self, data: buf):
        self.data = memoryview(data)
        self.source = source = Source(self.data)
        self.root = Root(source)

        self.half = None
        self.node = self.root
        self.end = None
        self.suffix_left = 0
        self.length_left = 0
        self.leaves: list[Leaf] = []

        for cursor in range(len(self.data)):
            source.end = cursor
            self.extend(cursor)

        del self.suffix_left
        del self.length_left
        del self.end
        del self.node
        del self.half

        self.root.unlink()

    def __iter__(self) -> Iterator[Node]:
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
        leaf = Leaf(self.source, self.root, cursor)
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
                split = Link(self.source, self.root, bridge.start, bridge.start + self.length_left - 1)
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
