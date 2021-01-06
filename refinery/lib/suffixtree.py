#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This module contains an implementation of Ukkonen's suffix tree algorithm.
"""
from __future__ import annotations

from abc import ABCMeta
from io import BytesIO
from typing import Any, ByteString, Iterable, List, Dict, Optional


class NodeMeta(ABCMeta):
    def __new__(mcls, name, bases, namespace: Dict[str, Any]):
        namespace.setdefault('__slots__', tuple(namespace.get('__annotations__', ())))
        return ABCMeta.__new__(mcls, name, bases, namespace)


class Node(metaclass=NodeMeta):
    children: Dict[int, Node]
    end: int
    link: Optional[Node]
    start: int
    tree: SuffixTree

    def __init__(self, tree: SuffixTree):
        self.tree = tree
        self.link = None
        self.children = {}

    @property
    def label(self) -> ByteString:
        return self.tree.data[self.start:self.end + 1]

    @property
    def rootpath(self) -> Iterable[Node]:
        if self.link is None:
            return
        yield from self.link.rootpath
        yield self

    def visualize(self, depth=0, **kwargs):
        r = repr(self)
        print(r.rjust(len(r) + depth * 2), **kwargs)
        for child in self.children.values():
            child.visualize(depth + 1, **kwargs)

    @property
    def depth(self) -> int:
        if self.link is None:
            return 0
        return 1 + self.link.depth

    @property
    def suffix(self) -> bytes:
        with BytesIO() as stream:
            for node in self.rootpath:
                stream.write(node.label)
            return stream.getvalue()

    def fixlinks(self):
        for child in self.children.values():
            child.fixlinks()
            child.link = self

    def __repr__(self) -> str:
        label = bytes(self.label).decode('utf8', errors='backslashreplace')
        if label: label = F': {label}'
        return F'<{self.__class__.__name__}{label}>'

    def __iter__(self) -> Iterable[Node]:
        yield from self.children.values()


class Link(Node):

    def __init__(self, tree: SuffixTree, start=None, end=None):
        Node.__init__(self, tree)
        self.start = start
        self.link = tree.root
        self.end = end


class Leaf(Node):
    def __init__(self, tree: SuffixTree, start=None):
        Node.__init__(self, tree)
        self.start = start
        self.link = tree.root

    @property
    def end(self): return self.tree.cursor


class Root(Node):
    def __init__(self, tree: SuffixTree):
        Node.__init__(self, tree)
        self.start = self.end = -1


class SuffixTree:
    root: Root
    data: ByteString
    cursor: int

    def __init__(self, data: ByteString):
        self.data = memoryview(data)
        self.root = Root(self)

        self.half = None
        self.node = self.root
        self.end = None
        self.suffix_left = 0
        self.length_left = 0
        self.leaves: List[Leaf] = []

        for self.cursor in range(len(self.data)):
            self.extend()

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

    def sprout(self) -> Leaf:
        leaf = Leaf(self, self.cursor)
        self.leaves.append(leaf)
        return leaf

    def extend(self):
        self.suffix_left += 1
        self.half = None

        while self.suffix_left > 0:

            if not self.length_left:
                self.end = self.cursor

            bridge = self.node.children.get(self.data[self.end])

            if bridge:
                if self.traversable(bridge):
                    continue
                if self.data[bridge.start + self.length_left] == self.data[self.cursor]:
                    if self.half is not None and self.node != self.root:
                        self.half.link = self.node
                        self.half = None
                    self.length_left += 1
                    break
                split = Link(self, bridge.start, bridge.start + self.length_left - 1)
                self.node.children[self.data[self.end]] = split
                split.children[self.data[self.cursor]] = self.sprout()
                bridge.start += self.length_left
                split.children[self.data[bridge.start]] = bridge
                if self.half:
                    self.half.link = split
                self.half = split
            else:
                self.node.children[self.data[self.end]] = self.sprout()
                if self.half:
                    self.half.link = self.node
                    self.half = None

            self.suffix_left -= 1

            if self.node is not self.root:
                self.node = self.node.link
            elif self.length_left:
                self.length_left -= 1
                self.end = self.cursor - self.suffix_left + 1
