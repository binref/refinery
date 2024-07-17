#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Custom XML parser that is intended to be less strict than the standard library one.
"""
from __future__ import annotations

import uuid
import weakref
import re
import defusedxml.ElementTree as et

from typing import Any, Dict, Iterable, List, Optional
from xml.parsers import expat
from xml.etree.ElementTree import Element, ElementTree

from refinery.lib.structures import MemoryFile
from refinery.lib.tools import exception_to_string


def ForgivingParse(data: bytes, entities=None) -> ElementTree:
    """
    Uses the `refinery.lib.xml.ForgivingXMLParser` to parse the input data.
    """
    try:
        codec = re.search(rb'^\s*<\?xml[^>]+?encoding="?([-\w]+)"?', data)
        data = data.decode('utf8').encode(codec[1].decode('utf8'))
    except Exception:
        pass
    try:
        return et.parse(MemoryFile(data), parser=ForgivingXMLParser(entities))
    except et.ParseError as PE:
        raise ValueError(exception_to_string(PE)) from PE


class ForgivingXMLParser(et.XMLParser):
    """
    A custom XML parser that handles unknown XML entities gracefully.
    """

    def __init__(self, emap=None):
        class ForgivingEntityResolver(dict):
            def __getitem__(self, key):
                if key in self:
                    return dict.__getitem__(self, key)
                uid = str(uuid.uuid4())
                self[key] = uid
                if emap is not None:
                    emap[uid] = key
                return uid

        self.__entity = ForgivingEntityResolver()
        _ParserCreate = expat.ParserCreate

        try:
            def PC(encoding, _):
                parser = _ParserCreate(
                    encoding, namespace_separator=None)
                parser.UseForeignDTD(True)
                return parser
            expat.ParserCreate = PC
            super().__init__()
        finally:
            expat.ParserCreate = _ParserCreate

    @property
    def entity(self):
        return self.__entity

    @entity.setter
    def entity(self, value):
        self.__entity.update(value)


class XMLNodeBase:
    """
    Base class for parsed XML nodes. While this is not currently implemented, this would allow for
    different types of XML node classes to represent e.g. leaves / text nodes from others.
    """

    __slots__ = 'tag', 'children', 'empty', 'attributes', 'content', '_parent', '__weakref__'

    attributes: Dict[str, Any]
    children: List[XMLNodeBase]
    content: Optional[str]
    parent: Optional[weakref.ProxyType[XMLNodeBase]]
    subtree: Iterable[XMLNodeBase]
    empty: bool
    tag: Optional[str]

    def __init__(
        self,
        tag: str,
        parent: Optional[XMLNodeBase] = None,
        content: Optional[str] = None,
        empty: bool = False,
        attributes: Optional[Dict[str, Any]] = None,
    ):
        if attributes is None:
            attributes = {}
        self.tag = tag
        self.content = content
        self.empty = empty
        self.children = []
        self.attributes = attributes
        self.parent = parent

    @property
    def parent(self) -> XMLNodeBase:
        parent = self._parent
        if parent is not None:
            parent = parent()
        return parent

    @parent.setter
    def parent(self, parent):
        if parent is not None:
            parent = weakref.ref(parent)
        self._parent = parent

    def __iter__(self):
        return iter(self.children)

    def __getitem__(self, key):
        return self.attributes[key]

    def get_attribute(self, key, default=None):
        return self.attributes.get(key, default)

    def child(self, tag: str):
        """
        Return the first child with the given tag. This is useful especialyl for documents where
        a node has one uniquely defined child with a given tag.
        """
        for child in self.children:
            if child.tag == tag:
                return child
        raise LookupError(tag)

    @property
    def subtree(self) -> Iterable[XMLNodeBase]:
        """
        Iterate all items that are reachable from the current node.
        """
        yield self
        for child in self.children:
            yield from child.subtree

    def __enter__(self):
        return self.subtree

    def __exit__(self, *a):
        return False


class XMLNode(XMLNodeBase):
    """
    This class epresents an XML node in a parsed document.
    """
    __slots__ = 'source',

    source: Optional[Element]

    def __init__(self, tag: str):
        super().__init__(tag)
        self.source = None

    def write(self, stream):
        """
        Write the element tree rooted at this node to the given I/O stream.
        """
        return ElementTree(self.source).write(stream)


def parse(data) -> XMLNode:
    """
    This function is the primary export of the `refinery.lib.xml` module. It accepts raw XML data
    as input and returns an `refinery.lib.xml.XMLNode` representing the document root node as
    output. Internally, it calls `refinery.lib.xml.ForgivingParse` to parse the XML and then adds
    a postprocessing step to put the `refinery.lib.xml.XMLNode` interface on top of the parsed
    tree that is generated by the standard library.
    """
    def translate(element: Element, cursor: XMLNode, level: int = 0):
        for child in element:
            node = XMLNode(child.tag)
            translate(child, node, level + 1)
            node.parent = cursor
            node.source = child
            cursor.children.append(node)
        cursor.attributes = element.attrib
        cursor.content = element.text or element.tail or ''
        return cursor
    root = ForgivingParse(data).getroot()
    rt = translate(root, XMLNode(root.tag))
    rt.source = root
    return rt
