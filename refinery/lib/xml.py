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
import collections

from typing import Any, Dict, Iterable, List, Optional, TYPE_CHECKING
from xml.parsers import expat
from xml.etree.ElementTree import Element, ElementTree

from refinery.lib.structures import MemoryFile
from refinery.lib.tools import exception_to_string
from refinery.lib.types import ByteStr

if TYPE_CHECKING:
    from typing import Self


def is_xml(data: ByteStr, default=True):
    """
    Implements a heuristic check for whether the input is likely XML data.
    """
    _be = data[0:120:2]
    _le = data[1:120:2]
    if isinstance(data, memoryview):
        _le = bytes(_le)
        _be = bytes(_be)
    if _le.count(0) > 100:
        data = _be
    if _be.count(0) > 100:
        data = _le
    if tag_match := re.search(BR'''(?x)
        ^(?:            # at the very start of the document
         \xef\xbb\xbf   # utf-8 byte order mark
        |\xfe           # (utf-16be)
        |\xff)?         # (utf-16le)
        \s{0,10}        # allow for some leading white space
        <               # a tag opens
        ([?!]?          # allow for question or exclamation mark
         [-:\w]{3,64})  # the tag name
        \s{1,20}        # white space after tag name
        (/?>            # the tag may end here, or:
        |[-:\w]{3,32})  # we have an attribute.
    ''', data):
        tag = tag_match[1].lower()
        end = tag_match[2].lower()
        # <?xml...
        if tag == B'?xml':
            return True
        # <HTML>
        # <BODY>
        if tag in (B'html', B'body'):
            return False
        # <!DOCTYPE html
        if tag == '!doctype' and end == B'html':
            return False
        # <project xmlns:xsi=...
        if end.startswith(b'xml'):
            return True
        # inconclusive, return default
        return default
    else:
        return False


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

    __slots__ = 'tag', 'index', 'children', 'empty', 'attributes', 'content', '_parent', '__weakref__'

    attributes: Dict[str, Any]
    children: List[Self]
    content: Optional[str]
    parent: Optional[weakref.ProxyType[Self]]
    subtree: Iterable[Self]
    empty: bool
    tag: Optional[str]

    def __init__(
        self,
        tag: Optional[str],
        index: Optional[int] = None,
        parent: Optional[Self] = None,
        content: Optional[str] = None,
        empty: bool = False,
        attributes: Optional[Dict[str, Any]] = None,
    ):
        if parent is None and index is not None:
            raise ValueError('Cannot set index for XML node without parent.')
        if attributes is None:
            attributes = {}
        self.tag = tag
        self.index = index
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

    def __eq__(self, other: XMLNodeBase):
        return self.parent == other.parent and self.tag == other.tag and self.index == other.index

    @property
    def basename(self):
        name = self.tag
        if self.index is not None:
            name = F'{name}[{self.index}]'
        return name

    @property
    def path(self):
        name = self.basename
        if self.parent is None:
            return name
        return F'{self.parent.path}/{name}'

    def __repr__(self):
        return F'<{self.__class__.__name__}:{self.path}>'

    def __iter__(self):
        return iter(self.children)

    def __getitem__(self, key):
        return self.attributes[key]

    def get_attribute(self, key, default=None):
        return self.attributes.get(key, default)

    def reindex(self):
        """
        Computes the index values of all nodes in the subtree.
        """
        pre_count = collections.Counter(child.tag for child in self.children)
        tag_count = collections.Counter()
        for child in self.children:
            tag = child.tag
            if pre_count[tag] == 1:
                child.index = None
            else:
                tag_count[tag] += 1
                child.index = tag_count[tag]
            child.reindex()

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
    def subtree(self) -> Iterable[Self]:
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

    def __init__(self, tag: str, parent: Optional[Self] = None, source: Optional[Element] = None):
        super().__init__(tag, parent=parent)
        self.source = source

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
            tag = child.tag
            node = XMLNode(tag, cursor, child)
            translate(child, node, level + 1)
            cursor.children.append(node)
        cursor.attributes = element.attrib
        cursor.content = element.text or element.tail or ''
        return cursor
    root = ForgivingParse(data).getroot()
    rt = translate(root, XMLNode(root.tag))
    rt.source = root
    rt.reindex()
    return rt
