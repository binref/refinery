#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from collections import defaultdict

from ...lib.structures import MemoryFile
from ...lib import xml
from ..sinks.ppxml import ppxml

from . import PathExtractorUnit, UnpackResult


class xtxml(PathExtractorUnit):
    """
    Extract values from an XML document.
    """
    _STRICT_PATH_MATCHING = True

    def unpack(self, data):
        def walk(node: xml.XMLNode, *path: str):
            def extract(node: xml.XMLNode = node):
                if not node.children:
                    return node.content.encode(self.codec)
                with MemoryFile() as stream:
                    node.write(stream)
                    return bytes(stream.getbuffer() | ppxml)
            children_by_tag = defaultdict(list)
            for child in node.children:
                children_by_tag[child.tag].append(child)
            yield UnpackResult('/'.join(path), extract, **node.attributes)
            for tag, children in children_by_tag.items():
                if len(children) == 1:
                    yield from walk(children[0], *path, tag)
                    continue
                width = len(F'{len(children):X}')
                for k, child in enumerate(children):
                    yield from walk(child, *path, F'{tag}[0x{k:0{width}X}]')
        root = xml.parse(data)
        name = root.tag or 'xml'
        yield from walk(root, name)
