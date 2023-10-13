#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List
from collections import defaultdict

from refinery.lib.structures import MemoryFile
from refinery.lib import xml
from refinery.units.sinks.ppxml import ppxml
from refinery.units.formats import PathExtractorUnit, UnpackResult


class xtxml(PathExtractorUnit):
    """
    Extract values from an XML document.
    """
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
                children: List[xml.XMLNode]
                if len(children) == 1:
                    child = children[0]
                    item = self._format_path(tag, tag=child.tag, **child.attributes)
                    yield from walk(child, *path, tag)
                    continue
                width = len(F'{len(children):X}')
                for k, child in enumerate(children):
                    item = self._format_path(F'{tag}[0x{k:0{width}X}]', tag=child.tag, **child.attributes)
                    yield from walk(child, *path, item)
        root = xml.parse(data)
        name = root.tag or 'xml'
        yield from walk(root, name)
