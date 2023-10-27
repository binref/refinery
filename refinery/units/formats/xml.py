#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from collections import Counter

from refinery.lib.structures import MemoryFile
from refinery.lib.meta import metavars
from refinery.lib import xml
from refinery.units.sinks.ppxml import ppxml
from refinery.units.formats import XMLToPathExtractorUnit, UnpackResult


class xtxml(XMLToPathExtractorUnit):
    """
    Extract values from an XML document.
    """
    def unpack(self, data):
        root = xml.parse(data.strip())
        meta = metavars(data)
        path = self._make_path_builder(meta, root)

        def walk(node: xml.XMLNode, *parts: str):
            def extract(node: xml.XMLNode = node):
                if not node.children:
                    return node.content.encode(self.codec)
                with MemoryFile() as stream:
                    node.write(stream)
                    return bytes(stream.getbuffer() | ppxml)
            tag_pre_count = Counter()
            tag_run_count = Counter()
            for child in node.children:
                tag_pre_count[child.tag] += 1
            yield UnpackResult('/'.join(parts), extract, **node.attributes)
            for child in node.children:
                if tag_pre_count[child.tag] == 1:
                    yield from walk(child, *parts, path(child))
                    continue
                tag_run_count[child.tag] += 1
                index = tag_run_count[child.tag]
                yield from walk(child, *parts, path(child, index))

        yield from walk(root, path(root))
