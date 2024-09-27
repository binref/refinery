#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
            yield UnpackResult('/'.join(parts), extract, **node.attributes)
            for child in node.children:
                yield from walk(child, *parts, path(child))

        yield from walk(root, path(root))
