#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import List, Optional, Dict
from collections import defaultdict, Counter

from refinery.lib.structures import MemoryFile
from refinery.lib.meta import metavars
from refinery.lib import xml
from refinery.units.sinks.ppxml import ppxml
from refinery.units.formats import Arg, PathExtractorUnit, UnpackResult

import re


class xtxml(PathExtractorUnit):
    """
    Extract values from an XML document.
    """
    def __init__(
        self, *paths,
        format: Arg('-f', type=str, metavar='F', help=(
            'A format expression to be applied for computing the path of an item. This must use '
            'metadata that is available on the item. The current tag can be accessed as {0}. If '
            'no format is specified, the unit attempts to derive a good attribute from the XML '
            'tree to use for generating paths.'
        )) = None,
        **keywords
    ):
        super().__init__(*paths, format=format, **keywords)

    @staticmethod
    def _normalize_val(attribute: str):
        return re.sub('[/\\$\.]+', '.', attribute)

    @staticmethod
    def _normalize_key(attribute: str):
        _, _, a = attribute.rpartition(':')
        return a

    def _path_defining_attribute(self, node: xml.XMLNode):
        def walk(node: xml.XMLNode):
            total = 1
            for key, val in node.attributes.items():
                val = self._normalize_val(val)
                key = self._normalize_key(key)
                if val not in seen and re.fullmatch(R'[-\w+,.;@\]\[{}]{1,64}', val):
                    counter[key] += 1
                    seen.add(val)
            for child in node.children:
                total += walk(child)
            return total
        seen = set()
        counter = Counter()
        total = walk(node)
        if not counter:
            return None
        best, count = counter.most_common(1)[0]
        if 3 * count > 2 * total:
            return best

    def unpack(self, data):
        meta = metavars(data)
        nfmt = self.args.format
        nkey = self._normalize_key
        nval = self._normalize_val

        root = xml.parse(data)
        name = root.tag or 'xml'

        pdef = self._path_defining_attribute(root)

        def path(node: xml.XMLNode, index: Optional[int] = None):
            attrs = {nkey(key): nval(val) for key, val in node.attributes.items()}
            if nfmt and meta:
                try:
                    return meta.format_str(nfmt, self.codec, node.tag, **attrs)
                except KeyError:
                    pass
            if pdef is not None and pdef in attrs:
                return attrs[pdef]
            if index is not None:
                return F'{node.tag}({index})'
            return node.tag

        def walk(node: xml.XMLNode, *parts: str):
            def extract(node: xml.XMLNode = node):
                if not node.children:
                    return node.content.encode(self.codec)
                with MemoryFile() as stream:
                    node.write(stream)
                    return bytes(stream.getbuffer() | ppxml)
            children_by_tag: Dict[str, List[xml.XMLNode]] = defaultdict(list)
            for child in node.children:
                children_by_tag[child.tag].append(child)
            yield UnpackResult('/'.join(parts), extract, **node.attributes)
            for children in children_by_tag.values():
                if len(children) == 1:
                    child = children[0]
                    yield from walk(child, *parts, path(child))
                    continue
                for k, child in enumerate(children):
                    yield from walk(child, *parts, path(child, k))

        yield from walk(root, name)
