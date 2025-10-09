from __future__ import annotations

from refinery.lib import xml
from refinery.lib.id import is_likely_xml
from refinery.lib.meta import is_valid_variable_name, metavars
from refinery.lib.structures import MemoryFile
from refinery.units.formats import UnpackResult, XMLToPathExtractorUnit
from refinery.units.sinks.ppxml import ppxml


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
                    return bytes(stream.getvalue() | ppxml)

            attributes = {
                self._normalize_key(k): self._normalize_val(v)
                for k, v in node.attributes.items()
            }

            if not all(is_valid_variable_name(k) for k in attributes):
                attributes = {F'_{k}': v for k, v in attributes.items()}

            yield UnpackResult('/'.join(parts), extract, **attributes)

            for child in node.children:
                yield from walk(child, *parts, path(child))

        yield from walk(root, path(root))

    @classmethod
    def handles(cls, data):
        return is_likely_xml(data)
