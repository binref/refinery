from __future__ import annotations

from refinery.lib import xml
from refinery.lib.id import is_likely_xml
from refinery.lib.meta import is_valid_variable_name, metavars
from refinery.lib.structures import MemoryFile
from refinery.lib.types import Callable
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
        yield from self._walk(path, root, path(root))

    def _walk(self, path: Callable[[xml.XMLNode], str], node: xml.XMLNode, *parts: str):
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

        if not all(
            is_valid_variable_name(k, allow_derivations=False) for k in attributes
        ):
            attributes = {F'_{k}': v for k, v in attributes.items()}

        yield UnpackResult('/'.join(parts), extract, **attributes)

        for child in node.children:
            yield from self._walk(path, child, *parts, path(child))

    @classmethod
    def handles(cls, data):
        return is_likely_xml(data)
