from __future__ import annotations

from refinery.lib import xml
from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.units.formats.office.xtdoc import xtdoc


class docmeta(PathExtractorUnit):
    """
    Extract metadata from Word Documents such as custom document properties.
    """
    @PathExtractorUnit.Requires('olefile', ['formats', 'office'])
    def _olefile():
        import olefile
        return olefile

    def unpack(self, data: bytearray):
        properties, = data | xtdoc('docProps/custom.xml')
        if not properties:
            return
        if dom := xml.parse(properties):
            while dom.tag.lower() != 'properties':
                dom = dom.children[0]
            for node in dom:
                assert node.tag.lower() == 'property'
                assert len(node.children) == 1
                content = node.children[0].content
                assert content is not None
                yield UnpackResult(node.attributes['name'], content.encode(self.codec))
