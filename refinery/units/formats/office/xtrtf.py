#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import TYPE_CHECKING
from refinery.units.formats import PathExtractorUnit, UnpackResult

if TYPE_CHECKING:
    from oletools.rtfobj import RtfObject


class xtrtf(PathExtractorUnit):
    """
    Extract embedded objects in RTF documents.
    """
    @PathExtractorUnit.Requires('oletools', 'formats', 'office')
    def _oletools():
        import oletools
        import oletools.rtfobj
        import oletools.oleobj
        return oletools

    def unpack(self, data):
        parser = self._oletools.rtfobj.RtfObjParser(data)
        parser.parse()
        width = len(str(len(parser.objects)))
        for k, item in enumerate(parser.objects):
            item: RtfObject
            path = item.filename or F'carve{k:0{width}}.bin'
            data = item.rawdata
            meta = {}
            if item.is_ole:
                if item.format_id == self._oletools.oleobj.OleObject.TYPE_EMBEDDED:
                    meta['ole_type'] = 'EMBEDDED'
                elif item.format_id == self._oletools.oleobj.OleObject.TYPE_LINKED:
                    meta['ole_type'] = 'LINKED'
                if item.is_package:
                    meta['src_path'] = item.src_path
                    meta['tmp_path'] = item.temp_path
                if item.clsid is not None:
                    meta['ole_info'] = item.clsid_desc
                    meta['ole_guid'] = item.clsid
                meta['ole_name'] = item.class_name
            if item.oledata:
                data = item.oledata
                pos = item.rawdata.find(data)
                if pos > 0:
                    meta['raw_header'] = item.rawdata[:pos]
                if item.olepkgdata:
                    data = item.olepkgdata
                    pos = item.oledata.find(data)
                    if pos >= 0:
                        meta['ole_header'] = item.oledata[:pos]
            yield UnpackResult(path, data, **meta)

    @classmethod
    def handles(self, data: bytearray) -> bool:
        return data[:500].lower().lstrip().startswith(b'{\\rtf')
