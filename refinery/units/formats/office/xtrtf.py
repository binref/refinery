from __future__ import annotations

from refinery.lib.id import buffer_offset
from refinery.lib.ole.rtf import RtfObjParser
from refinery.units.formats import PathExtractorUnit, UnpackResult


class xtrtf(PathExtractorUnit):
    """
    Extract embedded objects in RTF documents.
    """
    def unpack(self, data):
        parser = RtfObjParser(data)
        width = len(str(len(parser.objects)))
        for k, item in enumerate(parser.objects):
            path = item.filename or F'carve{k:0{width}}.bin'
            data = item.rawdata
            meta = {}
            if item.is_ole:
                if format_id := item.format_id:
                    meta['ole_type'] = format_id.name
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
                    pos = buffer_offset(item.oledata, data)
                    if pos >= 0:
                        meta['ole_header'] = item.oledata[:pos]
            yield UnpackResult(path, data, **meta)

    @classmethod
    def handles(cls, data) -> bool:
        import re
        return bool(re.search(bR'^\s{0,500}\{\\rtf', memoryview(data)[:505]))
