from __future__ import annotations

import zlib

from refinery.lib import json
from refinery.lib.id import Fmt, buffer_offset, get_image_format
from refinery.lib.png import Png, PngChunkType
from refinery.lib.structures import struct_to_json
from refinery.units.formats import PathExtractorUnit, UnpackResult


class png(PathExtractorUnit):
    """
    Extract raw data chunks from a PNG image.

    Parses the PNG chunk structure to recover image data segments, text metadata, and
    ancillary chunks such as eXIf, iCCP, and tIME.
    """
    def unpack(self, data):
        image = Png.Parse(memoryview(data))
        for k, chunk in enumerate(image.chunks):
            yield UnpackResult(F'chunks/{k}.{chunk.type_name}', chunk.data)
        for k, chunk in enumerate(image.text_chunks):
            text_data = chunk.data
            if chunk.type == PngChunkType.tEXt:
                sep = buffer_offset(text_data, B'\0')
                if sep >= 0:
                    text_data = text_data[sep + 1:]
            elif chunk.type == PngChunkType.zTXt:
                sep = buffer_offset(text_data, B'\0')
                if sep >= 0:
                    compression = text_data[sep + 1]
                    if compression == 0:
                        def _text_data(t=text_data[sep + 2:]):
                            return zlib.decompress(t)
                        text_data = _text_data
            elif chunk.type == PngChunkType.iTXt:
                sep = buffer_offset(text_data, B'\0')
                if sep >= 0 and len(rest := text_data[sep + 1:]) >= 2:
                    compressed = rest[0]
                    method = rest[1]
                    rest = rest[2:]
                    sep2 = buffer_offset(rest, B'\0')
                    if sep2 >= 0:
                        rest = rest[sep2 + 1:]
                        sep3 = buffer_offset(rest, B'\0')
                        if sep3 >= 0:
                            rest = rest[sep3 + 1:]
                    if compressed and method == 0:
                        def _text_data(t=rest):
                            return zlib.decompress(t)
                        text_data = _text_data
                    else:
                        text_data = rest
            yield UnpackResult(F'text/{k}', text_data)
        for k, chunk in enumerate(image.meta_chunks):
            yield UnpackResult(F'meta/{k}.{chunk.type_name}', chunk.data)
        if image.ihdr:
            yield UnpackResult('meta/dimensions.json', json.dumps(struct_to_json(image.ihdr)))

    @classmethod
    def handles(cls, data) -> bool:
        return get_image_format(data) == Fmt.PNG
