from __future__ import annotations

import json

from typing import Dict, Type, Union

from refinery.lib.structures import Struct, StructReader
from refinery.units.formats.archive import ArchiveUnit, UnpackResult

JSONDict = Dict[str, Union[int, float, str, Type[None], 'JSONDict']]


class AsarHeader(Struct):
    def __init__(self, reader: StructReader[bytearray]):
        if reader.u32() != 4:
            raise ValueError('Not an ASAR file.')
        size = reader.u32() - 8
        reader.seekrel(8)
        directory = reader.read(size)
        end = directory.rfind(B'}')
        if end < 0:
            raise RuntimeError('Directory not terminated')
        directory[end:] = []
        bl = directory.count(B'{'[0])
        br = directory.count(B'}'[0])
        if br < bl:
            directory += (bl - br) * B'}'
        self.directory = json.loads(directory)
        self.base = reader.tell()


class xtasar(ArchiveUnit, docs='{0}{s}{PathExtractorUnit}'):
    """
    Extract files from Atom Shell Archives (ASAR). These are often used to bundle Electron application
    data and resources.
    """
    def unpack(self, data: bytearray):
        def _unpack(dir: JSONDict, *path):
            for name, listing in dir.get('files', {}).items():
                yield from _unpack(listing, *path, name)
            try:
                offset = dir['offset']
                size = dir['size']
            except KeyError:
                return
            try:
                offset = int(offset) + header.base
                end = int(size) + offset
            except TypeError:
                self.log_warn(F'unable to convert offset "{offset}" and size "{size}" to integers')
                return
            if not path:
                self.log_warn(F'not processing item at root with offset {offset} and size {size}')
                return
            yield UnpackResult(
                '/'.join(path),
                lambda a=offset, b=end: data[a:b],
                offset=offset
            )

        header = AsarHeader.Parse(data)
        self.log_debug(F'header read successfully, base offset is {header.base}.')
        yield from _unpack(header.directory)

    @classmethod
    def handles(cls, data) -> bool | None:
        return data[:4] == b'\04\0\0\0' and data[0x10:0x18] == B'{"files"'
