#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.compression.zl import zl
from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.lib.meta import SizeInt
from refinery.lib.dotnet.types import (
    Byte,
    StreamReader,
    StringPrimitive,
    UInt32,
    UInt64,
    ParserEOF
)


class dnsfx(PathExtractorUnit):
    """
    Extracts files from .NET single file applications.
    """
    _SIGNATURE = bytes([
        # 32 bytes represent the bundle signature: SHA-256 for '.net core bundle'
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
        0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18,
        0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae
    ])

    def unpack(self, data):
        reader = StreamReader(data)
        reader.seek(self._find_bundle_manifest_offset(data))

        major_version = reader.expect(UInt32)
        minor_version = reader.expect(UInt32)
        self.log_info(F'version {major_version}.{minor_version}')

        count = reader.expect(UInt32)
        bhash = reader.expect(StringPrimitive)
        self.log_info(F'bundle {bhash} contains {count} files')

        if major_version >= 2:
            reader.expect(UInt64) # depsOffset
            reader.expect(UInt64) # depsSize
            reader.expect(UInt64) # runtimeConfigOffset
            reader.expect(UInt64) # runtimeConfigSize
            reader.expect(UInt64) # flags

        for _ in range(count):
            try:
                offset = reader.expect(UInt64)
                size = reader.expect(UInt64)
                compressed_size = 0
                if major_version >= 6:
                    compressed_size = reader.expect(UInt64)
                type = reader.expect(Byte)
                path = reader.expect(StringPrimitive)

                def _logmsg():
                    _log = F'read item at offset 0x{offset:08X}, type 0x{type:02X}, size {SizeInt(size)!r}'
                    if compressed_size:
                        return F'{_log}, compressed to size {SizeInt(compressed_size)!r}'
                    return F'{_log}, uncompressed'

                self.log_debug(_logmsg)

                with reader.checkpoint():
                    reader.seek(offset)
                    if compressed_size:
                        item_data = reader.read(compressed_size) | zl | bytearray
                    else:
                        item_data = reader.read(size)

                yield UnpackResult(path, item_data)
            except ParserEOF:
                self.log_warn('unexpected EOF while parsing bundle, terminating')
                break

    def _find_bundle_manifest_offset(self, data: bytearray) -> int:
        bundle_sig_offset = data.find(self._SIGNATURE, 0)
        if bundle_sig_offset < 0:
            raise ValueError('Cannot find valid Bundle Manifest offset. Is this a .NET Bundle?')
        return int.from_bytes(data[bundle_sig_offset - 8:bundle_sig_offset], 'little')

    @classmethod
    def handles(self, data: bytearray):
        return self._SIGNATURE in data
